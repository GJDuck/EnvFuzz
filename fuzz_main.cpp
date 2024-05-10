/*
 *  ____  ____  _____              
 * |  _ \|  _ \|  ___|   _ ________
 * | |_) | |_) | |_ | | | |_  /_  /
 * |  _ <|  _ <|  _|| |_| |/ / / / 
 * |_| \_\_| \_\_|   \__,_/___/___|
 *
 * Copyright (C) National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "rrCovPlugin.h"

static bool option_fuzz     = false;    // Fuzzer is enabled?
static int option_timeout   = 0;        // Fuzzer timeout.
static int option_depth     = 0;        // Fuzzer max depth.
static bool option_blackbox = false;    // Blackbox mode?

#define PIPE_FILENO         997

struct COVERAGE                 // Coverage bitmap
{
    void (*callback)(intptr_t loc);
    uint32_t prev_loc;          // prev_loc
    uint32_t mask;              // Mask
    uint8_t map[MAP_SIZE];      // Bits
};

struct BRANCH                   // Per-branch state
{
    struct
    {
        TLSH tlsh;              // LSH of input
    }
    in;

    struct
    {
        BKTREE best;            // Best outputs
        size_t mindist;         // Min distance b/n outputs
        size_t maxsz;           // Max size of best
    }
    out;

    CORPUS corpus;              // Seed corpus
};

struct FUZZER                   // The fuzzer state
{
    bool stop;                  // Stop fuzzing?

    uint64_t time;              // Start time
    size_t execs;               // # executions
    size_t crashes;             // # crashes
    size_t aborts;              // # aborts
    size_t hangs;               // # hangs
    size_t stage;               // Stage
    int timeout;                // Leaf timeout (ms)

    mutex_t lock;               // Fuzzer lock
    pid_t leaf;                 // Current leaf process
    PATCH *patch;               // Current patch
    int id;                     // Current message ID
    MSG *replay;                // Current replayed patch

    void *rip;                  // Crash address
    OUTPUT out;                 // Output tracking
    size_t ncov;                // #new coverage?
    void *coverage;             // Accurate coverage
    BRANCH *branches[];         // Per-branch state
};

static FUZZER *FUZZ = NULL;
static COVERAGE *fuzzer_cov = NULL;
static uint8_t *fuzzer_map  = NULL;     // Virgin bits

// Local fuzzer state:
#define FUZZ_MAIN       0   // Outer
#define FUZZ_SPINE      1   // Inner
#define FUZZ_LEAF       2   // Leaf
static int fuzzer_state = FUZZ_MAIN;    // What are we doing?
static int fuzzer_depth = 0;            // # messages since fork()
static bool fuzzer_emulate = false;     // Syscall emulation-mode enabled?
static RNG *fuzzer_RNG  = NULL;         // Fuzzer RNG

static void fuzzer_lock(const char *file, int line)
{
    if (mutex_lock(&FUZZ->lock) < 0)
        error("failed to lock fuzzer: %s", strerror(errno));
}
static void fuzzer_unlock(const char *file, int line)
{
    if (mutex_unlock(&FUZZ->lock) < 0)
        error("failed to unlock fuzzer: %s", strerror(errno));
}
#define FUZZER_LOCK()   fuzzer_lock(__FILE__, __LINE__)
#define FUZZER_UNLOCK() fuzzer_unlock(__FILE__, __LINE__)

/*
 * Signal name in 4 characters.
 */
static const char *signal_name4(int sig)
{
    switch (sig)
    {
        case SIGQUIT: return "QUIT";
        case SIGILL:  return "ILL ";
        case SIGABRT: return "ABRT";
        case SIGFPE:  return "FPE ";
        case SIGKILL: return "KILL";
        case SIGSEGV: return "SEGV";
        case SIGPIPE: return "PIPE";
        case SIGALRM: return "ALRM";
        case SIGTERM: return "TERM";
        case SIGUSR1: return "USR1";
        case SIGUSR2: return "USR2";
        case SIGBUS:  return "BUS ";
        case SIGTRAP: return "TRAP";
        default:      return "SIG?";
    }
}

/*
 * Create a new FUZZER.
 */
static void fuzzer_init(size_t nmsg, int timeout)
{
    struct rlimit limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) < 0)
        error("failed to disable core dumps: %s", strerror(errno));

    uintptr_t hint = 0xbbb00000000ull;
    (void)getrandom(&hint, sizeof(uint32_t), 0);
    hint &= ~(MA_PAGE_SIZE-1);
    void *ptr = mmap((void *)hint, MA_MAX_SIZE, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to reserve fuzzer pool: %s", strerror(errno));

    const size_t pool_size = (1 << 30);     // 1GB
    pool = pool_create(MAP_ANONYMOUS | MAP_SHARED | MAP_NORESERVE, ptr,
        pool_size, pool_size);
    if (pool == NULL)
        error("failed to create fuzzer pool: %s", strerror(errno));

    size_t size = sizeof(FUZZER) + nmsg * sizeof(BRANCH *);
    FUZZ = (FUZZER *)pmalloc(size);
    memset(FUZZ, 0x0, size);

    mutex_init(&FUZZ->lock);
    FUZZ->stage    = 1;
    FUZZ->timeout  = timeout;
    FUZZ->leaf     = INT_MIN;
    FUZZ->time     = get_time();
    FUZZ->out.reset();
}

/*
 * Initialize fuzzer coverage.
 */
static void coverage_init(COVERAGE *cov, uint8_t *map)
{
    static COVERAGE cov_0 = {0};
    static uint8_t map_0[MAP_SIZE] = {0};
    cov = (cov == NULL? &cov_0: cov);
    map = (map == NULL? map_0:  map);
    cov->callback = NULL;
    if (syscall(SYS_arch_prctl, /*ARCH_SET_GS=*/0x1001, cov) < 0)
        error("failed to set %%gs register: %s", strerror(errno));
    fuzzer_cov = cov;
    fuzzer_map = map;
}

/*
 * Sleep on the given fd for the given timeout.
 * Returns true on timeout, or false on POLLHUP.
 */
static bool fuzzer_sleep(int fd, int timeout)
{
    struct pollfd pfd = {fd, POLLIN, 0};
    int T0 = get_time() / 1000;
    while (timeout > 0)
    {
        int r = poll(&pfd, 1, timeout);
        if (r < 0)
            error("failed to poll file descriptor: %s", strerror(errno));
        if (r > 0)
            return false;
        int T1 = get_time() / 1000;
        timeout -= (T1 - T0);
        T0 = T1;
    }
    return true;
}

/*
 * Fuzzer main.
 */
static void fuzzer_main(size_t nmsg)
{
    if (!option_fuzz)
        return;
    fuzzer_init(nmsg, (option_timeout > 0? option_timeout: /*50ms=*/50));
    option_depth = (option_depth > 0? option_depth: 50);
    COVERAGE *cov = (COVERAGE *)pmalloc(sizeof(COVERAGE));
    memset(cov, 0x0, sizeof(*cov));
    uint8_t *map = (uint8_t *)pmalloc(MAP_SIZE);
    memset(map, 0x0, MAP_SIZE);
    coverage_init(cov, map);

    // Misc. setup
    (void)setvbuf(stderr, NULL, _IOLBF, 0);
    struct rlimit limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) < 0)
        error("failed to disable core dumps: %s", strerror(errno));
    const char name[] = "rrfuzz";
    if (syscall(SYS_prctl, /*PR_SET_NAME=*/15, name) < 0)
        error("failed to set fuzzer name to \"%s\": %s", name,
            strerror(errno));
    fuzzer_RNG = (RNG *)xmalloc(sizeof(RNG));

    // Outer fuzzing loop
    //
    // This loop repeatedly forks off instances of the program, where each
    // instance performs a tree-based-search over the replay.
    for ( ; !FUZZ->stop; FUZZ->stage++)
    {
        // Step (a): Fork-off a child process.
        pid_t child = INT_MIN;
        int fds[2];
        if (pipe2(fds, O_CLOEXEC) < 0)
            error("failed to create pipe: %s", strerror(errno));
        child = fork();
        if (child < 0)
            error("failed to fork child process: %s", strerror(errno));
        else if (child == 0)
        {
            close(fds[0]);
            if (dup2(fds[1], PIPE_FILENO) < 0)
                error("failed to dup pipe: %s", strerror(errno));
            close(fds[1]);
            fuzzer_state = FUZZ_SPINE;
            // Return = continue program execution normally
            return;
        }
        close(fds[1]);
        if (dup2(fds[0], PIPE_FILENO) < 0)
            error("failed to dup pipe: %s", strerror(errno));
        close(fds[0]);

        // Step (b): Monitor the child & leaf.
        //           Detect leaf timeouts and kill hangs
        pid_t prev = INT_MIN;
        while (fuzzer_sleep(PIPE_FILENO, 2 * FUZZ->timeout))
        {
            FUZZER_LOCK();
            if (FUZZ->leaf == prev)
            {
                // Leaf pid is unchanged --> assumed to be a hang
                if (kill(FUZZ->leaf, SIGKILL) < 0)
                {
                    FUZZER_UNLOCK();
                    if (errno == ESRCH)
                        continue;       // Leaf already terminated
                    error("failed to kill process %d: %s", prev,
                        strerror(errno));
                }
            }
            prev = FUZZ->leaf;
            FUZZER_UNLOCK();
        }
        close(PIPE_FILENO);

        // Step (c): Child has terminated; wait for it.
        int status;
        while (true)
        {
            pid_t pid = waitpid(-1, &status, 0);
            if (pid < 0)
                error("failed to wait for child process %d: %s",
                    child, strerror(errno));
            if (pid == child)
                break;
        }

        // Step (d): Print the outcome.
        const char *bar = "---------------------------------------------"
            "-----------------\n";
        if (WIFSIGNALED(status))
        {
            int sig = WTERMSIG(status);
            fprintf(stderr, "%s%sfuzzer (%d) crashed with %s (%d)%s\n%s",
                bar, RED, child, signal_name(sig), sig, OFF, bar);
        }
        else if (WIFEXITED(status))
        {
            int code = WEXITSTATUS(status);
            fprintf(stderr, "%s%sfuzzer (%d) exitted with status %d%s\n%s",
                bar, GREEN, child, code, OFF, bar);
        }
        child = INT_MIN;
    }

    exit(EXIT_FAILURE);
}

/*
 * Track outputs.
 */
static void fuzzer_track(const ENTRY *E, const iovec *iov, size_t iovcnt)
{
    if (E == NULL)
        return;
    if (fuzzer_state == FUZZ_LEAF)
        FUZZ->out.write(E, iov, iovcnt);
}
static void fuzzer_track(const ENTRY *E, const uint8_t *buf, size_t size)
{
    if (E == NULL)
        return;
    if (fuzzer_state != FUZZ_LEAF)
        return;
    struct iovec iov = {(void *)buf, size};
    FUZZ->out.write(E, &iov, 1);
}

/*
 * Get per-branch state.
 */
static BRANCH *fuzzer_get_branch(const MSG *M)
{
    if (FUZZ->branches[M->id] == NULL)
    {
        FUZZER_LOCK();
        FUZZ->branches[M->id] = (BRANCH *)pmalloc(sizeof(BRANCH));
        FUZZER_UNLOCK();
        BRANCH *B = FUZZ->branches[M->id];
        memset(B, 0x0, sizeof(*B));
        B->out.mindist = 1;
        B->out.maxsz   = 0;
        B->corpus.init();

        tlsh_init(&B->in.tlsh);
        tlsh_update(&B->in.tlsh, M->payload, M->len);
    }
    return FUZZ->branches[M->id];
}

/*
 * Calculate the coverage bits, similar to AFL.
 * This function also resets fuzzer_cov.
 */
static bool fuzzer_calc_coverage(BRANCH *B)
{
    static const uint8_t bits[256] =
    {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08, 0x08,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    };
    uint8_t cov = 0x0;
    // index 0 is ignored, allowing cov->mask=0x0 to disable coverage
    if (!option_blackbox)
    {
        fuzzer_cov->map[0] = 0x0;
        for (size_t i = 1; i < MAP_SIZE; i++)
        {
            uint8_t bit = bits[fuzzer_cov->map[i]];
            cov |= (fuzzer_map[i] & bit) ^ bit;
            fuzzer_map[i] |= bit;
        }
        FUZZ->out.coverage(fuzzer_cov->map, sizeof(fuzzer_cov->map));
    }
    fuzzer_cov->prev_loc = 0x0;
    memset(fuzzer_cov->map, 0x0, sizeof(fuzzer_cov->map));
    return (cov != 0x0);
}

/*
 * Calculate a hash of coverage bits.  This is used for divergence debugging.
 */
static uint32_t fuzzer_hash_coverage(void)
{
    uint64_t h = 0x0;
    uint64_t *map64 = (uint64_t *)fuzzer_cov->map;
    for (size_t i = 0; i < MAP_SIZE / sizeof(uint64_t); i++)
    {
        h ^= hash(map64[i]);
        map64[i] = 0x0;
    }
    fuzzer_cov->prev_loc = 0x0;
    return (uint32_t)h ^ (uint32_t)(h >> 32);
}

/*
 * Save the patch if it is interesting.
 */
static bool fuzzer_save_interesting(BRANCH *B, HASH K, PATCH *P, bool cov)
{
    if (option_blackbox)
    {
boring_patch:
        P->reset();
        pfree((void *)P);
        return false;
    }

    bool out = !bk_find(&B->out.best, K, B->out.mindist);
    bool good = out || cov;
    if (!good)
        goto boring_patch;

    // Save interesting patch to the corpus:
    P->cov = cov;
    B->corpus.insert(K, P);

    if (out)
    {
        bk_insert(&B->out.best, K, P);
        if (B->out.best.size > B->out.maxsz)
        {
            do
            {
                B->out.mindist++;
                bk_rebuild(&B->out.best, B->out.mindist);
            }
            while (B->out.best.size > B->out.maxsz);
            out = !bk_find(&B->out.best, K, B->out.mindist);
        }
    }

    if (cov)
        FUZZ->ncov++;

    return (out || cov);
}

/*
 * Fork the state.
 */
#define COLOR(x, c)    ((x) == 0? GREY: c)
static MSG *fuzzer_fork(MSG *M, PATCH *replay)
{
    // Step (0): Set-up the fork:
    FUZZ->patch = (PATCH *)pmalloc(sizeof(PATCH));
    FUZZ->patch->init();        // New patch to accumulate into
    FUZZ->replay = (replay->head == NULL? NULL: replay->head->next);
    FUZZ->rip    = NULL;
    fuzzer_cov->mask = 0xFFFFFFFF;

    // Step (1): Fork-off the child process:
    FUZZER_LOCK();
    uint64_t seed = option_RNG->rand64();
    pid_t child = fork();
    if (child < 0)
    {
        FUZZER_UNLOCK();
        error("failed to fork child process: %s", strerror(errno));
    }
    else if (child == 0)
    {   // Child:
        fuzzer_state = FUZZ_LEAF;
        fuzzer_RNG->reset(seed);
        option_log = -1;
        mutex_enable(false);    // Avoid settid() overheads
        return mutate(*fuzzer_RNG, M, fuzzer_depth, FUZZ->stage);
    }
    else
    {   // Parent:
        FUZZ->leaf = child;
        FUZZ->execs++;
        FUZZER_UNLOCK();
    }

    // Step (2): Wait for the child to terminate:
    int status;
    while (true)
    {
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0)
            error("failed to wait for child process %d: %s",
                child, strerror(errno));
        if (pid == child)
            break;
    }
    FUZZER_LOCK();
    FUZZ->leaf = INT_MIN;
    FUZZER_UNLOCK();
    FUZZ->replay = NULL;

    // Step (3): Process the result:
    BRANCH *B = fuzzer_get_branch(M);
    bool cov = fuzzer_calc_coverage(B);
    HASH K = FUZZ->out.hash(&B->in.tlsh, status);
    if (WIFSIGNALED(status))
    {
        RNG rng((uint64_t)FUZZ->rip);
        uint16_t bugid = (uint64_t)rng.rand();
        int sig = WTERMSIG(status);
        switch (sig)
        {
            case SIGABRT: fprintf(stderr, "%sABRT%s", YELLOW, OFF); break;
            case SIGKILL: fprintf(stderr, "%sHANG%s", YELLOW, OFF); break;
            default:
                fprintf(stderr, "%s%s%s", RED, signal_name4(sig), OFF);
                break;
        }
        PRINTER P;
        switch (sig)
        {
            case SIGABRT:
                P.format("%s/abort/ABORT_%.4x_m%.5d.patch", option_outname,
                    bugid, FUZZ->id);
                FUZZ->aborts += patch_save(P.str(), FUZZ->patch);
                break;
            case SIGKILL:
                P.format("%s/hang/HANG_%.4x_m%.5d.patch", option_outname,
                    bugid, FUZZ->id);
                FUZZ->hangs += patch_save(P.str(), FUZZ->patch);
                break;
            default:
                P.format("%s/crash/%s_%.4x_m%.5d.patch", option_outname,
                    signal_name(sig), bugid, FUZZ->id);
                FUZZ->crashes += patch_save(P.str(), FUZZ->patch);
                break;
        }
    }
    else if (WIFEXITED(status))
        fprintf(stderr, "%sEXIT%s", GREEN, OFF);

    bool good = fuzzer_save_interesting(B, K, FUZZ->patch, cov);
    FUZZ->patch = NULL;
    fuzzer_cov->mask = 0x0;

    size_t t = get_time() - FUZZ->time;
    t = (t == 0? 1: t);
    size_t R = 1000000000;
    size_t xps = (R * FUZZ->execs) / t;
    xps *= 1000000;
    fprintf(stderr, " #%.04zu: exec/s=%zu.%.3zu %souts=%zu/%zu%s "
        "%spath=%.2zu%s %scrash=%zu%s %sabort=%zu%s %shang=%zu%s "
        "%sout=%.16llx%.16llx%s\n",
        M->id, xps / R, (xps % R) / 1000000,
        COLOR(B->out.best.size >= B->out.maxsz, WHITE), B->out.best.size,
            B->out.maxsz, OFF,
        COLOR(FUZZ->ncov, WHITE), FUZZ->ncov, OFF,
        COLOR(FUZZ->crashes, RED), FUZZ->crashes, OFF,
        COLOR(FUZZ->aborts, YELLOW), FUZZ->aborts, OFF,
        COLOR(FUZZ->hangs, YELLOW), FUZZ->hangs, OFF,
        COLOR(good, GREEN), (uint64_t)(K >> 64), (uint64_t)K, OFF);
    
    return NULL;
}

/*
 * Syscall callback.
 */
static void fuzzer_syscall_callback(void)
{
    static int fuzzer_syscall_depth = 0;
    switch (fuzzer_state)
    {
        case FUZZ_LEAF:
            fuzzer_syscall_depth++;
            if (fuzzer_cov->mask != 0x0 &&
                    fuzzer_syscall_depth >= /*MAX_COV=*/0)
                fuzzer_cov->mask = 0x0; // Disable coverage after given depth
            if (fuzzer_syscall_depth >= option_depth * 8)
                exit(EXIT_FAILURE);     // Stuck in loop? -> boring, so exit
            return;
        default:
            break;
    }
}

/*
 * Inner fuzzing loop.
 */
static MSG *fuzzer_mutate(const ENTRY *E, MSG *M)
{
    // Step (1): Decide what to do:
    if (!option_fuzz || M->outbound || M->len == 0)
        return M;
    FUZZ->id = M->id;
    switch (fuzzer_state)
    {
        case FUZZ_LEAF:
            fuzzer_depth++;
            if (fuzzer_depth >= option_depth)
                exit(EXIT_FAILURE);     // Boring test case -> so exit
            if (FUZZ->replay != NULL && M->id == FUZZ->replay->id)
            {
                M = FUZZ->replay;
                FUZZ->replay = M->next;
            }
            // Return (possibly mutated) message:
            return mutate(*fuzzer_RNG, M, fuzzer_depth, FUZZ->stage,
                /*clone=*/true);
        default:
            break;
    }
    static int prev = -1;
    if (E->port != prev)
    {
        prev = E->port;
        fprintf(stderr, "%sFUZZ%s %s (port=%d)\n", MAGENTA, OFF, E->name,
            E->port);
    }

    // Step (2): Inner fuzzing loop:
    BRANCH *B = fuzzer_get_branch(M);
    PATCH *P  = &B->corpus.head;
    B->out.maxsz = 1 + NLOG2(1, 1000 * FUZZ->stage);
    do
    {
        P->load();
        for (size_t i = 0; !P->discard && i < FUZZ->stage; i++)
        {
            if (FUZZ->stop)
                exit(EXIT_FAILURE);

            MSG *M1 = fuzzer_fork(M, P);
            if (M1 != NULL)
                return M1;      // We are a leaf & M1 is the mutant message
        }
        P->unload();
        P = P->next;
    }
    while (P != &B->corpus.head);

    // Step (3): Clean-up any discarded patch:
    P = &B->corpus.head;
    PATCH *Q = NULL;
    do
    {
        Q = P->next;
        if (P->discard)
        {
            P->reset();
            pfree((void *)P);
        }
        P = Q;
    }
    while (P != &B->corpus.head);

    return M;
}

