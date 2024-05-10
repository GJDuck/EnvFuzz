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

#define INBOUND         false
#define OUTBOUND        true

#define INSTRUMENT      (-1)
#define REPLACE         0

#define MIN(x, y)       ((x) < (y)? (x): (y))
#define MAX(x, y)       ((x) > (y)? (x): (y))

#define OFF             (option_tty? "\33[0m"   : "")
#define WHITE           OFF
#define GREY            (option_tty? "\33[1;30m": "")
#define RED             (option_tty? "\33[31m"  : "")
#define GREEN           (option_tty? "\33[32m"  : "")
#define YELLOW          (option_tty? "\33[33m"  : "")
#define BLUE            (option_tty? "\33[34m"  : "")
#define MAGENTA         (option_tty? "\33[35m"  : "")
#define CYAN            (option_tty? "\33[36m"  : "")

#define NOINLINE        __attribute__((__noinline__))
#define NORETURN        __attribute__((__noreturn__))
#define PRINTF(i, j)    __attribute__((__format__(printf, i, j)))
#define PACKED          __attribute__((__packed__))

// Pseudo syscalls
#define SYS_rdtsc       335         // rdtsc instruction
#define SYS_start       336         // Thread start
#define SYS_setpid      337         // Set program pid
#define SYS_setenvp     338         // Set envp
#define SYS_signal      339         // Signal
#define SYS_enable      340         // Enable record&replay
#define SYS_disable     341         // Disable record&replay

#define MMAP_RECORD_MAX UINT16_MAX  // mmap() record threshold

#define PATH_MAX        4096
#define PAGE_SIZE       4096

/*
 * ucontext_t conversion.
 */
enum
{
    REG_R8 = /*gregs offset=*/5,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_RDI,
    REG_RSI,
    REG_RBP,
    REG_RBX,
    REG_RDX,
    REG_RAX,
    REG_RCX,
    REG_RSP,
    REG_RIP,
    REG_EFL,
};
static void state_init(const void *ctx_0, STATE *state)
{
    intptr_t *ctx = (intptr_t *)ctx_0;
    state->rflags = ctx[REG_EFL];
    state->r15    = ctx[REG_R15];
    state->r14    = ctx[REG_R14];
    state->r13    = ctx[REG_R13];
    state->r12    = ctx[REG_R12];
    state->r11    = ctx[REG_R11];
    state->r10    = ctx[REG_R10];
    state->r9     = ctx[REG_R9];
    state->r8     = ctx[REG_R8];
    state->rdi    = ctx[REG_RDI];
    state->rsi    = ctx[REG_RSI];
    state->rbp    = ctx[REG_RBP];
    state->rbx    = ctx[REG_RBX];
    state->rdx    = ctx[REG_RDX];
    state->rcx    = ctx[REG_RCX];
    state->rax    = ctx[REG_RAX];
    state->rsp    = ctx[REG_RSP];
    state->rip    = ctx[REG_RIP];
}

/*
 * Error handling.
 */
static NOINLINE NORETURN PRINTF(1, 2) void error(const char *msg, ...)
{
    if (option_log < 0)
        exit(EXIT_FAILURE);
    fprintf(stderr, "%serror%s: %d: ", RED, OFF, getpid());

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);

    exit(EXIT_FAILURE);
}
static NOINLINE PRINTF(1, 2) void warning(const char *msg, ...)
{
    if (option_log < 1)
        return;
    fprintf(stderr, "%swarning%s: %d: ", YELLOW, OFF, getpid());

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
}
#define assert(cond)                                                        \
    do {                                                                    \
        if (!(cond))                                                        \
            error("%s: %d: assertion (%s) failed", __FILE__, __LINE__,      \
                STRING(cond));                                              \
    } while (false)

/*
 * Malloc wrappers.
 */
static NOINLINE void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
        error("failed to malloc %zu bytes of memory: %s", size,
            strerror(errno));
    return ptr;
}
static NOINLINE void *xcalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL)
        error("failed to calloc %zu bytes of memory: %s",
            nmemb * size, strerror(errno));
    return ptr;
}
static NOINLINE void *xrealloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);
    if (ptr == NULL)
        error("failed to realloc %zu bytes of memory: %s",
            size, strerror(errno));
    return ptr;
}
static void xfree(void *ptr)
{
    free(ptr);
}
static NOINLINE char *xstrdup(const char *s)
{
    char *t = strdup(s);
    if (t == NULL)
        error("failed to duplicate string of length %zu: %s", strlen(s),
            strerror(errno));
    return t;
}

typedef struct malloc_pool_s POOL;
static POOL *pool = NULL;                       // Multi-process memory pool

static NOINLINE void *pmalloc(size_t size)
{
    void *ptr = pool_malloc(pool, size);
    if (ptr == NULL)
        error("failed to malloc %zu bytes of memory: %s", size,
            strerror(errno));
    return ptr;
}
static NOINLINE void *pcalloc(size_t nmemb, size_t size)
{
    void *ptr = pool_calloc(pool, nmemb, size);
    if (ptr == NULL)
        error("failed to calloc %zu bytes of memory: %s",
            nmemb * size, strerror(errno));
    return ptr;
}
static NOINLINE void *prealloc(void *ptr, size_t size)
{
    ptr = pool_realloc(pool, ptr, size);
    if (ptr == NULL)
        error("failed to realloc %zu bytes of memory: %s",
            size, strerror(errno));
    return ptr;
}
static void pfree(void *ptr)
{
    pool_free(pool, ptr);
}
static NOINLINE char *pstrdup(const char *s)
{
    assert(s != NULL);
    size_t len = strlen(s);
    char *t = (char *)pmalloc(len + 1);
    memcpy(t, s, len+1);
    return t;
}

/*
 * Get time (in microseconds)
 */
static uint64_t get_time(void)
{
    struct timeval t;
    int r = gettimeofday(&t, NULL);
    if (r < 0)
        error("failed to get time: %s", strerror(errno));
    return t.tv_sec * 1000000 + t.tv_usec;
}

/*
 * Decide if a char is printable.
 */
static bool escape_char(char c)
{
    if (!isprint(c))
        return true;
    if (isspace(c) && c != ' ')
        return true;
    if (c == '\"')
        return true;
    return false;
}

/*
 * Condition variable implementation.
 *
 * TODO: move to stdlib.c?
 */
struct cond_s
{
    mutex_t mutex;
    mutex_t seq;
};
typedef struct cond_s cond_t;
#define COND_INITIALIZER        {0}

static void cond_init(cond_t *x)
{
    memset(x, 0x0, sizeof(*x));
}

static NOINLINE int cond_wait(cond_t *x, mutex_t *m)
{
    if (mutex_lock(&x->mutex) < 0)
        return -1;
    pid_t *seq_ptr = mutex_get_ptr(&x->seq);
    pid_t SEQ = *seq_ptr;
    if (mutex_unlock(m))
        return -1;
    do
    {
        if (mutex_unlock(&x->mutex) < 0)
            return -1;
        long r = syscall(SYS_futex, seq_ptr, FUTEX_WAIT, SEQ, 0, NULL, NULL, 0);
        if (r < 0 && errno != EAGAIN)
            return -1;
        if (mutex_lock(&x->mutex) < 0)
            return -1;
    }
    while (SEQ == *seq_ptr);
    if (mutex_unlock(&x->mutex) < 0)
        return -1;
    return mutex_lock(m);
}
static NOINLINE int cond_signal(cond_t *x)
{
    if (mutex_lock(&x->mutex) < 0)
        return -1;
    pid_t *seq_ptr = mutex_get_ptr(&x->seq);
    *seq_ptr = *seq_ptr + 1;
    if (syscall(SYS_futex, seq_ptr, FUTEX_WAKE, 1, 0, NULL, NULL, 0) < 0)
        return -1;
    return mutex_unlock(&x->mutex);
}

static NOINLINE int cond_broadcast(cond_t *x)
{
    if (mutex_lock(&x->mutex) < 0)
        return -1;
    pid_t *seq_ptr = mutex_get_ptr(&x->seq);
    *seq_ptr = *seq_ptr + 1;
    if (syscall(SYS_futex, seq_ptr, FUTEX_WAKE, INT_MAX, 0, NULL, NULL, 0) < 0)
        return -1;
    return mutex_unlock(&x->mutex);
}

/*
 * "Fake" timestamp instruction.
 */
static intptr_t rdtsc(void)
{
    struct timespec ts;
    if (syscall(SYS_clock_gettime, /*CLOCK_MONOTONIC_RAW=*/4, &ts) < 0)
        error("failed to get time: %s", strerror(errno));
    return 1000000000 * ts.tv_sec + ts.tv_nsec;
}

/*
 * Hash function.
 */
static uint64_t hash(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return x;
}

/*
 * Random number generator.
 */
class RNG
{
    static const unsigned S = 32;
    static const uint64_t R = 0x1ull << S;
    static const uint64_t M = R - 1;

    uint64_t s;

    uint64_t next(void)
    {
        return hash(s++);
    }

public:
    RNG(void) : s(0)
    {
    }
    RNG(uint64_t seed) : s(seed)
    {
        ;
    }

    void reset(void)
    {
        if (getrandom((void *)&s, sizeof(s), 0) != sizeof(s))
            error("failed to read random number: %s", strerror(errno));
    }
    void reset(uint64_t seed)
    {
        s = seed;
        if (s == 0) reset();
    }
    uint32_t rand(void)
    {
        return (uint32_t)next();
    }
    uint32_t rand(uint32_t min, uint32_t max)
    {
        uint64_t x = next();
        x = x % (1 + max - min);
        return (uint32_t)x + min;
    }
    uint32_t bias(uint32_t min, uint32_t max, unsigned n)
    {
        uint32_t x = rand(min, max);
        for (; n > 0 && x > min; n--)
            x = rand(min, x);
        return x;
    }
    bool flip(uint32_t n = 1)
    {
        return (rand(0, n) == 0);
    }
    uint64_t rand64(void)
    {
        return ((uint64_t)rand() << 32 | (uint64_t)rand());
    }
};

/*
 * Names.
 */
static char *path_name(int fd, const char *path, char *name, size_t size)
{
    ssize_t r = snprintf(name, size-1, "/proc/self/fd/%d", fd);
    if (r <= 0 || r >= (ssize_t)size)
    {
        path_error:
        error("failed to generate path name for \"%s\": %s", path,
            strerror(errno));
    }
    r = readlink(name, name, size-1);
    if (r <= 0 || r >= (ssize_t)size)
        goto path_error;
    name[r] = '\0';
    return name;
}
static char *pipe_name(int fd, int idx, char *name, size_t size)
{
    int r = snprintf(name, size-1, "pipe://%d:%d", idx, fd);
    if (r <= 0 || r >= (ssize_t)size-1)
        error("failed to generate pipe name for (%d): %s", fd,
            strerror(errno));
    return name;
}
static char *socket_name(int fd, char *name, size_t size)
{
    int r = snprintf(name, size-1, "socket://%d", fd);
    if (r <= 0 || r >= (ssize_t)size-1)
        error("failed to generate socket name for (%d): %s", fd,
            strerror(errno));
    return name;
}
static char *event_name(int fd, char *name, size_t size)
{
    int r = snprintf(name, size-1, "event://%d", fd);
    if (r <= 0 || r >= (ssize_t)size-1)
        error("failed to generate event name for (%d): %s", fd,
            strerror(errno));
    return name;
}
static char *epoll_name(int fd, char *name, size_t size)
{
    int r = snprintf(name, size-1, "epoll://%d", fd);
    if (r <= 0 || r >= (ssize_t)size-1)
        error("failed to generate epoll name for (%d): %s", fd,
            strerror(errno));
    return name;
}

/*
 * Check if virtual address range is free.
 */
static bool is_mapping_available(void *addr_0, size_t size)
{
    uintptr_t addr = (uintptr_t)addr_0;
    uintptr_t end  = addr + size;
    FILE *stream = fopen("/proc/self/maps", "r");
    if (stream == NULL)
        return false;
    bool found = false;
    while (!found)
    {
        uintptr_t lo, hi;
        if (fscanf(stream, "%lx-%lx", &lo, &hi) != 2)
            break;
        found = MAX(addr, lo) < MIN(end, hi);
        char c;
        while ((c = getc(stream)) != '\n' && c != EOF)
            ;
    }
    fclose(stream);
    return !found;
}

