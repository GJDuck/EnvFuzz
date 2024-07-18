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

#define MUTEX_SAFE
#include "stdlib.c"
#include "rrfuzz.h"

static bool option_record = false;
#define RECORD  option_record                   // Are we recording?
#define REPLAY  (!option_record)                // Are we replaying?

struct QUEUE;
struct RNG;
struct PATCH;

static bool option_disabled         = false;    // Record/replay disabled?
static bool option_debug            = false;    // Attach GDB?
static unsigned option_cpu          = 0;        // CPU number
static FILE *option_pcap            = NULL;     // PCAP file
static bool option_tty              = false;    // Print colors?
static bool option_hex              = false;    // Print debug in hex?
static bool option_patch            = false;    // Patch replay?
static bool option_pku              = false;    // PKU enabled?
static bool option_fsgsbase         = false;    // fsgsbase support?
static int option_log               = 0;        // Log-level.
static int option_emulate           = 0;        // Emulation-level.
static int64_t option_seed          = 0;        // RNG seed.
static const char *option_filename  = NULL;     // Recording filename.
static const char *option_patchname = NULL;     // Patch filename.
static const char *option_outname   = NULL;     // Output dirname.
static const char *option_install   = NULL;     // Install dir.

static QUEUE *option_Q              = NULL;     // Local message queue
static RNG *option_RNG              = NULL;     // Random Number Generator
static PATCH *option_P              = NULL;     // Patch to apply.

#include "rr_misc.cpp"
#include "rr_iov.cpp"
#include "rr_thread.cpp"
#include "rr_fiber.cpp"
#include "rr_print.cpp"
#include "rr_fd.cpp"
#include "rr_msg.cpp"
#include "rr_pcap.cpp"
#include "rr_signal.cpp"
#include "rr_emulate.cpp"
#include "rr_record.cpp"
#include "rr_replay.cpp"

/*
 * Main E9Patch entry point.
 *
 * This function will be called for each patched syscall instruction.
 * This is the fast path (no context switch)!
 */
extern "C" void syscall_2(void);
void entry(void *arg)
{
    STATE *state = (STATE *)arg;
    switch (state->rax)
    {   // Special enable/disable pseudo-syscalls
        case SYS_enable:
            option_disabled = false;
            state->rax = 0;
            return;
        case SYS_disable:
            option_disabled = true;
            state->rax = 0;
            return;
        default:
            break;
    }
    if (option_disabled)
    {   // If disabled, just execute syscalls normally:
        long r = syscall(state->rax,
            state->rdi, state->rsi, state->rdx,
            state->r10, state->r8, state->r9);
        state->rax = (r < 0? -errno: r);
        return;
    }
    if (option_pku)
    {
        /*
         * BUG WORKAROUND: clear the %pkru register to prevent docker SEGVs
         */
        asm volatile
        (
            "xor %%eax,%%eax\n"
            "mov %%eax,%%edx\n"
            "mov %%eax,%%ecx\n"
            "wrpkru" : : : "rax", "rdx", "rcx"
        );
    }

    // Special case handling:
    switch (state->rax)
    {
        case SYS_execve:
            state->rax = -ENOSYS;
            return;
        case SYS_rt_sigreturn:
            // Must execute in original stack (%rsp) context:
            state->rip += /*sizeof(syscall)=*/2;
            asm volatile
            (
             /* "mov 0x00(%0),%%rflags\n" */
                "mov 0x08(%0),%%r15\n"
                "mov 0x10(%0),%%r14\n"
                "mov 0x18(%0),%%r13\n"
                "mov 0x20(%0),%%r12\n"
                "mov 0x28(%0),%%r11\n"
                "mov 0x30(%0),%%r10\n"
             /* "mov 0x38(%0),%%r9\n" */
                "mov 0x40(%0),%%r8\n"
                "mov 0x48(%0),%%rdi\n"
                "mov 0x50(%0),%%rsi\n"
                "mov 0x58(%0),%%rbp\n"
                "mov 0x60(%0),%%rbx\n"
                "mov 0x68(%0),%%rdx\n"
             /* "mov 0x70(%0),%%rcx\n" */
             /* "mov 0x78(%0),%%rax\n" */
                "mov 0x80(%0),%%rsp\n"
             /* "mov 0x88(%0),%%rip\n" */

                "mov 0x88(%0),%%r9\n"
                "mov %%r9,%%fs:" STRING(ERRNO_TLS_OFFSET) "\n"
                "mov 0x38(%0),%%r9\n"

                "mov 0x00(%0),%%rax\n"
                "add $0x7f,%%al\n"
                "sahf\n"

                "mov 0x78(%0),%%rax\n"
                "mov 0x70(%0),%%rcx\n"

                // We save the location of this syscall instruction to add to
                // the list of exceptions.  This is easier than attempting a
                // single location.
                ".globl syscall_2\n"
                "syscall_2:\n"
                "syscall\n"

                "jmpq *%%fs:" STRING(ERRNO_TLS_OFFSET) "\n"

                : "+c"(state)
            );
            while (true)
                asm volatile ("ud2");
        default:
            break;
    }
    
    // System call hook:
    int r = (RECORD? record_hook(state): replay_hook(state));

    // Replace?:
    if (r == INSTRUMENT)
    {
        if (RECORD) THREAD_UNLOCK();
        long r = syscall(state->rax,
            state->rdi, state->rsi, state->rdx,
            state->r10, state->r8, state->r9);
        if (RECORD) THREAD_LOCK();
        state->rax = (r < 0? -errno: r);
    }
}

/*
 * rdtsc instruction entry point.
 */
void rdtsc_hook(void *arg)
{
    STATE *state = (STATE *)arg;
    state->rax = SYS_rdtsc;
    int r = (RECORD? record_hook(state): replay_hook(state));
    assert(r == REPLACE);
    uint64_t result = (uint64_t)state->rax;
    state->rax = result & 0xFFFFFFFFull;
    state->rdx = result >> 32;
}

/*
 * rdtscp instruction entry point.
 */
void rdtscp_hook(void *arg)
{
    rdtsc_hook(arg);
    STATE *state = (STATE *)arg;
    state->rcx = option_cpu;
}

/*
 * abort() entry point.
 */
void abort_hook(void)
{
    // During reply, unexpected aborts should immediately generate a SIGABRT.
    // The glibc version of abort() tends to call other syscalls first, which
    // could confuse the replay.
    if (REPLAY)
    {
        SIGNAL_UNBLOCK(SIG_MASK(SIGABRT));
        abort();
    }
}

/*
 * SIGSYS handler.
 *
 * We use a seccomp filter to trap any syscall instruction not handled by
 * E9Patch.  This is the slow path.
 */
static void handler(int sig, siginfo_t *info, void *ctx_0)
{
    STATE state;
    state_init(ctx_0, &state);

    entry(&state);

    intptr_t *ctx = (intptr_t *)ctx_0;
    ctx[REG_RAX] = state.rax;
}

/*
 * VDSO entry.
 */
extern "C" intptr_t vdso_entry(intptr_t rdi, intptr_t rsi, intptr_t rdx,
    unsigned callno)
{
    struct STATE state = {0};
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = (intptr_t)(callno & 0xFFFF);

    entry(&state);
    return state.rax;
}

/*
 * VDSO patching.
 *
 * Some special syscalls use the VDSO and not the syscall instruction.  To
 * intercept these, we "patch" them into regular syscalls.
 */
#include <elf.h>
static void patch_vdso_func(const char *name, unsigned callno,
    uint8_t *entry, const uint8_t *end)
{
    if (entry == NULL)
        error("failed to find VDSO function \"%s\"", name);
    if (entry + 16 > end)
        error("failed to patch out-of-range VDSO function \"%s\"", name);
    
    size_t i = 0;

    // Note: patch must fit into 16 bytes!

    // mov $callno,%cx
    entry[i++] = 0x66;
    entry[i++] = 0xb9;
    entry[i++] = (callno >> 0) & 0xFF;
    entry[i++] = (callno >> 8) & 0xFF;

    // mov $vdso_entry,%rax
    uintptr_t target = (uintptr_t)vdso_entry;
    entry[i++] = 0x48;
    entry[i++] = 0xb8;
    memcpy(entry+i, &target, sizeof(target));
    i += sizeof(target);

    // jmp *%rax
    entry[i++] = 0xff;
    entry[i++] = 0xe0;
}
static void patch_vdso(char **envp)
{
    while (*envp++ != NULL)
        ;
    Elf64_auxv_t *aux = (Elf64_auxv_t *)envp;
    Elf64_auxv_t *sysinfo = NULL;
    for (; aux->a_type != AT_NULL; aux++)
    {
        switch (aux->a_type)
        {
            case AT_SYSINFO:
                break;
            case AT_SYSINFO_EHDR:
                sysinfo = aux;
                break;
            case AT_HWCAP2:
                // Note: we opportunisitcally check this here, although it
                //       has nothing to do with VDSO patching.
                if ((aux->a_un.a_val & /*HWCAP2_FSGSBASE*/0x2) == 0)
                    option_fsgsbase = false;
                break;
            case AT_RANDOM:
            {
                // Note: we opportunisitcally overwrite this here, although it
                //       has nothing to do with VDSO patching.
                uint8_t *ptr = (uint8_t *)aux->a_un.a_val;
                if (ptr != NULL)
                    memset(ptr, 0xe9, 16);
                break;
            }
            default:
                break;
        }
    }
    if (sysinfo == NULL)
        error("failed to find AT_SYSINFO_EHDR aux value");
    const Elf64_Ehdr *vdso = (const Elf64_Ehdr *)sysinfo->a_un.a_val;

    const uint8_t *data = (uint8_t *)vdso;
    const Elf64_Shdr *shdrs = (Elf64_Shdr *)(data + vdso->e_shoff);
    const char *strtab =
        (const char *)(data + shdrs[vdso->e_shstrndx].sh_offset);
    size_t strtab_size = shdrs[vdso->e_shstrndx].sh_size;

    size_t shnum = (size_t)vdso->e_shnum;
    const Elf64_Sym *dynsym = NULL;
    size_t dynsym_len = 0;
    const char *dynstr = NULL;
    for (size_t i = 0; i < shnum; i++)
    {
        const Elf64_Shdr *shdr = shdrs + i;
        if (shdr->sh_name >= strtab_size)
            continue;
        const char *name = strtab + shdr->sh_name;
        if (strcmp(name, ".dynsym") == 0)
        {
            dynsym = (const Elf64_Sym *)(data + shdr->sh_offset);
            dynsym_len = shdr->sh_size / sizeof(Elf64_Sym);
        }
        if (strcmp(name, ".dynstr") == 0)
            dynstr = (const char *)(data + shdr->sh_offset);
    }
    if (dynsym == NULL || dynstr == NULL || dynsym_len == 0)
        error("failed to find VDSO dynamic symbol table");

    size_t size = 2 * /*PAGE_SIZE=*/4096;   // Guess a fixed size
    uint8_t *fake = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((void *)fake == MAP_FAILED)
        error("failed to create fake VDSO: %s", strerror(errno));
    memcpy(fake, vdso, size);
    uint8_t *vdso_time          = NULL;
    uint8_t *vdso_clock_gettime = NULL;
    uint8_t *vdso_gettimeofday  = NULL;
    uint8_t *vdso_getcpu        = NULL;
    for (size_t i = 0; i < dynsym_len; i++)
    {
        const Elf64_Sym *sym = dynsym + i;
        const char *name = dynstr + sym->st_name;
        if (name[0] == '\0')
            continue;
        if (strcmp(name, "__vdso_time") == 0)
            vdso_time = fake + sym->st_value;
        else if (strcmp(name, "__vdso_clock_gettime") == 0)
            vdso_clock_gettime = fake + sym->st_value;
        else if (strcmp(name, "__vdso_gettimeofday") == 0)
            vdso_gettimeofday = fake + sym->st_value;
        else if (strcmp(name, "__vdso_getcpu") == 0)
            vdso_getcpu = fake + sym->st_value;
    }
    if (labs(vdso_time - vdso_clock_gettime)         < 16 ||
        labs(vdso_time - vdso_gettimeofday)          < 16 ||
        labs(vdso_time - vdso_getcpu)                < 16 ||
        labs(vdso_clock_gettime - vdso_gettimeofday) < 16 ||
        labs(vdso_clock_gettime - vdso_getcpu)       < 16 ||
        labs(vdso_gettimeofday - vdso_getcpu)        < 16)
        error("failed to patch VDSO; not enough space "
            "(need at least 16 bytes)");
    uint8_t *end = fake + size;
    patch_vdso_func("__vdso_time", SYS_time, vdso_time, end);
    patch_vdso_func("__vdso_clock_gettime", SYS_clock_gettime,
        vdso_clock_gettime, end);
    patch_vdso_func("__vdso_gettimeofday", SYS_gettimeofday,
        vdso_gettimeofday, end);
    patch_vdso_func("__vdso_getcpu", SYS_getcpu, vdso_getcpu, end);
    if (mprotect(fake, size, PROT_EXEC) < 0)
        error("failed to write-protect replacement VDSO: %s", strerror(errno));
    void *r = mremap((void *)fake, size, size, MREMAP_MAYMOVE | MREMAP_FIXED,
        (void *)vdso);
    if (r == MAP_FAILED)
    {
        // If mremap() fails with EINVAL, then size is too small.
        error("failed to replace VDSO: %s", strerror(errno));
    }

    // All done: the VDSO has been diverted
}

/*
 * Parse the config packet.
 */
static void parse_config(void)
{
    // CONFIG_FILENO is passed in from the wrapper
    uint8_t buf[BUFSIZ];
    ssize_t r = read(CONFIG_FILENO, buf, sizeof(buf));
    if (r <= (ssize_t)sizeof(CONFIG) + 2)
        error("failed to read config packet: %s", strerror(errno));
    close(CONFIG_FILENO);

    const CONFIG *config = (CONFIG *)buf;
    option_debug    = config->debug;
    option_fuzz     = config->fuzz;
    option_hex      = config->hex;
    option_patch    = config->patch;
    option_record   = config->record;
    option_tty      = config->tty;
    option_blackbox = config->blackbox;
    option_save     = config->save;
    option_log      = config->log;
    option_emulate  = config->emulate;
    option_depth    = config->depth;
    option_cpu      = config->cpu;
    option_timeout  = config->timeout;
    option_seed     = config->seed;
    const char *strs[4];
    size_t i = 0, n = (size_t)r - sizeof(CONFIG);
    for (size_t j = 0; j < sizeof(strs) / sizeof(strs[0]); j++)
    {
        size_t len = strnlen(config->strs + i, n);
        if (len == n)
            error("failed to parse config packet; bad string value");
        strs[j] = (len == 0? NULL: xstrdup(config->strs + i));
        i += len+1; n -= len+1;
    }
    option_filename  = (strs[0] == NULL? option_filename : strs[0]);
    option_patchname = (strs[1] == NULL? option_patchname: strs[1]);
    option_outname   = (strs[2] == NULL? option_outname  : strs[2]);
    option_install   = (strs[3] == NULL? option_install  : strs[3]);
    if (option_fuzz)
        option_log--;       // Fuzz mode lowers log-level
}

/*
 * RRFuzz initialization routine, called on program start.
 */
#include <stddef.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
void init(int argc, char **argv, char **envp)
{
    // Step (-2): Read options
    environ = envp;
    option_filename  = "./out/RECORD.pcap";
    option_patchname = "./out/PATCH.patch";
    option_outname   = "./out";
    option_install   = "./";
    parse_config();
    option_RNG = (RNG *)xmalloc(sizeof(RNG));
    option_RNG->reset(option_seed);
    const char *filename = option_filename;
 
    // Step (-1): Misc. config
    SIGNAL_BLOCK();
    uint32_t eax, ebx, ecx, edx;
    asm volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (7), "c" (0));
    if (ecx & 0x8)
        option_pku = true;
    // The following seems broken on some older systems:
//    if (ebx & 0x1)
//        option_fsgsbase = true;
    if (syscall(SYS_prctl, /*PR_SET_TSC=*/26, /*PR_TSC_SIGSEGV=*/2) < 0)
        warning("failed to enable rdtsc interception (replay may diverge): %s",
            strerror(errno));
    if (syscall(SYS_arch_prctl, /*ARCH_SET_CPUID=*/0x1012, 0x0) < 0)
        warning("failed to enable cpuid interception (replay may diverge): %s",
            strerror(errno));
    (void)setvbuf(stderr, NULL, _IOLBF, 0);

    // Step (0): Patch VDSO
    patch_vdso(envp);

    // Step (1): Find the syscall instruction:
    const uint8_t *p8 = (const uint8_t *)(long (*)(int, ...))syscall;
    const uint8_t *s8 = NULL;
    for (size_t i = 0; s8 == NULL && i < 32; i++)
        s8 = (p8[i] == 0x0f && p8[i+1] == 0x05? p8+i: NULL);
    if (s8 == NULL)
        error("failed to find syscall instruction");
    uintptr_t rip_1 = (uintptr_t)s8        + /*sizeof(syscall)=*/2;
    uintptr_t rip_2 = (uintptr_t)syscall_2 + /*sizeof(syscall)=*/2;

    // Step (2): Install SIGSYS handler
    struct sigaction action = {0};  
    action.sa_sigaction = handler;
    action.sa_flags     = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGSYS, &action, NULL) < 0)
        error("failed to set SIGSYS signal handler: %s", strerror(errno));

    // Step (3): Install seccomp filter
    if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        error("failed to set PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
    uint32_t offset = offsetof(struct seccomp_data, instruction_pointer);
    struct sock_filter filter[] =
    {
        // if (%rip == rip_1 or %rip == rip_2) then ALLOW else TRAP
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)rip_1, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset + (uint32_t)sizeof(uint32_t)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(rip_1 >> 32), 0, 5),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)rip_2, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset + (uint32_t)sizeof(uint32_t)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(rip_2 >> 32), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog fprog =
    {
        (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        filter
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, /*flags=*/0x0, &fprog)
            < 0)
        error("failed to set seccomp filter: %s", strerror(errno));

    // Step (4): Other initialization
    option_tty = true;  // isatty(STDERR_FILENO);
    fd_init();
    option_pcap = pcap_open(filename, (RECORD? 'w': 'r'));

    if (option_debug)
        kill(getpid(), SIGSTOP);        // Wait for GDB to attach
    signal_init();
    ctl_init();
    coverage_init(NULL, NULL);
    if (RECORD)
    {   // Record:
        thread_init();
        pcap_write_open(option_pcap, SCHED_FD);
        record_init(envp);
        pcap_write_open(option_pcap, 0);
        pcap_write_open(option_pcap, 1);
        pcap_write_open(option_pcap, 2);
    }
    else
    {   // Replay:
        fiber_init();
        option_Q = (QUEUE *)xcalloc(1, sizeof(QUEUE));
        if (option_patch)
            option_P = patch_load(option_patchname);
        size_t nmsg = pcap_parse(option_pcap, filename, option_Q);
        fclose(option_pcap);
        option_pcap = NULL;
        replay_init();
        fuzzer_main(nmsg);
    }
}

