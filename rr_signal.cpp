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

#define SIG_MASK(sig)       (0x1ull << ((sig)-1))

static struct ksigaction ACTION_TABLE[_NSIG] = {0};

/*
 * (Un)blocking signals.
 */
static void signal_set_mask(sigset_t set)
{
    set &= ~(SIG_MASK(SIGSYS) | SIG_MASK(SIGINT) | SIG_MASK(SIGSEGV) |
        (REPLAY? SIG_MASK(SIGILL) | SIG_MASK(SIGFPE) | SIG_MASK(SIGBUS) |
                 SIG_MASK(SIGTRAP) | SIG_MASK(SIGABRT): 0x0));
    if (syscall(SYS_rt_sigprocmask, /*SIG_SETMASK=*/2, &set, NULL,
            sizeof(set)) < 0)
        error("failed to set signal mask: %s", strerror(errno));
}
static void SIGNAL_BLOCK(sigset_t set = 0xFFFFFFFFFFFFFFFFull)
{
    signal_set_mask(set);
}
static void SIGNAL_UNBLOCK(sigset_t set = 0xFFFFFFFFFFFFFFFFull)
{
    signal_set_mask(~set);
}

/*
 * Safe memcpy (should not fault on src).
 */
static bool safe_memcpy(void *dst, const void *src, size_t size)
{
    intptr_t base = (intptr_t)src;
    off_t offset  = base % PAGE_SIZE;
    if (msync((void *)(base - offset), size + offset, MS_ASYNC) < 0)
        return false;
    memcpy(dst, src, size);
    return true;
}

/*
 * Handle SIGSEGV.
 */
static int record_hook(STATE *state);
static int replay_hook(STATE *state);
static void signal_segv_handler(int sig, siginfo_t *info, void *ctx_0)
{
    intptr_t *ctx = (intptr_t *)ctx_0;
    const uint8_t *rip = (uint8_t *)ctx[REG_RIP];
    uint8_t tmp[3];

    // Check for & handle rdtsc(p) instruction(s):
    for (size_t i = sizeof(tmp); i >= 2; i--)
    {
        memset(tmp, 0x0, sizeof(tmp));
        safe_memcpy(tmp, rip, i);
    }
    bool rdtsc  = (tmp[0] == 0x0f && tmp[1] == 0x31);
    bool rdtscp = (tmp[0] == 0x0f && tmp[1] == 0x01 && tmp[2] == 0xf9);
    bool cpuid  = (tmp[0] == 0x0f && tmp[1] == 0xa2);
    if (rdtsc || rdtscp)
    {
        STATE state;
        state_init(ctx_0, &state);
        state.rax = SYS_rdtsc;
        int r = (RECORD? record_hook(&state): replay_hook(&state));
        assert(r == REPLACE);
        uint64_t result = (uint64_t)state.rax;
        ctx[REG_RAX] = result & 0xFFFFFFFFull;
        ctx[REG_RDX] = result >> 32;
        if (rdtscp)
            ctx[REG_RCX] = option_cpu;
        ctx[REG_RIP] += (rdtsc? /*sizeof(rdtsc)=*/2: /*sizeof(rdtscp)=*/3);
        return;     // Continue
    }
    if (cpuid)
    {
        if (syscall(SYS_arch_prctl, /*ARCH_SET_CPUID=*/0x1012, 0x1) < 0)
            error("failed to disable cpuid interception: %s", strerror(errno));
        intptr_t rax = ctx[REG_RAX], rcx = ctx[REG_RCX];
        uint32_t eax, ebx, ecx, edx;
        asm volatile
        (
            "cpuid"
            : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (rax), "c" (rcx)
        );
        if (syscall(SYS_arch_prctl, /*ARCH_SET_CPUID=*/0x1012, 0x0) < 0)
            error("failed to enable cpuid interception: %s", strerror(errno));
        if (rax == 0x1)
            ecx &= ~(1u << 30);                 // Disable rdrand
        if (rax == 0x7 && rcx == 0x0)
            ebx &= ~((1u << 18) | (1u << 11));  // Disable rdseed & rtm
        ctx[REG_RAX] = eax;
        ctx[REG_RBX] = ebx;
        ctx[REG_RCX] = ecx;
        ctx[REG_RDX] = edx;
        ctx[REG_RIP] += /*sizeof(cpuid)=*/2;
        return;     // Continue
    }

    // Re-raise:
    signal(SIGSEGV, SIG_DFL);
    if (option_fuzz && fuzzer_state == FUZZ_LEAF && FUZZ->rip == NULL)
        FUZZ->rip = (void *)ctx[REG_RIP];
}

/*
 * Signal record handler.  Records as a SYS_signal message.
 */
static void signal_record_handler(int sig, siginfo_t *info, void *ctx)
{
    switch (sig)
    {
        case SIGINT:
            exit(EXIT_FAILURE);
    }

    THREAD_LOCK();

    // Record that a signal was recieved:
    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;
    call->no = SYS_signal;
    call->id = thread_self()->id;
    call->arg0.sig     = sig;
    call->arg1.siginfo = info;

    AUXVEC auxv(call);
    auxv.push((uint8_t *)info, sizeof(*info), M_I____, A_SI);
    auxv.end();

    print_hook(stderr, call);
    pcap_write(option_pcap, auxv.iov(), auxv.iovcnt(), SIZE_MAX, SCHED_FD,
        OUTBOUND);

    switch (sig)
    {
        case SIGABRT: case SIGBUS: case SIGFPE: case SIGILL: case SIGSEGV:
        sig_dfl:
            signal_set_mask(~SIG_MASK(sig));
            kill(getpid(), sig);
            break;
        default:
            if (ACTION_TABLE[sig].sa_handler_2 == SIG_IGN)
                break;
            if (ACTION_TABLE[sig].sa_handler_2 == SIG_DFL)
                goto sig_dfl;
            if (ACTION_TABLE[sig].sa_flags & SA_SIGINFO)
                ((void (*)(int, siginfo_t *, void *))
                    ACTION_TABLE[sig].sa_handler_2)(sig, info, ctx);
            else
                ((void (*)(int))ACTION_TABLE[sig].sa_handler_2)(sig);
            break;
    }

    struct sigaction action = {0};
    action.sa_sigaction = signal_record_handler;
    action.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    if (sigaction(sig, &action, NULL) < 0)
        error("failed to reset %s signal handler: %s",
            signal_name(sig), strerror(errno));

    THREAD_UNLOCK();
}

/*
 * Signal replay handler.  Replays SYS_signal message.
 */
static void signal_replay_handler(int sig, siginfo_t *info, void *ctx)
{
    switch (sig)
    {
        case SIGINT:
            exit(EXIT_FAILURE);
        case SIGABRT: case SIGBUS: case SIGFPE: case SIGILL: case SIGTRAP:
            if (option_fuzz && fuzzer_state == FUZZ_LEAF && FUZZ->rip == NULL)
            {
                intptr_t *ctx_1 = (intptr_t *)ctx;
                FUZZ->rip = (void *)ctx_1[REG_RIP];
            }
            signal_set_mask(~SIG_MASK(sig));
            kill(getpid(), sig);
            error("signal %s failed to terminate program", signal_name(sig));
        default:
            break;
    }

    MSG *M = queue_peek(option_Q, SCHED_PORT);
    if (M == NULL)
        error("unexpected end-of-schedule");
    const SYSCALL *exp = (SYSCALL *)M->payload;
    if (exp->id != fiber_self()->id || exp->no != SYS_signal ||
            sig != exp->arg0.sig)
    {
        warning("ignoring unexpected signal %s", signal_name(sig));
        return;
    }
    (void)queue_pop(option_Q, SCHED_PORT);

    if (option_log >= 3)
    {
        SYSCALL call_0 = {0};
        SYSCALL *call = &call_0;
        call->no = SYS_signal;
        call->id = exp->id;
        call->arg0.sig     = sig;
        call->arg1.siginfo = info;

        AUXVEC auxv(call);
        auxv.push((uint8_t *)info, sizeof(*info), M_I____, A_SI);
        auxv.end();

        print_hook(stderr, call);
    }

    // Overwrite info with the recorded info:
    if (!aux_get(exp->aux, (uint8_t *)info, sizeof(*info), M_I____, A_SI))
        error("missing siginfo_t for signal %s", signal_name(sig));

    switch (sig)
    {
        case SIGABRT: case SIGBUS: case SIGFPE: case SIGILL: case SIGSEGV:
        sig_dfl:
            signal_set_mask(~SIG_MASK(sig));
            kill(getpid(), sig);
            break;
        default:
            if (ACTION_TABLE[sig].sa_handler_2 == SIG_IGN)
                break;
            if (ACTION_TABLE[sig].sa_handler_2 == SIG_DFL)
                goto sig_dfl;
            if (ACTION_TABLE[sig].sa_flags & SA_SIGINFO)
                ((void (*)(int, siginfo_t *, void *))
                    ACTION_TABLE[sig].sa_handler_2)(sig, info, ctx);
            else
                ((void (*)(int))ACTION_TABLE[sig].sa_handler_2)(sig);
            break;
    }

    struct sigaction action = {0};
    action.sa_sigaction = signal_replay_handler;
    action.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    if (sigaction(sig, &action, NULL) < 0)
        error("failed to reset %s signal handler: %s",
            signal_name(sig), strerror(errno));
}

/*
 * Init signal handling.
 */
static void signal_init(void)
{
    struct sigaction action;
    memset(&action, 0x0, sizeof(action));
    action.sa_sigaction =
        (RECORD? signal_record_handler: signal_replay_handler);
    action.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    for (int sig = 1; sig < _NSIG; sig++)
    {
        switch (sig)
        {
            case SIGKILL: case SIGSTOP: case SIGSYS:
                continue;
        }
        if (sigaction(sig, &action, NULL) < 0)
            error("failed to set %s signal handler: %s",
                signal_name(sig), strerror(errno));
    }

    memset(&action, 0x0, sizeof(action));
    action.sa_sigaction = signal_segv_handler;
    action.sa_flags     = SA_SIGINFO;
    if (sigaction(SIGSEGV, &action, NULL) < 0)
        error("failed to set %s signal handler: %s",
            signal_name(SIGSEGV), strerror(errno));
}

/*
 * sigaction() handler.  We do not send it to the kernel, but "emulate" it.
 */
static int signal_action(int sig, const struct ksigaction *action,
    struct ksigaction *old)
{
    if (sig >= _NSIG)
        return -EINVAL;
    if (old != NULL)
        memcpy(old, ACTION_TABLE + sig, sizeof(*old));
    if (action != NULL)
        memcpy(ACTION_TABLE + sig, action, sizeof(*action));
    return 0;
}

/*
 * sigprocmask handler.
 */
static int signal_procmask(int how, const sigset_t *set, sigset_t *oldset)
{
    THREAD *self = thread_self();
    if (oldset != NULL)
        *oldset = self->sigmask;
    if (set == NULL)
        return 0;
    switch (how)
    {
        case /*SIG_BLOCK=*/0:   self->sigmask |= *set; break;
        case /*SIG_UNBLOCK=*/1: self->sigmask &= ~(*set); break;
        case /*SIG_SETMASK=*/2: self->sigmask  = *set; break;
        default:
            return -EINVAL;
    }
    return 0;
}

