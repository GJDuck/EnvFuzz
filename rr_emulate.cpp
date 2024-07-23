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

/*
 * Emulate getpid()/etc.
 */
static pid_t INFO_pid  = 0;
static pid_t INFO_tid  = 0;
static void emulate_set_pid(pid_t pid)
{
    INFO_pid = INFO_tid = pid;
}
static void emulate_set_tid(pid_t tid)
{
    INFO_tid = MAX(tid, INFO_tid);
}

/*
 * Emulate time.
 */
static uint64_t INFO_gettime[9] = {0};
static intptr_t emulate_gettime(int clk, struct timespec *ts)
{
    if (ts == NULL)
        return -EFAULT;
    if ((size_t)clk >= sizeof(INFO_gettime) / sizeof(INFO_gettime[0]))
        return -EINVAL;
    if (INFO_gettime[clk] == 0)
        return -ENOSYS;
    for (size_t i = 0; i < sizeof(INFO_gettime) / sizeof(INFO_gettime[0]); i++)
        INFO_gettime[i] += 1000000;   // 1ms
    ts->tv_sec  = INFO_gettime[clk] / 1000000000;
    ts->tv_nsec = INFO_gettime[clk] % 1000000000;
    return 0;
}
static intptr_t emulate_gettimeofday(struct timeval *tv, void *ptr)
{
    if (tv == NULL || ptr != NULL)
        return -ENOSYS;
    struct timespec ts;
    intptr_t r = emulate_gettime(CLOCK_REALTIME, &ts);
    if (r < 0)
        return r;
    tv->tv_sec  = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
    return r;
}
static intptr_t emulate_time(time_t *tp)
{
    struct timespec ts;
    intptr_t r = emulate_gettime(CLOCK_REALTIME, &ts);
    if (r < 0)
        return r;
    r = ts.tv_sec;
    if (tp != NULL)
        *tp = (time_t)r;
    return r;
}
static int emulate_nanosleep(const struct timespec *ts, struct timespec *rem)
{
    if (rem != NULL)
    {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
    uint64_t t = ts->tv_sec * 1000000000 + ts->tv_nsec;
    if (t == 0)
        return 0;
    for (size_t i = 0; i < sizeof(INFO_gettime) / sizeof(INFO_gettime[0]); i++)
        INFO_gettime[i] += t;
    FIBER_NEXT();
    return 0;
}

static void emulate_set_gettime(int clk, const struct timespec *ts)
{
    if ((size_t)clk >= sizeof(INFO_gettime) / sizeof(INFO_gettime[0]) ||
            ts == NULL)
        return;
    uint64_t t = ts->tv_sec * 1000000000 + ts->tv_nsec;
    INFO_gettime[clk] = MAX(t, INFO_gettime[clk]);
}
static void emulate_set_gettimeofday(const struct timeval *tv)
{
    if (tv == NULL)
        return;
    struct timespec ts = {tv->tv_sec, tv->tv_usec * 1000};
    emulate_set_gettime(CLOCK_REALTIME, &ts);
}
static void emulate_set_time(time_t t)
{
    struct timespec ts = {t, 0};
    emulate_set_gettime(CLOCK_REALTIME, &ts);
}

static intptr_t emulate_kill(pid_t pid, int sig)
{
    if (pid != 0 && pid != -1 && pid != INFO_pid)
        return -ENOSYS;
    switch (sig)
    {
        case SIGSTOP:
            return 0;   // Ignore
        default:
            return syscall(SYS_kill, INFO_pid, sig);
    }
}

/*
 * Emulate getuid()/getgid()/etc.
 */
static uid_t    INFO_uid  = 0;
static uid_t    INFO_euid = 0;
static uid_t    INFO_suid = 0;
static gid_t    INFO_gid  = 0;
static gid_t    INFO_egid = 0;
static gid_t    INFO_sgid = 0;
static uid_t emulate_getuid(void)
{
    return (INFO_uid == 0? 1000: INFO_uid);
}
static uid_t emulate_geteuid(void)
{
    return (INFO_euid == 0? emulate_getuid(): INFO_euid);
}
static uid_t emulate_getsuid(void)
{
    return (INFO_suid == 0? emulate_getuid(): INFO_suid);
}
static gid_t emulate_getgid(void)
{
    return (INFO_gid == 0? 1000: INFO_gid);
}
static gid_t emulate_getegid(void)
{
    return (INFO_egid == 0? emulate_getgid(): INFO_egid);
}
static gid_t emulate_getsgid(void)
{
    return (INFO_sgid == 0? emulate_getgid(): INFO_sgid);
}

/*
 * Generic syscall emulation.
 */
static void *INFO_syscall = NULL;
static const char *syscall_get_str(const SYSCALL *call, int idx)
{
    if (call->replay)
        return call->args[idx].str;
    else
    {
        const AUX *aux = call->aux;
        uint8_t mask = (MI_____ << idx);
        return (const char *)aux_data(aux, mask, ASTR);
    }
}


static int syscall_compare(const void *a, const void *b)
{
    const SYSCALL *A = (SYSCALL *)a;
    const SYSCALL *B = (SYSCALL *)b;
    if (A->no != B->no)
        return (A->no - B->no);
    switch (A->no)
    {
        case SYS_stat: case SYS_lstat:
            return strcmp(syscall_get_str(A, 0), syscall_get_str(B, 0));
        case SYS_getrlimit: case SYS_getrusage:
            return A->arg0.i32 - B->arg0.i32;
        default:
            return 0;
    }
}

static void emulate_set_syscall(const SYSCALL *call)
{
    if (call->result < 0) return;
    const AUX *aux = call->aux;
    switch (call->no)
    {
        case SYS_getuid:
            INFO_uid = call->result;
            break;
        case SYS_geteuid:
            INFO_euid = call->result;
            break;
        case SYS_getgid:
            INFO_gid = call->result;
            break;
        case SYS_getegid:
            INFO_egid = call->result;
            break;
        case SYS_getresuid:
            (void)aux_get(aux, (uint8_t *)&INFO_uid,  sizeof(INFO_uid),
                MI_____, A_IP);
            (void)aux_get(aux, (uint8_t *)&INFO_euid, sizeof(INFO_euid),
                M_I____, A_IP);
            (void)aux_get(aux, (uint8_t *)&INFO_suid, sizeof(INFO_suid),
                M__I___, A_IP);
            break;
        case SYS_getresgid:
            (void)aux_get(aux, (uint8_t *)&INFO_gid,  sizeof(INFO_gid),
                MI_____, A_IP);
            (void)aux_get(aux, (uint8_t *)&INFO_egid, sizeof(INFO_egid),
                M_I____, A_IP);
            (void)aux_get(aux, (uint8_t *)&INFO_sgid, sizeof(INFO_sgid),
                M__I___, A_IP);
            break;
        case SYS_stat: case SYS_lstat:
        case SYS_access: case SYS_uname:
        case SYS_getrlimit: case SYS_getrusage:
            if (syscall_get_str(call, 0) == NULL) break;
            (void)tsearch((void *)call, &INFO_syscall, syscall_compare);
            break;
        default:
            break;
    }
}
static intptr_t emulate_syscall(const SYSCALL *call)
{
    void *node = tfind(call, &INFO_syscall, syscall_compare);
    if (node == NULL)
    {
        switch (call->no)
        {
            case SYS_stat: case SYS_lstat:
                return -ENOENT;
            default:
                return -ENOSYS;
        }
    }
    const SYSCALL *exp = *(SYSCALL **)node;
    const AUX *aux = exp->aux;
    const INFO *info = syscall_info(call->no);
    int n = syscall_arity(call);
    for (int i = 0; i < n; i++)
    {
        uint8_t arg = info->args[i];
        if (arg == A___)
            break;
        uint8_t mask = (MI_____ << i);
        bool output = syscall_is_output(call, i);
        if (output || !syscall_used(call, i))
            continue;
        size_t size = 0;
        uint8_t *buf = syscall_buf(call, i, &size);
        if (buf == NULL)
            continue;
        if (!aux_get(aux, buf, size, mask, arg))
            return -ENOSYS;
    }
    return exp->result;
}

/*
 * Emulate a syscall as best as possible.
 */
static int emulate_hook(STATE *state)
{
    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;
    syscall_init(call, state, /*replay=*/true);
    call->id = fiber_self()->id;

    const INFO *info = &TABLE[call->no];
    if (info->passthru)
    {
        call->result = syscall(call);
        goto emulate_exit;
    }

    switch (call->no)
    {
        case SYS_close:
            call->result = (fd_close(call->arg0.fd)? 0: -EBADF);
            break;
        case SYS_sched_yield:
            call->result = 0;
            break;
        case SYS_kill:
            call->result = emulate_kill(call->arg0.pid, call->arg1.sig);
            break;
        case SYS_exit_group:
            print_hook(stderr, call);
            syscall(SYS_exit_group, call->arg0.i32);
            abort();    // Not reached
        case SYS_exit:
            print_hook(stderr, call);
            syscall(SYS_exit_group, EXIT_FAILURE);
            abort();    // Not reached
        case SYS_clone:
            call->result = fiber_clone(state, INFO_tid+1);
            break;
        case /*SYS_clone3=*/435:
            call->result = fiber_clone3(state, INFO_tid+1);
            break;
        case SYS_getpid:
            call->result = INFO_pid;
            break;
        case SYS_getuid:
            call->result = emulate_getuid();
            break;
        case SYS_geteuid:
            call->result = emulate_geteuid();
            break;
        case SYS_getgid:
            call->result = emulate_getgid();
            break;
        case SYS_getegid:
            call->result = emulate_getegid();
            break;
        case SYS_getresuid:
            *call->arg0.ip = emulate_getuid();
            *call->arg1.ip = emulate_geteuid();
            *call->arg2.ip = emulate_getsuid();
            call->result = 0;
            break;
        case SYS_getresgid:
            *call->arg0.ip = emulate_getgid();
            *call->arg1.ip = emulate_getegid();
            *call->arg2.ip = emulate_getsgid();
            call->result = 0;
            break;
        case SYS_clock_gettime:
            call->result = emulate_gettime(call->arg0.i32, call->arg1.ts);
            break;
        case SYS_gettimeofday:
            call->result = emulate_gettimeofday(call->arg0.tv, call->arg1.ptr);
            break;
        case SYS_time:
            call->result = emulate_time((time_t *)call->arg0.ptr);
            break;
        case SYS_nanosleep:
            call->result = emulate_nanosleep(call->arg0.ts, call->arg1.ts);
            break;
        case SYS_mmap:
        {
            int flags = call->arg3.flags;
            if (flags & MAP_ANONYMOUS)
            {
                call->result = syscall(call);
                break;
            }
            call->result = -ENOMEM;
            break;
        }
        case SYS_poll:
        {
            struct pollfd *fds = call->arg0.pfds;
            nfds_t nfds        = call->arg1.i32;
            int timeout        = call->arg2.i32;
            call->result = queue_emulate_poll(fds, nfds, timeout);
            break;
        }
        case SYS_select: case SYS_pselect6:
        {
            int nfds = call->arg0.i32;
            fd_set *rfds = call->arg1.fdset;
            fd_set *wfds = call->arg2.fdset;
            fd_set *efds = call->arg3.fdset;
            int timeout = -1;
            const struct timeval *tv = call->arg4.tv;
            const struct timespec *ts = call->arg4.ts;
            if (call->no == SYS_select && tv != NULL)
                timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (call->no == SYS_pselect6 && ts != NULL)
                timeout = ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
            call->result = queue_emulate_select(nfds, rfds, wfds, efds,
                timeout);
            break;
        }
        case SYS_epoll_wait:
        {
            int efd = call->arg0.fd;
            struct epoll_event *events = call->arg1.event;
            int maxevents = call->arg2.i32;
            int timeout = call->arg2.i32;
            call->result = queue_emulate_epoll_wait(efd, events, maxevents,
                timeout);
            break;
        }
        case SYS_epoll_ctl:
        {
            int efd = call->arg0.fd;
            int op = call->arg1.i32;
            int fd = call->arg2.fd;
            struct epoll_event *events = call->arg3.event;
            call->result = fd_epoll_ctl(efd, op, fd, events);
            break;
        }
        case SYS_rt_sigaction:
            call->result = signal_action(call->arg0.sig, call->arg1.action,
                call->arg2.action);
            break;
        case SYS_futex:
        {
            int *addr = (int *)call->arg0.ptr;
            int op    = call->arg1.i32 & 0xFF &
                ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
            int val   = call->arg2.i32;
            switch (op)
            {
                case FUTEX_WAIT:
                    if (fiber_self()->futex == addr)
                        FIBER_NEXT();
                    call->result = 0;
                    break;
                case FUTEX_WAKE:
                    call->result = fiber_wake(addr, val);
                    break;
                default:
                    call->result = -ENOSYS;
                    break;
            }
            break;
        }
        case SYS_stat: case SYS_lstat:
        case SYS_access: case SYS_uname:
        case SYS_getrlimit: case SYS_getrusage:
            call->result = emulate_syscall(call);
            break;
        default:
        {
            call->result = -ENOSYS;
            int fd = -1;
            int n = syscall_arity(call);
            for (int i = 0; i < n; i++)
            {
                uint8_t arg = info->args[i];
                if (arg == A___)
                    break;
                fd = (arg == A_FD? call->args[i].fd: fd);
                bool output = syscall_is_output(call, i);
                if (!syscall_used(call, i))
                    continue;
                size_t size = 0;
                uint8_t *buf = syscall_buf(call, i, &size);
                if (buf == NULL)
                    continue;
                struct msghdr *msg   = (struct msghdr *)buf;
                struct iovec *iov    = (struct iovec *)buf;
                size_t iovcnt        = size / sizeof(struct iovec);
                bool io = (info->kind == P_IO) && (fd >= 0);
                if (io && output)
                {
                    // Send output to fuzzer for tracking
                    switch (arg)
                    {
                        case ABUF:
                            fuzzer_track(fd_entry(fd), buf, size); break;
                        case AIOV:
                            fuzzer_track(fd_entry(fd), iov, iovcnt); break;
                        case AMSG:
                            fuzzer_track(fd_entry(fd), msg->msg_iov,
                                msg->msg_iovlen);
                            break;
                    }
                }
                switch (arg)
                {
                    case ABUF:
                        if (io)
                            call->result = queue_emulate_get(buf, size, fd,
                                output);
                        break;
                    case AIOV:
                        call->result = queue_emulate_get(iov, iovcnt, fd,
                            output);
                        break;
                    case AMSG:
                        call->result = queue_emulate_get(msg->msg_iov,
                            msg->msg_iovlen, fd, output);
                        if (!output)
                        {
                            msg->msg_namelen    = 0;
                            msg->msg_controllen = 0;
                            msg->msg_flags      = 0x0;
                        }
                        break;
                }
            }
            break;
        }
    }

emulate_exit:
    print_hook(stderr, call);

    state->rax = call->result;
    return REPLACE;
}

