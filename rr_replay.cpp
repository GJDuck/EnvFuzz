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
 * Check if AUX data is valid or not
 */
static void aux_validate(const AUX *aux, size_t size)
{
    while (aux->kind != AEND)
    {
        if (size <= sizeof(AUX) || aux->size + sizeof(AUX) >= size)
            goto error;
        size -= aux->size + sizeof(AUX);
        aux = (const AUX *)((uint8_t *)aux + aux->size + sizeof(AUX));
    }
    if (size == sizeof(AUX))
        return;
error:
    error("corrupted auxiliary data vector");
}

static void print_aux(PRINTER &P, const INFO *info, const SYSCALL *call, int i)
{
    const AUX *aux = call->aux;
    uint8_t mask = (MI_____ << i);
    if (mask & info->mask)
    {
        P.put("???");
        return;
    }
    uint8_t kind = info->args[i];
    aux = aux_find(aux, SIZE_MAX, mask, kind);
    if (aux == NULL)
    {
        if (!arg_is_pointer(kind))
            print_arg(P, info, call, i);
        else
            P.format("%p", call->args[i].ptr);
        return;
    }
    switch (kind)
    {
        case AIOV:
            print_iov_struct(P, (struct iovec *)aux->data,
                aux->size / sizeof(struct iovec));
            break;
        case AMSG:
            print_msghdr_struct(P, (struct msghdr *)aux->data);
            break;
        default:
        {
            size_t next = (i == 5? 0: call->args[i+1].size);
            size_t prev = (i == 0? 0: call->args[i-1].size);
            print_arg(P, info, kind, (intptr_t)aux->data, prev, next,
                aux->size);
            break;
        }
    }
}

static void print_aux_syscall(PRINTER &P, const SYSCALL *call)
{
#if 0
    const AUX *aux = call->aux;
    while (aux->kind != AEND)
    {
        fprintf(stderr, "[%s,#%d]",
            arg_name(aux->kind),
            (aux->mask == 0x1? 1:
             aux->mask == 0x2? 2:
             aux->mask == 0x4? 3:
             aux->mask == 0x8? 4:
             aux->mask == 0x10? 5: 6));
        aux = (const AUX *)((uint8_t *)aux + aux->size + sizeof(AUX));
    }
#endif

    P.format("%s(", syscall_name(call->no));
    int n = syscall_arity(call);
    const INFO *info = syscall_info(call->no);
    for (int i = 0; i < n; i++)
    {
        P.put(i > 0? ",": "");
        print_aux(P, info, call, i);
    }
    P.put(") = ");
    print_result(P, call);
}

/*
 * Report a mismatch.
 */
#define mismatch(msg, ...)                                              \
    (option_emulate == 0? error: warning)(msg, ##__VA_ARGS__)

/*
 * Check if an output matches the recording.
 */
static void queue_validate(const SYSCALL *exp, int i, uint8_t arg, int fd,
    const iovec *iov, size_t iovcnt)
{
    ENTRY *E = fd_get(fd);
    PRINTER P;
    if (option_log >= 1 && option_log <= 2 &&
            (fd == STDOUT_FILENO || fd == STDERR_FILENO))
    {
        print_output(P, iov, iovcnt);
        fprintf(stderr, "%s%s%s", CYAN, P.str(), OFF);
    }

    QUEUE *Q = option_Q;
    MSG *M = queue_pop(Q, E->port);
    if (M == NULL)
    {
        if (iov_len(iov, iovcnt) == 0)
            return;
        print_diff(P, iov, iovcnt, NULL, 0);
        mismatch("extraneous output (size=%zu) for %s() arg #%d\n%s",
            iov_len(iov, iovcnt), syscall_name(exp->no), i+1, P.str());
        return;
    }

    struct iovec iov2 = {M->payload, M->len};
    if (!iov_equal(iov, iovcnt, &iov2, 1, exp->result))
    {
        print_diff(P, iov, iovcnt, &iov2, 1);
        mismatch("mismatching output for %s() arg #%d\n%s",
             syscall_name(exp->no), i+1, P.str());
    }
    if (E->event.enabled)
        (void)eventfd_emulate_write(E, iov, iovcnt);
}
static void queue_validate(const SYSCALL *exp, int i, uint8_t arg, int fd,
    const uint8_t *buf, size_t size)
{
    struct iovec iov = {(void *)buf, size};
    queue_validate(exp, i, arg, fd, &iov, 1);
}

/*
 * Check if the syscall matches the recording.
 */
static bool validate(const SYSCALL *exp, const SYSCALL *call)
{
    PRINTER P, Q;
    if (option_patch || (option_fuzz && fuzzer_state == FUZZ_LEAF))
    {
        if (option_emulate >= 2 &&
                (call->no != exp->no || call->id != exp->id))
        {
            // Likely behaviour divergence due to mutation:
            fuzzer_emulate = true;
            fd_next = UINT16_MAX+1;
            if (option_log >= 3)
            {
                print_aux_syscall(P, exp);
                print_syscall(Q, call, /*exe=*/false);
                fprintf(stderr, "%sDESYNC%s:\n"
                    "\texpected %s%s%s\n\tgot      %s%s%s\n",
                    BLUE, OFF, YELLOW, P.str(), OFF, YELLOW, Q.str(), OFF);
            }
            return false;
        }
    }

    if (call->no != exp->no)
    {
        print_aux_syscall(P, exp);
        print_syscall(Q, call);
        error("failed to replay syscall\n\texpected %s\n\tgot      %s",
            P.str(), Q.str());
    }
    if (call->id != exp->id)
        error("failed to replay syscall; expected thread #%d, got #%d",
            exp->id, call->id);
    if ((size_t)call->no >= sizeof(TABLE) / sizeof(TABLE[0]))
        error("syscall number %d is not yet implemented", call->no);
    if (exp->result < 0)
        return true;

    const INFO *info = &TABLE[call->no];
    const AUX *aux = exp->aux;
    int fd = -1;
    int n = syscall_arity(exp);
    for (int i = 0; i < n; i++)
    {
        uint8_t arg = info->args[i];
        if (arg == A___ || arg == ADDD)
            break;
        if (!syscall_used(exp, i))
            continue;
        uint8_t mask = (MI_____ << i);
        bool output = ((info->mask & mask) == 0);
        size_t size = 0,
            prev = (i > 0? call->args[i-1].size: 0),
            next = (i < 5? call->args[i+1].size: 0);
        bool io = (info->kind == P_IO) && (fd >= 0) &&
            (call->args[i].buf != NULL);
        switch (arg)
        {
            case ANYI:
                error("syscall %s() is not-yet-implemented",
                    syscall_name(call->no));
            case A_FD:
                fd = call->args[i].val;
                goto value;
            case ASTR:
                if (output && !aux_check(aux, call->args[i].str, mask, arg))
                    goto error;
                goto value;
            case ABUF:
                size = next;
                if (output && io)
                {
                    queue_validate(exp, i, arg, fd, call->args[i].buf, size);
                    break;
                }
                goto buffer;
            case AIOV:
                size = next;
                if (output && io)
                    queue_validate(exp, i, arg, fd, call->args[i].iov, size);
                size *= sizeof(struct iovec);
                goto buffer;
            case AMSG:
            {
                struct msghdr *msg = call->args[i].msg;
                if (output && io)
                    queue_validate(exp, i, arg, fd,
                        msg->msg_iov, msg->msg_iovlen);
                size = sizeof(struct msghdr);
                goto buffer;
            }
            case A_MM:
            {
                struct msghdr *msg = &call->args[i].mmsg->msg_hdr;
                if (output && io)
                    queue_validate(exp, i, arg, fd,
                        msg->msg_iov, msg->msg_iovlen);
                size = sizeof(struct msghdr);
                goto buffer;
            }
            case ASTB: size = sizeof(struct stat); goto buffer;
            case APFD: size = next * sizeof(struct pollfd); goto buffer;
            case ASET: size = sizeof(fd_set); goto buffer;
            case A_TV: size = sizeof(struct timeval); goto buffer;
            case A_TS: size = sizeof(struct timespec); goto buffer;
            case AFD2: size = 2 * sizeof(int); goto buffer;
            case A_IP: size = sizeof(int); goto buffer;
            case ASZP: size = sizeof(size_t); goto buffer;
            buffer:
                // Check if the memory contents match the recording:
                if (output &&
                        !aux_check(aux, call->args[i].buf, size, mask, arg))
                {
            error:
                    print_aux(P.reset(), info, exp, i);
                    print_arg(Q.reset(), info, call, i);
                    mismatch("buffer mismatch detected for %s() arg #%d (%s)"
                        "\n\texpected %s\n\tgot      %s",
                        syscall_name(call->no), i+1, arg_name(arg),
                        P.str(), Q.str());
                }
                arg = APTR;
                size = next = sizeof(void *);
                // Fallthrough:
            value:
            default:
                // Check if the syscall argument value matches the recording:
                if (call->args[i].val != exp->args[i].val)
                {
                    arg = (arg_is_pointer(arg)? APTR: arg);
                    print_val(P.reset(), info, arg, exp->args[i].val,  prev,
                        next, size);
                    print_val(Q.reset(), info, arg, call->args[i].val, prev,
                        next, size);
                    mismatch("value mismatch detected for %s() arg #%d (%s); "
                        "expected %s, got %s",
                        syscall_name(call->no), i+1, arg_name(arg),
                        P.str(), Q.str());
                }
                break;
        }
    }
    return true;
}

/*
 * Replay a mmap() syscall.
 */
static intptr_t replay_mmap(const SYSCALL *exp, const SYSCALL *call)
{
    void *addr   = (void *)exp->result;
    size_t size  = call->arg1.size;
    int prot     = call->arg2.flags;
    int flags    = call->arg3.flags;
    int fd       = call->arg4.fd;
    off_t offset = call->arg5.offset;
    const AUX *aux = exp->aux;

    int prot1  = PROT_READ | PROT_WRITE;
    int flags1 = MAP_PRIVATE | MAP_ANONYMOUS |
        MAP_NORESERVE | ((flags & MAP_FIXED) != 0 ||
         is_mapping_available(addr, size)? MAP_FIXED: 0x0);
    intptr_t ptr = syscall(SYS_mmap, exp->result, size, prot1, flags1, -1, 0);
    intptr_t r = ptr;

    if (r < 0)
    {
mmap_error:
        if (ptr >= 0)
            (void)munmap((void *)ptr, call->arg1.size);
        return r;
    }

    uint8_t *buf = (uint8_t *)ptr;
    if (flags & MAP_ANONYMOUS)
    {
        if (prot != prot1 && mprotect(buf, size, prot) < 0)
            error("failed to protect memory: %s", strerror(errno));
        return r;
    }

    if (!aux_get(aux, (uint8_t *)&size, sizeof(size), M_I____, ASIZ))
        error("missing (%s) data for %s() arg #%d",
            arg_name(APTH), syscall_name(call->no), 2);

    if (size <= MMAP_RECORD_MAX)
    {
        // Read file from queue:
        ssize_t s = queue_read(buf, size, fd);
        if (s < 0)
        {
            r = s;
            goto mmap_error;
        }
    }
    else
    {
        // Read file from disk:
        const ENTRY *E = fd_lookup(fd);
        fd = open(E->name, E->flags & O_ACCMODE);
        if (fd < 0)
        {
            if (errno == ENOENT && (E->flags & O_CREAT) != 0)
            {
                // This is a new file created by the program:
                return r;
            }
            r = -errno;
            goto mmap_error;
        }
        if (offset > 0 && lseek(fd, offset, SEEK_SET) != offset)
        {
            r = -errno;
            goto mmap_error;
        }
        for (size_t i = 0; i < size; )
        {
            ssize_t s = read(fd, buf + i, size - i);
            if (s == 0)
                break;      // Short read is not an error
            if (s <= 0)
            {
                r = -errno;
                close(fd);
                goto mmap_error;
            }
            i += (size_t)s;
        }
        close(fd);
    }

    if (prot != prot1 && mprotect(buf, size, prot) < 0)
        error("failed to protect memory: %s", strerror(errno));
    return r;
}

/*
 * Set the pid.
 */
static void replay_setcontext(const SYSCALL *exp)
{
    const AUX *aux = exp->aux;
    const CONTEXT *ctx = (CONTEXT *)aux_data(aux, MI_____, ACTX);
    if (ctx == NULL)
        error("failed to get execution context");
    if (option_log >= 3)
    {
        SYSCALL call_0;
        SYSCALL *call = &call_0;
        memcpy(call, exp, sizeof(SYSCALL));
        call->arg0.ptr = (void *)ctx;
        print_hook(stderr, call);
    }
    pid_t pid = ctx->pid;
    emulate_set_pid(pid);
    asm volatile ("mov %0,%%fs:0x2d4" : : "r"(pid));
}

/*
 * Called during replay whenever a syscall occurs.
 */
static int replay_hook(STATE *state)
{
    fuzzer_syscall_callback();

    if (state->rax == SYS_futex)
    {   // Special futex handling: remember FUTEX_WAITs:
        int *addr = (int *)state->rdi;
        int op    = (int)state->rsi & 0xFF &
            ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
        int val   = (int)state->rdx;
        switch (op)
        {
            case FUTEX_WAIT:
                if (*addr == val)
                {
                    fiber_self()->futex = addr;
                    break;
                }
                // Fallthrough:
            default:
                fiber_self()->futex = NULL;
                break;
        }
    }
    else
        fiber_self()->futex = NULL;

    SCHED *R = NULL;
    SYSCALL *exp = NULL;
    while (!fuzzer_emulate)
    {
        R = option_SCHED;
        if (R == NULL)
            error("unexpected end-of-schedule");
        exp = (SYSCALL *)R->data;
        if (exp->id == fiber_self()->id)
        {
            if (exp->no == SYS_signal)
            {
                int sig = exp->arg0.sig;
                SIGNAL_UNBLOCK(SIG_MASK(sig));
                kill(getpid(), sig);
                SIGNAL_BLOCK(SIG_MASK(sig));
                continue;
            }

            option_SCHED = option_SCHED->next;

            // Special handling:
            switch (exp->no)
            {
                case SYS_start:
                    continue;
                case SYS_setcontext:
                    replay_setcontext(exp);
                    continue;
            }
            break;
        }
        if (exp->no == SYS_start)
            print_hook(stderr, exp);
        FIBER_SWITCH(exp->id);
    }
    if (fuzzer_emulate)
        return emulate_hook(state);

    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;
    syscall_init(call, state, /*relay=*/true);
    call->id = fiber_self()->id;

    const AUX *aux = exp->aux;
    aux_validate(aux, R->len - sizeof(SYSCALL));
    if (!validate(exp, call))
        return emulate_hook(state);

    PRINTER P, Q;
    const INFO *info = &TABLE[call->no];
    if (exp->result < 0)
    {
        call->result = state->rax = exp->result;    // Syscall failed
        goto replay_exit;
    }

    if (info->passthru)
    {
        // Some operations are passed directly to the O/S:
        call->result = state->rax = syscall(call);
        if (call->result != exp->result)
        {
            print_result(P, exp);
            print_result(Q, call);
            warning("mismatching result for %s(); expected=%s, got=%s",
                syscall_name(call->no), P.str(), Q.str());
        }
        goto replay_exit;
    }

    call->result = state->rax = exp->result;
    ENTRY *E;
    int flags, *fds;
    char name[BUFSIZ];
    switch (call->no)
    {
        // Special cases:
        case SYS_execve: case SYS_execveat:
            error("%s() is not-yet-implemented", syscall_name(call->no));
        case SYS_fork: case SYS_vfork: 
            call->result = fiber_fork();
            goto handler;
        case /*SYS_rseq=*/334:
            call->result = exp->result;
            goto handler;
        case SYS_clone:
            call->result = fiber_clone(state, (pid_t)exp->result);
            goto handler;
        case /*SYS_clone3=*/435:
            call->result = fiber_clone3(state, (pid_t)exp->result);
            goto handler;
        case SYS_madvise:
            if (call->arg2.i32 == MADV_DONTNEED &&
                    (uintptr_t)call >= call->arg0.u64 &&
                    (uintptr_t)call < call->arg0.u64 + call->arg1.u64)
            {
                // Ignore MADV_DONTNEED on current stack:
                call->result = -ENOSYS;
            }
            else
                call->result = syscall(call);
            goto handler;
        case SYS_open: case SYS_openat:
            if (!aux_get(aux, (uint8_t *)name, sizeof(name),
                    (call->no == SYS_open? MI_____: M_I____), APTH))
                error("missing (%s) data for %s() arg #%d",
                    arg_name(APTH), syscall_name(call->no),
                    (call->no == SYS_open? 1: 2));
            flags = (call->no == SYS_open? call->arg1.flags: call->arg2.flags);
            fd_open((int)call->result, S_IFREG, SOCK_STREAM, flags, name);
            goto handler;
        case SYS_socket:
            fd_open((int)call->result, S_IFSOCK, call->arg2.i32, 0x0,
                socket_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_socketpair:
            fds = call->arg3.fds;
            if (!aux_get(aux, (uint8_t *)fds, sizeof(int[2]), M___I__, AFD2))
                error("missing (%s) data for %s() arg #%d",
                    arg_name(AFD2), syscall_name(call->no), 1);
            fd_open(fds[0], S_IFSOCK, call->arg2.i32, 0x0,
                socket_name(fds[0], name, sizeof(name)));
            fd_open(fds[1], S_IFSOCK, call->arg2.i32, 0x0,
                socket_name(fds[0], name, sizeof(name)));
            goto handler;
        case SYS_eventfd: case SYS_eventfd2:
            fd_eventfd((int)call->result, call->arg0.u32,
                (call->no == SYS_eventfd2? call->arg1.flags: 0x0),
                event_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_epoll_create: case SYS_epoll_create1:
            fd_open((int)call->result, S_IFSOCK, SOCK_DGRAM, 0x0,
                epoll_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_connect: case SYS_bind:
            fd_bind(call->arg0.fd, call->arg1.addr, call->arg2.size);
            goto handler;
        case SYS_accept: case SYS_accept4:
            E = fd_entry(call->arg0.fd);
            flags = (call->no == SYS_accept4? call->arg3.i32: 0x0);
            fd_open((int)call->result, S_IFSOCK, E->socktype, flags, NULL);
            goto handler;
        case /*SYS_memfd_create=*/319:
            E = fd_open((int)call->result, S_IFSOCK, SOCK_STREAM, O_CREAT,
                memfd_name((int)call->result, call->arg0.path, name,
                    sizeof(name)));
            goto handler;
        case SYS_pipe: case SYS_pipe2:
            fds = call->arg0.fds;
            flags = (call->no == SYS_pipe2? call->arg1.i32: 0x0);
            if (!aux_get(aux, (uint8_t *)fds, sizeof(int[2]), MI_____, AFD2))
                error("missing (%s) data for %s() arg #%d",
                    arg_name(AFD2), syscall_name(call->no), 1);
            fd_open(fds[0], S_IFIFO, SOCK_STREAM, flags,
                pipe_name(fds[0], 0, name, sizeof(name)));
            fd_open(fds[1], S_IFIFO, SOCK_STREAM, flags,
                pipe_name(fds[1], 1, name, sizeof(name)));
            goto handler;
        case SYS_dup: case SYS_dup2: case SYS_dup3:
            fd_dup(fd_get(call->args[0].fd), (int)call->result);
            goto handler;
        case SYS_fcntl:
            switch (call->arg1.i32) 
            {
                case /*F_DUPFD=*/0: case /*F_DUPFD_CLOEXEC=*/1030:
                    E = fd_dup(fd_get(call->arg0.fd), (int)call->result);
                    break;
                default:
                    break;
            }
            goto handler;
        case SYS_close:
            fd_close(call->arg0.fd);
            goto handler;
        case SYS_rt_sigaction:
            call->result = signal_action(call->arg0.sig, call->arg1.action,
                call->arg2.action);
            goto handler;
        case SYS_mmap:
            call->result = state->rax = replay_mmap(exp, call);
            goto handler;
        handler:
        default:        // Generic syscall hander:
        {
            int fd = -1;
            int n = syscall_arity(call);
            for (int i = 0; i < n; i++)
            {
                uint8_t arg = info->args[i];
                if (arg == A___)
                    break;
                fd = (arg == A_FD? call->args[i].fd: fd);
                uint8_t mask = (MI_____ << i);
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
                struct mmsghdr *mmsg = (struct mmsghdr *)buf;
                bool io = (info->kind == P_IO) && (fd >= 0);
                if (io && output && option_fuzz)
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
                        case A_MM:
                            fuzzer_track(fd_entry(fd),
                                mmsg->msg_hdr.msg_iov,
                                mmsg->msg_hdr.msg_iovlen);
                            break;
                    }
                }
                if (io && output && info->result == RSIZ)
                {
                    // Ensure that the replayed result does not exceed the
                    // output length. This is a nasty corner case of
                    // divergence, where the program does a short write.
                    ssize_t max = INT64_MAX;
                    switch (arg)
                    {
                        case ABUF: max = size; break;
                        case AIOV: max = iov_len(iov, iovcnt); break;
                        case AMSG:
                            max = iov_len(msg->msg_iov, msg->msg_iovlen);
                            break;
                        case A_MM:
                            max = iov_len(mmsg->msg_hdr.msg_iov,
                                mmsg->msg_hdr.msg_iovlen);
                            break;
                    }
                    call->result = state->rax = MIN(max, call->result);
                }
                if (output)
                {
                    if (call->no == SYS_sendmmsg && call->result > 0)
                    {
                        // sendmmsg() special-case handling:
                        mmsg->msg_len = (unsigned)call->result;
                        state->rax = 1;
                    }
                    continue;
                }
                switch (arg)
                {
                    case ABUF:
                        if (io)
                        {
                            call->result = state->rax =
                                queue_read(buf, size, fd);
                        }
                        else if (!aux_get(aux, buf, size, mask, arg))
                            goto error;
                        break;
                    case AIOV:
                        call->result = state->rax = queue_read(iov, iovcnt, fd);
                        break;
                    case AMSG:
                        call->result = state->rax =
                            queue_read(msg->msg_iov, msg->msg_iovlen, fd);
                        if (!aux_get(aux, msg, mask, arg))
                            goto error;
                        if ((msg->msg_flags & /*MSG_TRUNC=*/0x20) != 0 &&
                                call->result < exp->result)
                            call->result = state->rax = exp->result;
                        break;
                    case A_MM:
                        call->result = state->rax =
                            queue_read(mmsg->msg_hdr.msg_iov,
                                mmsg->msg_hdr.msg_iovlen, fd);
                        if (!aux_get(aux, &mmsg->msg_hdr, mask, arg))
                            goto error;
                        if (call->result > 0)
                        {
                            // recvmmsg() special-case handling:
                            mmsg->msg_len = (unsigned)call->result;
                            state->rax = 1;
                        }
                        if ((mmsg->msg_hdr.msg_flags & /*MSG_TRUNC=*/0x20) &&
                                mmsg->msg_len < exp->result)
                            call->result = mmsg->msg_len = exp->result;
                        break;
                    case APTR:
                        error("missing input for %s() arg #%d; "
                            "not-yet-implemented?",
                            syscall_name(call->no), i+1);
                    default:
                        if (!aux_get(aux, buf, size, mask, arg))
                            goto error;
                        break;
                    error:
                        error("missing (%s) data for %s() arg #%d",
                            arg_name(arg), syscall_name(call->no), i+1);
                }
            }
            break;
        }
    }

    if (call->result != exp->result)
    {
        print_result(P, exp);
        print_result(Q, call);
        warning("mismatching result for %s(); expected=%s, got=%s",
            syscall_name(call->no), P.str(), Q.str());
    }

    // Special handling:
    if (call->result >= 0)
    {
        switch (call->no)
        {
            case SYS_start:
                return REPLACE; // Already printed
            case SYS_exit_group:
                print_hook(stderr, call);
                syscall(SYS_exit_group, call->arg0.i32);
                abort();        // Not reached
            case SYS_exit:
                print_hook(stderr, call);
                fiber_exit();
                R = option_SCHED;
                if (R == NULL)
                    error("unexpected end-of-schedule");
                exp = (SYSCALL *)R->data;
                FIBER_SWITCH(exp->id);
                abort();        // Not reached
            case SYS_clock_gettime:
                emulate_set_gettime(call->arg0.i32, call->arg1.ts);
                break;
            case SYS_gettimeofday:
                emulate_set_gettimeofday(call->arg0.tv);
                break;
            case SYS_time:
                emulate_set_time(call->result);
                break;
            case SYS_epoll_ctl:
                fd_epoll_ctl(call->arg0.fd, call->arg1.i32, call->arg2.fd,
                    call->arg3.event);
                break;
            default:
                break;
        }
    }

replay_exit:
    print_hook(stderr, call);

    return REPLACE;
}

/*
 * Replay initialization.
 */
static void replay_init(void)
{
    for (SCHED *R = option_SCHED; R != NULL; R = R->next)
    {
        const SYSCALL *call = (SYSCALL *)R->data;
        const AUX *aux = call->aux;
        aux_validate(aux, R->len - sizeof(SYSCALL));
        const char *name;
        int port;
        if ((name = aux_str(aux, MR_, ANAM)) != nullptr &&
                (port = aux_int(aux, MR_, APRT)) > 0)
            name_set(port, name, /*replace=*/true);
        if ((name = aux_str(aux, M_R, ANAM)) != nullptr &&
                (port = aux_int(aux, M_R, APRT)) > 0)
            name_set(port, name, /*replace=*/true);
        emulate_set_syscall(call);
    }
}

