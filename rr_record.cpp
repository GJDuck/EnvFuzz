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
 * Push auxillary information onto the aux vector.
 */
void AUXVEC::push(const void *buf, size_t size, uint8_t mask, unsigned kind)
{
    if (i >= MAX)
        error("auxillary buffer overflow");
    if (size >= AUX_MAX)
        error("auxillary data is too big; max is %u, got %zu", AUX_MAX,
            size);
    size_t len = sizeof(AUX) + size;
    AUX *aux = (AUX *)xmalloc(len);
    aux->kind = kind;
    aux->size = size;
    aux->mask = mask;
    memcpy(aux->data, buf, size);
    vec[i].iov_base = aux;
    vec[i].iov_len  = len;
    i++;
}
void AUXVEC::end(void)
{
    push(NULL, 0, 0x0, AEND);
}
void AUXVEC::push(const struct msghdr *msg, uint8_t mask, unsigned kind)
{
    size_t size = sizeof(*msg);
    size_t iov_size = msg->msg_iovlen * sizeof(struct iovec);
    size += msg->msg_namelen;
    size += msg->msg_controllen;
    size += iov_size;
    uint8_t buf[size];
    uint8_t *ptr = buf;
    memcpy(ptr, msg, sizeof(*msg));
    ptr += sizeof(*msg);
    memcpy(ptr, msg->msg_name, msg->msg_namelen);
    ptr += msg->msg_namelen;
    memcpy(ptr, msg->msg_control, msg->msg_controllen);
    ptr += msg->msg_controllen;
    memcpy(ptr, msg->msg_iov, iov_size);
    push(buf, size, mask, kind);
}

/*
 * Record thread start.
 */
static void record_start(int id)
{
    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;
    call->no = SYS_start;
    call->id = id;
    AUXVEC auxv(call); 
    auxv.end();
    pcap_write(option_pcap, auxv.iov(), auxv.iovcnt(), SIZE_MAX, SCHED_FD,
        OUTBOUND);
    print_hook(stderr, call);
}

/*
 * Record program start.
 */
static void record_init(char **envp)
{
    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;

    // First message must be SYS_setenvp
    PRINTER P;
    for (char **p = envp; *p != NULL; p++)
    {
        if (p != envp)
            P.put('\0');
        P.put(*p);
    }
    call->no = SYS_setenvp;
    call->id = 1;
    call->arg0.buf  = (uint8_t *)P.str();
    call->arg1.size = P.len()+1;
    {
        AUXVEC auxv(call);
        auxv.push(P.str(), P.len()+1, MI_____, ABUF);
        auxv.end();
        pcap_write(option_pcap, auxv.iov(), auxv.iovcnt(), SIZE_MAX,
            SCHED_FD, OUTBOUND);
    }
    print_hook(stderr, call);

    memset(call, 0x0, sizeof(*call));
    pid_t pid = getpid();
    call->no       = SYS_setpid;
    call->id       = 1;
    call->arg0.pid = pid;
    {
        AUXVEC auxv(call);
        auxv.end();
        pcap_write(option_pcap, auxv.iov(), auxv.iovcnt(), SIZE_MAX,
            SCHED_FD, OUTBOUND);
    }
    print_hook(stderr, call);

    asm volatile ("mov %0,%%fs:0x2d4" : : "r"(pid));
}

/*
 * Record a mmap().
 */
static intptr_t record_mmap(FILE *pcap, AUXVEC *auxv, void *addr,
    size_t length, int prot, int flags, int fd, ssize_t offset)
{
    if (flags & MAP_ANONYMOUS)
    {
        intptr_t r = (intptr_t)mmap(addr, length, prot, flags, fd, offset);
        return (r < 0? -errno: r);
    }
    int flags1 = MAP_ANONYMOUS | MAP_PRIVATE | (flags & MAP_FIXED);
    void *ptr = mmap(addr, length, PROT_READ | PROT_WRITE, flags1, -1, 0);
    if (ptr == MAP_FAILED)
        return -errno;

    struct stat buf;
    if (fstat(fd, &buf) < 0)
    {
mmap_error:
        intptr_t r = -errno;
        (void)munmap(ptr, length);
        return r;
    }
    size_t size = buf.st_size;
    size = (size > (size_t)offset? size - offset: 0);
    size = (size > length? length: size);
    auxv->push((uint8_t *)&size, sizeof(size), M_I____, ASIZ);
    void *map = ptr;
    int prot1 = prot | PROT_READ;
    if (size > 0)
    {
        map = mmap(ptr, size, prot1, flags | MAP_FIXED, fd, offset);
        if (map != ptr)
            goto mmap_error;
    }
    if (size <= MMAP_RECORD_MAX)
        pcap_write(pcap, (uint8_t *)map, size, fd, INBOUND);
    if (prot != prot1)
        (void)mprotect(map, size, prot);
    return (intptr_t)map;
}

/*
 * Called during recording whenever a syscall occurs.
 * Execute the syscall and record the result into the pcap file.
 */
static int record_hook(STATE *state)
{
    SYSCALL call_0 = {0};
    SYSCALL *call = &call_0;

    syscall_init(call, state);
    call->id = thread_self()->id;
    call->no = (int)state->rax;
    AUXVEC auxv(call);

    bool unlock = syscall_unlock(call);
    if (unlock)
    {
        THREAD_UNLOCK();
        SIGNAL_UNBLOCK();
    }

    FILE *pcap = option_pcap;

    // Execute the syscall:
    switch (call->no)
    {
        case SYS_close:
            switch (call->arg0.fd)
            {
                case PCAP_FILENO: case STDERR_FILENO:
                    // Stop program closing useful fds
                    call->result = 0;
                    break;
                default:
                    goto syscall;
            }
            break;
        case SYS_rt_sigaction:
            call->result = signal_action(call->arg0.sig,
                call->arg1.action, call->arg2.action);
            break;
        case SYS_rt_sigprocmask:
            call->result = signal_procmask(call->arg0.i32,
                call->arg1.sigset, call->arg2.sigset);
            break;
        case SYS_sched_setaffinity:
            call->result = -EPERM;
            break;
        case SYS_shmget: case SYS_shmctl: case SYS_shmat: case SYS_execve:
        case SYS_execveat: case SYS_arch_prctl: case SYS_get_thread_area:
        case /*SYS_rseq=*/334:
            call->result = 0;
            break;
        case SYS_set_thread_area:
            call->result = -ENOSYS;
            break;
        case SYS_fork: case SYS_vfork:
            call->result = thread_fork();
            break;
        case SYS_rdtsc:
            call->result = rdtsc();
            break;
        case SYS_clone:
            call->result = thread_clone(state);
            break;
        case /*SYS_clone3=*/435:
            call->result = thread_clone3(state);
            break;
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
            break;
        case SYS_ioctl:
            if (ioctl_info(call->arg1.i32)->fail)
                call->result = -ENOSYS;
            else
                call->result = syscall(call);
            break;
        case SYS_fcntl:
            if (fcntl_info(call->arg1.i32)->fail)
                call->result = -ENOSYS;
            else
                call->result = syscall(call);
            break;
        case SYS_prctl:
            if (prctl_info(call->arg0.i32)->fail)
                call->result = -ENOSYS;
            else
                call->result = syscall(call);
            break;
        case SYS_mmap:
            call->result = record_mmap(pcap, &auxv, call->arg0.ptr,
                call->arg1.size, call->arg2.flags, call->arg3.flags,
                call->arg4.fd, call->arg5.offset);
            break;
        case SYS_sendmmsg: case SYS_recvmmsg:
        {
            // For simplicity, we truncate these calls to a single message.
            // This effectively converts sendmmsg()/recvmmsg() into hacked
            // versions of sendmsg()/recvmsg().
            unsigned vlen = (unsigned)call->arg2.u32;
            call->result  = 0;
            if (vlen == 0) break;
            struct mmsghdr *mmsg = call->arg1.mmsg;
            call->result = syscall(call->no, call->arg0.fd, mmsg, /*vlen=*/1,
                call->arg3.u32);
            call->result = (call->result > 0? (intptr_t)mmsg->msg_len:
                                              call->result);
            break;
        }
        case SYS_exit: case SYS_exit_group:
            // Syscall does not return, so defer execution
            call->result = 0;
            break;
        case SYS_kill:
            call->result = syscall(SYS_kill, call->arg0.pid, 0);
            break;
        case SYS_tgkill:
            call->result = syscall(SYS_tgkill, call->arg0.pid, call->arg1.pid,
                0);
            break;
        default:
        syscall:
            call->result = syscall(call);
            break;
    }

    if (unlock)
    {
        SIGNAL_BLOCK();
        THREAD_LOCK();
    }

    ENTRY *E = NULL, *F = NULL;
    int flags, *fds;
    if (call->result < 0)
        goto handler;

    char name[BUFSIZ];
    switch (call->no)
    {
        // Special cases:
        case SYS_open: case SYS_openat:
            path_name((int)call->result,
                (call->no == SYS_open? call->arg0.path: call->arg1.path),
                name, sizeof(name));
            flags = (call->no == SYS_open? call->arg1.flags: call->arg2.flags);
            E = fd_open((int)call->result, S_IFREG, SOCK_STREAM, flags, name);
            pcap_write_open(pcap, (int)call->result);
            auxv.push(E->name, strlen(E->name)+1,
                (call->no == SYS_open?  MI_____: M_I____), APTH);
            goto handler;
        case SYS_socket:
            E = fd_open((int)call->result, S_IFSOCK, call->arg2.i32, 0x0,
                socket_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_eventfd: case SYS_eventfd2:
            E = fd_open((int)call->result, S_IFSOCK, SOCK_DGRAM, 0x0,
                event_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_epoll_create: case SYS_epoll_create1:
            E = fd_open((int)call->result, S_IFSOCK, SOCK_DGRAM, 0x0,
                epoll_name((int)call->result, name, sizeof(name)));
            goto handler;
        case SYS_connect: case SYS_bind:
            E = fd_bind(call->arg0.fd, call->arg1.addr, call->arg2.size);
            pcap_write_open(pcap, call->arg0.fd);
            goto handler;
        case SYS_accept: case SYS_accept4:
            E = fd_entry(call->arg0.fd);
            flags = (call->no == SYS_accept4? call->arg3.i32: 0x0);
            E = fd_open((int)call->result, S_IFSOCK, E->socktype, flags, NULL);
            goto handler;
        case SYS_pipe: case SYS_pipe2:
            fds = call->arg0.fds;
            flags = (call->no == SYS_pipe2? call->arg1.i32: 0x0);
            E = fd_open(fds[0], S_IFIFO, SOCK_STREAM, flags,
                pipe_name(fds[0], 0, name, sizeof(name)));
            F = fd_open(fds[1], S_IFIFO, SOCK_STREAM, flags,
                pipe_name(fds[1], 1, name, sizeof(name)));
            pcap_write_open(pcap, fds[0]);
            pcap_write_open(pcap, fds[1]);
            goto handler;
        case SYS_dup: case SYS_dup2: case SYS_dup3:
            E = fd_dup(fd_get(call->arg0.fd), (int)call->result);
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
            if (call->arg0.fd == PCAP_FILENO)
                goto handler;
            pcap_write_close(pcap, call->arg0.fd);
            fd_close(call->arg0.fd);
            goto handler;
        handler:
        default:        // Generic syscall hander:
        {
            if ((size_t)call->no >= sizeof(TABLE) / sizeof(TABLE[0]))
                error("syscall number %d is not yet implemented", call->no);
            if (E != NULL)
            {
                auxv.push(&E->port, sizeof(E->port), MR_, APRT);
                auxv.push(E->name, strlen(E->name)+1, MR_, ANAM);
            }
            if (F != NULL)
            {
                auxv.push(&F->port, sizeof(F->port), M_R, APRT);
                auxv.push(F->name, strlen(F->name)+1, M_R, ANAM);
            }
            const INFO *info = &TABLE[call->no];
            int fd = -1;
            bool success = (call->result >= 0);
            int n = syscall_arity(call);
            for (int i = 0; i < n; i++)
            {
                uint8_t arg = info->args[i];
                if (arg == A___)
                    break;
                fd = (arg == A_FD? call->args[i].fd: fd);
                uint8_t mask = (MI_____ << i);
                bool outbound = syscall_output(call, i);
                if (!success)
                    continue;   // Nothing to record
                if (!syscall_used(call, i))
                    continue;
                size_t size = 0;
                const uint8_t *buf = syscall_buf(call, i, &size);
                if (buf == NULL)
                    continue;
                const struct iovec *iov    = (struct iovec *)buf;
                const struct msghdr *msg   = (struct msghdr *)buf;
                const struct mmsghdr *mmsg = (struct mmsghdr *)buf;
                bool io = (info->kind == P_IO) && (fd >= 0);
                switch (arg)
                {
                    case ABUF:
                        if (io)
                            pcap_write(pcap, buf, call->result, fd, outbound);
                        else
                            auxv.push(buf, size, mask, arg);
                        break;
                    case AIOV:
                        pcap_write(pcap, iov, size / sizeof(struct iovec),
                            call->result, fd, outbound);
                        auxv.push(buf, size, mask, AIOV);
                        break;
                    case AMSG:
                        pcap_write(pcap, msg->msg_iov, msg->msg_iovlen,
                            call->result, fd, outbound);
                        auxv.push(msg, mask, AMSG);
                        break;
                    case A_MM:
                        pcap_write(pcap, mmsg->msg_hdr.msg_iov,
                            mmsg->msg_hdr.msg_iovlen, call->result,
                            fd, outbound);
                        auxv.push(&mmsg->msg_hdr, mask, A_MM);
                        break;
                    default:
                        auxv.push(buf, size, mask, arg);
                        break;
                }
            }
            break;
        }
    }

    auxv.end();
    pcap_write(pcap, auxv.iov(), auxv.iovcnt(), SIZE_MAX, SCHED_FD, OUTBOUND);

    print_hook(stderr, call);
 
    // Special handling:
    switch (call->no)
    {
        case SYS_tgkill: case SYS_kill:
            (void)syscall(call);
            break;
        case SYS_exit_group:
            fclose(pcap);
            syscall(SYS_exit_group, call->arg0.i32);
            abort();        // Not reached
        case SYS_exit:
            thread_exit(state);
            abort();        // Not reached
        case SYS_sendmmsg: case SYS_recvmmsg:
            call->result = (call->result >= 0? 1: call->result);
            break;
        default:
            break;
    }
    state->rax = call->result;
    return REPLACE;
}

