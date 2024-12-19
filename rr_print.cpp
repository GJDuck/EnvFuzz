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

#include "rr_info.cpp"

static const char SIG_INFO[][10] =
{
    "0",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS",
    "SIG32",
    "SIG33",
    "SIG34",
    "SIG35",
    "SIG36",
    "SIG37",
    "SIG38",
    "SIG39",
    "SIG40",
    "SIG41",
    "SIG42",
    "SIG43",
    "SIG44",
    "SIG45",
    "SIG46",
    "SIG47",
    "SIG48",
    "SIG49",
    "SIG50",
    "SIG51",
    "SIG52",
    "SIG53",
    "SIG54",
    "SIG55",
    "SIG56",
    "SIG57",
    "SIG58",
    "SIG59",
    "SIG60",
    "SIG61",
    "SIG62",
    "SIG63",
    "SIG64",
};

static const char ERRNO_INFO[][16] =
{
    "0",
    "EPERM",
    "ENOENT",
    "ESRCH",
    "EINTR",
    "EIO",
    "ENXIO",
    "E2BIG",
    "ENOEXEC",
    "EBADF",
    "ECHILD",
    "EAGAIN",
    "ENOMEM",
    "EACCES",
    "EFAULT",
    "ENOTBLK",
    "EBUSY",
    "EEXIST",
    "EXDEV",
    "ENODEV",
    "ENOTDIR",
    "EISDIR",
    "EINVAL",
    "ENFILE",
    "EMFILE",
    "ENOTTY",
    "ETXTBSY",
    "EFBIG",
    "ENOSPC",
    "ESPIPE",
    "EROFS",
    "EMLINK",
    "EPIPE",
    "EDOM",
    "ERANGE",
    "EDEADLK",
    "ENAMETOOLONG",
    "ENOLCK",
    "ENOSYS",
    "ENOTEMPTY",
    "ELOOP",
    "EWOULDBLOCK",
    "ENOMSG",
    "EIDRM",
    "ECHRNG",
    "EL2NSYNC",
    "EL3HLT",
    "EL3RST",
    "ELNRNG",
    "EUNATCH",
    "ENOCSI",
    "EL2HLT",
    "EBADE",
    "EBADR",
    "EXFULL",
    "ENOANO",
    "EBADRQC",
    "EBADSLT",
    "EDEADLOCK",
    "EBFONT",
    "ENOSTR",
    "ENODATA",
    "ETIME",
    "ENOSR",
    "ENONET",
    "ENOPKG",
    "EREMOTE",
    "ENOLINK",
    "EADV",
    "ESRMNT",
    "ECOMM",
    "EPROTO",
    "EMULTIHOP",
    "EDOTDOT",
    "EBADMSG",
    "EOVERFLOW",
    "ENOTUNIQ",
    "EBADFD",
    "EREMCHG",
    "ELIBACC",
    "ELIBBAD",
    "ELIBSCN",
    "ELIBMAX",
    "ELIBEXEC",
    "EILSEQ",
    "ERESTART",
    "ESTRPIPE",
    "EUSERS",
    "ENOTSOCK",
    "EDESTADDRREQ",
    "EMSGSIZE",
    "EPROTOTYPE",
    "ENOPROTOOPT",
    "EPROTONOSUPPORT",
    "ESOCKTNOSUPPORT",
    "EOPNOTSUPP",
    "EPFNOSUPPORT",
    "EAFNOSUPPORT",
    "EADDRINUSE",
    "EADDRNOTAVAIL",
    "ENETDOWN",
    "ENETUNREACH",
    "ENETRESET",
    "ECONNABORTED",
    "ECONNRESET",
    "ENOBUFS",
    "EISCONN",
    "ENOTCONN",
    "ESHUTDOWN",
    "ETOOMANYREFS",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "EHOSTDOWN",
    "EHOSTUNREACH",
    "EALREADY",
    "EINPROGRESS",
    "ESTALE",
    "EUCLEAN",
    "ENOTNAM",
    "ENAVAIL",
    "EISNAM",
    "EREMOTEIO",
    "EDQUOT",
    "ENOMEDIUM",
    "EMEDIUMTYPE",
    "ECANCELED",
    "ENOKEY",
    "EKEYEXPIRED",
    "EKEYREVOKED",
    "EKEYREJECTED",
    "EOWNERDEAD",
    "ENOTRECOVERABLE",
    "ERFKILL",
    "EHWPOISON",
    "ENOTSUP",
};

struct PRINTER
{
    char *buf   = NULL;
    size_t size = 0;
    size_t i    = 0;

    const char *str(void)
    {
        return (buf == NULL? "": buf);
    }
    void reserve(size_t n);
    bool put(char c);
    bool put(const char *s);
    bool PRINTF(2, 3) format(const char *fmt, ...);
    PRINTER &reset(void)
    {
        i = 0;
        return *this;
    }
    size_t len(void)
    {
        return i;
    }

    ~PRINTER()
    {
        xfree(buf);
    }
};

void PRINTER::reserve(size_t n)
{
    if (size - i < n)
    {
        size += n - (size - i) + /*extra=*/64;
        size *= 3;
        size /= 2;
        buf   = (char *)xrealloc(buf, size);
    }
}
bool PRINTER::put(char c)
{
    reserve(2);
    buf[i++] = c;
    buf[i]   = '\0';
    return true;
}
bool PRINTER::put(const char *s)
{
    size_t n = strlen(s);
    reserve(n+1);
    memcpy(buf+i, s, n+1);
    i += n;
    return true;
}
bool PRINTER::format(const char *fmt, ...)
{
    va_list ap, aq;
    va_start(ap, fmt);
    va_copy(aq, ap);
    int r = vsnprintf(NULL, SIZE_MAX, fmt, ap);
    if (r >= 0)
    {
        reserve(r+1);
        r = vsnprintf(buf+i, r+1, fmt, aq);
        i += (r >= 0? r: 0);
    }
    if (r < 0)
        put("???");
    va_end(ap);
    va_end(aq);
    return true;
}

static const char *signal_name(int sig)
{
    if (sig == 0 || (size_t)sig >= sizeof(SIG_INFO) / sizeof(SIG_INFO[0]))
        return "???";
    else
        return SIG_INFO[sig];
}

static const char *errno_name(int err)
{
    if (err == 0 || (size_t)err >= sizeof(ERRNO_INFO) / sizeof(ERRNO_INFO[0]))
        return "???";
    else
        return ERRNO_INFO[err];
}

static void print_char(PRINTER &P, char c)
{
    if (option_hex)
        P.format("%.2X", (uint8_t)c);
    else
    {
        if (escape_char(c))
            P.put('.');
        else
            P.put(c);
    }
}

static void print_buf(PRINTER &P, const void *buf_0, ssize_t len)
{
    if (buf_0 == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('\"');
    const char *buf = (char *)buf_0;
    for (ssize_t i = 0; i < len; i++)
        print_char(P, buf[i]);
    P.put('\"');
}

static void print_buf_2(PRINTER &P, const void *buf, const socklen_t *len)
{
    print_buf(P, (len == NULL? NULL: buf), (len == NULL? 0: *len));
}

static void print_len_2(PRINTER &P, ssize_t *len)
{
    if (len == NULL)
        P.put("NULL");
    else
        P.format("%zd", *len);
}

static void print_ptr(PRINTER &P, const void *ptr)
{
    if (ptr == NULL)
        P.put("NULL");
    else
        P.format("%p", ptr);
}

static void print_iov(PRINTER &P, const struct iovec *iov, size_t iovcnt,
    size_t max = SIZE_MAX)
{
    P.put('[');
    for (size_t i = 0; i < iovcnt && max != 0; i++)
    {
        P.format("%s", (i > 0? ",": ""));
        size_t len = MIN(max, iov[i].iov_len);
        print_buf(P, iov[i].iov_base, len);
        max -= iov[i].iov_len;
    }
    P.put(']');
}

static void print_iov_struct(PRINTER &P, const struct iovec *iov,
    size_t iovcnt)
{
    P.put('[');
    for (size_t i = 0; i < iovcnt; i++)
        P.format("%s{%p,%zu}", (i > 0? ",": ""), iov[i].iov_base,
            iov[i].iov_len);
    P.put(']');
}

static void print_output(PRINTER &P, const struct iovec *iov,
    size_t iovcnt)
{
    for (size_t i = 0; i < iovcnt; i++)
    {
        const char *buf = (char *)iov[i].iov_base;
        for (size_t j = 0; j < iov[i].iov_len; j++)
        {
            char c = buf[j];
            if (escape_char(c) && !isspace(c))
                P.put('.');
            else
                P.put(c);
        }
    }
}

static void print_open_flags(PRINTER &P, int flags, int mode)
{
    bool r = false;
    switch (flags & O_ACCMODE)
    {
        case O_RDONLY: r = P.put("O_RDONLY"); break;
        case O_WRONLY: r = P.put("O_WRONLY"); break;
        case O_RDWR:   r = P.put("O_RDWR"); break;
        default:       r = P.format("0x%x", flags & O_ACCMODE); break;
    }
    flags &= ~O_ACCMODE;
    if (flags & O_APPEND)   r = P.format("%sO_APPEND", (r? "|": ""));
    if (flags & O_CLOEXEC)  r = P.format("%sO_CLOEXEC", (r? "|": ""));
    if (flags & O_CREAT)    r = P.format("%sO_CREAT", (r? "|": ""));
    if (flags & O_EXCL)     r = P.format("%sO_EXCL", (r? "|": ""));
    if (flags & O_NOFOLLOW) r = P.format("%sO_NOFOLLOW", (r? "|": ""));
    if (flags & O_NONBLOCK) r = P.format("%sO_NONBLOCK", (r? "|": ""));
    if (flags & O_TRUNC)    r = P.format("%sO_TRUNC", (r? "|": ""));
    bool creat = ((flags & O_CREAT) != 0);
    flags &= ~(O_APPEND | O_CLOEXEC | O_CREAT | O_EXCL | O_NOFOLLOW |
        O_NONBLOCK | O_TRUNC);
    if (flags != 0x0) P.format("%s0x%x", (r? "|": ""), flags);
    if (creat) P.format(",%o", mode);
}

static void print_prot_flags(PRINTER &P, int flags)
{
    bool r = false;
    if (flags == 0x0)
    {
        P.put("PROT_NONE");
        return;
    }
    if (flags & PROT_READ)  r = P.format("%sPROT_READ", (r? "|": ""));
    if (flags & PROT_WRITE) r = P.format("%sPROT_WRITE", (r? "|": ""));
    if (flags & PROT_EXEC)  r = P.format("%sPROT_EXEC", (r? "|": ""));
    flags &= ~(PROT_READ | PROT_WRITE | PROT_EXEC);
    if (flags != 0x0) P.format("%s0x%x", (r? "|": ""), flags);
}

static void print_map_flags(PRINTER &P, int flags)
{
    bool r = false;
    if (flags & MAP_SHARED)  r = P.format("%sMAP_SHARED", (r? "|": ""));
    if (flags & MAP_PRIVATE) r = P.format("%sMAP_PRIVATE", (r? "|": ""));
    if (flags & MAP_ANONYMOUS) r = P.format("%sMAP_ANONYMOUS", (r? "|": ""));
    if (flags & MAP_FIXED)   r = P.format("%sMAP_FIXED", (r? "|": ""));
    if (flags & MAP_NORESERVE) r = P.format("%sMAP_NORESERVE", (r? "|": ""));
    if (flags & MAP_POPULATE) r = P.format("%sMAP_POPULATE", (r? "|": ""));
    flags &= ~(MAP_SHARED |  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED |
        MAP_NORESERVE | MAP_POPULATE);
    if (flags != 0x0) P.format("%s0x%x", (r? "|": ""), flags);
}

static void print_timeval(PRINTER &P, const struct timeval *tv)
{
    if (tv == NULL)
        P.put("NULL");
    else
        P.format("%luus",
            1000000 * (size_t)tv->tv_sec + (size_t)tv->tv_usec);
}

static void print_timespec(PRINTER &P, const struct timespec *ts)
{
    if (ts == NULL)
        P.put("NULL");
    else
        P.format("%luns",
            1000000000 * (size_t)ts->tv_sec + (size_t)ts->tv_nsec);
}

static void print_stat_buf(PRINTER &P, const struct stat *buf)
{
    const char *type = "???";
    switch (buf->st_mode & S_IFMT)
    {
        case S_IFSOCK: type = "S_IFSOCK"; break;
        case S_IFLNK : type = "S_IFLNK";  break;
        case S_IFREG : type = "S_IFREG";  break;
        case S_IFBLK : type = "S_IFBLK";  break;
        case S_IFDIR : type = "S_IFDIR";  break;
        case S_IFCHR : type = "S_IFCHR";  break;
        case S_IFIFO : type = "S_IFIFO";  break;
    }
    P.format("{%lu,%lu,0%o|%s,%lu,%d,%d,%zd,%zd,%zd,%zd,", buf->st_dev,
        buf->st_ino, buf->st_mode & ~S_IFMT, type, buf->st_nlink, buf->st_uid,
        buf->st_gid, buf->st_rdev, buf->st_size, buf->st_blksize,
        buf->st_blocks);
    print_timespec(P, &buf->st_atim);
    P.put(',');
    print_timespec(P, &buf->st_mtim);
    P.put(',');
    print_timespec(P, &buf->st_ctim);
    P.put('}');
}

static void print_poll_events(PRINTER &P, short events)
{
    bool r = false;
    if (events & POLLHUP)  r = P.format("POLLHUP");
    if (events & POLLIN)   r = P.format("%sPOLLIN",  (r? "|": ""));
    if (events & POLLOUT)  r = P.format("%sPOLLOUT", (r? "|": ""));
    if (events & POLLPRI)  r = P.format("%sPOLLPRI", (r? "|": ""));
    if (events & POLLERR)  r = P.format("%sPOLLERR", (r? "|": ""));
    if (events & POLLNVAL) r = P.format("%sPOLLERR", (r? "|": ""));
    events &= ~(POLLHUP | POLLIN | POLLOUT | POLLPRI | POLLERR | POLLNVAL);
    if (events) r = P.format("%s0x%x", (r? "|": ""), events);
    P.format("%s", (r? "": "0x0"));
}

#define EPOLLIN     0x01
#define EPOLLPRI    0x02
#define EPOLLOUT    0x04
#define EPOLLERR    0x08
#define EPOLLHUP    0x10
static void print_epoll_events(PRINTER &P, uint32_t events)
{
    bool r = false;
    if (events & EPOLLHUP)  r = P.format("EPOLLHUP");
    if (events & EPOLLIN)   r = P.format("%sEPOLLIN",  (r? "|": ""));
    if (events & EPOLLOUT)  r = P.format("%sEPOLLOUT", (r? "|": ""));
    if (events & EPOLLPRI)  r = P.format("%sEPOLLPRI", (r? "|": ""));
    if (events & EPOLLERR)  r = P.format("%sEPOLLERR", (r? "|": ""));
    events &= ~(EPOLLHUP | EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR);
    if (events) r = P.format("%s0x%x", (r? "|": ""), events);
    P.format("%s", (r? "": "0x0"));
}

static void print_pollfds(PRINTER &P, const struct pollfd *fds, size_t size)
{
    size_t nfds = size / sizeof(struct pollfd);
    P.put('[');
    for (size_t i = 0; i < nfds; i++)
    {
        P.format("%s{%d,", (i > 0? ",": ""), fds[i].fd);
        print_poll_events(P, fds[i].events);
        P.put(',');
        print_poll_events(P, fds[i].revents);
        P.put('}');
    }
    P.put(']');
}

static void print_signal(PRINTER &P, int sig)
{
    if ((size_t)sig <= sizeof(SIG_INFO) / sizeof(SIG_INFO[0]))
        P.put(SIG_INFO[sig]);
    else
        P.format("%d", sig);
}

static void print_fd_set(PRINTER &P, const fd_set *fds)
{
    if (fds == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('[');
    int r = 0;
    for (size_t fd = 0; fd < FD_NBITS; fd++)
    {
        if (FD_ISSET(fd, fds))
            r = P.format("%s%d", (r > 0? ",": ""), (int)fd);
    }
    P.put(']');
}

static void print_whence(PRINTER &P, int whence)
{
    switch (whence)
    {
        case SEEK_SET: P.put("SEEK_SET"); break;
        case SEEK_CUR: P.put("SEEK_CUR"); break;
        case SEEK_END: P.put("SEEK_END"); break;
        default: P.format("0x%x", whence); break;
    }
}

static void print_socket_domain(PRINTER &P, int domain)
{
    switch (domain)
    {
        case AF_UNSPEC: P.put("AF_UNSPEC"); break;
        case AF_UNIX:   P.put("AF_UNIX");   break;
        case AF_INET:   P.put("AF_INET");   break;
        case AF_INET6:  P.put("AF_INET6");  break;
        default: P.format("0x%x", domain); break;
    }
}

#define SOCK_NONBLOCK   00004000
#define SOCK_CLOEXEC    02000000
static void print_socket_type(PRINTER &P, int type)
{
    if (type & SOCK_NONBLOCK) P.put("SOCK_NONBLOCK|");
    if (type & SOCK_CLOEXEC)  P.put("SOCK_CLOEXEC|");
    type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    switch (type)
    {
        case SOCK_STREAM:    P.put("SOCK_STREAM");    break;
        case SOCK_DGRAM:     P.put("SOCK_DGRAM");     break;
        case SOCK_RAW:       P.put("SOCK_RAW");       break;
        case SOCK_SEQPACKET: P.put("SOCK_SEQPACKET"); break;
        case SOCK_PACKET:    P.put("SOCK_PACKET");    break;
        default: P.format("0x%x", type); break;
    }
}

static void print_socket_protocol(PRINTER &P, int protocol)
{
    switch (protocol)
    {
        case IPPROTO_ICMP: P.put("IPPROTO_ICMP"); break;
        case IPPROTO_TCP:  P.put("IPPROTO_TCP");  break;
        case IPPROTO_UDP:  P.put("IPPROTO_UDP");  break;
        default: P.format("0x%x", protocol); break;
    }
}

struct sockaddr_nl
{
    sa_family_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};
static void print_sockaddr(PRINTER &P, const struct sockaddr *addr,
    const socklen_t *addrlen_ptr)
{
    if (addr == NULL || addrlen_ptr == NULL)
    {
        P.put("NULL");
        return;
    }
    if (*addrlen_ptr < (socklen_t)sizeof(sa_family_t))
    {
        P.put("<empty>");
        return;
    }
    socklen_t addrlen = *addrlen_ptr;
    switch (addr->sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *Addr = (struct sockaddr_in *)addr;
            if (addrlen != sizeof(struct sockaddr_in))
                goto bad_addr;
            P.format("ip://%d.%d.%d.%d:%u",
                (Addr->sin_addr.s_addr >>  0) & 0xFF,
                (Addr->sin_addr.s_addr >>  8) & 0xFF,
                (Addr->sin_addr.s_addr >> 16) & 0xFF,
                (Addr->sin_addr.s_addr >> 24) & 0xFF,
                ntohs(Addr->sin_port));
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 *Addr = (struct sockaddr_in6 *)addr;
            if (addrlen != sizeof(struct sockaddr_in6))
                goto bad_addr;
            P.format("ip6://%x:%x:%x:%x:%x:%x:%x:%x:%u",
                ntohs(Addr->sin6_addr.s6_addr16[0]),
                ntohs(Addr->sin6_addr.s6_addr16[1]),
                ntohs(Addr->sin6_addr.s6_addr16[2]),
                ntohs(Addr->sin6_addr.s6_addr16[3]),
                ntohs(Addr->sin6_addr.s6_addr16[4]),
                ntohs(Addr->sin6_addr.s6_addr16[5]),
                ntohs(Addr->sin6_addr.s6_addr16[6]),
                ntohs(Addr->sin6_addr.s6_addr16[7]),
                ntohs(Addr->sin6_port));
            break;
        }
        case AF_UNIX:
        {
            const struct sockaddr_un *Addr = (struct sockaddr_un *)addr;
            ssize_t offset = sizeof(Addr->sun_family);
            if (addrlen < offset + 1)
                goto bad_addr;
            P.put("unix://");
            ssize_t i = 0, len;
            if (Addr->sun_path[0] == '\0')
            {
                i++;
                P.put('@');
                len = addrlen - offset;
            }
            else
            {
                len = addrlen - offset - 1;
                len = strnlen(Addr->sun_path, len);
            }
            for (; i < len; i++)
            {
                char c = Addr->sun_path[i];
                if (c != '@' && c != '\\' && !escape_char(c))
                    P.put(c);
                else
                {
                    P.put('\\');
                    unsigned d = ((c >> 4) & 0xF);
                    P.put(d < 10? '0' + d: 'a' + d - 10);
                    d = (c & 0xF);
                    P.put(d < 10? '0' + d: 'a' + d - 10);
                }
            }
            break;
        }
        case /*AF_NETLINK=*/16:
        {
            const struct sockaddr_nl *Addr = (struct sockaddr_nl *)addr;
            if (addrlen != sizeof(struct sockaddr_nl))
                goto bad_addr;
            P.format("netlink://%u:%x", Addr->nl_pid, Addr->nl_groups);
            break;
        }
        bad_addr:
            P.put("<invalid>");
            break;
        default:
            P.put("<unknown>");
            break;
    }
}

static void print_int64_ptr(PRINTER &P, const int64_t *ptr)
{
    if (ptr == NULL)
        P.put("NULL");
    else
        P.format("{%ld}", *ptr);
}

static void print_int32_ptr(PRINTER &P, const int32_t *ptr)
{
    if (ptr == NULL)
        P.put("NULL");
    else
        P.format("{%d}", *ptr);
}

static void print_msghdr(PRINTER &P, const struct msghdr *msg, size_t max)
{
    P.put('{');
    print_sockaddr(P, (sockaddr *)msg->msg_name, &msg->msg_namelen);
    P.put(',');
    print_iov(P, msg->msg_iov, msg->msg_iovlen, max);
    P.format(",%zu,", msg->msg_iovlen);
    print_buf(P, msg->msg_control, msg->msg_controllen);
    P.put(',');
    P.format("0x%x", msg->msg_flags);
    P.put('}');
}

static void print_msghdr_struct(PRINTER &P, const struct msghdr *msg)
{
    P.format("{%p,%d,%p,%zu,%p,%zu,0x%x}",
        msg->msg_name, msg->msg_namelen, msg->msg_iov, msg->msg_iovlen,
        msg->msg_control, msg->msg_controllen, msg->msg_flags);
}

static void print_mmsghdr(PRINTER &P, const struct mmsghdr *mmsg, size_t max)
{
    if (mmsg == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('{');
    print_msghdr(P, &mmsg->msg_hdr, max);
    P.format(",%u}", mmsg->msg_len);
}

#define SHUT_RD                 0
#define SHUT_WR                 1
#define SHUT_RDWR               2
static void print_how(PRINTER &P, int how)
{
    switch (how)
    {
        case SHUT_RD:   P.put("SHUT_RD");   break;
        case SHUT_WR:   P.put("SHUT_WR");   break;
        case SHUT_RDWR: P.put("SHUT_RDWR"); break;
        default: P.format("0x%x", how); break;
    }
}

#define CLONE_VM                0x00000100
#define CLONE_FS                0x00000200
#define CLONE_FILES             0x00000400
#define CLONE_SIGHAND           0x00000800
#define CLONE_PTRACE            0x00002000
#define CLONE_VFORK             0x00004000
#define CLONE_PARENT            0x00008000
#define CLONE_THREAD            0x00010000
#define CLONE_PARENT_SETTID     0x00100000
#define CLONE_CHILD_CLEARTID    0x00200000
#define CLONE_CHILD_SETTID      0x01000000
static void print_clone_flags(PRINTER &P, int flags)
{
    bool r = false;
    if (flags & CLONE_VM)    r = P.format("%sCLONE_VM", (r? "|": ""));
    if (flags & CLONE_FS)    r = P.format("%sCLONE_FS", (r? "|": ""));
    if (flags & CLONE_FILES) r = P.format("%sCLONE_FILES", (r? "|": ""));
    if (flags & CLONE_SIGHAND)
        r = P.format("%sCLONE_SIGHAND", (r? "|": ""));
    if (flags & CLONE_PTRACE)
        r = P.format("%sCLONE_PTRACE", (r? "|": ""));
    if (flags & CLONE_VFORK)
        r = P.format("%sCLONE_VFORK", (r? "|": ""));
    if (flags & CLONE_PARENT)
        r = P.format("%sCLONE_PARENT", (r? "|": ""));
    if (flags & CLONE_THREAD)
        r = P.format("%sCLONE_THREAD", (r? "|": ""));
    if (flags & CLONE_PARENT_SETTID)
        r = P.format("%sCLONE_PARENT_SETTID", (r? "|": ""));
    if (flags & CLONE_CHILD_CLEARTID)
        r = P.format("%sCLONE_CHILD_CLEARTID", (r? "|": ""));
    if (flags & CLONE_CHILD_SETTID)
        r = P.format("%sCLONE_CHILD_SETTID", (r? "|": ""));
    flags &= ~(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
        CLONE_PTRACE | CLONE_VFORK | CLONE_PARENT | CLONE_THREAD |
        CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID);
    if (flags) r = P.format("%s0x%x", (r? "|": ""), flags);
    P.put(r? "": "0x0");
}

static void print_futex_op(PRINTER &P, int op)
{
    if (op & FUTEX_PRIVATE_FLAG) P.put("FUTEX_PRIVATE_FLAG|");
    if (op & FUTEX_CLOCK_REALTIME) P.put("FUTEX_CLOCK_REALTIME|");
    op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    switch (op)
    {
        case FUTEX_WAIT: P.put("FUTEX_WAIT"); break;
        case FUTEX_WAKE: P.put("FUTEX_WAKE"); break;
        case FUTEX_REQUEUE: P.put("FUTEX_REQUEUE"); break;
        case FUTEX_CMP_REQUEUE: P.put("FUTEX_CMP_REQUEUE"); break;
        case FUTEX_WAKE_OP: P.put("FUTEX_WAKE_OP"); break;
        case FUTEX_WAIT_BITSET: P.put("FUTEX_WAIT_BITSET"); break;
        case FUTEX_WAKE_BITSET: P.put("FUTEX_WAKE_BITSET"); break;
        case FUTEX_LOCK_PI: P.put("FUTEX_LOCK_PI"); break;
        case FUTEX_TRYLOCK_PI: P.put("FUTEX_TRYLOCK_PI"); break;
        case FUTEX_UNLOCK_PI: P.put("FUTEX_UNLOCK_PI"); break;
        case FUTEX_CMP_REQUEUE_PI: P.put("FUTEX_CMP_REQUEUE_PI"); break;
        case FUTEX_WAIT_REQUEUE_PI: P.put("FUTEX_WAIT_REQUEUE_PI"); break;
        default: P.format("0x%x", op); break;
    }
    op &= ~0xFF;
    if (op) P.format("|0x%x", op);
}

#define CLOCK_REALTIME              0
#define CLOCK_MONOTONIC             1
#define CLOCK_PROCESS_CPUTIME_ID    2
#define CLOCK_THREAD_CPUTIME_ID     3
#define CLOCK_MONOTONIC_RAW         4
static void print_clock(PRINTER &P, int clk)
{
    switch (clk)
    {
        case CLOCK_REALTIME: P.put("CLOCK_REALTIME"); break;
        case CLOCK_MONOTONIC: P.put("CLOCK_MONOTONIC"); break;
        case CLOCK_PROCESS_CPUTIME_ID: P.put("CLOCK_PROCESS_CPUTIME_ID"); break;
        case CLOCK_THREAD_CPUTIME_ID: P.put("CLOCK_THREAD_CPUTIME_ID"); break;
        case CLOCK_MONOTONIC_RAW: P.put("CLOCK_MONOTONIC_RAW"); break;
        default: P.format("%d", clk);
    }
}

#define AT_FDCWD    -100
static void print_dir(PRINTER &P, int dir)
{
    if (dir == AT_FDCWD) P.put("AT_FDCWD");
    else P.format("%d", dir);
}

static void print_utsname(PRINTER &P, const struct utsname *uname)
{
    P.format("{\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"}",
        uname->sysname, uname->nodename, uname->release, uname->version,
        uname->machine, uname->domainname);
}

struct dirent
{
    uint64_t d_ino;
    uint64_t d_off;
    uint16_t d_reclen;
    char     d_name[];
};
struct dirent64
{
    uint64_t d_ino;
    uint64_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};
static void print_dirent(PRINTER &P, const struct dirent *entry, size_t size)
{
    P.put('[');
    for (int i = 0; ; i++)
    {
        if (size < sizeof(struct dirent))
            break;
        if (size < entry->d_reclen)
            break;
        P.format("%s{%lu,+%zu,%hu,\"%s\"}", (i > 0? ",": ""),
            entry->d_ino, entry->d_off, entry->d_reclen, entry->d_name);
        size_t reclen = entry->d_reclen;
        entry = (struct dirent *)((uint8_t *)entry + reclen);
        size -= reclen;
    }
    P.put(']');
}
static void print_dirent64(PRINTER &P, const struct dirent64 *entry,
    size_t size)
{
    P.put('[');
    for (int i = 0; ; i++)
    {
        if (size < sizeof(struct dirent))
            break;
        if (size < entry->d_reclen)
            break;
        P.format("%s{%lu,+%zu,%hu,0x%.2x,\"%s\"}", (i > 0? ",": ""),
            entry->d_ino, entry->d_off, entry->d_reclen,
                entry->d_type, entry->d_name);
        size_t reclen = entry->d_reclen;
        entry = (struct dirent64 *)((uint8_t *)entry + reclen);
        size -= reclen;
    }
    P.put(']');
}

static void print_ioctl(PRINTER &P, int cmd)
{
    P.put(ioctl_info(cmd)->name);
}

static void print_ioctl_arg(PRINTER &P, int cmd, intptr_t arg)
{
    size_t size = ioctl_info(cmd)->size;
    if (size > 0)
        print_buf(P, (const uint8_t *)arg, size);
    else
        P.format("%ld", arg);
}

static void print_sysinfo(PRINTER &P, const struct sysinfo *info)
{
    P.format("{%ld,[%lu,%lu,%lu],%lu,%lu,%lu,%lu,%lu,%lu,%hu,%lu,%lu,%d}",
        info->uptime, info->loads[0], info->loads[1], info->loads[2],
        info->totalram, info->freeram, info->sharedram, info->bufferram,
        info->totalswap, info->freeswap, info->procs, info->totalhigh,
        info->freehigh, info->mem_unit);
}

static void print_sigaction(PRINTER &P, const struct ksigaction *action)
{
    if (action == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{%p,",action->sa_handler_2);
    bool r = false;
    unsigned long flags = action->sa_flags;
    if (flags & SA_NOCLDSTOP) r = P.format("%sSA_NOCLDSTOP", (r? "|": ""));
    if (flags & SA_NOCLDWAIT) r = P.format("%sSA_NOCLDWAIT", (r? "|": ""));
    if (flags & SA_SIGINFO)   r = P.format("%sSA_SIGINFO", (r? "|": ""));
    if (flags & SA_ONSTACK)   r = P.format("%sSA_ONSTACK", (r? "|": ""));
    if (flags & SA_RESTART)   r = P.format("%sSA_RESTART", (r? "|": ""));
    if (flags & SA_NODEFER)   r = P.format("%sSA_NODEFER", (r? "|": ""));
    if (flags & SA_RESETHAND) r = P.format("%sSA_RESETHAND", (r? "|": ""));
    if (flags & SA_NOMASK)    r = P.format("%sSA_NOMASK", (r? "|": ""));
    if (flags & SA_ONESHOT)   r = P.format("%sSA_ONESHOT", (r? "|": ""));
    if (flags & SA_RESTORER)  r = P.format("%sSA_RESTORER", (r? "|": ""));
    flags &= ~(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_SIGINFO | SA_ONSTACK |
        SA_RESTART | SA_NODEFER | SA_RESETHAND | SA_NOMASK | SA_ONESHOT |
        SA_RESTORER);
    if (flags) P.format("%s0x%lx", (r? "|": ""), flags);
    P.put(r? "": "0x0");
    P.format(",%p,0x%lx}", action->sa_restorer, action->sa_mask);
}

static void print_statfs(PRINTER &P, const struct statfs *statfs)
{
    P.format("{%u,%u,%u,%u,%u,%u,%u,{%d,%d},%d,%d,0x%x}",
        statfs->f_type, statfs->f_bsize, statfs->f_blocks, statfs->f_bfree,
        statfs->f_bavail, statfs->f_files, statfs->f_ffree,
        statfs->f_fsid.val[0], statfs->f_fsid.val[1], statfs->f_namelen,
        statfs->f_frsize, statfs->f_flags);
}

static void print_fcntl(PRINTER &P, int cmd)
{
    P.put(fcntl_info(cmd)->name);
}

static void print_fcntl_arg(PRINTER &P, int cmd, intptr_t arg)
{
    size_t size = fcntl_info(cmd)->size;
    if (size > 0)
        print_buf(P, (const uint8_t *)arg, size);
    else
        P.format("%ld", arg);
}

static void print_resource(PRINTER &P, int resource)
{
    switch (resource)
    {
        case RLIMIT_CPU: P.put("RLIMIT_CPU"); break;
        case RLIMIT_FSIZE: P.put("RLIMIT_FSIZE"); break;
        case RLIMIT_DATA: P.put("RLIMIT_DATA"); break;
        case RLIMIT_STACK: P.put("RLIMIT_STACK"); break;
        case RLIMIT_CORE: P.put("RLIMIT_CORE"); break;
        case RLIMIT_RSS: P.put("RLIMIT_RSS"); break;
        case RLIMIT_NPROC: P.put("RLIMIT_NPROC"); break;
        case RLIMIT_NOFILE: P.put("RLIMIT_NOFILE"); break;
        case RLIMIT_MEMLOCK: P.put("RLIMIT_MEMLOCK"); break;
        case RLIMIT_AS: P.put("RLIMIT_AS"); break;
        case RLIMIT_LOCKS: P.put("RLIMIT_LOCKS"); break;
        default: P.format("%d", resource); break;
    }
}

#define RLIM_INFINITY   0xFFFFFFFFFFFFFFFFull
static void print_rlimit(PRINTER &P, const struct rlimit *limit)
{
    if (limit == NULL)
    {
        P.put("NULL");
        return;
    }
    if (limit->rlim_cur == RLIM_INFINITY) P.put("{RLIM_INFINITY,");
    else P.format("{%lu,", limit->rlim_cur);
    if (limit->rlim_max == RLIM_INFINITY) P.put("RLIM_INFINITY}");
    else P.format("%lu}", limit->rlim_max);
}

static void print_who(PRINTER &P, int who)
{
    switch (who)
    {
        case RUSAGE_SELF: P.put("RUSAGE_SELF"); break;
        case RUSAGE_CHILDREN: P.put("RUSAGE_CHILDREN"); break;
        case RUSAGE_THREAD: P.put("RUSAGE_THREAD"); break;
        default: P.format("%d", who);
    }
}

static void print_rusage(PRINTER &P, const struct rusage *usage)
{
    if (usage == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('{');
    print_timeval(P, &usage->ru_utime);
    P.put(',');
    print_timeval(P, &usage->ru_stime);
    P.format(",%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld}",
        usage->ru_maxrss, usage->ru_ixrss, usage->ru_idrss, usage->ru_isrss,
        usage->ru_minflt, usage->ru_majflt, usage->ru_nswap, usage->ru_inblock,
        usage->ru_oublock, usage->ru_msgsnd, usage->ru_msgrcv,
        usage->ru_nsignals, usage->ru_nvcsw, usage->ru_nivcsw);
}

static void print_statx_timestamp(PRINTER &P, const struct statx_timestamp *ts)
{
    P.format("%luns",
        1000000000 * (size_t)ts->tv_sec + (size_t)ts->tv_nsec);
}

static void print_statx(PRINTER &P, const struct statx *statx)
{
    if (statx == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{%u,%u,0x%lx,%u,%u,%u,%u,%lu,%zu,%lu,0x%lx,",
        statx->stx_mask, statx->stx_blksize, statx->stx_attributes,
        statx->stx_nlink, statx->stx_uid, statx->stx_gid, statx->stx_mode,
        statx->stx_ino, statx->stx_size, statx->stx_blocks,
        statx->stx_attributes_mask);
    print_statx_timestamp(P, &statx->stx_atime);
    P.put(',');
    print_statx_timestamp(P, &statx->stx_btime);
    P.put(',');
    print_statx_timestamp(P, &statx->stx_ctime);
    P.put(',');
    print_statx_timestamp(P, &statx->stx_mtime);
    P.format(",%u,%u,%u,%u,%lu}",
        statx->stx_rdev_major, statx->stx_rdev_minor, statx->stx_dev_major,
        statx->stx_dev_minor, statx->stx_mnt_id);
}

static void print_clone_args(PRINTER &P, const struct clone_args *args)
{
    if (args == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('{'),
    print_clone_flags(P, args->flags);
    P.format(",%lu,0x%lx,0x%lx,",
        args->pidfd, args->child_tid, args->parent_tid);
    print_signal(P, (int)args->exit_signal);
    P.format(",0x%lx,%zu,0x%lx,0x%lx,%zu,%lu}",
        args->stack, args->stack_size, args->tls, args->set_tid,
        args->set_tid_size, args->cgroup);
}

static void print_siginfo(PRINTER &P, const siginfo_t *info)
{
    if (info == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{%s,%s,%d.{", signal_name(info->si_signo),
        errno_name(info->si_errno), info->si_code);
    switch (info->si_signo)
    {
        case SIGILL: case SIGFPE: case SIGSEGV: case SIGBUS:
            P.format("%p,%hd,{%p,%p}}}",
                info->_sifields._sigfault.si_addr,
                info->_sifields._sigfault.si_addr_lsb,
                info->_sifields._sigfault.si_addr_bnd._lower,
                info->_sifields._sigfault.si_addr_bnd._upper);
            break;
        case SIGALRM:
            P.format("%d,%d,%p}}",
                info->_sifields._timer.si_tid,
                info->_sifields._timer.si_overrun,
                info->_sifields._timer.si_sigval.sival_ptr);
        case SIGPOLL:
            P.format("%ld,%d}}",
                info->_sifields._sigpoll.si_band,
                info->_sifields._sigpoll.si_fd);
            break;
        case SIGCHLD:
            P.format("%d,%d,%d,%ld,%ld",
                info->_sifields._sigchld.si_pid,
                info->_sifields._sigchld.si_uid,
                info->_sifields._sigchld.si_status,
                info->_sifields._sigchld.si_utime,
                info->_sifields._sigchld.si_stime);
            break;
        default:
            P.format("%d,%d,%p}}",
                info->_sifields._rt.si_pid,
                info->_sifields._rt.si_uid,
                info->_sifields._rt.si_sigval.sival_ptr);
            break;
    }
}

#define EPOLL_CTL_ADD     1
#define EPOLL_CTL_DEL     2
#define EPOLL_CTL_MOD     3
static void print_epoll_control(PRINTER &P, int op)
{
    switch (op)
    {
        case EPOLL_CTL_ADD: P.put("EPOLL_CTL_ADD"); break;
        case EPOLL_CTL_DEL: P.put("EPOLL_CTL_DEL"); break;
        case EPOLL_CTL_MOD: P.put("EPOLL_CTL_MOD"); break;
        default: P.format("%d", op); break;
    }
}

static void print_epoll_event(PRINTER &P, const struct epoll_event *event)
{
    if (event == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('{');
    print_epoll_events(P, event->events);
    P.format(",%ld}", event->data);
}

static void print_epoll_events(PRINTER &P, const struct epoll_event *events,
    int maxevents)
{
    P.put('[');
    for (int i = 0; i < maxevents; i++)
    {
        P.put(i == 0? "": ",");
        print_epoll_event(P, events+i);
    }
    P.put(']');
}

static void print_ints(PRINTER &P, const int *a, size_t size)
{
    if (a == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('[');
    for (size_t i = 0; i < size; i++)
        P.format("%s%d", (i == 0? "": ","), a[i]);
    P.put(']');
}

static void print_sigset(PRINTER &P, const sigset_t *set)
{
    if (set == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{0x%.8X}", (uint32_t)*set);
}

static void print_cpuset(PRINTER &P, const unsigned long *set, size_t size)
{
    if (set == NULL)
    {
        P.put("NULL");
        return;
    }
    P.put('[');
    for (size_t i = 0; i < size / sizeof(unsigned long); i++)
        P.format("%s0x%.16lx", (i == 0? "": ","), set[i]);
    P.put(']');
}

static void print_stack(PRINTER &P, const stack_t *stack)
{
    if (stack == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{%p,0x%x,%zu}", stack->ss_sp, stack->ss_flags, stack->ss_size);
}

static void print_prctl(PRINTER &P, int cmd)
{
    P.put(prctl_info(cmd)->name);
}

static void print_prctl_arg(PRINTER &P, int cmd, intptr_t arg)
{
    size_t size = prctl_info(cmd)->size;
    if (size > 0)
        print_buf(P, (const uint8_t *)arg, size);
    else
        P.format("%ld", arg);
}

static void print_tms(PRINTER &P, const struct tms *tms)
{
    if (tms == NULL)
    {
        P.put("NULL");
        return;
    }
    P.format("{%ld,%ld,%ld,%ld}", tms->tms_utime, tms->tms_stime,
        tms->tms_cutime, tms->tms_cstime);
}

static void print_context(PRINTER &P, const CONTEXT *ctx)
{
    P.format("{cpu=%d,pid=%d,argv=[", ctx->cpu, ctx->pid);
    const char *p = ctx->args;
    bool r = false;
    for (unsigned i = 0; i < ctx->argc; i++)
    {
        r = P.format("%s\"%s\"", (r? ",": ""), p);
        p += strlen(p)+1;
    }
    P.put("],envp=[");
    r = false;
    for (unsigned i = 0; i < ctx->envl; i++)
    {
        r = P.format("%s\"%s\"", (r? ",": ""), p);
        p += strlen(p)+1;
    }
    P.put("]}");
}

/*
 * Print the difference between IOVs.
 */
static void print_diff(PRINTER &P, const struct iovec *iov1, size_t iovcnt1,
    const struct iovec *iov2, size_t iovcnt2)
{
    struct iov_itr_s i0 = IOV_ITR(iov1, iovcnt1);
    struct iov_itr_s j0 = IOV_ITR(iov2, iovcnt2);
    iov_itr_t i = &i0, j = &j0;

    P.put("\t< ");
    while (!iov_itr_end(i))
    {
        print_char(P, iov_itr_getc(i));
        iov_itr_inc(i);
    }
    P.put("\n\t---\n\t> ");
    iov_itr_reset(i);
    bool same = true;
    while (!iov_itr_end(i) || !iov_itr_end(j))
    {
        bool diff = (iov_itr_end(i) != iov_itr_end(j) ||
                     iov_itr_get(i) != iov_itr_get(j));
        if (option_tty && same && diff)
            P.put(MAGENTA);
        if (option_tty && !same && !diff)
            P.put(OFF);
        same = !diff;
        print_char(P, iov_itr_getc(j));
        iov_itr_inc(i);
        iov_itr_inc(j);
    }
    if (option_tty && !same)
        P.put(OFF);
}

/*
 * Print an argument.
 */
static void print_arg(PRINTER &P, const INFO *info, uint8_t arg,
    intptr_t val, size_t prev, size_t next, size_t size)
{
    socklen_t addrlen;
    switch (arg)
    {
        case AXXX: case AHEX:
            P.format("0x%lx", (uintptr_t)val); break;
        case APTR:
            print_ptr(P, (const void *)val); break;
        case A_FD:
            P.format("%d", (int)val); break;
        case ABUF:
            print_buf(P, (const uint8_t *)val, size); break;
        case ASIZ: case ADEC:
            P.format("%ld", (intptr_t)val); break;
        case ASTR:
            P.format("\"%s\"", (const char *)val); break;
        case AOPN:
            print_open_flags(P, (int)val, (int)next); break;
        case ASTB:
            print_stat_buf(P, (const struct stat *)val); break;
        case APFD:
            print_pollfds(P, (struct pollfd *)val, (size_t)next);
            break;
        case AOCT:
            P.format("0%lo", (uintptr_t)val); break;
        case AOFF:
            P.format("%+zd", (off_t)val); break;
        case ASEK:
            print_whence(P, (int)val); break;
        case ARWX:
            print_prot_flags(P, (int)val); break;
        case AMAP:
            print_map_flags(P, (int)val); break;
        case ASIG:
            print_signal(P, (int)val); break;
        case ADDD: case ANYI:
            P.put("..."); break;
        case AIOV:
            print_iov(P, (struct iovec *)val, next, size);
            break;
        case AFD2:
            P.format("[%d,%d]", *(int *)val, *((int *)val + 1));
            break;
        case ASET:
            print_fd_set(P, (fd_set *)val); break;
        case A_TV:
            print_timeval(P, (struct timeval *)val); break;
        case A_TS:
            print_timespec(P, (struct timespec *)val); break;
        case ADOM:
            print_socket_domain(P, (int)val); break;
        case ATYP:
            print_socket_type(P, (int)val); break;
        case APRO:
            print_socket_protocol(P, (int)val); break; 
        case ADDR:
            addrlen = (socklen_t)next;
            print_sockaddr(P, (struct sockaddr *)val, &addrlen);
            break;
        case ADDP:
            print_sockaddr(P, (struct sockaddr *)val, (socklen_t *)next);
            break;
        case A_IP:
            print_int32_ptr(P, (int32_t *)val); break;
        case ASZP:
            print_int32_ptr(P, (int32_t *)val); break;
        case AMSG:
            print_msghdr(P, (msghdr *)val, size);
            break;
        case AHOW:
            print_how(P, (int)val); break;
        case ABFP:
            print_buf_2(P, (void *)val, (socklen_t *)next); break;
        case ACLN:
            print_clone_flags(P, (int)val); break;
        case AFUT:
            print_futex_op(P, (int)val); break;
        case ACLK:
            print_clock(P, (int)val); break;
        case ADIR:
            print_dir(P, (int)val); break;
        case AUNM:
            print_utsname(P, (struct utsname *)val); break;
        case AENT:
            print_dirent(P, (struct dirent *)val, size); break;
        case AE64:
            print_dirent64(P, (struct dirent64 *)val, size); break;
        case AIOC:
            print_ioctl(P, (int)val); break;
        case AIOA:
            print_ioctl_arg(P, (int)prev, val); break;
        case ASYS:
            print_sysinfo(P, (struct sysinfo *)val); break;
        case A_SA:
            print_sigaction(P, (struct ksigaction *)val); break;
        case ASFS:
            print_statfs(P, (struct statfs *)val); break;
        case AFCC:
            print_fcntl(P, (int)val); break;
        case AFCA:
            print_fcntl_arg(P, (int)prev, val); break;
        case ARES:
            print_resource(P, (int)val); break;
        case ALIM:
            print_rlimit(P, (struct rlimit *)val); break;
        case AWHO:
            print_who(P, (int)val); break;
        case AUSE:
            print_rusage(P, (struct rusage *)val); break;
        case ASTX:
            print_statx(P, (struct statx *)val); break;
        case AC3A:
            print_clone_args(P, (struct clone_args *)val); break;
        case A_SI:
            print_siginfo(P, (siginfo_t *)val); break;
        case AEPE:
            print_epoll_event(P, (struct epoll_event *)val); break;
        case AEPA:
            print_epoll_events(P, (struct epoll_event *)val, (int)size); break;
        case AEPC:
            print_epoll_control(P, (int)val); break;
        case A_MM:
            print_mmsghdr(P, (struct mmsghdr *)val, size); break;
        case A_IA:
            print_ints(P, (int *)val, prev); break;
        case A_SS:
            print_sigset(P, (sigset_t *)val); break;
        case ACPU:
            print_cpuset(P, (unsigned long *)val, prev); break;
        case ASTK:
            print_stack(P, (stack_t *)val); break;
        case APRC:
            print_prctl(P, (int)val); break;
        case APRA:
            print_prctl_arg(P, (int)prev, val); break;
        case ATMS:
            print_tms(P, (struct tms *)val); break;
        case ACTX:
            print_context(P, (CONTEXT *)val); break;
        default:
            P.put("<unknown>"); break;
    }
}
static bool print_arg(PRINTER &P, const INFO *info, const SYSCALL *call,
    int idx, bool exe = true)
{
    uint8_t arg = info->args[idx];
    if (arg == A___)
        return false;
    bool input = ((info->mask & (0x1 << idx)) != 0);
    if (input && (!exe || call->result < 0))
    {
        P.put("???");
        return true;
    }
    if (!syscall_used(call, idx))
    {
        P.put("...");
        return true;
    }
    intptr_t val = call->args[idx].val;
    size_t  next = (idx == 5? 0: call->args[idx+1].size);
    size_t  prev = (idx == 0? 0: call->args[idx-1].size);
    size_t  size = next;
    switch (arg)
    {
        case ABUF: case AENT: case AE64:
            size = (input? (size_t)call->result: size);
            break;
        case AIOV: case AMSG: case A_MM: case AEPA:
            size = (input? (size_t)call->result: SIZE_MAX);
            break;
        case APFD:
            next = size = size * sizeof(struct pollfd);
            break;
        case A_IA:
            prev = (size_t)call->result;
            break;
    }
    print_arg(P, info, arg, val, prev, next, size);
    return true;
}

/*
 * Print an argument as a value.
 */
static void print_val(PRINTER &P, const INFO *info, uint8_t arg,
    intptr_t val, size_t prev, size_t next, size_t size)
{
    if (arg_is_pointer(arg))
        P.format("%p", (void *)val);
    else
        print_arg(P, info, arg, val, prev, next, size);
}

/*
 * Print a result.
 */
static void print_result(PRINTER &P, uint8_t kind, intptr_t result)
{
    if (result < 0)
    {
        size_t err = (size_t)-result;
        if (err == 0 || err >= sizeof(ERRNO_INFO) / sizeof(ERRNO_INFO[0]))
            P.format("%ld", result);
        else
            P.format("-%s", ERRNO_INFO[err]);
        return;
    }
    switch (kind)
    {
        case R__0: case RXXX:
            if (result == 0)
            {
                P.put('0');
                break;
            }
            // Fallthrough
        default:
        case RHEX:
            P.format("0x%lx", result); break;
        case R_FD:
            P.format("%d", (int)result); break;
        case RSIZ: case RDEC:
            P.format("%zu", (size_t)result); break;
        case ROCT:
            P.format("0%zo", (size_t)result); break;
        case ROFF:
            P.format("%+zd", (off_t)result); break;
        case RPTR:
            print_ptr(P, (const void *)result); break;
        case RSIG:
            print_signal(P, (int)result); break;
    }
}
void print_result(PRINTER &P, const SYSCALL *call)
{
    uint8_t rxx = RXXX;
    if ((size_t)call->no < sizeof(TABLE) / sizeof(TABLE[0]))
    {
        const INFO *info = &TABLE[call->no];
        rxx = info->result;
    }
    print_result(P, rxx, call->result);
}

/*
 * Print a syscall.
 */
static void print_syscall(PRINTER &P, const SYSCALL *call, bool exe = true)
{
    P.format("%s(", syscall_name(call->no));
    int n = syscall_arity(call);
    const INFO *info = syscall_info(call->no);
    for (int i = 0; i < n; i++)
    {
        P.put(i > 0? ",": "");
        print_arg(P, info, call, i, exe);
    }
    P.put(") = ");
    if (exe)
        print_result(P, call);
    else
        P.put("???");
}

/*
 * Print hook.
 */
static int fd_port(int fd);
static uint32_t fuzzer_hash_coverage(void);
static void print_hook(FILE *stream, const SYSCALL *call)
{
    if (option_log < 3)
        return;

    PRINTER P;
    fprintf(stream, "#%d ", call->id);
    int port = -1;
    if ((size_t)call->no >= sizeof(TABLE) / sizeof(TABLE[0]))
        fprintf(stream, "syscall(%d,...", call->no);
    else
    {
        const INFO *info = &TABLE[call->no];
        const char *color = WHITE;
        switch (info->kind)
        {
            case P_FD: color = YELLOW;  break;
            case P_IO: color = CYAN;    break;
            case PINF: color = GREEN;   break;
            case POLL: color = RED;     break;
            case PMEM: color = MAGENTA; break;
            case PSIG: color = GREEN;   break;
            case PTHR: color = MAGENTA; break;
            case PROC: color = MAGENTA; break;
            default: break;
        }

        fprintf(stream, "%s%s%s(", color, info->name, OFF);
        int n = syscall_arity(call);
        for (int i = 0; i < n; i++)
        {
            if (!print_arg(P.reset(), info, call, i))
                break;
            fprintf(stream, "%s%s", (i > 0? ",": ""), P.str());
        }
        if (info->result == R_FD && call->result >= 0)
        {
            int fd = (int)call->result;
            port = fd_port(fd);
        }
    }

    print_result(P.reset(), call);
    fprintf(stream, ") = %s", P.str());
    if (port > 0)
        fprintf(stream, " [port=%d]", port);
    if (option_log >= 4)
    {
        uint32_t h = fuzzer_hash_coverage();
        if (h != 0x0)
            fprintf(stream, " [hash=0x%.8x]", h);
    }
    fputc('\n', stderr);
}

