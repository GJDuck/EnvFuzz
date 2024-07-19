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

#define SCHED_FD            9999
#define SCHED_PORT          9999

struct EPOLL
{                           // epoll() info
    struct epoll_event event;   // Event
    int fd;                 // File descriptor
    EPOLL *next;            // Next info
};

struct ENTRY
{
    int fd;                 // File descriptor
    uint16_t filetype;      // File type (S_IF*)
    bool mutate;            // Can mutate this input?
    uint8_t eof;            // EOF counter (emulation).
    int socktype;           // Socket type (SOCK_STREAM or SOCK_DGRAM)
    int flags;              // O_* flags
    int port;               // Port #
    uint32_t seq;           // Seq #
    uint32_t ack;           // Ack #
    EPOLL *epoll;           // epoll() info
    const char *name;       // Name
};

struct NAME
{
    int port;               // Port #
    char name[];            // Name
};

// Current file descriptor information:
static void *FD_TABLE   = NULL;
static void *NAME_TABLE = NULL;
static int fd_next      = 0;  // Next free port;

/*
 * (Simplified) regular expression matching.
 */
static bool fd_match(const char *pattern, const char *name)
{
    while (*pattern && *name)
    {
        if (*pattern == '*')
        {
            while (*(pattern + 1) == '*')
                pattern++;
            do
            {
                if (fd_match(pattern + 1, name))
                    return true;
            }
            while (*name++);
            return false;
        }
        else if (*pattern == '?')
        {
            pattern++;
            name++;
        }
        else
        {
            if (*pattern != *name)
                return false;
            pattern++;
            name++;
        }
    }
    if (*pattern == '*' && *(pattern + 1) == '\0')
        return true;
    return *pattern == *name;
}

/*
 * Parse the ignore table.
 */
struct IGNORE
{
    const IGNORE *next;
    char pattern[];
};
static const IGNORE *FD_IGNORE = NULL;
static void fd_ignore_parse(void)
{
    const char *filename = "ignore.tab";
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
        error("failed to open \"%s\" for reading: %s", filename,
            strerror(errno));
    char buf[1001];
    while (!feof(stream) && fscanf(stream, "%1000s", buf) == 1)
    {
        char c;
        while ((c = fgetc(stream)) != '\n' && c != EOF)
            ;
        size_t len = strlen(buf);
        IGNORE *ignore = (IGNORE *)xmalloc(sizeof(IGNORE) + len+1);
        memcpy(ignore->pattern, buf, len+1);
        ignore->next = FD_IGNORE;
        FD_IGNORE = ignore;
    }
    if (ferror(stream))
        error("failed to parse \"%s\": %s", filename, strerror(errno));
    fclose(stream);
}

/*
 * Check if we should mutate (fuzz) or ignore this input.
 */
static bool fd_ignore(const char *name)
{
    if (name == NULL)
        return true;

    for (const IGNORE *ignore = FD_IGNORE; ignore != NULL;
        ignore = ignore->next)
    {
        if (fd_match(ignore->pattern, name))
            return true;
    }
    return false;
}

static int name_compare(const void *a, const void *b)
{
    NAME *A = (NAME *)a;
    NAME *B = (NAME *)b;
    if (A->port == B->port)
        return 0;
    return (A->port < B->port? -1: 1);
}

static const char *name_set(int port, const char *name, bool replace = false)
{
    PRINTER P;
    if (name == NULL)
    {
        P.format("port://%d", port);
        name = P.str();
    }

    NAME key;
    key.port = port;
    void *node = tfind(&key, &NAME_TABLE, name_compare);
    if (node != NULL)
    {
        NAME *info = *(NAME **)node;
        if (!replace || strcmp(name, info->name) == 0)
            return info->name;
        (void)tdelete(info, &NAME_TABLE, name_compare);
        xfree((void *)info);
    }
 
    size_t size = strlen(name) + 1;
    NAME *info = (NAME *)xmalloc(sizeof(NAME) + size);
    info->port = port;
    memcpy(info->name, name, size);
    (void)tsearch(info, &NAME_TABLE, name_compare);
    return info->name;
}

static const char *name_get(int port)
{
    NAME key;
    key.port = port;
    void *node = tfind(&key, &NAME_TABLE, name_compare);
    if (node == NULL)
        return NULL;
    const NAME *info = *(NAME **)node;
    return info->name;
}

static const char *port_name(int port)
{
    const char *name = name_get(port);
    return (name == NULL? "<unknown>": name);
}

static int fd_compare(const void *a, const void *b)
{
    ENTRY *A = (ENTRY *)a;
    ENTRY *B = (ENTRY *)b;
    return A->fd - B->fd;
}

static ENTRY *fd_entry(int fd)
{
    ENTRY key;
    key.fd = fd;
    const void *node = tfind(&key, &FD_TABLE, fd_compare);
    if (node == NULL) return NULL;
    ENTRY *E = *(ENTRY **)node;
    return E;
}

static ENTRY *fd_lookup(int fd)
{
    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        error("failed to find file descriptor %d", fd);
    return E;
}

static ENTRY *fd_open(int fd, int filetype, int socktype, int flags,
    const char *name)
{
    if (fd < 0)
        return NULL;
    if (fd_next >= UINT16_MAX)
        error("failed to assign new port; maxium port number (%u) exceeded",
            UINT16_MAX);
    ENTRY *E = (ENTRY *)xmalloc(sizeof(struct ENTRY));
    memset(E, 0x0, sizeof(ENTRY));
    E->fd       = fd;
    E->filetype = filetype;
    E->socktype = socktype;
    E->flags    = flags;
    E->port     = fd_next++;
    E->seq      = 0;
    E->ack      = 0;
    E->mutate   = !fd_ignore(name);
    void *node = tsearch(E, &FD_TABLE, fd_compare);
    if (E != *(ENTRY **)node)
        error("failed to open input %s; file descriptor %d is already open",
            name, fd);
    E->name = name_set(E->port, name);
    return E;
}

static ENTRY *fd_bind(int fd, const sockaddr *addr, socklen_t addrlen)
{
    if (fd < 0)
        return NULL;
    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        return NULL;
    PRINTER P;
    print_sockaddr(P, addr, &addrlen);
    E->name = name_set(E->port, P.str(), /*replace=*/true);
    E->mutate = !fd_ignore(E->name);
    return E;
}

static ENTRY *fd_get(int fd)
{
    ENTRY *E = fd_entry(fd);
    if (E != NULL)
        return E;
    E = fd_open(fd, S_IFSOCK, SOCK_STREAM, 0x0, NULL);
    assert(E != NULL);
    return E;
}

static bool fd_close(int fd)
{
    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        return false;
    (void)tdelete(E, &FD_TABLE, fd_compare);
    xfree(E);
    return true;
}

static ENTRY *fd_dup(const ENTRY *E, int fd)
{
    fd_close(fd);
    return fd_open(fd, E->filetype, E->socktype, 0x0, E->name);
}

static void fd_init(void)
{
    if (REPLAY)
        fd_ignore_parse();
    fd_next = SCHED_PORT;
    (void)fd_open(SCHED_FD, S_IFREG, SOCK_DGRAM, 0x0, "SYSCALLS");
    (void)fd_open(0, S_IFIFO, SOCK_STREAM, 0x0, "stdio://stdin");
    (void)fd_open(1, S_IFIFO, SOCK_STREAM, 0x0, "stdio://stdout");
    (void)fd_open(2, S_IFIFO, SOCK_STREAM, 0x0, "stdio://stderr");
}

static int fd_port(int fd)
{
    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        return -1;
    return E->port;
}

static void fd_epoll_ctl(int efd, int op, int fd,
    struct epoll_event *event)
{
    ENTRY *E = fd_entry(efd);
    if (E == NULL)
        return;
    EPOLL *info = nullptr, *prev = nullptr;
    switch (op)
    {
        case EPOLL_CTL_ADD:
            info = (EPOLL *)xmalloc(sizeof(EPOLL));
            memcpy(&info->event, event, sizeof(info->event));
            info->fd   = fd;
            info->next = E->epoll;
            E->epoll   = info;
            return;
        case EPOLL_CTL_MOD: case EPOLL_CTL_DEL:
            for (info = E->epoll; info != NULL && info->fd != fd;
                    info = info->next)
                prev = info;
            break;
        default:
            return;
    }
    switch (op)
    {
        case EPOLL_CTL_MOD:
            memcpy(&info->event, event, sizeof(info->event));
            break;
        case EPOLL_CTL_DEL:
            if (prev == NULL)
                E->epoll = info->next;
            else
                prev->next = info->next;
            xfree((void *)info);
            break;
    }
}

