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

struct mmsghdr;
typedef struct sigaltstack stack_t;
struct epoll_event;

union ARG                       // Syscall arg
{
    intptr_t val;               // Argument value
    int64_t i64;                // Case to int64_t
    int32_t i32;                // Cast to int32_t
    int16_t i16;                // Cast to int16_t
    uint64_t u64;               // Case to uint64_t
    uint32_t u32;               // Cast to uint32_t
    uint16_t u16;               // Cast to uint16_t
    int fd;                     // Cast to file descriptor
    int flags;                  // Cast to flags
    int sig;                    // Cast to signal
    int *fds;                   // Cast to int[2]
    uint8_t *buf;               // Cast to buffer
    void *ptr;                  // Cast to (void *)
    int *ip;                    // Cast to (int *)
    size_t size;                // Cast to size
    off_t offset;               // Cast to offset
    const char *path;           // Cast to pathname
    const char *str;            // Cast to string
    struct iovec *iov;          // Cast to iovec
    const sockaddr *addr;       // Cast to sockaddr
    struct msghdr *msg;         // Cast to msghdr
    struct ksigaction *action;  // Cast to ksigaction
    struct mmsghdr *mmsg;       // Cast to mmsghdr
    siginfo_t *siginfo;         // Cast to siginfo_t
    sigset_t *sigset;           // Cast to sigset_t
    unsigned long *cpuset;      // Cast to CPU set
    stack_t *stack;             // Cast to stack_t
    struct pollfd *pfds;        // Cast to pollfd
    struct epoll_event *event;  // Cast to struct epoll_event
    fd_set *fdset;              // Cast to fd_set
    struct timeval *tv;         // Cast to timeval
    struct timespec *ts;        // Cast to timespec
    pid_t pid;                  // Cast to pid
};

struct AUX                      // Syscall auxiliary data
{
    uint32_t size:24;           // Aux data size
    uint32_t kind:8;            // Aux data kind (A***)
    uint8_t mask;               // Aux arg mask
    uint8_t data[];             // Aux data
} PACKED;
#define AUX_MAX                 0x00FFFFFF

struct SYSCALL                  // Syscall instance
{
    int no;                     // Syscall number
    int id:31;                  // Thread ID
    int replay:1;               // Replay?
    union
    {
        struct
        {
            ARG arg0;           // Syscall arg #1
            ARG arg1;           // Syscall arg #2
            ARG arg2;           // Syscall arg #3
            ARG arg3;           // Syscall arg #4
            ARG arg4;           // Syscall arg #5
            ARG arg5;           // Syscall arg #6
        };
        ARG args[6];            // Syscall args
    };
    intptr_t result;            // Syscall result
    AUX aux[];                  // Aux data
} PACKED;

struct SCHED                    // Recording
{
    SCHED *next;                // Next syscall
    uint32_t len;               // Length of data[]
    uint8_t data[];             // Current SYSCALL struct
} PACKED;

struct INFO                     // Syscall INFO
{
    char name[24];              // Name
    bool passthru;              // Replay passthru?
    bool block;                 // Recording can block indefinitely?
    uint8_t kind;               // Syscall class  (P***)
    uint8_t args[6];            // Argument types (A***)
    uint8_t result;             // Return type    (R***)
    uint8_t mask;               // Input mask     (M******)
} PACKED;

struct AUXVEC                   // Auxiliary data helper
{
    static const int MAX = 16;
    struct iovec vec[MAX];      // Vector
    int i = 0;                  // Current pointer

    void push(const void *buf, size_t size, uint8_t mask, unsigned kind);
    void push(const struct msghdr *msg, uint8_t mask, unsigned kind);
    void end(void);

    int iovcnt(void)
    {
        return i;
    }
    const struct iovec *iov(void)
    {
        return vec;
    }

    AUXVEC(const SYSCALL *call)
    {
        vec[i++] = (struct iovec){(void *)call, sizeof(*call)};
    }
    ~AUXVEC()
    {
        for (int j = 1; j < i; j++)
            xfree(vec[j].iov_base);
    }
};

#define PXXX            0       // Misc
#define P_FD            1       // File
#define P_IO            2       // I/O
#define PINF            3       // Info
#define POLL            4       // Poll
#define PMEM            5       // Memory
#define PSIG            6       // Signal
#define PTHR            7       // Thread
#define PROC            8       // Process

#define A___            0       // Unused
#define AXXX            1       // Misc
#define ABUF            2       // Buffer
#define ASIZ            3       // Size
#define A_FD            4       // File descriptor
#define ASTR            5       // Filename/string
#define AOPN            6       // Open flags
#define ASTB            7       // Stat buf
#define APFD            8       // Poll fds
#define ADEC            9       // Decimal integer
#define AOCT            10      // Octal integer
#define AHEX            11      // Hex integer
#define AOFF            12      // Offset
#define ASEK            13      // Whence
#define ARWX            14      // PROT_* flags
#define AMAP            15      // MAP_* flags
#define ASIG            16      // Signal
#define ADDD            17      // ...
#define AIOV            18      // IOV
#define ASET            19      // fd_set
#define A_TV            20      // timeval
#define A_TS            21      // timespec
#define AFD2            22      // fd[2]
#define ADOM            23      // socket domain
#define ATYP            24      // socket type
#define APRO            25      // socket protocol
#define ADDR            26      // sockaddr+socklen
#define ADDP            27      // sockaddr+(socklen *)
#define ASZP            28      // (socklen *)
#define AMSG            29      // msghdr
#define AHOW            30      // shutdown how
#define ABFP            31      // buffer+(size_t *)
#define ACLN            32      // CLONE_* flags
#define A_IP            33      // int *
#define AFUT            34      // FUTEX op
#define ACLK            35      // CLOCK_*
#define APTR            36      // void *
#define ADIR            37      // Dir fd
#define AUNM            38      // utsname
#define AENT            39      // dirent
#define AE64            40      // dirent64
#define AIOC            41      // ioctl cmd
#define AIOA            42      // ioctl arg
#define ASYS            43      // sysinfo
#define A_SA            44      // sigaction
#define ASFS            45      // statfs
#define AFCC            46      // fcntl cmd
#define AFCA            47      // fcntl arg
#define ARES            48      // resource
#define ALIM            49      // rlimit
#define AWHO            50      // rusage who
#define AUSE            51      // rusage
#define ASTX            52      // statx
#define AC3A            53      // clone_args
#define A_SI            54      // siginfo_t
#define AEPE            55      // epoll_event
#define AEPA            56      // epoll_event[]
#define AEPC            57      // epoll control
#define A_MM            58      // mmsghdr
#define A_IA            59      // int[]
#define A_SS            60      // sigset
#define ACPU            61      // cpuset
#define ASTK            62      // stack_t
#define APRC            63      // prctl option
#define APRA            64      // prctl arg
// #define ACTX         250     // CONTEXT (see rrfuzz.h)
#define ANAM            251     // Port name
#define APTH            252     // Pathname
#define ANYI            253     // Not-yet-implemented
#define APRT            254     // Port number
#define AEND            255     // End marker

#define RXXX            0       // Misc
#define R__0            1       // Zero
#define R_FD            2       // File descriptor
#define RDEC            3       // Decimal integer
#define ROCT            4       // Octal integer
#define RHEX            5       // Hex integer
#define RSIZ            6       // Size
#define ROFF            7       // Offset
#define RSIG            8       // Signal
#define RPTR            9       // Pointer

#define M______         0x00
#define MI_____         0x01
#define M_I____         0x02
#define M__I___         0x04
#define M___I__         0x08
#define M____I_         0x10
#define M_____I         0x20
#define MII____         (MI_____ | M_I____)
#define MI___I_         (MI_____ | M____I_)
#define M_II___         (M_I____ | M__I___)
#define M_I_I__         (M_I____ | M___I__)
#define M__II__         (M__I___ | M___I__)
#define M__I_I_         (M__I___ | M____I_)
#define M___II_         (M___I__ | M____I_)
#define MIII___         (MI_____ | M_I____ | M__I___)
#define M_III__         (M_I____ | M__I___ | M___I__)
#define M_I__II         (M_I____ | M____I_ | M_____I)
#define M__III_         (M__I___ | M___I__ | M____I_)
#define M_IIII_         (M_I____ | M__I___ | M___I__ | M____I_)
#define MIII_II         (MI_____ | M_I____ | M__I___ | M____I_ | M_____I)
#define MR_             0x40
#define M_R             0x80

static const INFO TABLE[] =
{
    {"read",                    0, 1, P_IO, {A_FD, ABUF, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"write",                   0, 0, P_IO, {A_FD, ABUF, ASIZ, A___, A___, A___}, RSIZ, M______},
    {"open",                    0, 0, P_FD, {ASTR, AOPN, A___, A___, A___, A___}, R_FD, M______},
    {"close",                   0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R__0, M______},
    {"stat",                    0, 0, P_FD, {ASTR, ASTB, A___, A___, A___, A___}, R__0, M_I____},
    {"fstat",                   0, 0, PINF, {A_FD, ASTB, A___, A___, A___, A___}, R__0, M_I____},
    {"lstat",                   0, 0, PINF, {ASTR, ASTB, A___, A___, A___, A___}, R__0, M_I____},
    {"poll",                    0, 1, POLL, {APFD, ASIZ, ADEC, A___, A___, A___}, RSIZ, MI_____},
    {"lseek",                   0, 0, P_FD, {A_FD, AOFF, ASEK, A___, A___, A___}, ROFF, M______},
    {"mmap",                    0, 0, PMEM, {APTR, ASIZ, ARWX, AMAP, A_FD, AOFF}, RPTR, M______},
    {"mprotect",                1, 0, PMEM, {APTR, ASIZ, ARWX, A___, A___, A___}, R__0, M______},
    {"munmap",                  1, 0, PMEM, {APTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"brk",                     1, 0, PMEM, {APTR, A___, A___, A___, A___, A___}, RPTR, M______},
    {"rt_sigaction",            0, 0, PSIG, {ASIG, A_SA, A_SA, A___, A___, A___}, R__0, M__I___},
    {"rt_sigprocmask",          0, 0, PSIG, {ASIG, A_SS, A_SS, ASIZ, A___, A___}, R__0, M__I___},
    {"rt_sigreturn",            0, 0, PSIG, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"ioctl",                   0, 1, P_IO, {A_FD, AIOC, AIOA, A___, A___, A___}, R__0, M__I___},
    {"pread64",                 0, 1, P_IO, {A_FD, ABUF, ASIZ, AOFF, A___, A___}, RSIZ, M_I____},
    {"pwrite64",                0, 0, P_IO, {A_FD, ABUF, ASIZ, AOFF, A___, A___}, RSIZ, M______},
    {"readv",                   0, 1, P_IO, {A_FD, AIOV, ADEC, A___, A___, A___}, RSIZ, M_I____},
    {"writev",                  0, 0, P_IO, {A_FD, AIOV, ADEC, A___, A___, A___}, RSIZ, M______},
    {"access",                  0, 0, PINF, {ASTR, AOCT, A___, A___, A___, A___}, R__0, M______},
    {"pipe",                    0, 0, P_FD, {AFD2, A___, A___, A___, A___, A___}, R__0, MI_____},
    {"select",                  0, 1, POLL, {ADEC, ASET, ASET, ASET, A_TV, A___}, RSIZ, M_IIII_},
    {"sched_yield",             0, 0, PTHR, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"mremap",                  1, 0, PMEM, {APTR, ASIZ, ASIZ, AHEX, ADDD, A___}, RPTR, M______},
    {"msync",                   0, 0, PMEM, {APTR, ASIZ, AHEX, A___, A___, A___}, R__0, M______},
    {"mincore",                 1, 0, PMEM, {APTR, ASIZ, APTR, A___, A___, A___}, R__0, M__I___},
    {"madvise",                 0, 0, PMEM, {APTR, ASIZ, AHEX, A___, A___, A___}, R__0, M______},
    {"shmget",                  0, 0, PMEM, {ADEC, ASIZ, AHEX, A___, A___, A___}, RSIZ, M______},
    {"shmat",                   0, 0, PMEM, {ADEC, APTR, AHEX, A___, A___, A___}, RPTR, M______},
    {"shmctl",                  0, 0, PMEM, {ADEC, ADEC, APTR, A___, A___, A___}, RSIZ, M______},
    {"dup",                     0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R_FD, M______},
    {"dup2",                    0, 0, P_FD, {A_FD, A_FD, A___, A___, A___, A___}, R_FD, M______},
    {"pause",                   0, 1, PSIG, {A___, A___, A___, A___, A___, A___}, RSIG, M______},
    {"nanosleep",               0, 1, PTHR, {A_TS, A_TS, A___, A___, A___, A___}, R__0, M_I____},
    {"getitimer",               0, 0, PSIG, {ADEC, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"alarm",                   0, 0, PSIG, {ADEC, A___, A___, A___, A___, A___}, RSIZ, M______},
    {"setitimer",               0, 0, PSIG, {ADEC, APTR, APTR, A___, A___, A___}, RXXX, M__I___},
    {"getpid",                  0, 0, PROC, {A___, A___, A___, A___, A___, A___}, RSIZ, M______},
    {"sendfile",                0, 0, P_IO, {A_FD, A_FD, APTR, ASIZ, A___, A___}, RSIZ, M__I___},
    {"socket",                  0, 0, P_FD, {ADOM, ATYP, APRO, A___, A___, A___}, R_FD, M______},
    {"connect",                 0, 1, P_FD, {A_FD, ADDR, ASIZ, A___, A___, A___}, R__0, M______},
    {"accept",                  0, 1, P_FD, {A_FD, ADDP, A_IP, A___, A___, A___}, R_FD, M_II___},
    {"sendto",                  0, 0, P_IO, {A_FD, ABUF, ASIZ, AHEX, ADDR, ADEC}, RSIZ, M______},
    {"recvfrom",                0, 1, P_IO, {A_FD, ABUF, ASIZ, AHEX, ADDP, A_IP}, RSIZ, M_I__II},
    {"sendmsg",                 0, 0, P_IO, {A_FD, AMSG, AHEX, A___, A___, A___}, RSIZ, M______},
    {"recvmsg",                 0, 1, P_IO, {A_FD, AMSG, AHEX, A___, A___, A___}, RSIZ, M_I____},
    {"shutdown",                0, 0, P_FD, {A_FD, AHOW, A___, A___, A___, A___}, R__0, M______},
    {"bind",                    0, 0, P_FD, {A_FD, ADDR, ADEC, A___, A___, A___}, R__0, M______},
    {"listen",                  0, 1, P_FD, {A_FD, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"getsockname",             0, 0, PINF, {A_FD, ADDP, A_IP, A___, A___, A___}, R__0, M_II___},
    {"getpeername",             0, 0, PINF, {A_FD, ADDP, A_IP, A___, A___, A___}, R__0, M_II___},
    {"socketpair",              0, 0, P_FD, {ADOM, ATYP, APRO, AFD2, A___, A___}, R__0, M___I__},
    {"setsockopt",              0, 0, PINF, {A_FD, APRO, ADEC, ABUF, ASIZ, A___}, R__0, M______},
    {"getsockopt",              0, 1, PINF, {A_FD, APRO, ADEC, ABFP, ASZP, A___}, R__0, M___II_},
    {"clone",                   0, 1, PTHR, {ACLN, APTR, APTR, APTR, APTR, A___}, RSIZ, M______},
    {"fork",                    0, 0, PROC, {A___, A___, A___, A___, A___, A___}, RSIZ, M______},
    {"vfork",                   0, 0, PROC, {A___, A___, A___, A___, A___, A___}, RSIZ, M______},
    {"execve",                  0, 0, PROC, {ASTR, ADDD, A___, A___, A___, A___}, R__0, M______},
    {"exit",                    0, 0, PROC, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"wait4",                   0, 1, PROC, {ADEC, A_IP, AHEX, APTR, A___, A___}, RSIZ, M_I_I__},
    {"kill",                    0, 0, PSIG, {ADEC, ASIG, A___, A___, A___, A___}, R__0, M______},
    {"uname",                   0, 0, PINF, {AUNM, A___, A___, A___, A___, A___}, R__0, MI_____},
    {"semget",                  0, 0, PTHR, {AHEX, ASIZ, AHEX, A___, A___, A___}, RSIZ, M______},
    {"semop",                   0, 1, PTHR, {ADEC, APTR, ASIZ, A___, A___, A___}, R__0, M_I____},
    {"semctl",                  0, 0, PTHR, {ADEC, ADEC, ADEC, ADDD, A___, A___}, RSIZ, M______},
    {"shmdt",                   0, 0, PMEM, {ADEC, APTR, AHEX, A___, A___, A___}, RPTR, M______},
    {"msgget",                  0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"msgsnd",                  0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"msgrcv",                  0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"msgctl",                  0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fcntl",                   0, 1, P_FD, {A_FD, AFCC, AFCA, A___, A___, A___}, RSIZ, M__I___},
    {"flock",                   0, 0, P_FD, {A_FD, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"fsync",                   0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R__0, M______},
    {"fdatasync",               0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R__0, M______},
    {"truncate",                0, 0, P_FD, {ASTR, AOFF, A___, A___, A___, A___}, R__0, M______},
    {"ftruncate",               0, 0, P_FD, {A_FD, AOFF, A___, A___, A___, A___}, R__0, M______},
    {"getdents",                0, 1, P_IO, {A_FD, AENT, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"getcwd",                  0, 0, PINF, {ABUF, ASIZ, A___, A___, A___, A___}, RSIZ, MI_____},
    {"chdir",                   0, 0, P_FD, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"fchdir",                  0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R__0, M______},
    {"rename",                  0, 0, P_FD, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"mkdir",                   0, 0, P_FD, {ASTR, AOCT, A___, A___, A___, A___}, R__0, M______},
    {"rmdir",                   0, 0, P_FD, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"creat",                   0, 0, P_FD, {ASTR, AOCT, A___, A___, A___, A___}, R_FD, M______},
    {"link",                    0, 0, P_FD, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"unlink",                  0, 0, P_FD, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"symlink",                 0, 0, P_FD, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"readlink",                0, 0, P_FD, {ASTR, ABUF, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"chmod",                   0, 0, P_FD, {ASTR, AOCT, A___, A___, A___, A___}, R__0, M______},
    {"fchmod",                  0, 0, P_FD, {A_FD, AOCT, A___, A___, A___, A___}, R__0, M______},
    {"chown",                   0, 0, P_FD, {ASTR, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"fchown",                  0, 0, P_FD, {A_FD, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"lchown",                  0, 0, P_FD, {ASTR, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"umask",                   0, 0, P_FD, {AOCT, A___, A___, A___, A___, A___}, ROCT, M______},
    {"gettimeofday",            0, 0, PINF, {A_TV, APTR, A___, A___, A___, A___}, R__0, MII____},
    {"getrlimit",               0, 0, PROC, {ARES, ALIM, A___, A___, A___, A___}, RXXX, M_I____},
    {"getrusage",               0, 0, PROC, {AWHO, AUSE, A___, A___, A___, A___}, R__0, M_I____},
    {"sysinfo",                 0, 0, PINF, {ASYS, A___, A___, A___, A___, A___}, R__0, MI_____},
    {"times",                   0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"ptrace",                  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"getuid",                  0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"syslog",                  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"getgid",                  0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setuid",                  0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"setgid",                  0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"geteuid",                 0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"getegid",                 0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setpgid",                 0, 0, PXXX, {ADEC, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"getppid",                 0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"getpgrp",                 0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setsid",                  0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setreuid",                0, 0, PXXX, {ADEC, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"setregid",                0, 0, PXXX, {ADEC, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"getgroups",               0, 0, PINF, {ADEC, A_IA, A___, A___, A___, A___}, RDEC, M_I____},
    {"setgroups",               0, 0, PINF, {ASIZ, A_IA, A___, A___, A___, A___}, R__0, M______},
    {"setresuid",               0, 0, PXXX, {ADEC, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"getresuid",               0, 0, PXXX, {A_IP, A_IP, A_IP, A___, A___, A___}, R__0, MIII___},
    {"setresgid",               0, 0, PXXX, {ADEC, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"getresgid",               0, 0, PXXX, {A_IP, A_IP, A_IP, A___, A___, A___}, R__0, MIII___},
    {"getpgid",                 0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setfsuid",                0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"setfsgid",                0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"getsid",                  0, 0, PXXX, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"capget",                  0, 0, PXXX, {APTR, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"capset",                  0, 0, PXXX, {APTR, APTR, A___, A___, A___, A___}, R__0, M______},
    {"rt_sigpending",           0, 0, PSIG, {A_SS, A___, A___, A___, A___, A___}, R__0, MI_____},
    {"rt_sigtimedwait",         0, 0, PSIG, {A_SS, A_SI, A_TS, ASIZ, A___, A___}, RSIG, M_I____},
    {"rt_sigqueueinfo",         0, 0, PSIG, {ADEC, ASIG, A_SI, A___, A___, A___}, R__0, M__I___},
    {"rt_sigsuspend",           0, 0, PSIG, {A_SS, A___, A___, A___, A___, A___}, R__0, M______},
    {"sigaltstack",             0, 0, PSIG, {ASTK, ASTK, A___, A___, A___, A___}, R__0, M_I____},
    {"utime",                   0, 0, PXXX, {ASTR, APTR, A___, A___, A___, A___}, R__0, M______},
    {"mknod",                   0, 0, P_FD, {ASTR, AOCT, ADEC, A___, A___, A___}, R__0, M______},
    {"uselib",                  0, 0, PXXX, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"personality",             0, 0, PROC, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"ustat",                   0, 0, PXXX, {ADEC, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"statfs",                  0, 0, P_FD, {ASTR, ASFS, A___, A___, A___, A___}, R__0, M_I____},
    {"fstatfs",                 0, 0, P_FD, {A_FD, ASFS, A___, A___, A___, A___}, R__0, M_I____},
    {"sysfs",                   0, 0, PXXX, {ADEC, ADDD, A___, A___, A___, A___}, R__0, M_II___},
    {"getpriority",             0, 0, PTHR, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"setpriority",             0, 0, PTHR, {ADEC, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"sched_setparam",          0, 0, PTHR, {ADEC, APTR, A___, A___, A___, A___}, R__0, M______},
    {"sched_getparam",          0, 0, PTHR, {ADEC, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"sched_setscheduler",      0, 0, PTHR, {ADEC, ADEC, APTR, A___, A___, A___}, R__0, M______},
    {"sched_getscheduler",      0, 0, PTHR, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"sched_get_priority_max",  0, 0, PTHR, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"sched_get_priority_min",  0, 0, PTHR, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"sched_rr_get_interval",   0, 0, PTHR, {ADEC, A_TS, A___, A___, A___, A___}, R__0, M_I____},
    {"mlock",                   1, 0, PMEM, {APTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"munlock",                 1, 0, PMEM, {APTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"mlockall",                1, 0, PMEM, {AHEX, A___, A___, A___, A___, A___}, R__0, M______},
    {"munlockall",              1, 0, PMEM, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"vhangup",                 0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"modify_ldt",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"pivot_root",              0, 0, P_FD, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"_sysctl",                 0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, R__0, MI_____},
    {"prctl",                   0, 0, PROC, {APRC, APRA, ADDD, A___, A___, A___}, RDEC, M_I____},
    {"arch_prctl",              0, 0, PXXX, {ADEC, AHEX, A___, A___, A___, A___}, R__0, M_I____},
    {"adjtimex",                0, 0, PXXX, {APTR, A___, A___, A___, A___, A___}, RDEC, MI_____},
    {"setrlimit",               0, 0, PROC, {ARES, ALIM, A___, A___, A___, A___}, R__0, M______},
    {"chroot",                  0, 0, P_FD, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"sync",                    0, 0, P_FD, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"acct",                    0, 0, PXXX, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"settimeofday",            0, 0, PINF, {A_TV, APTR, A___, A___, A___, A___}, R__0, M______},
    {"mount",                   0, 0, P_FD, {ASTR, ASTR, ASTR, AHEX, APTR, A___}, R__0, M______},
    {"umount2",                 0, 0, P_FD, {ASTR, AHEX, A___, A___, A___, A___}, R__0, M______},
    {"swapon",                  0, 0, PXXX, {ASTR, AHEX, A___, A___, A___, A___}, R__0, M______},
    {"swapoff",                 0, 0, PXXX, {ASTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"reboot",                  0, 0, PXXX, {AHEX, AHEX, ADEC, APTR, A___, A___}, R__0, M______},
    {"sethostname",             0, 0, PXXX, {ASTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"setdomainname",           0, 0, PXXX, {ASTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"iopl",                    0, 0, PXXX, {ADEC, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"ioperm",                  0, 0, PXXX, {ADEC, ADEC, ADEC, A___, A___, A___}, R__0, M______},
    {"create_module",           0, 0, PXXX, {ASTR, ASIZ, A___, A___, A___, A___}, RHEX, M______},
    {"init_module",             0, 0, PXXX, {ASTR, ASIZ, ASTR, A___, A___, A___}, R__0, M______},
    {"delete_module",           0, 0, PXXX, {ASTR, AHEX, A___, A___, A___, A___}, R__0, M______},
    {"get_kernel_syms",         0, 0, PXXX, {APTR, A___, A___, A___, A___, A___}, R__0, M______},
    {"query_module",            0, 0, PXXX, {ASTR, ADEC, APTR, ASIZ, ASZP, A___}, R__0, M__I_I_},
    {"quotactl",                0, 0, PXXX, {ADEC, ASTR, ADEC, APTR, A___, A___}, R__0, M______},
    {"nfsservctl",              0, 0, PXXX, {ADEC, APTR, APTR, A___, A___, A___}, R__0, M__I___},
    {"getpmsg",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"putpmsg",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"afs_syscall",             0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"tuxcall",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"security",                0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"gettid",                  0, 0, PTHR, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"readahead",               0, 0, P_FD, {A_FD, AOFF, ASIZ, A___, A___, A___}, R__0, M______},
    {"setxattr",                0, 0, PINF, {ASTR, ASTR, ABUF, ASIZ, AHEX, A___}, RSIZ, M______},
    {"lsetxattr",               0, 0, PINF, {ASTR, ASTR, ABUF, ASIZ, AHEX, A___}, RSIZ, M______},
    {"fsetxattr",               0, 0, PINF, {A_FD, ASTR, ABUF, ASIZ, AHEX, A___}, RSIZ, M______},
    {"getxattr",                0, 0, PINF, {ASTR, ASTR, ABUF, ASIZ, A___, A___}, RSIZ, M__I___},
    {"lgetxattr",               0, 0, PINF, {ASTR, ASTR, ABUF, ASIZ, A___, A___}, RSIZ, M______},
    {"fgetxattr",               0, 0, PINF, {A_FD, ASTR, ABUF, ASIZ, A___, A___}, RSIZ, M______},
    {"listxattr",               0, 0, PINF, {ASTR, ASTR, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"llistxattr",              0, 0, PINF, {ASTR, ASTR, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"flistxattr",              0, 0, PINF, {A_FD, ASTR, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"removexattr",             0, 0, PINF, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"lremovexattr",            0, 0, PINF, {ASTR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"fremovexattr",            0, 0, PINF, {A_FD, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"tkill",                   0, 0, PTHR, {ADEC, ASIG, A___, A___, A___, A___}, R__0, M______},
    {"time",                    0, 0, PINF, {A_IP, A___, A___, A___, A___, A___}, RDEC, MI_____},
    {"futex",                   0, 1, PTHR, {A_IP, AFUT, ADEC, A_TS, A_IP, AHEX}, RDEC, MI___I_},
    {"sched_setaffinity",       0, 0, PTHR, {ADEC, ASIZ, ACPU, A___, A___, A___}, RSIZ, M______},
    {"sched_getaffinity",       0, 0, PTHR, {ADEC, ASIZ, ACPU, A___, A___, A___}, RSIZ, M__I___},
    {"set_thread_area",         0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_setup",                0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_destroy",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_getevents",            0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_submit",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_cancel",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"get_thread_area",         0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"lookup_dcookie",          0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"epoll_create",            0, 0, P_FD, {ASIZ, A___, A___, A___, A___, A___}, R_FD, M______},
    {"epoll_ctl_old",           0, 0, P_FD, {A_FD, AEPC, A_FD, AEPE, A___, A___}, R__0, M______},
    {"epoll_wait_old",          0, 1, P_FD, {A_FD, AEPA, ADEC, ADEC, A___, A___}, RDEC, M_I____},
    {"remap_file_pages",        0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, RXXX, M______},
    {"getdents64",              0, 0, P_IO, {A_FD, AE64, ASIZ, A___, A___, A___}, RSIZ, M_I____},
    {"set_tid_address",         0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, RXXX, M______},
    {"restart_syscall",         0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, RXXX, M______},
    {"semtimedop",              0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fadvise64",               0, 0, P_FD, {A_FD, AOFF, AOFF, ADEC, A___, A___}, R__0, M______},
    {"timer_create",            0, 0, PINF, {ACLK, APTR, APTR, A___, A___, A___}, R__0, M______},
    {"timer_settime",           0, 0, PINF, {ADEC, AHEX, APTR, APTR, A___, A___}, R__0, M___I__},
    {"timer_gettime",           0, 0, PINF, {ADEC, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"timer_getoverrun",        0, 0, PINF, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"timer_delete",            0, 0, PINF, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"clock_settime",           0, 0, PINF, {ACLK, A_TS, A___, A___, A___, A___}, R__0, M______},
    {"clock_gettime",           0, 0, PINF, {ACLK, A_TS, A___, A___, A___, A___}, R__0, M_I____},
    {"clock_getres",            0, 0, PINF, {ACLK, A_TS, A___, A___, A___, A___}, R__0, M_I____},
    {"clock_nanosleep",         0, 1, PTHR, {ACLK, APTR, A_TS, A_TS, A___, A___}, RDEC, M___I__},
    {"exit_group",              0, 0, PROC, {ADEC, A___, A___, A___, A___, A___}, R__0, M______},
    {"epoll_wait",              0, 1, P_FD, {A_FD, AEPA, ADEC, ADEC, A___, A___}, RDEC, M_I____},
    {"epoll_ctl",               0, 0, P_FD, {A_FD, AEPC, A_FD, AEPE, A___, A___}, R__0, M______},
    {"tgkill",                  0, 0, PTHR, {ADEC, ADEC, ASIG, A___, A___, A___}, R__0, M______},
    {"utimes",                  0, 0, P_FD, {ASTR, APTR, A___, A___, A___, A___}, R__0, M______},
    {"vserver",                 0, 0, PXXX, {ADDD, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mbind",                   0, 0, PXXX, {APTR, ASIZ, ADEC, APTR, ADEC, AHEX}, R__0, M______},
    {"set_mempolicy",           0, 0, PXXX, {ADEC, APTR, ASIZ, A___, A___, A___}, R__0, M______},
    {"get_mempolicy",           0, 0, PXXX, {APTR, APTR, ASIZ, APTR, AHEX, A___}, R__0, MII____},
    {"mq_open",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mq_unlink",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mq_timedsend",            0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mq_timedreceive",         0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mq_notify",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mq_getsetattr",           0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"kexec_load",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"waitid",                  0, 0, PROC, {ADEC, ADEC, APTR, AHEX, A___, A___}, R__0, M__I___},
    {"add_key",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"request_key",             0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"keyctl",                  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"ioprio_set",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"ioprio_get",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"inotify_init",            0, 0, P_FD, {A___, A___, A___, A___, A___, A___}, R_FD, M______},
    {"inotify_add_watch",       0, 0, P_FD, {A_FD, ASTR, AHEX, A___, A___, A___}, RDEC, M______},
    {"inotify_rm_watch",        0, 0, P_FD, {A_FD, ADEC, A___, A___, A___, A___}, R__0, M______},
    {"migrate_pages",           1, 0, PMEM, {ADEC, ASIZ, APTR, APTR, A___, A___}, RDEC, M______},
    {"openat",                  0, 0, P_FD, {ADIR, ASTR, AOPN, A___, A___, A___}, R_FD, M______},
    {"mkdirat",                 0, 0, P_FD, {ADIR, ASTR, AOCT, A___, A___, A___}, R__0, M______},
    {"mknodat",                 0, 0, P_FD, {ADIR, ASTR, AOCT, ADEC, A___, A___}, R__0, M______},
    {"fchownat",                0, 0, P_FD, {ADIR, A_FD, ADEC, ADEC, A___, A___}, R__0, M______},
    {"futimesat",               0, 0, P_FD, {ADIR, ASTR, APTR, A___, A___, A___}, R__0, M______},
    {"newfstatat",              0, 0, PINF, {ADIR, ASTR, ASTB, AHEX, A___, A___}, R__0, M__I___},
    {"unlinkat",                0, 0, P_FD, {ADIR, ASTR, A___, A___, A___, A___}, R__0, M______},
    {"renameat",                0, 0, P_FD, {ADIR, ASTR, ASTR, A___, A___, A___}, R__0, M_I____},
    {"linkat",                  0, 0, P_FD, {ADIR, ASTR, ASTR, A___, A___, A___}, R__0, M______},
    {"symlinkat",               0, 0, P_FD, {ADIR, ASTR, ASTR, A___, A___, A___}, R__0, M______},
    {"readlinkat",              0, 0, P_FD, {ADIR, ASTR, ABUF, ASIZ, A___, A___}, RSIZ, M__I___},
    {"fchmodat",                0, 0, P_FD, {ADIR, A_FD, AOCT, A___, A___, A___}, R__0, M______},
    {"faccessat",               0, 0, P_FD, {ADIR, ASTR, AOCT, A___, A___, A___}, R__0, M______},
    {"pselect6",                0, 1, POLL, {ADEC, ASET, ASET, ASET, A_TS, APTR}, RSIZ, M_IIII_},
    {"ppoll",                   0, 1, POLL, {APFD, ASIZ, A_TS, A_IP, A___, A___}, RSIZ, MI_____},
    {"unshare",                 0, 0, PXXX, {ACLN, A___, A___, A___, A___, A___}, R__0, M______},
    {"set_robust_list",         0, 0, PXXX, {APTR, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"get_robust_list",         0, 0, PXXX, {ADEC, APTR, APTR, A___, A___, A___}, R__0, M_II___},
    {"splice",                  0, 0, P_FD, {A_FD, APTR, A_FD, APTR, ASIZ, AHEX}, RSIZ, M_I_I__},
    {"tee",                     0, 0, P_FD, {A_FD, A_FD, ASIZ, AHEX, A___, A___}, RSIZ, M______},
    {"sync_file_range",         0, 0, P_FD, {A_FD, AOFF, AOFF, AHEX, A___, A___}, R__0, M______},
    {"vmsplice",                0, 0, PXXX, {A_FD, AIOV, ASIZ, AHEX, A___, A___}, RSIZ, M______},
    {"move_pages",              0, 0, PMEM, {ADEC, ASIZ, APTR, APTR, APTR, AHEX}, R__0, M__III_},
    {"utimensat",               0, 0, P_FD, {ADIR, ASTR, APTR, AHEX, A___, A___}, R__0, M______},
    {"epoll_pwait",             0, 1, POLL, {A_FD, AEPA, ADEC, ADEC, APTR, A___}, RDEC, M_I____},
    {"signalfd",                0, 0, P_FD, {A_FD, APTR, AHEX, A___, A___, A___}, R_FD, M______},
    {"timerfd_create",          0, 0, P_FD, {ACLK, AHEX, A___, A___, A___, A___}, R_FD, M______},
    {"eventfd",                 0, 0, P_FD, {ADEC, AHEX, A___, A___, A___, A___}, R_FD, M______},
    {"fallocate",               0, 0, P_FD, {A_FD, AOCT, AOFF, ASIZ, A___, A___}, R__0, M______},
    {"timerfd_settime",         0, 0, P_FD, {A_FD, AHEX, APTR, APTR, A___, A___}, R__0, M___I__},
    {"timerfd_gettime",         0, 0, P_FD, {A_FD, APTR, A___, A___, A___, A___}, R__0, M_I____},
    {"accept4",                 0, 1, P_FD, {A_FD, ADDP, A_IP, AHEX, A___, A___}, R_FD, M_II___},
    {"signalfd4",               0, 0, P_FD, {A_FD, APTR, AHEX, AHEX, A___, A___}, R_FD, M______},
    {"eventfd2",                0, 0, P_FD, {ADEC, AHEX, A___, A___, A___, A___}, R_FD, M______},
    {"epoll_create1",           0, 0, POLL, {AHEX, A___, A___, A___, A___, A___}, R_FD, M______},
    {"dup3",                    0, 0, P_FD, {A_FD, A_FD, AHEX, A___, A___, A___}, R_FD, M______},
    {"pipe2",                   0, 0, P_FD, {AFD2, AHEX, A___, A___, A___, A___}, R__0, MI_____},
    {"inotify_init1",           0, 0, P_FD, {AHEX, A___, A___, A___, A___, A___}, R_FD, M______},
    {"preadv",                  0, 1, P_IO, {A_FD, AIOV, ADEC, ADEC, ADEC, A___}, RSIZ, M_I____},
    {"pwritev",                 0, 0, P_IO, {A_FD, AIOV, ADEC, ADEC, ADEC, A___}, RSIZ, M______},
    {"rt_tgsigqueueinfo",       0, 0, PSIG, {ADEC, ADEC, ASIG, A_SI, A___, A___}, R__0, M___I__},
    {"perf_event_open",         0, 0, P_FD, {APTR, ADEC, ADEC, A_FD, AHEX, A___}, R_FD, M______},
    {"recvmmsg",                0, 1, P_IO, {A_FD, A_MM, ADEC, AHEX, A_TS, A___}, RSIZ, M_I____},
    {"fanotify_init",           0, 0, P_FD, {AHEX, AHEX, A___, A___, A___, A___}, R_FD, M______},
    {"fanotify_mark",           0, 0, P_FD, {A_FD, AHEX, AHEX, A_FD, ASTR, A___}, R__0, M______},
    {"prlimit64",               0, 0, PROC, {ADEC, ARES, ALIM, ALIM, A___, A___}, R__0, M___I__},
    {"name_to_handle_at",       0, 0, P_FD, {ADIR, ASTR, APTR, APTR, AHEX, A___}, R__0, M__II__},
    {"open_by_handle_at",       0, 0, P_FD, {A_FD, APTR, AHEX, A___, A___, A___}, R_FD, M_I____},
    {"clock_adjtime",           0, 0, PXXX, {ACLK, APTR, A___, A___, A___, A___}, R__0, M______},
    {"syncfs",                  0, 0, P_FD, {A_FD, A___, A___, A___, A___, A___}, R__0, M______},
    {"sendmmsg",                0, 0, P_IO, {A_FD, A_MM, ADEC, AHEX, A___, A___}, RSIZ, M______},
    {"setns",                   0, 0, P_FD, {A_FD, ACLN, A___, A___, A___, A___}, R__0, M______},
    {"getcpu",                  0, 0, PXXX, {APTR, APTR, APTR, A___, A___, A___}, R__0, MIII___},
    {"process_vm_readv",        0, 0, PXXX, {ADEC, AIOV, ADEC, AIOV, ADEC, ADEC}, RSIZ, M______},
    {"process_vm_writev",       0, 0, PXXX, {ADEC, AIOV, ADEC, AIOV, ADEC, ADEC}, RSIZ, M______},
    {"kcmp",                    0, 0, PXXX, {ADEC, ADEC, ADEC, ADEC, A___, A___}, RDEC, M______},
    {"finit_module",            0, 0, PXXX, {A_FD, ASIZ, ASTR, A___, A___, A___}, R__0, M______},
    {"sched_setattr",           0, 0, PROC, {ADEC, APTR, AHEX, A___, A___, A___}, R__0, M______},
    {"sched_getattr",           0, 0, PROC, {ADEC, APTR, AHEX, A___, A___, A___}, R__0, M_I____},
    {"renameat2",               0, 0, P_FD, {ADIR, ASTR, ADIR, ASTR, A___, A___}, R__0, M______},
    {"seccomp",                 0, 0, PXXX, {ADEC, AHEX, APTR, A___, A___, A___}, RDEC, M______},
    {"getrandom",               0, 1, PXXX, {ABUF, ASIZ, AHEX, A___, A___, A___}, RSIZ, MI_____},
    {"memfd_create",            0, 0, P_FD, {ASTR, AHEX, A___, A___, A___, A___}, R_FD, M______},
    {"kexec_file_load",         0, 0, PXXX, {A_FD, A_FD, ASIZ, ASTR, AHEX, A___}, R__0, M______},
    {"bpf",                     0, 0, PXXX, {ADEC, APTR, ASIZ, A___, A___, A___}, R_FD, M______},
    {"execveat",                0, 0, PROC, {ADIR, ASTR, ADDD, A___, A___, A___}, R__0, M______},
    {"userfaultfd",             0, 0, PXXX, {AHEX, A___, A___, A___, A___, A___}, R_FD, M______},
    {"membarrier",              1, 0, PMEM, {ADEC, AHEX, A___, A___, A___, A___}, R__0, M______},
    {"mlock2",                  1, 0, PMEM, {APTR, ASIZ, AHEX, A___, A___, A___}, R__0, M______},
    {"copy_file_range",         0, 0, P_IO, {A_FD, APTR, A_FD, APTR, ASIZ, AHEX}, RSIZ, M_I_I__},
    {"preadv",                  0, 1, P_IO, {A_FD, AIOV, ADEC, ADEC, ADEC, AHEX}, RSIZ, M_I____},
    {"pwritev",                 0, 0, P_IO, {A_FD, AIOV, ADEC, ADEC, ADEC, AHEX}, RSIZ, M______},
    {"pkey_mprotect",           1, 0, PMEM, {APTR, ASIZ, APRO, ADEC, A___, A___}, R__0, M______},
    {"pkey_alloc",              1, 0, PMEM, {ADEC, AHEX, A___, A___, A___, A___}, RDEC, M______},
    {"pkey_free",               1, 0, PMEM, {ADEC, A___, A___, A___, A___, A___}, RDEC, M______},
    {"statx",                   0, 0, PINF, {ADIR, ASTR, AHEX, AHEX, ASTX, A___}, R__0, M____I_},
    {"io_pgetevents",           0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"rseq",                    0, 0, PMEM, {APTR, ADEC, AHEX, AHEX, A___, A___}, R__0, M______},

    // Pseudo syscalls:
    {"rdtsc",                   0, 0, PINF, {A___, A___, A___, A___, A___, A___}, RDEC, M______},
    {"start",                   0, 0, PINF, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"<unused>",                0, 0, PXXX, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"setcontext",              0, 0, PINF, {ACTX, ASIZ, A___, A___, A___, A___}, R__0, M______},
    {"signal",                  0, 0, PSIG, {ASIG, A_SI, A___, A___, A___, A___}, R__0, M_I____},
    {"enable",                  0, 0, PINF, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    {"disable",                 0, 0, PINF, {A___, A___, A___, A___, A___, A___}, R__0, M______},
    
    // Padding to "common" syscalls1, :
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"<unused>",                0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},

    // "Common" syscall:
    {"pidfd_send_signal",       0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_uring_setup",          0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_uring_enter",          0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"io_uring_register",       0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"open_tree",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"move_mount",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fsopen",                  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fsconfig",                0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fsmount",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fspick",                  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"pidfd_open",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"clone3",                  0, 1, PTHR, {AC3A, ASIZ, A___, A___, A___, A___}, RDEC, M______},
    {"close_range",             0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"openat2",                 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"pidfd_getfd",             0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"faccessat2",              0, 0, P_FD, {ADIR, ASTR, AOCT, AHEX, A___, A___}, R__0, M______},
    {"process_madvise",         0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"epoll_pwait2",            0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"mount_setattr",           0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"quotactl_fd",             0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"landlock_create_ruleset", 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"landlock_add_rule",       0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"landlock_restrict_self",  0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"memfd_secret",            0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"process_mrelease",        0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"futex_waitv",             0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"set_mempolicy_home_node", 0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"cachestat",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"fchmodat2",               0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"map_shadow_stack",        0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"futex_wake",              0, 0, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"futex_wait",              0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
    {"futex_requeue",           0, 1, PXXX, {ANYI, A___, A___, A___, A___, A___}, RXXX, M______},
};

/*
 * Extra types.
 */
#define UTS_LEN 64
struct utsname
{
    char sysname[UTS_LEN + 1];
    char nodename[UTS_LEN + 1];
    char release[UTS_LEN + 1];
    char version[UTS_LEN + 1];
    char machine[UTS_LEN + 1];
    char domainname[UTS_LEN + 1];
};
struct sysinfo
{
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    char _f[20-2*sizeof(uint64_t)-sizeof(uint32_t)];
};
struct statfs
{
    uint32_t f_type;
    uint32_t f_bsize;
    uint32_t f_blocks;
    uint32_t f_bfree;
    uint32_t f_bavail;
    uint32_t f_files;
    uint32_t f_ffree;
    struct { int val[2]; } f_fsid;
    uint32_t f_namelen;
    uint32_t f_frsize;
    uint32_t f_flags;
    uint32_t f_spare[4];
};
struct statx_timestamp
{
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};
struct statx
{
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime; 
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime; 
    uint32_t stx_rdev_major; 
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t __spare2;
    uint64_t __spare3[12];
};
struct epoll_event
{
    uint32_t events;
    uint64_t data;
} PACKED;
struct mmsghdr
{
    struct msghdr msg_hdr;
    unsigned msg_len;
};
typedef struct sigaltstack
{
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

/*
 * Get syscall info.
 */
static const INFO *syscall_info(int callno)
{
    if ((size_t)callno >= sizeof(TABLE) / sizeof(TABLE[0]))
        return NULL;
    return TABLE + callno;
}

/*
 * Get syscall name.
 */
static const char *syscall_name(int callno)
{
    const INFO *info = syscall_info(callno);
    return (info == NULL? "???": info->name);
}

static const char *arg_name(uint8_t arg)
{
    switch (arg)
    {
        case ACTX: return "CONTEXT";
        case ANAM: return "NAME";
        case APTH: return "PATH";
        case APRT: return "PORT";
        case AEND: return "END";
        case A___: return "unused";
        case A_FD: return "file descriptor";
        case ABUF: return "buffer";
        case ASIZ: return "size";
        case ASTR: return "string";
        case AOPN: return "open flags";
        case ASTB: return "struct stat *";
        case APFD: return "struct pollfd *";
        case ADEC: return "decimal integer";
        case AOCT: return "octal integer";
        case AHEX: return "hexadecimal integer";
        case AOFF: return "offset";
        case ASEK: return "whence";
        case ARWX: return "prot flags";
        case AMAP: return "mmap flags";
        case ASIG: return "signal";
        case AIOV: return "struct iovec *";
        case ASET: return "fd_set *";
        case A_TV: return "struct timeval *";
        case A_TS: return "struct timespec *";
        case AFD2: return "int[2]";
        case ADOM: return "socket domain";
        case ATYP: return "socket type";
        case APRO: return "socket protocol";
        case ADDR: return "struct sockaddr * / socklen_t";
        case ADDP: return "struct sockaddr * / socklen_t *";
        case ASZP: return "socklen_t *";
        case AMSG: return "struct msghdr *";
        case AHOW: return "shutdown how";
        case ABFP: return "buffer / size_t *";
        case ACLN: return "clone flags";
        case A_IP: return "int *";
        case AFUT: return "futex operation";
        case ACLK: return "clockid_t";
        case APTR: return "pointer";
        case ADIR: return "directory fd";
        case AUNM: return "struct utsname *";
        case AENT: return "struct dirent *";
        case AE64: return "struct dirent64 *";
        case AIOC: return "ioctl command";
        case AIOA: return "ioctl arg";
        case ASYS: return "struct sysinfo *";
        case A_SA: return "struct sigaction *";
        case ASFS: return "struct statfs *";
        case AFCC: return "fcntl command";
        case AFCA: return "fcntl arg";
        case ARES: return "resource";
        case ALIM: return "struct rlimit *";
        case AWHO: return "rusage who";
        case AUSE: return "struct rusage *";
        case ASTX: return "struct statx *";
        case AC3A: return "struct clone_args *";
        case A_SI: return "siginfo_t *";
        case AEPE: return "struct epoll_event *";
        case AEPA: return "struct epoll_event *";
        case AEPC: return "epoll control";
        case A_MM: return "struct mmsghdr *";
        case A_IA: return "int[]";
        case ACPU: return "unsigned long *";
        case ASTK: return "stack_t *";
        case APRC: return "prctl option";
        case APRA: return "prctl arg";
        default: return "<unknown>";
    }
}

/*
 * Return 'true' if the argument is a pointer.
 */
static bool arg_is_pointer(uint8_t arg)
{
    switch (arg)
    {
        case APTR: case ABUF: case ASTR: case ASTB: case AIOV: case ASET:
        case A_TV: case A_TS: case ADDR: case ADDP: case A_IP: case ASZP:
        case AMSG: case ABFP: case AUNM: case AENT: case AE64: case ASYS:
        case A_SA: case ASFS: case ALIM: case AUSE: case ASTX: case AC3A:
        case A_SI: case AEPE: case AEPA: case A_MM: case A_IA: case A_SS:
        case ACPU: case ASTK:
            return true;
        default:
            return false;
    }
}

/*
 * Init a syscall from a state.
 */
static void syscall_init(SYSCALL *call, const STATE *state, bool replay)
{
    call->no       = state->rax;
    call->arg0.val = state->rdi;
    call->arg1.val = state->rsi;
    call->arg2.val = state->rdx;
    call->arg3.val = state->r10;
    call->arg4.val = state->r8;
    call->arg5.val = state->r9;
    call->replay   = replay;
}

/*
 * Execute a syscall.
 */
static intptr_t syscall(const SYSCALL *call)
{
    intptr_t r = syscall(call->no,
        call->arg0, call->arg1, call->arg2,
        call->arg3, call->arg4, call->arg5);
    if (r < 0)
        r = -(intptr_t)errno;
    return r;
}

/*
 * Control table management.
 */
struct CTL
{
    uint32_t val;           // Control code
    uint16_t size;          // Buffer size
    bool input;             // Is this an input?
    bool fail;              // Just fail this code?
    char name[32];          // Symbolic name
};
struct CTL_TABLE
{
    size_t size;
    CTL *ctl;
};

static int ctl_compare(const void *a, const void *b)
{
    const CTL *A = (CTL *)a, *B = (CTL *)b;
    if (A->val == B->val)
        return 0;
    return (A->val < B->val? -1: 1);
}
static void ctl_read(const char *filename, CTL_TABLE *table)
{
    int dfd = open(option_install, O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        error("failed to open directory \"%s\": %s", option_install,
            strerror(errno));
    int fd = syscall(SYS_openat, dfd, filename, O_RDONLY);
    FILE *stream = fdopen(fd, "r");
    if (stream == NULL)
    {
        warning("failed to open file \"%s\": %s", filename, strerror(errno));
        return;
    }
    close(dfd);
    char c;
    while ((c = getc(stream)) != '\n' && c != EOF)
        ;
    size_t i = 0;
    while (true)
    {
        char name[16] = {0}, io[5];
        int64_t val;
        uint16_t size;
        if (fscanf(stream, "%32s %lli %4s %hu", name, &val, io, &size) != 4)
            break;
        while (i >= table->size)
        {
            table->size = (table->size * 3) / 2 + 32;
            table->ctl   = (CTL *)xrealloc((void *)table->ctl,
                table->size * sizeof(CTL));
        }
        CTL *ctl   = table->ctl + i++;
        ctl->val   = (uint32_t)val;
        ctl->size  = size;
        ctl->fail  = (strcmp(io, "fail") == 0);
        ctl->input = (strcmp(io, "in") == 0);
        memcpy(ctl->name, name, sizeof(ctl->name));
    }
    fclose(stream);
    table->size = i;
    table->ctl  = (CTL *)xrealloc((void *)table->ctl,
        table->size * sizeof(CTL));
    qsort(table->ctl, table->size, sizeof(CTL), ctl_compare);
}
static const CTL *ctl_lookup(int val, CTL_TABLE *table)
{
    CTL key;
    key.val = (uint32_t)val;
    return (CTL *)bsearch(&key, table->ctl, table->size, sizeof(CTL),
        ctl_compare);
}

/*
 * Get info about an ioctl().
 */
static CTL_TABLE ioctl_table = {0};
typedef CTL IOCTL;
static const IOCTL *ioctl_info(int cmd)
{
    const IOCTL *ioctl = ctl_lookup(cmd, &ioctl_table);
    if (ioctl == NULL)
        error("ioctl() command %u (0x%x) is not found in \"%s\"", cmd, cmd,
            "ioctl.tab");
    return ioctl;
}

/*
 * Get info about an fcntl().
 */
static CTL_TABLE fcntl_table = {0};
typedef CTL FCNTL;
static const FCNTL *fcntl_info(int cmd)
{
    const FCNTL *fcntl = ctl_lookup(cmd, &fcntl_table);
    if (fcntl == NULL)
        error("fcntl() command %u (0x%x) is not found in \"%s\"", cmd, cmd,
            "fcntl.tab");
    return fcntl;
}

/*
 * Get info about a prctl().
 */
static CTL_TABLE prctl_table = {0};
typedef CTL PRCTL;
static const PRCTL *prctl_info(int cmd)
{
    const PRCTL *prctl = ctl_lookup(cmd, &prctl_table);
    if (prctl == NULL)
        error("prctl() command %u (0x%x) is not found in \"%s\"", cmd, cmd,
            "prctl.tab");
    return prctl;
}

/*
 * Init the ioctl/fcntl tables.
 */
static void ctl_init(void)
{
    ctl_read("ioctl.tab", &ioctl_table);
    ctl_read("fcntl.tab", &fcntl_table);
    ctl_read("prctl.tab", &prctl_table);
}

/*
 * Get syscall buffer.
 */
static uint8_t *syscall_buf(const SYSCALL *call, int i, size_t *size_ptr)
{
    const INFO *info = syscall_info(call->no);
    if (info == NULL)
        return NULL;
    uint8_t *buf = call->args[i].buf;
    if (buf == NULL)
        return NULL;
    size_t size = 0,
           prev = (i > 0? call->args[i-1].size: 0),
           next = (i < 5? call->args[i+1].size: 0);
    switch (info->args[i])
    {
        case ABUF: size = next; break;
        case ASTR: size = strlen((char *)buf)+1; break;
        case ASTB: size = sizeof(struct stat); break;
        case APFD: size = next * sizeof(struct pollfd); break;
        case ASET: size = sizeof(fd_set); break;
        case AIOV: size = next * sizeof(struct iovec); break;
        case A_TV: size = sizeof(struct timeval); break;
        case A_TS: size = sizeof(struct timespec); break;
        case AFD2: size = 2 * sizeof(int); break;
        case ADDR: size = next; break;
        case ADDP: if (i < 5 && call->args[i+1].buf != NULL)
                       size = *(socklen_t *)call->args[i+1].buf;
                   break;
        case A_IP: size = (buf != NULL? sizeof(int32_t): 0); break;
        case ASZP: size = (buf != NULL? sizeof(socklen_t): 0); break;
        case AMSG: size = sizeof(struct msghdr); break;
        case ABFP: if (i < 5 && call->args[i+1].buf != NULL)
                       size = *(socklen_t *)call->args[i+1].buf;
                   break;
        case AUNM: size = sizeof(struct utsname); break;
        case AENT: size = next; break;
        case AE64: size = next; break;
        case AIOA: size = ioctl_info((int)prev)->size; break;
        case ASYS: size = sizeof(struct sysinfo); break;
        case A_SA: size = sizeof(struct ksigaction); break;
        case ASFS: size = sizeof(struct statfs); break;
        case AFCA: size = fcntl_info((int)prev)->size; break;
        case ALIM: size = sizeof(struct rlimit); break;
        case AUSE: size = sizeof(struct rusage); break;
        case ASTX: size = sizeof(struct statx); break;
        case AC3A: size = MAX(sizeof(struct clone_args), next); break;
        case A_SI: size = sizeof(siginfo_t); break;
        case AEPE: size = sizeof(struct epoll_event); break;
        case AEPA: size = next * sizeof(struct epoll_event); break;
        case A_MM: size = sizeof(struct mmsghdr); break;
        case A_IA: size = prev * sizeof(int); break;
        case A_SS: size = sizeof(sigset_t); break;
        case ACPU: size = prev; break;
        case ASTK: size = sizeof(stack_t); break;
        case APRA: size = prctl_info((int)prev)->size; break;
        default: return NULL;
    }
    *size_ptr = size;
    return buf;
}

/*
 * Determine if a syscall arg is an input or output.
 */
static bool syscall_is_output(const SYSCALL *call, int i)
{
    const INFO *info = syscall_info(call->no);
    if (info == NULL)
        return true;
    uint8_t mask = (MI_____ << i);
    bool outbound = ((info->mask & mask) == 0);
    if (outbound)
        return true;
    size_t prev = (i > 0? call->args[i-1].size: 0);
    switch (call->no)
    {
        case SYS_ioctl:
            return !ioctl_info((int)prev)->input;
        case SYS_fcntl:
            return !fcntl_info((int)prev)->input;
        case SYS_prctl:
            return !prctl_info((int)prev)->input;
        case SYS_futex:
        {
            if (i != 4) return true;
            int op = call->arg2.i32 & 0xFF &
                ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
            return (op == FUTEX_WAKE_OP);
        }
        default:
            return false;
    }
}

/*
 * Determine the number of arguments for a syscall.
 */
static int syscall_arity(const SYSCALL *call)
{
    const INFO *info = syscall_info(call->no);
    if (info == NULL)
        return true;
    int op;
    switch (call->no)
    {
        case SYS_futex:
            op = call->arg1.i32 & 0xFF &
                ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
            switch (op)
            {
                case FUTEX_WAKE_OP: case FUTEX_CMP_REQUEUE:
                    return 6;
                case FUTEX_REQUEUE:
                    return 5;
                case FUTEX_WAIT: case FUTEX_WAIT_BITSET:
                    return 4;
                default:
                    return 3;
            }
        default:
            for (int i = 0; i < 6; i++)
            {
                if (info->args[i] == A___)
                    return i;
            }
            return 6;
    }
}

/*
 * Determine if the argument is used by the syscall.
 */
static bool syscall_used(const SYSCALL *call, int i)
{
    int op;
    switch (call->no)
    {
        case SYS_futex:
            op = call->arg1.i32 & 0xFF &
                ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
            switch (op)
            {
                case FUTEX_WAKE_OP:
                    return (i != 3);
                default:
                    return true;
            }
        default:
            return true;
    }
}

/*
 * Determine if the syscall should be locked (recording).
 */
static bool syscall_unlock(const SYSCALL *call)
{
    const INFO *info = syscall_info(call->no);
    if (info == NULL)
        return true;
    int op;
    switch (call->no)
    {
        case SYS_futex:
            op = call->arg1.i32 & 0xFF &
                ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
            switch (op)
            {
                // Some operations can complete & switch to another thread.
                // For the recording we want to stay on the same thread.
                case FUTEX_WAKE: case FUTEX_WAKE_OP: case FUTEX_WAKE_BITSET:
                case FUTEX_REQUEUE: case FUTEX_CMP_REQUEUE:
                    return false;
                default:
                    return true;
            }
        default:
            return info->block;
    }
}

/*
 * AUX helper functions.
 */
static const AUX *aux_find(const AUX *aux, size_t size, uint8_t mask,
    unsigned kind)
{
    if (mask == 0x0)
        return NULL;
    while (aux->kind != AEND)
    {
        if (aux->mask == mask && aux->kind == kind && size >= aux->size)
            return aux;
        aux = (const AUX *)((uint8_t *)aux + aux->size + sizeof(AUX));
    }
    return NULL;
}

static const uint8_t *aux_deserialize(const uint8_t *data, const uint8_t *end,
    struct msghdr *msg)
{
    const struct msghdr *MSG = (struct msghdr *)data;
    data = (uint8_t *)(MSG + 1);
    if (data > end) return NULL;
    const uint8_t *name = (uint8_t *)data;
    name = (MSG->msg_namelen == 0? NULL: name);
    data += MSG->msg_namelen;
    const uint8_t *ctl = (uint8_t *)data;
    ctl = (MSG->msg_controllen == 0? NULL: ctl);
    data += MSG->msg_controllen;
    if (data > end) return NULL;
    if (name == NULL || msg->msg_name == NULL ||
            msg->msg_namelen < MSG->msg_namelen)
        msg->msg_namelen = 0;
    else
    {
        memcpy(msg->msg_name, name, MSG->msg_namelen);
        msg->msg_namelen = MSG->msg_namelen;
    }
    if (ctl == NULL || msg->msg_control == NULL ||
            msg->msg_controllen < MSG->msg_controllen)
        msg->msg_controllen = 0;
    else
    {
        memcpy(msg->msg_control, ctl, MSG->msg_controllen);
        msg->msg_controllen = MSG->msg_controllen;
    }
    msg->msg_flags = MSG->msg_flags;
    return data;
}

static bool aux_get(const AUX *aux, uint8_t *buf, size_t size,
    uint8_t mask, unsigned kind)
{
    aux = aux_find(aux, size, mask, kind);
    if (aux == NULL) return false;
    memcpy(buf, aux->data, aux->size);
    return true;
}
static bool aux_get(const AUX *aux, char *str, size_t size, uint8_t mask,
    unsigned kind)
{
    size = aux_get(aux, (uint8_t *)str, size, mask, kind);
    return (size != 0 && str[size-1] == '\0');
}
static bool aux_get(const AUX *aux, struct msghdr *msg, uint8_t mask,
    unsigned kind)
{
    aux = aux_find(aux, SIZE_MAX, mask, kind);
    if (aux == NULL) return false;
    return (aux_deserialize(aux->data, aux->data + aux->size, msg) != NULL);
}
static const uint8_t *aux_data(const AUX *aux, uint8_t mask, unsigned kind)
{
    aux = aux_find(aux, SIZE_MAX, mask, kind);
    if (aux == NULL) return NULL;
    return aux->data;
}
static const char *aux_str(const AUX *aux, uint8_t mask, unsigned kind)
{
    return (const char *)aux_data(aux, mask, kind);
}
static int aux_int(const AUX *aux, uint8_t mask, unsigned kind)
{
    int r;
    if (!aux_get(aux, (uint8_t *)&r, sizeof(r), mask, kind)) return -1;
    return r;
}

static bool aux_check(const AUX *aux, const uint8_t *buf, size_t size,
    uint8_t mask, unsigned kind)
{
    aux = aux_find(aux, SIZE_MAX, mask, kind);
    if (aux == NULL) return (buf == NULL);
    if (buf == NULL) return false;
    if (aux->size < size) return false;
    return (memcmp(buf, aux->data, size) == 0);
}
static bool aux_check(const AUX *aux, const char *str, uint8_t mask,
    unsigned kind)
{
    aux = aux_find(aux, SIZE_MAX, mask, kind);
    if (aux == NULL) return (str == NULL);
    if (str == NULL) return false;
    size_t size = strlen(str)+1;
    if (aux->size != size) return false;
    return (strcmp(str, (const char *)aux->data) == 0);
}

