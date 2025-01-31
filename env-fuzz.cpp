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

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <elf.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "rrfuzz.h"

#define VERSION                 0.1-alpha

#define STRING(s)               STRING_2(s)
#define STRING_2(s)             #s

#define PACKED                  __attribute__((__packed__))

#define RED                     (option_tty? "\33[31m": "")
#define GREEN                   (option_tty? "\33[32m": "")
#define YELLOW                  (option_tty? "\33[33m": "")
#define OFF                     (option_tty? "\33[0m" : "")

static bool option_tty = false;

/*
 * PCAP
 */
struct pcap_s                   // PCAP file header
{
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snaplen;
    uint32_t linktype:28;
    uint32_t f:1;
    uint32_t fcs:3;
};
#define PCAP_MAGIC      0xA1B2C3D4
#define LINKTYPE        1       // LINKTYPE_ETHERNET
struct AUX                      // Syscall auxiliary data
{
    uint32_t size:24;           // Aux data size
    uint32_t kind:8;            // Aux data kind (A***)
    uint8_t mask;               // Aux arg mask
    uint8_t data[];             // Aux data
} PACKED;

/*
 * Report an error and exit.
 */
void __attribute__((noreturn)) error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s  : ",
        (option_tty? "\33[31m": ""),
        (option_tty? "\33[0m" : ""));
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
    exit(EXIT_FAILURE);
}

/*
 * Report a warning.
 */
void warning(const char *msg, ...)
{
    fprintf(stderr, "%swarning%s : ",
        (option_tty? "\33[33m": ""),
        (option_tty? "\33[0m" : ""));
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
}

/*
 * Parse an int.
 */
static int64_t parseInt(const char *name, const char *val, int64_t lb,
    int64_t ub)
{
    bool neg = (val[0] == '-');
    val += (neg? 1: 0);
    char *end = NULL;
    errno = 0;
    int64_t r = strtoull(val, &end, 0);
    r = (neg? -r: r);
    if (errno != 0 || end == NULL || *end != '\0' || r < lb || r > ub)
        error("failed to parse `--%s' option; expected integer within the "
            "range %zd..%zd; found \"%s\"", name, lb, ub, val);
    return r;
}

/*
 * Read information from the ELF file.
 */
static void parseELF(const char *filename, std::string &path,
    std::string &interpreter)
{
    // Step (1): Parse the PATH environment variable
    const char *pathval = getenv("PATH");
    switch (filename[0])
    {
        default:
            if (pathval != nullptr)
            {
                std::string pathstr = pathval;
                std::string::size_type start = 0, end = 0;
                bool found = false;
                while ((end = pathstr.find(':', start)) != std::string::npos)
                {
                    std::string candidate(pathstr, start, end - start);
                    if (candidate.size() == 0 || candidate.back() != '/')
                        candidate += '/';
                    candidate += filename;
                    struct stat buf;
                    if (stat(candidate.c_str(), &buf) == 0 &&
                            (buf.st_mode & S_IXUSR) != 0 &&
                            S_ISREG(buf.st_mode))
                    {
                        found = true;
                        path.swap(candidate);
                        break;
                    }
                    start = end + 1;
                }
                if (found)
                    break;
            }
            // Fallthrough
        case '/': case '.':
            path = filename;
            break;
    }
    filename = path.c_str();

    // Step (2): Parse the ELF file
    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", filename,
            strerror(errno));

    struct stat stat;
    if (fstat(fd, &stat) != 0)
        error("failed to get statistics for file \"%s\": %s", filename,
            strerror(errno));

    size_t size = (size_t)stat.st_size;
    void *ptr = mmap(NULL, size, MAP_SHARED | MAP_NORESERVE, PROT_READ, fd, 0);
    if (ptr == MAP_FAILED)
        error("failed to map file \"%s\" into memory: %s", filename,
            strerror(errno));
    close(fd);
    const uint8_t *data = (const uint8_t *)ptr;
    const uint8_t *end  = data + size;

    /*
     * Basic ELF file parsing.
     */
    if (size < sizeof(Elf64_Ehdr))
        error("failed to parse ELF EHDR from file \"%s\"; file is too small",
            filename);
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
            ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
            ehdr->e_ident[EI_MAG3] != ELFMAG3)
        error("failed to parse ELF file \"%s\"; invalid magic number (file not "
            "an ELF executable?)", filename);
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        error("failed to parse ELF file \"%s\"; file is not 64bit",
            filename);
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        error("failed to parse ELF file \"%s\"; file is not little endian",
            filename);
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
        error("failed to parse ELF file \"%s\"; invalid version",
            filename);
    if (ehdr->e_machine != EM_X86_64)
        error("failed to parse ELF file \"%s\"; file is not x86_64",
            filename);
    if (ehdr->e_phoff < sizeof(Elf64_Ehdr) || ehdr->e_phoff >= size)
        error("failed to parse ELF file \"%s\"; invalid program header "
            "offset", filename);
    if (ehdr->e_phnum > PN_XNUM)
        error("failed to parse ELF file \"%s\"; too many program headers",
            filename);
    if (ehdr->e_phoff < sizeof(Elf64_Ehdr) ||
        ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size)
        error("failed to parse ELF file \"%s\"; invalid program headers",
            filename);

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    size_t phnum = (size_t)ehdr->e_phnum;
    bool found = false;
    for (size_t i = 0; !found && i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        switch (phdr->p_type)
        {
            case PT_INTERP:
            {
                const char *interp = (char *)(data + phdr->p_offset);
                if (interp + phdr->p_memsz > (char *)end ||
                        strlen(interp) != phdr->p_memsz-1)
                    error("failed to parse ELF file \"%s\"; invalid "
                        "interpreter", filename);
                interpreter = interp;
                found = true;
                break;
            }
            default:
                break;
        }
    }
    if (!found)
        error("failed to parse ELF file \"%s\"; not dynamically linked",
            filename);
    (void)munmap(ptr, size);
}

/*
 * Open a .pcap.gz file.
 */
static void dup(int oldfd, int newfd)
{
    if (dup2(oldfd, newfd) < 0)
        error("failed to dup file descriptor %d to %d: %s",
            oldfd, newfd, strerror(errno));
}
static int openPCAPFile(const char *filename, char mode)
{
    int fd = -1;
    switch (mode)
    {
        case 'r':
            fd = open(filename, O_RDONLY);
            break;
        case 'w':
            fd = open(filename, O_WRONLY | O_CREAT, 0644);
            break;
        default:
            assert(mode == 'r' || mode == 'w');
    }
    if (fd < 0)
        error("failed to open file \"%s\" for %s: %s",
            filename, (mode == 'r'? "reading": "writing"), strerror(errno));

    int fds[2];
    if (pipe(fds) < 0)
        error("failed to create pipe: %s", strerror(errno));
    pid_t child = fork();
    if (child < 0)
        error("failed to fork process: %s", strerror(errno));
    if (child == 0)
    {
        signal(SIGINT, SIG_IGN);
        switch (mode)
        {
            case 'r':
                close(fds[0]);
                dup(fd, STDIN_FILENO);
                close(fd);
                dup(fds[1], STDOUT_FILENO);
                close(fds[1]);
                execlp("gzip", "gzip", "-d", "--stdout", nullptr);
                break;
            case 'w':
                close(fds[1]);
                dup(fd, STDOUT_FILENO);
                close(fd);
                dup(fds[0], STDIN_FILENO);
                close(fds[0]);
                execlp("gzip", "gzip", "--stdout", nullptr);
                break;
        }
        error("failed to execute `gzip' command: %s", strerror(errno));
    }
    close(fd);
    switch (mode)
    {
        case 'r':
            close(fds[1]);
            return fds[0];
        case 'w':
            close(fds[0]);
            return fds[1];
        default:
            abort();
    }
}

/*
 * Setup the output directory.
 */
static int lockDir(const std::string &outname)
{
    std::string lockname(outname);
    lockname += "/LOCK";
    int fd = open(lockname.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0 && errno == ENOENT)
        return -1;
    if (fd < 0 || lockf(fd, F_TLOCK, 0) < 0)
        error("failed to lock directory \"%s\" (already in use?)",
            outname.c_str());
    return fd;
}
static int removeCallback(const char *path, const struct stat *sb,
    int type, struct FTW *ftwbuf)
{
    if (remove(path) < 0)
        error("failed to delete \"%s\": %s", path, strerror(errno));
    return 0;
}
static void rmDir(const std::string &outname, const char *name)
{
    std::string dirname(outname);
    dirname += '/';
    dirname += name;
    if (nftw(dirname.c_str(), removeCallback, 16,
            FTW_DEPTH | FTW_PHYS | FTW_MOUNT) < 0 && errno != ENOENT)
        error("failed to delete \"%s\": %s", dirname.c_str(), strerror(errno));
}
static void makeDir(const std::string &outname, const char *name)
{
    std::string dirname(outname);
    dirname += '/';
    dirname += name;
    if (mkdir(dirname.c_str(), 0777) < 0 && errno != EEXIST)
        error("failed to make directory \"%s\": %s", dirname.c_str(),
            strerror(errno));
}
static void setupRecordDir(const std::string &outname)
{
    int fd = lockDir(outname);
    if (fd > 0)
    {
        std::string bakname(outname);
        bakname += ".bak";

        // Delete old backup directory:
        std::string currdir(".");
        rmDir(currdir, bakname.c_str());

        // Move old output directory:
        if (rename(outname.c_str(), bakname.c_str()) && errno != ENOENT)
            error("failed to rename \"%s\": %s", outname.c_str(),
                strerror(errno));
        close(fd);
    }

    // Make new output directory:
    makeDir(outname, "");
    (void)lockDir(outname);
}
static void resetRecordDir(const std::string &outname)
{
    (void)lockDir(outname);
    rmDir(outname, "crash");
    rmDir(outname, "hang");
    rmDir(outname, "abort");
    rmDir(outname, "queue");
    exit(EXIT_SUCCESS);
}
static void setupFuzzDir(const std::string &outname)
{
    (void)lockDir(outname);
    // Create fuzzer sub-directories:
    makeDir(outname, "crash");
    makeDir(outname, "hang");
    makeDir(outname, "abort");
    makeDir(outname, "queue");
}
static void realPath(std::string &filename)
{
    const char *path = realpath(filename.c_str(), nullptr);
    if (path == nullptr)
    {
        if (errno == ENOENT)
            return;
        error("failed to resolve path \"%s\": %s", filename.c_str(),
            strerror(errno));
    }
    filename = path;
    free((void *)path);
}

/*
 * Get the CONTEXT structure.
 */
static const CONTEXT *getContext(const std::string &pcapname)
{
    // Read the CONTEXT from the PCAP file:
    const char *filename = pcapname.c_str();
    int fd = openPCAPFile(filename, 'r');
    FILE *stream = fdopen(fd, "r");
    if (stream == NULL)
        error("failed to open file \"%s\" for reading: %s",
            filename, strerror(errno));
    struct pcap_s pcap;
    if (fread(&pcap, sizeof(pcap), 1, stream) != 1)
        error("failed to read PCAP header from \"%s\": %s",
            filename, strerror(errno));
    if (pcap.magic != PCAP_MAGIC ||
            pcap.major != 2 || pcap.minor != 4 ||
            pcap.snaplen != INT32_MAX ||
            pcap.linktype != LINKTYPE)
        error("failed to parse PCAP header from \"%s\"", filename);

    // Read the CONTEXT struct directly from the file.  This assumes:
    // (1) The SYS_setcontext message is in the 4th packet.
    // (2) The first 3 packets are TCP control (SYN/SYNACK/ACK).
    // (3) The envp AUX data is a fixed offset within the 4th packet.
    // This is very ugly, but parsing the PCAP file "properly" would
    // take a lot of code so it is not worth it.
    off_t offset = 4 * (/*sizeof(packet_s)=*/16 +
                        /*sizeof(ethhdr)=*/14 +
                        /*sizeof(ip6_hdr)=*/40 +
                        /*sizeof(tcphdr)=*/20 +
                        /*sizeof(fcs)=*/4) +
                        /*sizeof(SYSCALL)=*/64 - /*sizeof(fcs)=*/4;
    uint8_t tmp[offset];
    if (fread(tmp, sizeof(uint8_t), sizeof(tmp), stream) != sizeof(tmp))
        error("failed to seek to CONTEXT AUX data: %s", strerror(errno));
    AUX aux;
    if (fread(&aux, sizeof(aux), 1, stream) != 1)
        error("failed to head CONTEXT AUX data: %s", strerror(errno));
    if (aux.kind != ACTX || aux.mask != /*MI_____=*/0x1 ||
            aux.size == 0 || aux.size > /*AUX_MAX=*/0xFFFFFF)
        error("failed to parse CONTEXT AUX data");
    if (aux.size < sizeof(CONTEXT))
        error("failed to parse CONTEXT data; size too small");
    char *buf = new char[aux.size];
    if (fread(buf, sizeof(char), aux.size, stream) != aux.size)
        error("failed to read CONTEXT data: %s", strerror(errno));
    fclose(stream);
    const CONTEXT *ctx = (CONTEXT *)buf;
    if (aux.size != sizeof(CONTEXT) + ctx->size || buf[aux.size-1] != '\0')
        error("failed to parse CONTEXT data");

    return (CONTEXT *)buf;
}

/*
 * Set the CPU number.
 */
static bool lockCPU(int cpu, bool lock)
{
    if (!lock)
        return true;
    std::string lockstr("/tmp/env-fuzz.CPU_");
    lockstr += std::to_string(cpu);
    const char *lockname = lockstr.c_str();
    int fd = open(lockname, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0)
        return false;
    if (lockf(fd, F_TLOCK, 0) < 0)
    {
        close(fd);
        return false;
    }
    // fd is kept open & locked, and only closed on termination.

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(getpid(), sizeof(set), &set) < 0)
        error("failed to set CPU %u affinity: %s", cpu, strerror(errno));
    return true;
}
static uint16_t getCPU(const CONTEXT *ctx, int cpu, bool lock)
{
    cpu = (ctx != nullptr? ctx->cpu: cpu);
    if (cpu >= 0)
    {
        if (!lockCPU(cpu, lock))
            error("failed to acquire lock for CPU #%d "
                "(already in use?)", cpu);
    }
    else
    {
        // Find a free CPU:
        int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        ncpu = std::min(UINT16_MAX, ncpu);
        for (int i = 0; i < ncpu; i++)
        {
            if (lockCPU(i, lock))
            {
                cpu = i;
                break;
            }
        }
        if (cpu < 0)
            error("failed to acquire lock for any CPU");
    }
    return (uint16_t)cpu;
}

/*
 * Get the command-line and environment variables.
 */
static void getEnv(const CONTEXT *ctx, int optind, char ***argvp,
    int *argcp, char ***envpp, std::vector<char *> &args,
    std::vector<char *> &envs)
{
    if (ctx != nullptr)
    {
        char *ptr = (char *)ctx->args;
        char *end = ptr + ctx->size;
        for (unsigned i = 0; i < ctx->argc; i++)
        {
            if (ptr >= end)
                error("failed to parse CONTEXT data");
            args.push_back(ptr);
            ptr += strlen(ptr) + 1;
        }
        for (unsigned i = 0; i < ctx->envl; i++)
        {
            if (ptr >= end)
                error("failed to parse CONTEXT data");
            envs.push_back(ptr);
            ptr += strlen(ptr) + 1;
        }
    }
    else
    {
        char **argv = *argvp, **envp = *envpp;
        for (int i = optind; argv[i] != nullptr; i++)
            args.push_back(argv[i]);
        for (int i = 0; envp[i] != nullptr; i++)
            envs.push_back(envp[i]);
    }
    args.push_back(nullptr);
    envs.push_back(nullptr);
    args.shrink_to_fit();
    envs.shrink_to_fit();
    *argvp = args.data();
    *argcp = (int)args.size()-1;
    *envpp = envs.data();
}
static void setEnv(char **envp, const std::string &preloads)
{
    if (clearenv() != 0)
        error("failed to clear the environment");
    for (size_t i = 0; envp[i] != nullptr; i++)
    {
        if (putenv(envp[i]) != 0)
            error("failed to set environment \"%s\": %s",
                envp[i], strerror(errno));
    }
    if (preloads != "")
    {
        std::string ld_preload("LD_PRELOAD=");
        ld_preload += preloads;
        char *str = strdup(ld_preload.c_str());
        if (str == nullptr || putenv(str) != 0)
            error("failed to set environment \"%s\": %s",
                ld_preload.c_str(), strerror(errno));
    }
}

/*
 * Check if a string is a library or not.
 */
static bool isLibrary(const char *binname, const char **basename)
{
    const char *str = binname, *ss = NULL;
    while ((ss = strchr(str, '/')) != NULL)
        str = ss+1;
    *basename = str;
    if (strncmp(str, "lib", 3) != 0)
        return false;
    while (*str != '\0' && strncmp(str, ".so", 3) != 0)
        str++;
    if (*str == '\0')
        return false;
    str += 3;
    while (*str != '\0')
    {
        if (*str != '.')
            return false;
        str++;
        if (!isdigit(*str++))
            return false;
        while (isdigit(*str))
            str++;
    }
    return true;
}

/*
 * Instrument the given binary.
 */
static void instrument(const char *binname)
{
    if (binname[0] == '\0')
        return;
    const char *basename = nullptr;
    bool lib = isLibrary(binname, &basename);
    std::string outname;
    if (lib)
    {
        outname += "./lib/";
        outname += basename;
    }
    else
    {
        outname += "./";
        outname += basename;
        outname += ".rr";
    }

    printf("%sINSTRUMENT%s: %s --> %s\n", YELLOW, OFF, binname,
        outname.c_str());
    pid_t child = fork();
    if (child < 0)
        error("failed to fork process: %s", strerror(errno));
    if (child == 0)
    {
        std::vector<const char *> args;
        execlp("./e9tool", "./e9tool",
            "-M",
            "plugin(rrCovPlugin).match()",
            "-P",
            "plugin(rrCovPlugin).patch()",
            "--option",
            "--log=false",
            "--shared",
            "-o",
            outname.c_str(),
            binname,
            nullptr);
        error("failed to execute e9tool: %s", strerror(errno));
    }

    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, 0)) >= 0 && errno != ECHILD)
    {
        if (pid < 0)
            error("failed to wait for child process: %s", strerror(errno));
    }
}

/*
 * Usage message.
 */
static void usage(const char *progname)
{
    printf("usage: %s record [OPTIONS] -- PROGRAM [ARGS ...]\n", progname);
    printf("     : %s replay [OPTIONS] [PATCH ...]\n", progname);
    printf("     : %s fuzz [OPTIONS]\n", progname);
    printf("     : %s reset [OPTIONS]\n", progname);
    printf("     : %s instrument BINARY [BINARY ...]\n", progname);
    fputs(
        "\n"
        "COMMAND:\n"
        "\trecord\n"
        "\t\tRecord program\n"
        "\treplay\n"
        "\t\tReplay recorded program\n"
        "\tfuzz\n"
        "\t\tFuzz recorded program\n"
        "\treset\n"
        "\t\tReset the fuzzer state\n"
        "\n"
        "OPTIONS:\n"
        "\t--blackbox\n"
        "\t\tUse \"blackbox\" mode (no feedback)\n"
        "\t--cpu CPU\n"
        "\t\tUse CPU number\n"
        "\t--debug, -d\n"
        "\t\tReplay inside GDB (debugger)\n"
        "\t--depth DEPTH\n"
        "\t\tSet the fuzz DEPTH (in messages)\n"
        "\t--dir DIR\n"
        "\t\tRun the program in DIR\n"
        "\t--emulate LEVEL, -e LEVEL\n"
        "\t\tSet the fuzzer emulation LEVEL.\n"
        "\t--fork MODE\n"
        "\t\tSet the fork MODE to {parent,child,fail}.\n"
        "\t--hex\n"
        "\t\tLog output as hexadecimal\n"
        "\t--log LEVEL\n"
        "\t\tSet the log LEVEL\n"
        "\t--max-execs MAX\n"
        "\t\tLimit fuzz campaign to MAX executions.\n"
        "\t--max-time MAX\n"
        "\t\tLimit fuzz campaign to MAX seconds.\n"
        "\t--out DIR, -o DIR\n"
        "\t\tSet the output directory to be DIR\n"
        "\t--pcap FILE\n"
        "\t\tSave (record) or load (replay) to FILE\n"
        "\t--preload LIBRARY\n"
        "\t\tPreload LIBRARY using LD_PRELOAD\n"
        "\t--save\n"
        "\t\tNever delete \"interesting\" patches\n"
        "\t--seed SEED\n"
        "\t\tSet SEED to be the random seed (0=random seed)\n"
        "\t--timeout TIMEOUT\n"
        "\t\tSet the fuzz TIMEOUT (in milliseconds)\n"
        "\t--tty\n"
        "\t\tForce terminal mode (shows colors)\n"
        "\t--help, -h\n"
        "\t\tPrint help and exit\n"
        "\t--version, -v\n"
        "\t\tPrint version and exit\n\n", stdout);
}

/*
 * Main.
 */
enum OPTION
{
    OPTION_BLACKBOX,
    OPTION_COUNT,
    OPTION_CPU,
    OPTION_DEBUG,
    OPTION_DEPTH,
    OPTION_DIR,
    OPTION_EMULATE,
    OPTION_FORK,
    OPTION_FUZZ,
    OPTION_HEX,
    OPTION_LOG,
    OPTION_MAX_EXECS,
    OPTION_MAX_TIME,
    OPTION_OUT,
    OPTION_PCAP,
    OPTION_PRELOAD,
    OPTION_RECORD,
    OPTION_REPLAY,
    OPTION_SAVE,
    OPTION_SEED,
    OPTION_TIMEOUT,
    OPTION_TTY,
    OPTION_HELP,
    OPTION_VERSION
};
int main(int argc, char **argv, char **envp)
{
    option_tty = isatty(STDERR_FILENO);
    std::string option_dir("");
    std::string option_pcapname("RECORD.pcap.gz");
    std::string option_outname("./out");
    std::string option_preload("");
    bool option_debug = false, option_fuzz = false, option_hex = false,
         option_record = false, option_replay = false, option_reset = false,
         option_blackbox = false, option_save = false,
         option_instrument = false;
    int8_t option_log = 1;
    uint16_t option_depth = 50;
    int option_timeout = 50, option_cpu = -1, option_emulate = -1,
        option_fork = FORK_CHILD;
    int64_t option_seed = 0;
    uint64_t option_nonce[2];
    size_t option_max_execs = SIZE_MAX, option_max_time = SIZE_MAX;
    static const struct option long_options[] =
    {
        {"blackbox",  no_argument,       nullptr, OPTION_BLACKBOX},
        {"cpu",       required_argument, nullptr, OPTION_CPU},
        {"debug",     no_argument,       nullptr, OPTION_DEBUG},
        {"depth",     required_argument, nullptr, OPTION_DEPTH},
        {"dir",       required_argument, nullptr, OPTION_DIR},
        {"emulate",   required_argument, nullptr, OPTION_EMULATE},
        {"fork",      required_argument, nullptr, OPTION_FORK},
        {"hex",       no_argument,       nullptr, OPTION_HEX},
        {"log",       required_argument, nullptr, OPTION_LOG},
        {"out",       required_argument, nullptr, OPTION_OUT},
        {"max-execs", required_argument, nullptr, OPTION_MAX_EXECS},
        {"max-time",  required_argument, nullptr, OPTION_MAX_TIME},
        {"pcap",      required_argument, nullptr, OPTION_PCAP},
        {"preload",   required_argument, nullptr, OPTION_PRELOAD},
        {"save",      no_argument,       nullptr, OPTION_SAVE},
        {"seed",      required_argument, nullptr, OPTION_SEED},
        {"timeout",   required_argument, nullptr, OPTION_TIMEOUT},
        {"tty",       no_argument,       nullptr, OPTION_TTY},
        {"help",      no_argument,       nullptr, OPTION_HELP},
        {"version",   no_argument,       nullptr, OPTION_VERSION},
        {nullptr,     no_argument,       nullptr, 0},
    };
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "de:hm:p:v", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_BLACKBOX:
                option_blackbox = true; break;
            case OPTION_CPU:
                option_cpu = (int)parseInt(long_options[idx].name, optarg,
                    0, UINT16_MAX);
                break;
            case OPTION_DEBUG: case 'd':
                option_debug = true; break;
            case OPTION_DEPTH:
                option_depth = (uint16_t)parseInt(long_options[idx].name,
                    optarg, 0, UINT16_MAX);
                break;
            case OPTION_DIR:
                option_dir = optarg; break;
            case OPTION_EMULATE: case 'e':
                option_emulate = (int)parseInt(
                    (opt == 'e'? "-e": long_options[idx].name), optarg, 0, 2);
                break;
            case OPTION_FORK:
                option_fork = (strcmp(optarg, "parent") == 0? FORK_PARENT:
                               strcmp(optarg, "child")  == 0? FORK_CHILD:
                               strcmp(optarg, "fail")   == 0? FORK_FAIL: -1);
                if (option_fork < 0)
                    error("failed to parse fork-mode \"%s\"; expected one of "
                        "{parent,child,fail}", optarg);
                break;
            case OPTION_HEX:
                option_hex = true; break;
            case OPTION_LOG:
                option_log = (int8_t)parseInt(long_options[idx].name, optarg,
                    -1, 10);
                break;
            case OPTION_OUT: case 'o':
                option_outname = optarg; break;
            case OPTION_MAX_EXECS:
                option_max_execs = (size_t)parseInt(long_options[idx].name,
                    optarg, 1, INT64_MAX);
                break;
            case OPTION_MAX_TIME:
                option_max_time = (size_t)parseInt(long_options[idx].name,
                    optarg, 1, INT64_MAX);
                break;
            case OPTION_PCAP:
                option_pcapname = optarg; break;
            case OPTION_PRELOAD:
                if (option_preload != "")
                    option_preload += ':';
                option_preload += optarg;
                break;
            case OPTION_SAVE:
                option_save = true; break;
            case OPTION_SEED:
                option_seed = parseInt(long_options[idx].name, optarg,
                    INT64_MIN, INT64_MAX);
                break;
            case OPTION_TIMEOUT:
                option_timeout = (int)parseInt(long_options[idx].name,
                    optarg, 1, INT32_MAX);
                break;
            case OPTION_TTY:
                option_tty = true; break;
            case OPTION_HELP: case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case OPTION_VERSION: case 'v':
                puts("RRFuzz " STRING(VERSION));
                exit(EXIT_SUCCESS);
            default:
                error("failed to parse command-line arguments; try "
                    "`%s --help' for more information", argv[0]);
        }
    }

    if (argv[optind] == nullptr)
        error("missing command; try `%s --help' for more information", argv[0]);
    if (strcmp(argv[optind], "record") == 0)
        option_record = true;
    else if (strcmp(argv[optind], "replay") == 0)
        option_replay = true;
    else if (strcmp(argv[optind], "fuzz") == 0)
        option_fuzz = true;
    else if (strcmp(argv[optind], "reset") == 0)
        option_reset = true;
    else if (strcmp(argv[optind], "instrument") == 0)
        option_instrument = true;
    else
        error("unknown command `%s'; try `%s --help' for more "
            "information", argv[optind], argv[0]);
    optind++;
    if (!option_record && !option_replay && !option_instrument &&
            argv[optind] != nullptr)
        error("extraneous argument `%s'; try `%s --help' for more "
            "information", argv[optind], argv[0]);
    if (option_record && argv[optind] == nullptr)
        error("missing command for recording; try `%s --help' for more "
            "information", argv[0]);
    if (option_cpu > 0 && !option_record)
        error("`--cpu' can only be used in \"record\" mode");
    if (option_dir != "" && !option_record)
        error("`--dir' can only be used in \"record\" mode");
    if (option_preload != "" && !option_record)
        error("`--preload' can only be used in \"record\" mode");
    option_dir = (option_dir == ""? ".": option_dir);
    if (option_emulate >= 0 && !option_fuzz && !option_replay)
        error("`--emulate' can only be used in \"fuzz\" or \"replay\" modes");
    option_emulate = (option_emulate < 0? 2: option_emulate);

    // Create the tasks
    std::vector<const char *> tasks;
    bool option_patch = false;
    if (option_replay || option_instrument)
    {
        for (int i = optind; i < argc; i++)
            tasks.push_back(argv[i]);
        option_patch = (tasks.size() > 0);
    }
    if (tasks.size() == 0)
        tasks.push_back("");

    // Set-up the directory for recording
    if (option_reset)
        resetRecordDir(option_outname);
    if (option_record)
        setupRecordDir(option_outname);
    if (option_fuzz)
        setupFuzzDir(option_outname);
    realPath(option_outname);
    {
        std::string tmpname;
        tmpname = option_outname;
        tmpname += '/';
        tmpname += option_pcapname;
        option_pcapname.swap(tmpname);
    }
    std::string libname("./lib/"), installdir(".");
    realPath(libname);
    realPath(installdir);
    if (chdir(option_dir.c_str()) < 0)
        error("failed to change directory to \"%s\": %s",
            option_dir.c_str(), strerror(errno));

    // Get the CONTEXT (for replay)
    const CONTEXT *ctx = nullptr;
    if (option_replay || option_fuzz)
        ctx = getContext(option_pcapname);

    // Save (record) or restore (replay/fuzz) the command-line:
    const char *argv0 = argv[0];
    std::vector<char *> args, envs;
    if (option_record || option_replay || option_fuzz)
        getEnv(ctx, optind, &argv, &argc, &envp, args, envs);
    if (argv[0] == nullptr)
        error("missing program; try `%s --help' for more information", argv0);
    
    // Get the program path:
    std::string progname(argv[0]);
    realPath(progname);

    // Disable ASLR (for child):
    if (personality(ADDR_NO_RANDOMIZE) < 0)
        error("failed to disable ASLR: %s", strerror(errno));

    // Bind to a specific CPU:
    bool lock_cpu = (option_record || option_fuzz);
    if (option_record || option_replay || option_fuzz)
        option_cpu  = getCPU(ctx, option_cpu, lock_cpu);
    if (ctx != nullptr)
    {
        option_fork = ctx->fork;
        memcpy(option_nonce, ctx->nonce, sizeof(option_nonce));
    }
    else if (syscall(SYS_getrandom, option_nonce, sizeof(option_nonce), 0) <
            (ssize_t)sizeof(option_nonce))
        error("failed to generate random nonce: %s", strerror(errno));

    // Loop over the tasks
    for (const char *task: tasks)
    {
        if (option_instrument)
        {
            instrument(task);
            continue;
        }

        std::string option_patchname(task);

        // Open the pcap pipe:
        const char *filename = option_pcapname.c_str();
        int fd = openPCAPFile(filename, (option_record? 'w': 'r'));
        dup(fd, PCAP_FILENO);
        close(fd);

        // Send the configuration to the child:
        int fds[2];
        if (pipe2(fds, O_DIRECT) < 0)
            error("failed to create pipe: %s", strerror(errno));
        size_t size = sizeof(CONFIG)  +
            option_pcapname.size()+1  +
            option_patchname.size()+1 +
            option_outname.size()+1   +
            installdir.size()+1;
        uint8_t *buf = new uint8_t[size];
        CONFIG *config    = (CONFIG *)buf;
        memcpy(config->nonce, option_nonce, sizeof(config->nonce));
        config->debug     = option_debug;
        config->fuzz      = option_fuzz;
        config->hex       = option_hex;
        config->patch     = option_patch;
        config->record    = option_record;
        config->tty       = option_tty;
        config->blackbox  = option_blackbox;
        config->save      = option_save;
        config->log       = option_log;
        config->emulate   = option_emulate;
        config->depth     = option_depth;
        config->cpu       = option_cpu;
        config->max_execs = option_max_execs;
        config->max_time  = option_max_time;
        config->timeout   = option_timeout;
        config->seed      = option_seed;
        config->fork      = option_fork;
        size_t i = 0;
        memcpy(config->strs+i, option_pcapname.c_str(), option_pcapname.size()+1);
        i += option_pcapname.size()+1;
        memcpy(config->strs+i, option_patchname.c_str(), option_patchname.size()+1);
        i += option_patchname.size()+1;
        memcpy(config->strs+i, option_outname.c_str(), option_outname.size()+1);
        i += option_outname.size() + 1;
        memcpy(config->strs+i, installdir.c_str(), installdir.size()+1);
        i += installdir.size() + 1;
        assert(size == sizeof(CONFIG) + i);
        errno = 0;
        if (write(fds[1], buf, size) != (ssize_t)size)
            error("failed to write configuration to pipe: %s");
        delete buf;
        close(fds[1]);      // Config is "in flight", close write end
        dup(fds[0], CONFIG_FILENO);
        close(fds[0]);

        // Launch the program:
        pid_t child = fork();
        if (child < 0)
            error("failed to fork process: %s", strerror(errno));
        if (child == 0)
        {
            // Prepare debugger (if necessary):
            std::string path, interp;
            parseELF(argv[0], path, interp);
            if (option_debug)
            {
                child = fork();
                if (child < 0)
                    error("failed to fork process: %s", strerror(errno));
                while (child > 0)
                {
                    int status;
                    if (waitpid(child, &status, WUNTRACED) < 0)
                        error("failed to wait for child process %d: %s", child,
                            strerror(errno));
                    if (WIFEXITED(status) || WIFSIGNALED(status))
                        error("child process %d terminated unexpectedly",
                            child);
                    if (WIFSTOPPED(status))
                    {
                        // Child is ready; start GDB:
                        execlp("sudo", "sudo",
                            "gdb",
                            "-x",
                            "env-fuzz.gdb",
                            interp.c_str(),
                            std::to_string(child).c_str(),
                            nullptr);
                        error("failed to execute GDB: %s", strerror(errno));
                    }
                }
            }

            // Construct and execute the command:
            setEnv(envp, option_preload);
            std::vector<const char *> args;
            args.push_back(interp.c_str());
            args.push_back("--library-path");
            args.push_back(libname.c_str());
            args.push_back(path.c_str());
            for (int i = 1; argv[i] != nullptr; i++)
                args.push_back(argv[i]);
            args.push_back(nullptr);
            execvp(interp.c_str(), (char * const *)args.data());
            error("failed to execute \"%s\" (from directory \"%s\"): %s",
                progname.c_str(), option_dir.c_str(), strerror(errno));
        }

        close(CONFIG_FILENO);
        close(PCAP_FILENO);
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, 0)) >= 0 && errno != ECHILD)
        {
            if (pid < 0)
                error("failed to wait for child process: %s", strerror(errno));
            if (pid != child)
                continue;

            if (option_patch)
                fprintf(stderr, "%s%s%s: ", YELLOW, task, OFF);
            if (WIFEXITED(status))
                fprintf(stderr, "%sEXIT %d%s\n", GREEN, WEXITSTATUS(status),
                    OFF);
            else if (WIFSIGNALED(status))
                fprintf(stderr, "%s%s%s\n", RED, strsignal(WTERMSIG(status)),
                    OFF);
            else
                fprintf(stderr, "???\n");
        }
    }

    return 0;
}

