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

#ifndef __RRFUZZ_H
#define __RRFUZZ_H

#define PCAP_FILENO             999
#define CONFIG_FILENO           998
#define ERROR_FILENO            997

#define ACTX                    250     // CONTEXT structure

#define SYS_enable              340     // Enable record&replay
#define SYS_disable             341     // Disable record&replay

#define FORK_CHILD              0       // fork() follows child
#define FORK_PARENT             1       // fork() follows parent
#define FORK_FAIL               2       // fork() fails

#define MAP_SHIFT               14
#define MAP_SIZE                (1ull << MAP_SHIFT)

struct CONFIG                   // RRFuzz config
{
    uint64_t nonce[2];          // Random nonce.
    bool debug;                 // Attach debugger?
    bool fuzz;                  // Fuzz mode?
    bool hex;                   // Log output in hex?
    bool patch;                 // Patch replay?
    bool record;                // Record mode (false = replay mode)
    bool tty;                   // Is TTY? (print colors)
    bool blackbox;              // Blackbox mode?
    bool save;                  // Save-all mode?
    uint8_t fork;               // Fork-mode?
    int8_t log;                 // Log level.
    int8_t emulate;             // Emulation level.
    int64_t seed;               // RNG seed.
    int32_t timeout;            // Fuzz timeout.
    uint16_t depth;             // Fuzz depth.
    uint16_t cpu;               // CPU number.
    size_t count;               // Max executions.
    char strs[];                // String options
};

struct CONTEXT                  // Execution context
{
    uint64_t nonce[2];          // Random nonce.
    uint32_t cpu;               // Which CPU to run on.
    pid_t pid;                  // Process ID
    uint8_t fork;               // Fork-mode
    uint32_t argc;              // Length of argv[]
    uint32_t envl;              // Length of envp[]
    uint32_t size;              // Size of args[]
    char args[];                // argv[] followed by envp[].
};

#define COMMAND_ENABLE          0   // Enable record&replay
#define COMMAND_DISABLE         1   // Disable record&replay
#define COMMAND_SET_MEM_CHECK   2   // Set memory checker
#define COMMAND_SET_STR_CHECK   3   // Set string checker

typedef intptr_t (*CALLBACK)(int cmd, ...);
struct INTERFACE
{
    CALLBACK callback;
    uint64_t nonce[2];
    struct
    {
        uint32_t prev_loc;
        uint32_t mask;
        uint8_t map[MAP_SIZE];
    } cov;
};

static inline CALLBACK rr_callback(void)
{
    CALLBACK r;
    asm volatile ("mov %%gs:0x0,%0" : "=r"(r));
    return r;
}
static inline void rr_enable(void)
{
    (void)(rr_callback())(COMMAND_ENABLE);
}
static inline void rr_disable(void)
{
    (void)(rr_callback())(COMMAND_DISABLE);
}

#endif
