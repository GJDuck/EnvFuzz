/*
 *
 *  ____      __________ 
 * |  _ \ ___|__  /__  /__ _ _ __  
 * | |_) / _ \ / /  / // _` | '_ \
 * |  _ <  __// /_ / /| (_| | | | |
 * |_| \_\___/____/____\__,_|_| |_|
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
 * This is the core ReZZan runtime library module.
 * Please see the paper for more information:
 *
 *    Jinsheng Ba, Gregory J. Duck, Abhik Roychoudhury,
 *    Efficient Greybox Fuzzing to Detect Memory Errors,
 *    Automated Software Engineering (ASE), 2022
 *
 * This version is designed to work with EnvFuzz.
 */

#define _GNU_SOURCE
#include <dlfcn.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "rrfuzz.h"

#define REZZAN_ALIAS(X)     __attribute__((__alias__(X)))
#define REZZAN_CONSTRUCTOR  __attribute__((__constructor__(101)))
#define REZZAN_DESTRUCTOR   __attribute__((__destructor__(101)))

#define REZZAN_BASE         0xccc00000000ull
#define REZZAN_MAX          (1ull << 32)                // 4GB

static bool option_enabled  = false;
static bool option_inited   = false;
static bool option_debug    = false;
static bool option_checks   = false;
static bool option_tty      = false;
static bool option_stats    = false;
static bool option_populate = false;

#define DEBUG(msg, ...)                                                 \
    do                                                                  \
    {                                                                   \
        if (option_debug)                                               \
        {                                                               \
            rr_disable();                                               \
            fprintf(stderr, "%sDEBUG%s: %s: %u: " msg "\n",             \
                (option_tty? "\33[35m": ""),                            \
                (option_tty? "\33[0m": ""),                             \
                __FILE__, __LINE__,                                     \
                ## __VA_ARGS__);                                        \
            rr_enable();                                                \
        }                                                               \
    }                                                                   \
    while (false)
#define error(msg, ...)                                                 \
    do                                                                  \
    {                                                                   \
        rr_disable();                                                   \
        fprintf(stderr, "%serror%s: %s: %u: " msg "\n",                 \
            (option_tty? "\33[31m": ""),                                \
            (option_tty? "\33[0m" : ""),                                \
            __FILE__, __LINE__,                                         \
            ##__VA_ARGS__);                                             \
        asm volatile ("ud2");                                           \
    }                                                                   \
    while (false)
#define warning(msg, ...)                                               \
    do                                                                  \
    {                                                                   \
        rr_disable();                                                   \
        fprintf(stderr, "%swarning%s: %s: %u: " msg "\n",               \
            (option_tty? "\33[33m": ""),                                \
            (option_tty? "\33[0m" : ""),                                \
            __FILE__, __LINE__,                                         \
            ##__VA_ARGS__);                                             \
    }                                                                   \
    while (false)

#ifndef PAGE_SIZE
#define PAGE_SIZE   ((size_t)4096)
#endif
#define POOL_SIZE   ((size_t)(1ull << 31))      // 2GB

/*
 * Token representation.
 */
union Token
{
    struct
    {
        uint64_t boundary:3;
        uint64_t nonce61:61;
    };
    uint64_t nonce;
};
typedef union Token Token;

/*
 * Malloc unit.
 */
struct Unit
{
    Token t[2];
};
typedef struct Unit Unit;

/*
 * Config.
 */
static size_t nonce_size = 0;
static size_t pool_size  = 0;

/*
 * Malloc memory pool.
 */
static Unit  *pool      = NULL;
static size_t pool_ptr  = 0;
static size_t pool_mmap = 0;
#define POOL_MMAP_SIZE          (((size_t)(1ull << 15)) / sizeof(Unit))

/*
 * Glibc memory functions.
 */
extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_calloc(size_t nmemb, size_t size);
extern int __vsnprintf (char *string, size_t maxlen, const char *format,
                      va_list args, unsigned int mode_flags);

extern int arch_prctl(int code, unsigned long *addr);

/*
 * Low-level memory operations.
 */
void rezzan_init_nonce61(void);
void rezzan_set_token61(Token *ptr64, size_t boundary);
bool rezzan_test_token61(const Token *ptr64);
void rezzan_init_nonce64(void);
void rezzan_set_token64(Token *ptr64);
bool rezzan_test_token64(const Token *ptr64);
void rezzan_zero_token(Token *ptr64);
uint64_t rezzan_get_nonce(void);

#define NONCE_ADDR      "%gs:0x8"

asm (
    ".type rezzan_init_nonce64, @function\n"
    ".globl rezzan_init_nonce64\n"
    "rezzan_init_nonce64:\n"
    "\tretq\n"

    ".type rezzan_set_token64, @function\n"
    ".globl rezzan_set_token64\n"
    "rezzan_set_token64:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tmov %rax,(%rdi)\n"
    "\tnegq (%rdi)\n"
    "\txor %eax,%eax\n"
    "\tretq\n"

    ".type rezzan_test_token64, @function\n"
    ".globl rezzan_test_token64\n"
    "rezzan_test_token64:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tmov (%rdi),%rdi\n"
    "\tlea (%rdi,%rax),%rax\n"
    "\ttestq %rax,%rax\n"
    "\tsete %al\n"
    "\tretq\n"

    ".type rezzan_init_nonce61, @function\n"
    ".globl rezzan_init_nonce61\n"
    "rezzan_init_nonce61:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tandq $-0x8,%rax\n"
    "\tmov %rax, " NONCE_ADDR "\n"
    "\tretq\n"

    ".type rezzan_set_token61, @function\n"
    ".globl rezzan_set_token61\n"
    "rezzan_set_token61:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tnegq %rax\n"
    "\tandq $-0x8,%rax\n"
    "\txor %rsi,%rax\n"
    "\tmov %rax,(%rdi)\n"
    "\txor %eax,%eax\n"
    "\tretq\n"

    ".type rezzan_test_token61, @function\n"
    ".globl rezzan_test_token61\n"
    "rezzan_test_token61:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tmov (%rdi),%rdi\n"
    "\tandq $-0x8,%rdi\n"
    "\tlea (%rdi,%rax),%rax\n"
    "\ttestq %rax,%rax\n"
    "\tsete %al\n"
    "\tretq\n"

    ".type rezzan_zero_token, @function\n"
    ".globl rezzan_zero_token\n"
    "rezzan_zero_token:\n"
    "\txor %eax,%eax\n"
    "\tmov %rax,(%rdi)\n"
    "\rretq\n"

    ".type rezzan_get_nonce, @function\n"
    ".globl rezzan_get_nonce\n"
    "rezzan_get_nonce:\n"
    "\tmov " NONCE_ADDR ", %rax\n"
    "\tnegq %rax\n"
    "\tretq\n"
);

/*
 * mmap() wrapper.
 */
static void *rezzan_mmap(void *addr, size_t len, int prot, int flags,
    int fd, off_t offset)
{
    DEBUG("mmap(%p,%zu)", addr, len);
    rr_disable();
    void *r = mmap(addr, len, prot, flags, fd, offset);
    rr_enable();
    return r;
}

/*
 * Poison the 64-bit aligned pointer `ptr64'.
 */
static void poison(Token *ptr64, size_t size)
{
    switch (nonce_size)
    {
        case 61:
        {
            size_t boundary = size % sizeof(Token);
            rezzan_set_token61(ptr64, boundary);
            return;
        }
        case 64:
            rezzan_set_token64(ptr64);
    }
}

/*
 * Zero the 64-bit aligned pointer `ptr64'.
 */
static void zero(Token *ptr64)
{
    rezzan_zero_token(ptr64);
}

/*
 * Test if the 64-bit aligned pointer `ptr64' is poisoned or not.
 */
static bool is_poisoned(Token *ptr64)
{
    switch (nonce_size)
    {
        case 61:
            return rezzan_test_token61(ptr64);
        case 64:
            return rezzan_test_token64(ptr64);
        default:
            return false;
    }
}

/*
 * Checking the memory region start from ptr with n length is memory safe.
 */
static void check_poisoned(const void *ptr, size_t n)
{
    // Check the token of the destination
    uintptr_t iptr = (uintptr_t)ptr;
    if (iptr + n < REZZAN_BASE || iptr > REZZAN_BASE + REZZAN_MAX)
        return;
    size_t front_delta = iptr % sizeof(Token);
    int check_len = n + front_delta;
    iptr -= front_delta;
    size_t end_delta = check_len % sizeof(Token);
    if (end_delta)
        check_len += sizeof(Token);
    check_len /= sizeof(Token);
    Token *ptr64 = (Token *)iptr;
    for (size_t i = 0; i < check_len; i++)
    {
        // Check the token of each memory
        if (is_poisoned(ptr64 + i))
            asm volatile ("ud2");
    }
    if (end_delta && nonce_size == 61)
    {
        // Check the token after the current memory for byte-accurate checking
        ptr64 += check_len;
        if ((uintptr_t)ptr64 % PAGE_SIZE != 0 &&
                rezzan_test_token61((const Token *)ptr64))
        {
            Token tail_token = *ptr64;
            if (tail_token.boundary && (tail_token.boundary < end_delta))
            {
                // If the token equals to 0x00, which means 0x08
                asm volatile ("ud2");
            }
        }
    }
}

/*
 * Read a configuration value.
 */
static size_t get_config(const char *name, size_t _default)
{
    const char *str = getenv(name);
    if (str == NULL)
        return _default;
    char *end = NULL;
    errno = 0;
    size_t val = (size_t)strtoull(str, &end, 0);
    if (errno != 0)
        error("failed to parse string \"%s\" into an integer: %s",
            str, strerror(errno));
    else if (end == NULL || *end != '\0')
        error("failed to parse string \"%s\" into an integer", str);
    return val;
}

/*
 * ReZZan initialization.
 */
void REZZAN_CONSTRUCTOR rezzan_init(void)
{
    if (option_inited)
        return;

    option_tty = isatty(STDERR_FILENO);
    unsigned long gs;
    rr_disable();
    if (arch_prctl(ARCH_GET_GS, &gs) < 0 || gs == 0x0)
        error("this version of ReZZan is only compatiable with env-fuzz");
    rr_enable();

    option_stats   = (bool)get_config("REZZAN_STATS", 0);
    option_enabled = !(bool)get_config("REZZAN_DISABLED", 0);
    if (!option_enabled)
    {
        option_inited = true;
        return;
    }

    // Check config:
    if (sizeof(Token) != sizeof(uint64_t))
        error("invalid token size (%zu); must be %zu", sizeof(Token),
            sizeof(uint64_t));
    if (sizeof(Unit) != 2 * sizeof(uint64_t))
        error("invalid unit size (%zu); must be %zu", sizeof(Unit),
            2 * sizeof(uint64_t));
    nonce_size = get_config("REZZAN_NONCE_SIZE", 61);
    switch (nonce_size)
    {
        case 61:
            rezzan_init_nonce61();
            break;
        case 64:
            rezzan_init_nonce64();
            break;
        default:
            error("invalid nonce size (%zu); must be one of {%u,%u}",
                nonce_size, 61, 64);
    }
    pool_size = get_config("REZZAN_POOL_SIZE", POOL_SIZE);
    if (pool_size < POOL_MMAP_SIZE * sizeof(Unit))
        error("invalud pool size (%zu); must be greater than %zu", pool_size,
            POOL_MMAP_SIZE);
    if (pool_size % PAGE_SIZE != 0)
        error("invalid pool size (%zu); must be divisible by the page size "
            "(%zu)", pool_size, PAGE_SIZE);
    option_debug    = (bool)get_config("REZZAN_DEBUG", 0);
    option_checks   = (bool)get_config("REZZAN_CHECKS", 0);
    option_populate = (bool)get_config("REZZAN_POPULATE", 0);

    // Initialize malloc() pool:
    int flags  = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED |
        (option_populate? MAP_POPULATE: 0);
    void *base   = (void *)REZZAN_BASE;
    void *ptr = rezzan_mmap(base, POOL_MMAP_SIZE * sizeof(Unit),
        PROT_READ | PROT_WRITE, flags, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to allocate memory pool of size %zu: %s",
            pool_size, strerror(errno));
    pool       = (Unit *)ptr;
    pool_size /= sizeof(Unit);
    pool_ptr   = 0;
    pool_mmap  = POOL_MMAP_SIZE;

    // Poison the first unit so underflows will be detected:
    poison(&pool->t[0], 0);
    poison(&pool->t[1], 0);
    pool_ptr++;

    option_inited = true;
}

/*
 * ReZZan finalization.
 */
void REZZAN_DESTRUCTOR rezzan_fini(void)
{
    if (!option_stats)
        return;

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) < 0)
        error("failed to get resource usage: %s", strerror(errno));

    printf("maxrss          = %zu bytes\n", usage.ru_maxrss * 1024);
    printf("pagefaults      = %zu faults\n", usage.ru_minflt + usage.ru_majflt);
    printf("allocated       = %zu bytes\n", pool_ptr * sizeof(Unit));
}

/*
 * Allocate from the memory pool.
 */
static void *pool_malloc(size_t size128)
{
    void *ptr = (void *)(pool + pool_ptr);
    size_t new_pool_ptr = pool_ptr + size128;
    if (new_pool_ptr > pool_size)
    {
        // Out-of-space:
        errno = ENOMEM;
        return NULL;
    }
    if (new_pool_ptr > pool_mmap)
    {
        size_t old_pool_mmap = pool_mmap;
        pool_mmap = new_pool_ptr + POOL_MMAP_SIZE;
        size_t page_units = PAGE_SIZE / sizeof(Unit);
        if (pool_mmap % page_units != 0)
        {
            pool_mmap += page_units;
            pool_mmap -= pool_mmap % page_units;
        }
        if (pool_mmap > pool_size)
            pool_mmap = pool_size;

        uint8_t *start = (uint8_t *)(pool + old_pool_mmap);
        uint8_t *end   = (uint8_t *)(pool + pool_mmap);
        int flags  = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED |
            (option_populate? MAP_POPULATE: 0);
        void *ptr = rezzan_mmap(start, end - start, PROT_READ | PROT_WRITE,
            flags, -1, 0);
        if (ptr != (void *)start)
            error("failed to allocate %zu bytes for malloc pool: %s",
                end - start, strerror(errno));
    }
    pool_ptr += size128;
    return ptr;
}

/*
 * Malloc.
 */
void *rezzan_malloc(size_t size)
{
    // Check for initialization:
    if (!option_enabled)
        return __libc_malloc(size);

    // Calculate the necessary sizes:
    if (size == 0)
        size = 1;               // Treat 0 size as 1byte alloc.
    size_t size128 = size;
    size128 += sizeof(Token);   // Space for at least one token.
    if (size128 % sizeof(Unit) != 0)
    {
        size128 -= size128 % sizeof(Unit);
        size128 += sizeof(Unit);
    }
    size128 /= sizeof(Unit);

    // Allocate from the pool:
    void *ptr = pool_malloc(size128);
    if (ptr == NULL)
    {
        warning("failed to allocate memory of size %zu: %s", size,
            strerror(ENOMEM));
        exit(EXIT_FAILURE);
    }

    // Make sure the last word is poisoned *before* releasing the lock:
    Token *end64 = (Token *)((uint8_t *)ptr + size128 * sizeof(Unit));
    end64--;
    poison(end64, size);

    // Poison the rest of the redzone:
    uint8_t *end8 = (uint8_t *)ptr + size;
    for (end64--; (uint8_t *)end64 >= end8; end64--)
        poison(end64, size);

    // Debugging:
    DEBUG("malloc(%zu) = %p [size128=%zu (%zu)]", size, ptr,
        size128, size128 * sizeof(Unit));
    if (option_checks)
    {
        size_t i = 0;

        // Extra sanity checks:
        if ((uintptr_t)ptr % 16 != 0)
            error("invalid object alignment detected; %p %% 16 != 0", ptr);
        if (size >= size128 * sizeof(Unit))
            error("invalid object length detected; %zu >= %zu",
                size, size128 * sizeof(Unit));
        if ((intptr_t)end64 - (intptr_t)end8 < sizeof(Token))
            error("invalid object length detected; %p-%p < %zu"
                "[ptr=%p, size=%zu]", end64, end8, sizeof(Token), ptr, size);
        Token *ptr64 = (Token *)ptr;
        if (!is_poisoned(ptr64-1))
            error("invalid object base detected [ptr=%p, size=%zu]", ptr, size);
        for (i = 0; i * sizeof(Token) < size; i++)
        {
            if (is_poisoned(ptr64+i))
                error("invalid object initialization detected [size=%zu]",
                    size);
        }
        if (!is_poisoned(ptr64+i))
            error("invalid redzone detected; missing token [size=%zu]", size);
        i++;
        size_t size64 = 2 * size128;
        for (; i < size64; i++)
            if (!is_poisoned(ptr64+i))
                error("invalid redzone detected; missing extra token "
                    "[size=%zu]", size);
    }

    return ptr;
}

/*
 * Free.
 */
void rezzan_free(void *ptr)
{
    if (ptr == NULL)
        return;
    if (!option_enabled)
    {
        __libc_free(ptr);
        return;
    }

    DEBUG("free(%p)", ptr);
    if ((uintptr_t)ptr % sizeof(Unit) != 0)
        error("bad free detected with pointer %p; pointer is not "
            "16-byte aligned", ptr);
    Unit *ptr128 = (Unit *)ptr;
    if (ptr128 < pool || ptr128 >= pool + pool_size)
    {
        // Not allocated by us...
        __libc_free(ptr);
        return;
    }
    if (is_poisoned(ptr))
        error("bad or double-free detected with pointer %p; memory is "
            "already poisoned", ptr);
    Token *ptr64 = (Token *)ptr;
    if (!is_poisoned(ptr64-1))
        error("bad free detected with pointer %p; pointer does not "
            "point to the base of the object (corrupt malloc state?)", ptr64);

    // Poison the free'ed memory, and work out the object size.
    size_t i = 0;
    for (; !is_poisoned(ptr64 + i); i++)
        poison(ptr64 + i, 0);
}

/*
 * Realloc.
 */
void *rezzan_realloc(void *ptr, size_t size)
{
    if (!option_enabled)
        return __libc_realloc(ptr, size);

    if (ptr == NULL)
        return malloc(size);
    if ((uintptr_t)ptr % sizeof(Unit) != 0)
        error("bad free with (ptr=%p) not aligned to a 16 byte boundary",
            ptr);
    Unit *ptr128 = (Unit *)ptr;
    if (ptr128 < pool || ptr128 >= pool + pool_size)
    {
        // Not allocated by us...
        return __libc_realloc(ptr, size);
    }

    size_t old_size64 = 0;
    Token *ptr64 = (Token *)ptr;
    while (!is_poisoned(ptr64++))
        old_size64++;
    size_t old_size = old_size64 * sizeof(Token);
    size_t new_size = size;
    size_t copy_size = (old_size < new_size? old_size: new_size);
    void *old_ptr = ptr;
    void *new_ptr = rezzan_malloc(new_size);
    if (new_ptr == NULL)
        return new_ptr;
    // Debugging:
    DEBUG("realloc(old:%p, size:%zu) = %p", old_ptr,
        copy_size, new_ptr);
    uint8_t *dst8 = (uint8_t *)new_ptr;
    uint8_t *src8 = (uint8_t *)old_ptr;
    for (size_t i = 0; i < copy_size; i++)
        dst8[i] = src8[i];
    rezzan_free(old_ptr);
    return new_ptr;
}

/*
 * Calloc.
 */
void *rezzan_calloc(size_t nmemb, size_t size)
{
    if (!option_enabled)
        return __libc_calloc(nmemb, size);

    // ReZZan's malloc() already zero's memory.
    void *ptr = rezzan_malloc(nmemb * size);
    if (ptr != NULL && option_checks)
    {
        uint8_t *ptr8 = (uint8_t *)ptr;
        for (size_t i = 0; i < nmemb * size; i++)
            if (ptr8[i] != 0x0)
                error("invalid calloc allocation; byte %zu is non-zero", i);
    }
    return ptr;
}

/*
 * The glib runtime support.
 */
void *memcpy(void * restrict dst, const void * restrict src, size_t n)
{
    check_poisoned(dst, n);
    check_poisoned(src, n);

    uint8_t *dst8 = (uint8_t *)dst;
    const uint8_t *src8 = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++)
        dst8[i] = src8[i];
    return dst;
}
void *memmove(void * restrict dst, const void * restrict src, size_t n)
{
    check_poisoned(dst, n);
    check_poisoned(src, n);

    uint8_t *dst8 = (uint8_t *)dst;
    uint8_t *src8 = (uint8_t *)src;
    if (dst8 < src8)
    {
        while (n--)
            *dst8++ = *src8++;
    }
    else
    {
        uint8_t *lasts = src8 + (n-1);
        uint8_t *lastd = dst8 + (n-1);
        while (n--)
            *lastd-- = *lasts--;
    }
    return dst;
}
void *memset(void *dst, int c, size_t n)
{
    check_poisoned(dst, n);

    uint8_t *dst8 = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++)
        dst8[i] = (uint8_t)(int8_t)c;
    return dst;
}
size_t strlen(const char *str)
{
    size_t n = 0;
    while (true)
    {
        check_poisoned(str + n, 1);
        if (str[n] == '\0')
            return n;
        n++;
    }
}
size_t strnlen(const char *str, size_t maxlen)
{
    size_t n = 0;
    while (n < maxlen)
    {
        check_poisoned(str + n, 1);
        if (str[n] == '\0')
            return n;
        n++;
    }
    return maxlen;
}
char *strcpy(char *dst, const char *src)
{
    for (size_t i = 0; ; i++)
    {
        check_poisoned(src + i, 1);
        check_poisoned(dst + i, 1);
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
    return dst;
}
char *strcat(char *dst, const char *src)
{
    strcpy(dst + strlen(dst), src);
    return dst;
}
char* strncpy(char *dst, const char *src, size_t n)
{
    size_t len = strnlen(src, n);
    if (len != n)
        memset(dst + len, '\0', n - len);
    return memcpy(dst, src, len + 1);
}
char* strncat(char *s1, const char *s2, size_t n)
{
    char *s = s1;
    /* Find the end of S1.  */
    s1 += strlen(s1);
    size_t ss = strnlen(s2, n);
    s1[ss] = '\0';
    memcpy(s1, s2, ss);
    return s;
}
wchar_t *__wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)
{
    return (wchar_t *)memcpy((void *)dst, (const void *)src,
        n * sizeof(wchar_t));
}
size_t __wcslen(const wchar_t *str)
{
    size_t n = 0;
    while (true)
    {
        check_poisoned(str + n, 1);
        if (str[n] == L'\0')
            return n;
        n++;
    }
}
wchar_t* wcscpy(wchar_t *dst, const wchar_t *src)
{
    for (size_t i = 0; ; i++)
    {
        check_poisoned(src + i, 1);
        check_poisoned(dst + i, 1);
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
    return dst;
}

#if 0
int snprintf(char *dst, size_t n, const char *format, ...)
{

    check_poisoned(dst, n);

    va_list arg;
    int done;
    va_start(arg, format);
    done = __vsnprintf(dst, n, format, arg, 0);
    va_end (arg);
    return done;
}

// This function is not fully implemented, so it is only enabled when necessary.
int printf(const char *format,...)
{
    if (get_config("REZZAN_PRINTF", 0) == 1) {
        va_list ap;
        const char *p;
        const char *dst;
        int ival;
        double dval;

        va_start(ap,format);
        for(p = format; *p; ++p)
        {
            if(*p != '%')
            {
                continue;
            }
            switch(*++p)
            {
                case 's':
                    dst = va_arg(ap,char *);
                    int n = strlen(dst);
                    check_poisoned(dst, n);
                    break;
            }

        }
        va_end(ap);
    }

    // The original work
    va_list arg;
    int done;
    va_start (arg, format);
    done = vfprintf(stdout, format, arg);
    va_end (arg);
    return done;
}
#endif

extern void *malloc(size_t size) REZZAN_ALIAS("rezzan_malloc");
extern void free(void *ptr) REZZAN_ALIAS("rezzan_free");
extern void *realloc(void *ptr, size_t size) REZZAN_ALIAS("rezzan_realloc");
extern void *calloc(size_t nmemb, size_t size) REZZAN_ALIAS("rezzan_calloc");
extern void *_Znwm(size_t size) REZZAN_ALIAS("rezzan_malloc");
extern void *_Znam(size_t size) REZZAN_ALIAS("rezzan_malloc");
extern void *_ZnwmRKSt9nothrow_t(size_t size) REZZAN_ALIAS("rezzan_malloc");
extern void *_ZnamRKSt9nothrow_t(size_t size) REZZAN_ALIAS("rezzan_malloc");
extern void _ZdlPv(void *ptr) REZZAN_ALIAS("rezzan_free");
extern void _ZdaPv(void *ptr) REZZAN_ALIAS("rezzan_free");

typedef size_t (*malloc_usable_size_t)(void *);
extern size_t malloc_usable_size(void *ptr)
{
    Unit *ptr128 = (Unit *)ptr;
    if (ptr128 < pool || ptr128 >= pool + pool_size)
    {
        // Not allocated by us...
        static malloc_usable_size_t libc_malloc_usable_size = NULL;
        if (libc_malloc_usable_size == NULL)
        {
            libc_malloc_usable_size =
                (malloc_usable_size_t)dlsym(RTLD_NEXT, "malloc_usable_size");
            if (libc_malloc_usable_size == NULL)
                error("failed to find libc malloc_usable_size()");
        }
        return libc_malloc_usable_size(ptr);
    }

    size_t size64 = 0;
    Token *ptr64 = (Token *)ptr;
    while (!is_poisoned(ptr64++))
        size64++;
    return size64 * sizeof(Token);
}
