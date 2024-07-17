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
 * RECORDING:
 *
 * Threads are allowed to run as normal, but context switches may only occur
 * during syscalls.  This is to prevent switches during unknown states, which
 * would significantly complicate replay.
 *
 * REPLAY:
 *
 * Uses fibers (see rr_fiber.cpp)
 */

/*
 * Linux clone_args struct.
 */
struct clone_args
{
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

/*
 * Thread state structure.
 */
struct THREAD
{
    pid_t tid;                  // Real thread-ID
    int id;                     // Virtual thread-ID
    pid_t *ctid;                // CLONE_CHILD_CLEARTID pointer
    int *futex;                 // Waiting on futex?
    intptr_t prev_loc;          // Previous location (coverage tracking)
    sigset_t sigmask;           // Signal mask
    STATE state;                // Thread state
    intptr_t fs;                // %fs register (TLS)
    uint32_t mxcsr;             // %mxcsr register
    uint8_t xsave[4096];        // xsave state
};

#define THREAD_TLS      0xb8    // Unused %fs offset
#define MAX_CPU         4096    // (Assumed) max CPU number
static int thread_id = 0;       // Next thread-ID

/*
 * Thread run lock.
 */
static mutex_t thread_mutex = MUTEX_INITIALIZER;

/*
 * Create a new THREAD struct.
 */
static THREAD *thread_new(const STATE *state)
{
    THREAD *thread = (THREAD *)xmalloc(sizeof(THREAD));
    thread_id++;
    thread->id      = thread_id;
    thread->tid     = gettid();
    thread->ctid    = NULL;
    thread->sigmask = 0x0;
    if (state != NULL)
        memcpy(&thread->state, state, sizeof(thread->state));
    else
        memset(&thread->state, 0x0, sizeof(thread->state));
    thread->fs = 0x0;
    memset(thread->xsave, 0x0, sizeof(thread->xsave));
    return thread;
}

/*
 * Get the THREAD struct for the current thread.
 */
static THREAD *thread_self(void)
{
    struct THREAD *self;
    asm volatile ("mov %%fs:" STRING(THREAD_TLS) ",%0" : "=a"(self));
    return self;
}

/*
 * Set the THREAD struct for the current thread.
 */
static void thread_set_self(THREAD *self)
{
    asm volatile ("mov %0,%%fs:" STRING(THREAD_TLS) : : "r"(self));
}

/*
 * Call before a syscall.
 */
static void THREAD_UNLOCK(void)
{
    mutex_unlock(&thread_mutex);
}

/*
 * Call after a syscall.
 */
static void THREAD_LOCK(void)
{
    if (mutex_lock(&thread_mutex) < 0)
        error("failed to lock THREAD mutex: %s", strerror(errno));
}

/*
 * Thread start handling.
 */
static void record_start(int id);
extern "C"
{
    void thread_start_2(THREAD *self)
    {
        THREAD_LOCK();
        thread_set_self(self);
        self->tid = gettid();
        self->state.rip += /*sizeof(syscall)=*/2;
        asm volatile ("vzeroall");
        uint32_t mxcsr = 0x1f80;
        asm volatile ("ldmxcsr %0" : : "m"(mxcsr));
        record_start(self->id);
        jump(&self->state);
    }
    void thread_start(void);
    asm (
        ".globl thread_start\n"
        ".type thread_start,@function\n"
        "thread_start:\n"
        "pop %rdi\n"
        "jmp thread_start_2\n"
    );
}

/*
 * Thread fork() handler.
 */
static long thread_fork(void)
{
    mutex_settid(INT_MIN);
    return 0;       // Follow child
}

/*
 * Thread clone() handler.
 */
static long thread_clone(STATE *state)
{
    uintptr_t *stack = (uintptr_t *)state->rsi;
    if (stack == NULL)
        return thread_fork();

    THREAD *thread = thread_new(state);
    thread->state.rsp = (uintptr_t)stack;
    thread->state.rax = 0;

    stack--;
    stack[0] = (uintptr_t)thread;
    stack--;
    stack[0] = (uintptr_t)thread_start;

    int flags = (int)state->rdi;
    if (flags & /*CLONE_CHILD_CLEARTID=*/0x200000)
        thread->ctid = (pid_t *)state->r10;

    long r = syscall(SYS_clone, state->rdi, (uintptr_t)stack, state->rdx,
        state->r10, state->r8, state->r9);
    if (r < 0)
    {
        r = -errno;
        xfree(thread);
    }
    return r;
}

/*
 * Thread clone3() handler.
 */
static long thread_clone3(STATE *state)
{
    const struct clone_args *args_0 = (struct clone_args *)state->rdi;
    struct clone_args args_1;
    struct clone_args *args = &args_1;
    memcpy(args, args_0, sizeof(*args));

    uintptr_t *stack = (uintptr_t *)args->stack;
    if (stack == 0x0)
        return thread_fork();
    size_t stack_size = (size_t)args->stack_size;
    if (stack_size <= 2 * sizeof(uintptr_t))
        return -ENOSYS;
    stack = (uintptr_t *)((uint8_t *)stack + stack_size);

    THREAD *thread = thread_new(state);
    thread->state.rsp = (uintptr_t)stack;
    thread->state.rax = 0;

    stack--;
    stack[0] = (uintptr_t)thread;
    stack--;
    stack[0] = (uintptr_t)thread_start;
    stack_size -= 2 * sizeof(uintptr_t);

    args->stack_size = (uintptr_t)stack_size;

    int flags = (int)args->flags;
    if (flags & /*CLONE_CHILD_CLEARTID=*/0x200000)
        thread->ctid = (pid_t *)args->child_tid;

    long r = syscall(/*SYS_clone3=*/435, args, sizeof(*args),
        state->rdx, state->r10, state->r8, state->r9);
    if (r < 0)
    {
        r = -errno;
        xfree(thread);
    }
    return r;
}

/*
 * Thread exit() handler.
 */
static NORETURN void thread_exit(STATE *state)
{
    THREAD *self = thread_self();
    if (self->ctid != NULL)
        *self->ctid = 0x0;
    mutex_unlock(&thread_mutex);
    xfree(self);
    syscall(SYS_exit, (int)state->rdi);
    while (true)
        asm volatile ("ud2");
}

/*
 * Thread module initialization.
 */
static void thread_init(void)
{
    THREAD *self = thread_new(NULL);
    thread_set_self(self);
    mutex_unlock(&thread_mutex);
}

