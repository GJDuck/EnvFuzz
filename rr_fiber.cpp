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

#define ARCH_SET_FS     0x1002
#define ARCH_GET_FS     0x1003

#define XSAVE_MASK      0x3FFFF

typedef THREAD FIBER;

static void *fibers    = NULL;          // Set of all active fibers
static FIBER *running  = NULL;          // Current running fiber

static void emulate_set_tid(pid_t tid);

static int fiber_compare(const void *a, const void *b)
{
    const FIBER *A = (FIBER *)a;
    const FIBER *B = (FIBER *)b;
    return (A->id - B->id);
}

static FIBER *fiber_new(const STATE *state)
{
    FIBER *fiber = thread_new(state);
    (void)tsearch(fiber, &fibers, fiber_compare);
    return fiber;
}

static FIBER *fiber_self(void)
{
    return running;
}

static void fiber_set_self(FIBER *fiber)
{
    running = fiber;
}

static bool inline fiber_save(FIBER *fiber)
{
    int64_t restore = 0;
    STATE *state    = &fiber->state;
    uint8_t *xsave  = fiber->xsave;
    xsave += 64 - (uintptr_t)xsave % 64;    // xsave needs 64-bit alignment
    if (option_fsgsbase)
        asm volatile ("rdfsbase %0" : "=r"(fiber->fs));
    else if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fiber->fs) < 0)
        error("failed to get %%fs register for thread #%d: %s",
            fiber->id, strerror(errno));
    asm volatile ("stmxcsr %0" : "=m"(fiber->mxcsr));
    asm volatile
    (
        "mov %%r15,0x08(%0)\n"
        "mov %%r14,0x10(%0)\n"
        "mov %%r13,0x18(%0)\n"
        "mov %%r12,0x20(%0)\n"
        "mov %%r11,0x28(%0)\n"
        "mov %%r10,0x30(%0)\n"
        "mov %%r9, 0x38(%0)\n"
        "mov %%r8, 0x40(%0)\n"
        "mov %%rdi,0x48(%0)\n"
        "mov %%rsi,0x50(%0)\n"
        "mov %%rbp,0x58(%0)\n"
        "mov %%rbx,0x60(%0)\n"
        "mov %%rdx,0x68(%0)\n"
        "mov %%rcx,0x70(%0)\n"
        "mov %%rax,0x78(%0)\n"
        "mov %%rsp,0x80(%0)\n"

        "lea .Lrestore_%=(%%rip),%%rax\n"
        "mov %%rax,0x88(%0)\n"

        "seto %%al\n"
        "lahf\n"
        "mov %%rax,0x00(%0)\n"

        "xor %%edx,%%edx\n"
        "mov $" STRING(XSAVE_MASK) ",%%eax\n"
        "mov %%rdx,512(%2)\n"       // Zero XSAVE header
        "mov %%rdx,512+8(%2)\n"
        "mov %%rdx,512+16(%2)\n"
        "mov %%rdx,512+24(%2)\n"
        "xsave (%2)\n"

        "mov $0,%1\n"
        "jmp .Ldone_%=\n"
        ".Lrestore_%=:\n"            // On restore(), control-flow jumps here
        "mov $1,%1\n"
        ".Ldone_%=:\n"

        : "+c"(state), "=a"(restore) : "b"(xsave) : "rdx"
    );
    return (restore != 0);
}

static NORETURN void fiber_restore(FIBER *fiber)
{
    if (option_fsgsbase)
        asm volatile ("wrfsbase %0" : : "r"(fiber->fs));
    else if (syscall(SYS_arch_prctl, ARCH_SET_FS, fiber->fs) < 0)
        error("failed to restore %%fs register for thread #%d: %s",
            fiber->id, strerror(errno));
    uint8_t *xsave  = fiber->xsave;
    xsave += 64 - (uintptr_t)xsave % 64;
    asm volatile (
        "xor %%edx,%%edx\n"
        "mov $" STRING(XSAVE_MASK) ",%%eax\n"
        "xrstor (%0)\n"
        : : "r"(xsave) : "rax", "rdx", "cc"
    );
    asm volatile ("ldmxcsr %0" : : "m"(fiber->mxcsr));
    fiber_set_self(fiber);
    jump(&fiber->state);
}

/*
 * Switch to thread #id.
 */
static void FIBER_SWITCH(int id)
{
    FIBER *self = fiber_self();
    if (self->id == id)
        return;

    FIBER key;
    key.id = id;
    void *node = tfind(&key, &fibers, fiber_compare);
    if (node == NULL)
        error("cannot switch to thread #%d; no such thread exists", id);

    FIBER *next = *(FIBER **)node;
    if (fiber_save(self))
        return;
    fiber_restore(next);
}

/*
 * Switch to the next thread.
 */
static void FIBER_NEXT(void)
{
    FIBER *self = fiber_self();
    FIBER key;
    key.id = self->id;
    void *node = tfind(&key, &fibers, fiber_compare);
    assert(node != NULL);

    for (void *n = tnext(node); ; n = tnext(n))
    {
        if (n == NULL)
            n = tmin(&fibers);
        if (n == node)
            break;
        FIBER *next = *(FIBER **)n;
        if (next->futex == NULL)
        {
            FIBER_SWITCH(next->id);
            return;
        }
    }
    if (self->futex == NULL)
        return;

    // Deadlock:
    error("all threads are blocked: %s", strerror(EDEADLK));
}

/*
 * Fiber fork handler.
 */
static long fiber_fork(void)
{
    return thread_fork();
}

/*
 * Fiber clone handler.
 */
static long fiber_clone(STATE *state, pid_t tid)
{
    const uint8_t *stack = (uint8_t *)state->rsi;
    if (stack == NULL)
        return fiber_fork();

    FIBER *fiber = fiber_new(state);
    fiber->tid       = tid;
    fiber->state.rsp = (uintptr_t)stack;
    fiber->state.rax = 0;
    fiber->state.rip += /*sizeof(syscall)=*/2;

    int flags = (int)state->rdi;
    if (flags & /*CLONE_SETTLS=*/0x80000)
        fiber->fs = state->r8;
    if (flags & /*CLONE_PARENT_SETTID=*/0x100000)
        *(pid_t *)state->rdx = tid;
    if (flags & /*CLONE_CHILD_CLEARTID=*/0x200000)
        fiber->ctid = (pid_t *)state->r10;

    fiber->mxcsr = 0x1f80;
    asm volatile ("ldmxcsr %0" : : "m"(fiber->mxcsr));

    emulate_set_tid(tid);
    return tid;
}

/*
 * Fiber clone3 handler.
 */
static long fiber_clone3(STATE *state, pid_t tid)
{
    const struct clone_args *args = (struct clone_args *)state->rdi;

    const uint8_t *stack = (uint8_t *)args->stack;
    if (stack == NULL)
        return fiber_fork();
    stack += args->stack_size;

    FIBER *fiber = fiber_new(state);
    fiber->tid = tid;
    fiber->state.rsp = (uintptr_t)stack;
    fiber->state.rax = 0;
    fiber->state.rip += /*sizeof(syscall)=*/2;

    int flags = (int)args->flags;
    if (flags & /*CLONE_SETTLS=*/0x80000)
        fiber->fs = args->tls;
    if (flags & /*CLONE_PARENT_SETTID=*/0x100000)
        *(pid_t *)args->parent_tid = tid;
    if (flags & /*CLONE_CHILD_CLEARTID=*/0x200000)
        fiber->ctid = (pid_t *)args->child_tid;

    fiber->mxcsr = 0x1f80;
    asm volatile ("ldmxcsr %0" : : "m"(fiber->mxcsr));

    emulate_set_tid(tid);
    return tid;
}

/*
 * Fiber wake handler.
 */
static long fiber_wake(int *addr, int max)
{
    FIBER *self = fiber_self();
    FIBER key;
    key.id = self->id;
    void *node = tfind(&key, &fibers, fiber_compare);
    assert(node != NULL);

    int count = 0; 
    for (void *n = tnext(node); count < max; n = tnext(n))
    {
        if (n == NULL)
            n = tmin(&fibers);
        if (n == node)
            break;
        FIBER *next = *(FIBER **)n;
        if (next->futex == addr)
        {
            next->futex = NULL;
            count++;
        }
    }
    return count;
}

/*
 * Fiber exit() handler.
 */
static void fiber_exit(void)
{
    FIBER *self = fiber_self();
    (void)tdelete(self, &fibers, fiber_compare);
    if (self->ctid != NULL)
        *self->ctid = 0x0;
    xfree(self);
    self = NULL;
}

/*
 * Fiber module initialization.
 */
static void fiber_init(void)
{
    FIBER *self = fiber_new(NULL);
    fiber_set_self(self);
}

