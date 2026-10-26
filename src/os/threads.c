/*
 * src/os/threads.c — Thread-group clone, thread exit, host-fault guard (lane L4b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 lane L4b: the full clone(2) flag set, TLS, and the host-fault
 * guard for JIT code. Thread-group clones (CLONE_VM|CLONE_THREAD|
 * CLONE_SIGHAND) spawn a host pthread sharing the guest reservation
 * (guest_base + va is process memory, so host threads share it by
 * construction); process clones fall back to fork(2). The LL/SC
 * reservation is invalidated across every clone. Mirrors
 * ../rvrt/src/linux/thread.c (flag decoding) and
 * ../rvrt/src/runtime/exec_tid.c (per-thread TID bookkeeping).
 *
 * Seam argument order (flags, stack_va, parent_tid_va, tls_va,
 * child_tid_va) is the phase-4.md contract; the raw MIPS clone order
 * carries child_tid (a3) before tls (a4). The RC4 coordinator adapts
 * the register order at the dispatch site.
 *
 * Limitations (documented RC4 scope): signal actions are shared
 * by value (memcpy at clone, no shared sighand); a lone CLONE_VM
 * without the thread-group triple reports -ENOSYS (fork cannot share
 * an address space); vfork arrives as fork without parent suspension;
 * robust lists are recorded per thread, never installed on the host;
 * fork while another thread holds the clone lock is unsupported.
 */

#define _GNU_SOURCE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "core/cpu.h"

#include "dbt/dbt.h"
#include "os/quiesce.h"
#include "os/signal_core.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <ucontext.h>
#elif defined(__APPLE__)
#include <sys/ucontext.h>
#endif

/* Guest clone flags (Linux arch-independent values, shared by MIPS64).
 * MIPS signal numbers (asm/signal.h): SIGCHLD is 18 on MIPS. The exit
 * signal occupies the low 8 bits; CLONE_DETACHED is a legacy no-op
 * without PIDFD and is accepted but ignored. */
#define L4B_CLONE_VM UINT64_C(0x00000100)
#define L4B_CLONE_FS UINT64_C(0x00000200)
#define L4B_CLONE_FILES UINT64_C(0x00000400)
#define L4B_CLONE_SIGHAND UINT64_C(0x00000800)
#define L4B_CLONE_VFORK UINT64_C(0x00004000)
#define L4B_CLONE_PARENT UINT64_C(0x00008000)
#define L4B_CLONE_THREAD UINT64_C(0x00010000)
#define L4B_CLONE_SYSVSEM UINT64_C(0x00040000)
#define L4B_CLONE_SETTLS UINT64_C(0x00080000)
#define L4B_CLONE_PARENT_SETTID UINT64_C(0x00100000)
#define L4B_CLONE_CHILD_CLEARTID UINT64_C(0x00200000)
#define L4B_CLONE_DETACHED UINT64_C(0x00400000)
#define L4B_CLONE_CHILD_SETTID UINT64_C(0x01000000)
#define L4B_CLONE_THREAD_GROUP \
    (L4B_CLONE_VM | L4B_CLONE_THREAD | L4B_CLONE_SIGHAND)

/* Cap on live guest threads (host pthreads). Past it clone fails with
 * -EAGAIN, matching the kernel under thread exhaustion. */
#define L4B_THREAD_MAX 128U

/* Shared helpers owned by sibling files (same pattern as
 * src/os/syscalls_sync.c): the $a3 return convention (syscalls.c),
 * the validated guest window (mem.c), and the endian-aware 32-bit
 * store (mem.c, faults the ctx on a bad address). */
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int guest_st32(mips64_ctx_t *ctx, uint64_t va, uint64_t val);

/* N32 carries 32-bit pointers: truncate the register to the low word
 * (the frozen N32 pointer rule; N64 VAs use the full 64 bits). */
static uint64_t l4b_trunc_va(const mips64_ctx_t *ctx, uint64_t va)
{
    if (ctx->is_n32 != 0U) {
        return va & UINT64_C(0xFFFFFFFF);
    }
    return va;
}

/* Portable thread id: the host tid on Linux (equals the guest tid the
 * NPTL matching code observes via gettid(2)), pid elsewhere. */
static long l4b_gettid(void)
{
#if defined(__linux__) && defined(SYS_gettid)
    return (long)syscall((long)SYS_gettid);
#else
    return (long)getpid();
#endif
}

/* Host FUTEX_WAKE for the clear-tid word on thread exit (best effort:
 * the joining thread may already be gone). */
static void l4b_futex_wake(uint32_t *word)
{
#if defined(__linux__) && defined(SYS_futex)
    (void)syscall((long)SYS_futex, word, 1 /* FUTEX_WAKE */, INT_MAX,
                  NULL, NULL, 0);
#else
    (void)word;
#endif
}

/* Live-thread table: slot per spawned pthread, guarded by l4b_mu. The
 * handshake fields (host_tid >= 0, ack != 0) are the parent/child
 * rendezvous for clone(2) tid publication. */
typedef struct {
    int used;
    int acked;
    long host_tid;
    pthread_t pt;
    mips64_ctx_t *child;
    uint64_t parent_tid_va;
    uint64_t child_tid_va;
    uint64_t child_flags;
} l4b_slot_t;

static pthread_mutex_t l4b_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t l4b_cv = PTHREAD_COND_INITIALIZER;
static l4b_slot_t l4b_slots[L4B_THREAD_MAX];

/* Endian-aware 32-bit tid store. Pre-validated by the caller; records
 * a guest fault on the racing failure instead of crashing the host. */
static void l4b_store_tid(mips64_ctx_t *ctx, uint64_t va, uint32_t tid)
{
    if (va == 0U) {
        return;
    }
    if ((va & 3U) != 0U ||
        !mips_mem_ok(ctx, va, 4U, (uint32_t)MIPS_PROT_WRITE)) {
        mips_fault(ctx, va);
        return;
    }
    (void)guest_st32(ctx, va, (uint64_t)tid);
}

/* Child entry: publish the host tid, wait for the parent's ack (so the
 * parent_tid word is stored before the child can run guest code that
 * reads it), publish the child_tid word, then run the interpreter
 * until it returns and exit the thread. */
static void *l4b_entry(void *arg)
{
    mips64_ctx_t *child = (mips64_ctx_t *)arg;
    l4b_slot_t *slot = NULL;
    size_t i;
    long tid;

    if (child == NULL) {
        return NULL;
    }
    tid = l4b_gettid();
    (void)pthread_mutex_lock(&l4b_mu);
    for (i = 0U; i < L4B_THREAD_MAX; i++) {
        if (l4b_slots[i].used != 0 && l4b_slots[i].child == child) {
            slot = &l4b_slots[i];
            break;
        }
    }
    if (slot != NULL) {
        slot->host_tid = tid;
        slot->pt = pthread_self();
        (void)pthread_cond_broadcast(&l4b_cv);
        while (slot->acked == 0) {
            (void)pthread_cond_wait(&l4b_cv, &l4b_mu);
        }
    }
    (void)pthread_mutex_unlock(&l4b_mu);
    child->host_tid = (int)tid;
    if (slot != NULL && (slot->child_flags & L4B_CLONE_CHILD_SETTID) != 0U) {
        l4b_store_tid(child, slot->child_tid_va, (uint32_t)tid);
    }
    /* Claim the quiescence slot up front so a pure-compute worker
     * that never syscalls is still visible to preemption. */
    mips_qs_register(child);
    (void)interp_run(child);
    mips_thread_exit(child, 0);
    return NULL;
}

/* Validate one optional tid word (0 = absent, else aligned + mapped
 * writable). Returns 0 or -EFAULT. */
static int l4b_check_tid(const mips64_ctx_t *ctx, uint64_t va)
{
    if (va == 0U) {
        return 0;
    }
    if ((va & 3U) != 0U ||
        !mips_mem_ok(ctx, va, 4U, (uint32_t)MIPS_PROT_WRITE)) {
        return -EFAULT;
    }
    return 0;
}

/* Thread-group clone: copy the parent ctx, install TLS + stack, record
 * robust + clear-tid state, spawn a detached host thread, and return
 * the child's host tid after the handshake. */
static int64_t l4b_clone_thread(mips64_ctx_t *ctx, uint64_t flags,
                                uint64_t stack_va, uint64_t parent_tid_va,
                                uint64_t tls_va, uint64_t child_tid_va)
{
    mips64_ctx_t *child = NULL;
    l4b_slot_t *slot = NULL;
    pthread_attr_t attr;
    size_t i;
    int attr_ok = 0;
    int rc;

    if (stack_va == 0U || stack_va > ctx->task_size) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (l4b_check_tid(ctx, parent_tid_va) != 0 ||
        l4b_check_tid(ctx, child_tid_va) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    child = (mips64_ctx_t *)malloc(sizeof *child);
    if (child == NULL) {
        return l2a_ret(ctx, -(int64_t)ENOMEM);
    }
    memcpy(child, ctx, sizeof *child);
    mips64_ctx_clear_ll(child);
    /* The child resumes after the clone with return value 0 in
     * $v0/$a3 (re-executing the syscall would respawn grandchildren;
     * the parent's pc still points at the clone). */
    child->pc += 4U;
    child->next_pc = child->pc + 4U;
    child->gpr[MIPS64_REG_V0] = 0U;
    child->gpr[MIPS64_REG_A3] = 0U;
    child->gpr[MIPS64_REG_SP] = stack_va;
    if ((flags & L4B_CLONE_SETTLS) != 0U) {
        child->ulr = tls_va;
    }
    child->is_thread_clone = true;
    child->host_tid = 0;
    /* Robust list recorded (inherited copy); never installed on host. */
    if ((flags & L4B_CLONE_CHILD_CLEARTID) != 0U) {
        child->clear_child_tid = child_tid_va;
    } else {
        child->clear_child_tid = 0U;
    }
    (void)pthread_mutex_lock(&l4b_mu);
    for (i = 0U; i < L4B_THREAD_MAX; i++) {
        if (l4b_slots[i].used == 0) {
            slot = &l4b_slots[i];
            break;
        }
    }
    if (slot == NULL) {
        (void)pthread_mutex_unlock(&l4b_mu);
        free(child);
        return l2a_ret(ctx, -(int64_t)EAGAIN);
    }
    memset(slot, 0, sizeof *slot);
    slot->used = 1;
    slot->host_tid = -1;
    slot->child = child;
    slot->parent_tid_va = parent_tid_va;
    slot->child_tid_va = child_tid_va;
    slot->child_flags = flags;
    if (pthread_attr_init(&attr) == 0) {
        attr_ok = 1;
        if (pthread_attr_setdetachstate(&attr,
                                        PTHREAD_CREATE_DETACHED) != 0) {
            (void)pthread_attr_destroy(&attr);
            attr_ok = 0;
        }
    }
    if (attr_ok == 0) {
        slot->used = 0;
        slot->child = NULL;
        (void)pthread_mutex_unlock(&l4b_mu);
        free(child);
        return l2a_ret(ctx, -(int64_t)EAGAIN);
    }
    rc = pthread_create(&slot->pt, &attr, l4b_entry, child);
    (void)pthread_attr_destroy(&attr);
    if (rc != 0) {
        slot->used = 0;
        slot->child = NULL;
        (void)pthread_mutex_unlock(&l4b_mu);
        free(child);
        return l2a_ret(ctx, -(int64_t)EAGAIN);
    }
    while (slot->host_tid < 0L) {
        (void)pthread_cond_wait(&l4b_cv, &l4b_mu);
    }
    rc = (int)slot->host_tid;
    if ((flags & L4B_CLONE_PARENT_SETTID) != 0U) {
        l4b_store_tid(ctx, parent_tid_va, (uint32_t)slot->host_tid);
    }
    slot->acked = 1;
    (void)pthread_cond_broadcast(&l4b_cv);
    (void)pthread_mutex_unlock(&l4b_mu);
    return l2a_ret(ctx, (int64_t)rc);
}

/* Process clone: host fork(2) with the sc_clone tid bookkeeping. Never
 * touches the thread table lock (the lock state is undefined in the
 * child when other threads exist). */
static int64_t l4b_clone_fork(mips64_ctx_t *ctx, uint64_t flags,
                               uint64_t parent_tid_va,
                               uint64_t child_tid_va)
{
    pid_t pid;

    if (l4b_check_tid(ctx, parent_tid_va) != 0 ||
        l4b_check_tid(ctx, child_tid_va) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    pid = fork();
    if (pid < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (pid == 0) {
        int32_t tid;

        mips64_ctx_clear_ll(ctx);
        ctx->is_thread_clone = false;
        if ((flags & L4B_CLONE_CHILD_CLEARTID) != 0U) {
            ctx->clear_child_tid = child_tid_va;
        }
        if ((flags & L4B_CLONE_CHILD_SETTID) != 0U) {
            tid = (int32_t)l4b_gettid();
            l4b_store_tid(ctx, child_tid_va, (uint32_t)tid);
        }
        return l2a_ret(ctx, 0);
    }
    if ((flags & L4B_CLONE_PARENT_SETTID) != 0U) {
        l4b_store_tid(ctx, parent_tid_va, (uint32_t)pid);
    }
    return l2a_ret(ctx, (int64_t)pid);
}

/*
 * Full clone(2) dispatch (phase-4.md seam). Thread-group clones spawn
 * a host thread; a lone CLONE_VM (shared mm without the thread-group
 * triple) is -ENOSYS; every other combination falls back to fork(2).
 * The LL reservation is cleared on the calling context at entry (and
 * on each child before it runs).
 */
int64_t mips_clone_full(mips64_ctx_t *ctx, uint64_t flags,
                        uint64_t stack_va, uint64_t parent_tid_va,
                        uint64_t tls_va, uint64_t child_tid_va)
{
    uint64_t group;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    mips64_ctx_clear_ll(ctx);
    parent_tid_va = l4b_trunc_va(ctx, parent_tid_va);
    child_tid_va = l4b_trunc_va(ctx, child_tid_va);
    tls_va = l4b_trunc_va(ctx, tls_va);
    stack_va = l4b_trunc_va(ctx, stack_va);
    group = flags & L4B_CLONE_THREAD_GROUP;
    if (group == L4B_CLONE_THREAD_GROUP) {
        return l4b_clone_thread(ctx, flags, stack_va, parent_tid_va,
                                tls_va, child_tid_va);
    }
    if ((flags & L4B_CLONE_VM) != 0U) {
        /* Shared-mm process clone: fork cannot share the address
         * space, so report -ENOSYS (same precedent as the Phase 1
         * sc_clone share mask). */
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    return l4b_clone_fork(ctx, flags, parent_tid_va, child_tid_va);
}

/*
 * Terminate the calling thread: clear the LL reservation, store 0 to
 * the CLONE_CHILD_CLEARTID word (endian-correct), issue the joining
 * FUTEX_WAKE on it, drop the table slot, release the heap ctx, and end
 * the host thread (never returns). Non-worker contexts fall back to
 * process exit with the status.
 */
void mips_thread_exit(mips64_ctx_t *ctx, int status)
{
    uint64_t clear_va;
    size_t i;

    if (ctx == NULL) {
        _Exit(status);
    }
    mips64_ctx_clear_ll(ctx);
    if (!ctx->is_thread_clone) {
        _Exit(status);
    }
    clear_va = ctx->clear_child_tid;
    ctx->clear_child_tid = 0U;
    if (clear_va != 0U && (clear_va & 3U) == 0U &&
        mips_mem_ok(ctx, clear_va, 4U, (uint32_t)MIPS_PROT_WRITE)) {
        (void)guest_st32(ctx, clear_va, 0U);
        l4b_futex_wake((uint32_t *)mips64_guest_ptr(ctx, clear_va));
    }
    (void)pthread_mutex_lock(&l4b_mu);
    for (i = 0U; i < L4B_THREAD_MAX; i++) {
        if (l4b_slots[i].used != 0 && l4b_slots[i].child == ctx) {
            l4b_slots[i].used = 0;
            l4b_slots[i].child = NULL;
            break;
        }
    }
    (void)pthread_mutex_unlock(&l4b_mu);
    /* Drop the quiescence slot (releases any lease the exiting thread
     * still held, so a dead worker never blocks a future drain). */
    mips_qs_unregister(ctx);
    free(ctx);
    pthread_exit(NULL);
}

/* ---- Host-fault guard for JIT code (mips_hostfault_install/run/disarm) ---- */

/* Size check for the pedantic-safe void * -> function pointer copy. */
typedef void (*l4b_code_t)(mips64_ctx_t *);

/* Plain jump buffer (no signal-mask save): the dispatcher mask is
 * constant across blocks, and the handler unblocks the fault signals
 * itself before jumping, so per-block entry pays register saves only
 * instead of a sigprocmask round-trip (lane H3: the mask save cost
 * more than the translated block on branch-heavy code). */
static _Thread_local jmp_buf l4b_jb;
static _Thread_local volatile sig_atomic_t l4b_armed = 0;
static _Thread_local int l4b_fault_sig = 0;
static _Thread_local uint64_t l4b_fault_addr = 0U;
/* In-handler capture of the faulting host pc (integer only; the
 * site-table resolve runs after the longjmp, outside signal
 * context). The ctx is stashed by mips_hostfault_run so the guard
 * can report the precise guest pc through the scratch slot. */
static _Thread_local uint64_t l4b_fault_host_pc = 0U;
static _Thread_local mips64_ctx_t *l4b_ctx = NULL;

/* Faulting host pc from the machine context (AArch64 only; 0
 * elsewhere, which disables site resolution on those hosts). */
static uint64_t l4b_host_pc(void *uc)
{
    if (uc == NULL) {
        return 0U;
    }
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64__))
    return (uint64_t)((ucontext_t *)uc)->uc_mcontext.pc;
#elif defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
    return (uint64_t)((ucontext_t *)uc)->uc_mcontext->__ss.__pc;
#else
    (void)uc;
    return 0U;
#endif
}

static const void *l4b_pool = NULL;
static size_t l4b_pool_len = 0U;
static pthread_mutex_t l4b_hmu = PTHREAD_MUTEX_INITIALIZER;
static int l4b_hinstalled = 0;
static struct sigaction l4b_old_segv;
static struct sigaction l4b_old_bus;

/* Forward a foreign fault to the previously installed disposition:
 * custom handler, ignore, or restore-and-reraise for the default. */
static void l4b_forward(int sig, siginfo_t *si, void *uc)
{
    const struct sigaction *old;

    old = (sig == SIGBUS) ? &l4b_old_bus : &l4b_old_segv;
    if (old->sa_handler == SIG_IGN) {
        return;
    }
    if (old->sa_handler != SIG_DFL) {
        if ((old->sa_flags & SA_SIGINFO) != 0) {
            old->sa_sigaction(sig, si, uc);
        } else if (old->sa_handler != NULL) {
            old->sa_handler(sig);
        }
        return;
    }
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

static void l4b_handler(int sig, siginfo_t *si, void *uc)
{
    uintptr_t addr = 0U;
    uintptr_t base;
    int inside;

    if (si != NULL) {
        addr = (uintptr_t)si->si_addr;
    }
    base = (uintptr_t)l4b_pool;
    inside = (l4b_pool == NULL) ||
             (addr >= base && addr - base < (uintptr_t)l4b_pool_len);
    if (l4b_armed != 0 && inside) {
        sigset_t unblock;

        /* The plain setjmp above saves no mask, and this signal is
         * blocked for the handler's duration: unblock here (async
         * safe) so a later fault still reaches this handler instead
         * of killing the process with the signal blocked. */
        (void)sigemptyset(&unblock);
        (void)sigaddset(&unblock, SIGSEGV);
        (void)sigaddset(&unblock, SIGBUS);
        (void)sigprocmask(SIG_UNBLOCK, &unblock, NULL);
        l4b_fault_sig = sig;
        /* Report the pool-relative offset: the coordinator installs
         * the guard over the guest reservation, so this is the guest
         * VA the faulting access targeted. */
        l4b_fault_addr = (l4b_pool == NULL) ? (uint64_t)addr :
            (uint64_t)(addr - base);
        /* Capture the faulting host pc (async-safe integer read);
         * the run side resolves it to the precise guest pc through
         * the retained miss-site tables. */
        l4b_fault_host_pc = l4b_host_pc(uc);
        longjmp(l4b_jb, 1);
    }
    l4b_forward(sig, si, uc);
}

/* Install the SIGSEGV/SIGBUS guard over [pool, pool+len). A NULL pool
 * guards every fault while armed. Idempotent; keeps the previous
 * dispositions for foreign faults. */
void mips_hostfault_install(const void *pool, size_t len)
{
    struct sigaction sa;

    (void)pthread_mutex_lock(&l4b_hmu);
    l4b_pool = pool;
    l4b_pool_len = len;
    if (l4b_hinstalled == 0) {
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = l4b_handler;
        (void)sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO;
        if (sigaction(SIGSEGV, &sa, &l4b_old_segv) == 0 &&
            sigaction(SIGBUS, &sa, &l4b_old_bus) == 0) {
            l4b_hinstalled = 1;
        }
    }
    (void)pthread_mutex_unlock(&l4b_hmu);
}

/*
 * Run JIT code under the guard: 0 on success (reasonp takes the ctx
 * exit reason), MIPS_FAULT (-1) on a caught fault (records EXIT_FAULT
 * with the fault-address low half, reasonp takes EXIT_FAULT),
 * -EINVAL on bad arguments. code is a void (*)(mips64_ctx_t *) entry
 * point. The caller owns the mips_fault trap+deliver step (dbt.c's
 * EXIT_FAULT case), so a handled SIGSEGV is trapped exactly once and
 * no stale duplicate stays queued.
 */
int mips_hostfault_run(mips64_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    l4b_code_t fn;

    if (ctx == NULL || code == NULL) {
        return -EINVAL;
    }
    _Static_assert(sizeof(l4b_code_t) == sizeof(void *),
                   "code pointer must fit a function pointer");
    memcpy(&fn, &code, sizeof fn);
    if (fn == NULL) {
        return -EINVAL;
    }
    l4b_armed = 1;
    l4b_fault_sig = 0;
    l4b_fault_addr = 0U;
    l4b_fault_host_pc = 0U;
    l4b_ctx = ctx;
    if (setjmp(l4b_jb) == 0) {
        fn(ctx);
        l4b_armed = 0;
        l4b_ctx = NULL;
        if (reasonp != NULL) {
            *reasonp = ctx->exit_reason;
        }
        return 0;
    }
    l4b_armed = 0;
    l4b_ctx = NULL;
    (void)l4b_fault_sig;
    ctx->llbit = 0U;
    ctx->exit_reason = MIPS64_EXIT_FAULT;
    ctx->exit_info = (uint32_t)l4b_fault_addr;
    /* Rev4 precise-pc channel: resolve the captured host pc to the
     * faulting guest pc and report it in ctx->pc directly (the
     * dispatcher's EXIT_FAULT case reads pc as-is). Unresolvable pcs
     * leave pc alone for the legacy decode-at-pc path. The scratch
     * slot is not used: it doubles as the unaligned shift park, and
     * a stale shift would masquerade as a fault pc. */
    if (l4b_fault_host_pc != 0U) {
        uint64_t gpc = 0U;

        if (dbt_host_pc_to_guest(l4b_fault_host_pc, &gpc) != 0) {
            ctx->pc = gpc;
            ctx->next_pc = gpc + 4u;
        }
    }
    if (reasonp != NULL) {
        *reasonp = ctx->exit_reason;
    }
    return MIPS_FAULT;
}

/* Disarm the current thread's guard (handlers stay installed; a
 * disarmed handler forwards to the previous disposition). */
void mips_hostfault_disarm(void)
{
    l4b_armed = 0;
}
