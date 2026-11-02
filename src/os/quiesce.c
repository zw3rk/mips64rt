/*
 * src/os/quiesce.c — Lane U12 VM-mutation quiescence transaction.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements src/os/quiesce.h: a small process-wide worker registry
 * (16 slots keyed by ctx, like the backend registry) with a Dekker
 * lease handshake and reserved-signal preemption. Slots are claimed
 * with an atomic CAS (no lock, safe to probe from the preempt
 * handler); the mutation mutex serializes mutators. The handler
 * only writes its own slot state and spins on the sequence — no
 * allocation, no locks — and resumes the interrupted code when the
 * sequence clears.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/quiesce.h"

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "os/backend.h"

#if defined(__linux__) && !defined(SYS_tgkill)
#define SYS_tgkill 131
#endif
#if defined(__linux__) && !defined(SYS_gettid)
#define SYS_gettid 178
#endif

#define QS_MAX_SLOTS 160u
#define QS_SLOT_FREE 0
#define QS_SLOT_INIT 1
#define QS_SLOT_LIVE 2

typedef struct {
    _Atomic(int) used;
    _Atomic(const mips64_ctx_t *) key;
    pthread_t pthread;
    _Atomic(long) tid;
    _Atomic(long) pid;
    _Atomic(int) state;
    _Atomic(int) leases;
    int saved_leases;
    int depth;
} qs_slot_t;

static qs_slot_t qs_slots[QS_MAX_SLOTS];
static pthread_mutex_t qs_mu = PTHREAD_MUTEX_INITIALIZER;
static _Atomic(int) qs_mutating = 0;
static _Atomic(int) qs_leases = 0;
static _Atomic(int) qs_worker_count = 0;
static pthread_once_t qs_once = PTHREAD_ONCE_INIT;

int mips_qs_has_peers(void)
{
    return atomic_load_explicit(&qs_worker_count, memory_order_relaxed) > 1;
}

static qs_slot_t *qs_slot_for(const mips64_ctx_t *ctx, int create)
{
    size_t i;

    if (ctx == NULL) {
        return NULL;
    }
    for (i = 0u; i < QS_MAX_SLOTS; i++) {
        if (atomic_load_explicit(&qs_slots[i].used, memory_order_acquire) ==
                QS_SLOT_LIVE &&
            atomic_load_explicit(&qs_slots[i].key, memory_order_relaxed) ==
                ctx) {
            return &qs_slots[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (i = 0u; i < QS_MAX_SLOTS; i++) {
        int expect = QS_SLOT_FREE;

        if (atomic_compare_exchange_strong_explicit(
                &qs_slots[i].used, &expect, QS_SLOT_INIT,
                memory_order_acq_rel, memory_order_relaxed)) {
            atomic_store_explicit(&qs_slots[i].key, ctx, memory_order_relaxed);
            qs_slots[i].pthread = pthread_self();
            qs_slots[i].depth = 0;
            qs_slots[i].saved_leases = 0;
            atomic_store_explicit(&qs_slots[i].leases, 0, memory_order_relaxed);
            atomic_store_explicit(&qs_slots[i].state, MIPS_QS_RUNNING,
                                  memory_order_relaxed);
#if defined(__linux__)
            atomic_store_explicit(&qs_slots[i].tid, syscall(SYS_gettid),
                                  memory_order_relaxed);
            atomic_store_explicit(&qs_slots[i].pid, (long)getpid(),
                                  memory_order_relaxed);
#else
            atomic_store_explicit(&qs_slots[i].tid, 0L, memory_order_relaxed);
            atomic_store_explicit(&qs_slots[i].pid, (long)getpid(),
                                  memory_order_relaxed);
#endif
            atomic_fetch_add_explicit(&qs_worker_count, 1,
                                      memory_order_relaxed);
            atomic_store_explicit(&qs_slots[i].used, QS_SLOT_LIVE,
                                  memory_order_release);
            return &qs_slots[i];
        }
    }
    return NULL;
}

/* Refresh the calling thread's binding (a ctx never migrates
 * threads in this tree, but the refresh is one TLS read and keeps
 * preemption aimed if it ever does). */
static void qs_touch(qs_slot_t *s)
{
    pthread_t self = pthread_self();

    if (!pthread_equal(s->pthread, self)) {
        s->pthread = self;
#if defined(__linux__)
        atomic_store_explicit(&s->tid, syscall(SYS_gettid),
                              memory_order_relaxed);
#endif
    }
}

static uint64_t qs_handler_pc(void *uc)
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

static void qs_handler_set_pc(void *uc, uint64_t pc)
{
    if (uc == NULL) {
        return;
    }
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64__))
    ((ucontext_t *)uc)->uc_mcontext.pc = pc;
#elif defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
    ((ucontext_t *)uc)->uc_mcontext->__ss.__pc = pc;
#else
    (void)pc;
#endif
}

/* Reserved-signal preemption (step 3): park, rewind a caught
 * sequence prefix, spin until the sequence clears, resume. */
static void qs_preempt_handler(int sig, siginfo_t *si, void *uc)
{
    pthread_t self = pthread_self();
    size_t i;

    (void)sig;
    (void)si;
    for (i = 0u; i < QS_MAX_SLOTS; i++) {
        if (atomic_load_explicit(&qs_slots[i].used, memory_order_acquire) ==
                QS_SLOT_LIVE &&
            pthread_equal(qs_slots[i].pthread, self)) {
            uint64_t hpc;
            uint64_t seq = 0u;

            if (atomic_load(&qs_mutating) == 0 ||
                atomic_load(&qs_slots[i].leases) > 0) {
                return;
            }
            atomic_store(&qs_slots[i].state, MIPS_QS_PARKED);
            hpc = qs_handler_pc(uc);
            if (hpc != 0u && dbt_rewind_pc(hpc, &seq) != 0) {
                qs_handler_set_pc(uc, seq);
            }
            while (atomic_load(&qs_mutating) != 0) {
                sched_yield();
            }
            atomic_store(&qs_slots[i].state, MIPS_QS_RUNNING);
            return;
        }
    }
}

static void qs_install(void)
{
    struct sigaction sa;

    (void)memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = qs_preempt_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    (void)sigemptyset(&sa.sa_mask);
    (void)sigaction(QS_PREEMPT_SIG, &sa, NULL);
}

static void qs_preempt_peer(qs_slot_t *s)
{
#if defined(__linux__)
    long pid = atomic_load_explicit(&s->pid, memory_order_relaxed);
    long tid = atomic_load_explicit(&s->tid, memory_order_relaxed);

    (void)syscall(SYS_tgkill, pid, tid, QS_PREEMPT_SIG);
#else
    (void)pthread_kill(s->pthread, QS_PREEMPT_SIG);
#endif
}

void mips_qs_lease_enter(mips64_ctx_t *ctx)
{
    qs_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    (void)pthread_once(&qs_once, qs_install);
    s = qs_slot_for(ctx, 1);
    if (s == NULL) {
        return;
    }
    qs_touch(s);
    if (s->depth != 0 || atomic_load(&s->leases) > 0) {
        atomic_fetch_add(&s->leases, 1);
        atomic_fetch_add(&qs_leases, 1);
        return;
    }
    /* Dekker lease acquisition: publish LEASE + lease count first, then
     * check qs_mutating; if a mutation is active, back out to PARKED
     * and wait so no leased helper ever runs or parks mid-mutation. */
    for (;;) {
        while (atomic_load(&qs_mutating) != 0) {
            atomic_store(&s->state, MIPS_QS_PARKED);
            sched_yield();
        }
        atomic_fetch_add(&s->leases, 1);
        atomic_fetch_add(&qs_leases, 1);
        atomic_store(&s->state, MIPS_QS_LEASE);
        if (atomic_load(&qs_mutating) == 0) {
            break;
        }
        atomic_fetch_sub(&s->leases, 1);
        atomic_fetch_sub(&qs_leases, 1);
        atomic_store(&s->state, MIPS_QS_PARKED);
    }
}

void mips_qs_lease_exit(mips64_ctx_t *ctx)
{
    qs_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    s = qs_slot_for(ctx, 0);
    if (s == NULL) {
        return;
    }
    if (atomic_load(&s->leases) > 0) {
        int rem = atomic_fetch_sub(&s->leases, 1) - 1;

        atomic_fetch_sub(&qs_leases, 1);
        if (rem <= 0 && s->depth == 0) {
            if (atomic_load(&qs_mutating) != 0) {
                atomic_store(&s->state, MIPS_QS_PARKED);
                while (atomic_load(&qs_mutating) != 0) {
                    sched_yield();
                }
            }
            atomic_store(&s->state, MIPS_QS_RUNNING);
        }
    }
}

void mips_qs_begin(mips64_ctx_t *ctx)
{
    qs_slot_t *s;
    size_t i;

    if (ctx == NULL) {
        return;
    }
    (void)pthread_once(&qs_once, qs_install);
    s = qs_slot_for(ctx, 1);
    if (s == NULL) {
        return;
    }
    qs_touch(s);
    if (s->depth != 0) {
        s->depth++;
        return;
    }
    /* Step 1 (Rev 4 §4.5): drop any held dispatch lease and park
     * before acquiring qs_mu so two concurrent mutating syscalls
     * never deadlock waiting for each other's lease. */
    {
        int saved = atomic_exchange(&s->leases, 0);

        if (saved > 0) {
            atomic_fetch_sub(&qs_leases, saved);
        }
        atomic_store(&s->state, MIPS_QS_PARKED);
        (void)pthread_mutex_lock(&qs_mu);
        s->saved_leases = saved;
    }
    s->depth = 1;
    atomic_store(&s->state, MIPS_QS_MUTATING);
    atomic_store(&qs_mutating, 1);
    /* Drive every peer to PARKED with zero active leases: leased
     * helpers run to mips_qs_lease_exit without signal preemption
     * and park on exit when qs_mutating is set. */
    for (;;) {
        int quiet = 1;
        int held = 0;
        pthread_t self = pthread_self();

        for (i = 0u; i < QS_MAX_SLOTS; i++) {
            int st;

            if (atomic_load_explicit(&qs_slots[i].used,
                                     memory_order_acquire) != QS_SLOT_LIVE ||
                &qs_slots[i] == s ||
                pthread_equal(qs_slots[i].pthread, self)) {
                continue;
            }
            st = atomic_load(&qs_slots[i].state);
            if (st != MIPS_QS_PARKED) {
                quiet = 0;
            }
            held += atomic_load(&qs_slots[i].leases);
        }
        if (quiet && held <= 0) {
            break;
        }
        for (i = 0u; i < QS_MAX_SLOTS; i++) {
            if (atomic_load_explicit(&qs_slots[i].used,
                                     memory_order_acquire) == QS_SLOT_LIVE &&
                &qs_slots[i] != s &&
                !pthread_equal(qs_slots[i].pthread, self) &&
                atomic_load(&qs_slots[i].state) != MIPS_QS_PARKED &&
                atomic_load(&qs_slots[i].leases) == 0) {
                qs_preempt_peer(&qs_slots[i]);
            }
        }
        sched_yield();
    }
}

static void qs_end(mips64_ctx_t *ctx, int publish)
{
    qs_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    s = qs_slot_for(ctx, 0);
    if (s == NULL || s->depth == 0) {
        return;
    }
    s->depth--;
    if (s->depth != 0) {
        return;
    }
    if (publish != 0) {
        /* Step 5: every worker's soft TLB goes before the sequence
         * clears, so no filler can repopulate from racing metadata
         * (fillers are parked or lease-gated throughout). */
        mips_soft_tlb_invalidate_all();
    }
    if (s->saved_leases > 0) {
        int saved = s->saved_leases;

        s->saved_leases = 0;
        atomic_store(&s->leases, saved);
        atomic_fetch_add(&qs_leases, saved);
        atomic_store(&s->state, MIPS_QS_LEASE);
    } else {
        atomic_store(&s->state, MIPS_QS_RUNNING);
    }
    atomic_store(&qs_mutating, 0);
    (void)pthread_mutex_unlock(&qs_mu);
}

void mips_qs_commit(mips64_ctx_t *ctx)
{
    qs_end(ctx, 1);
}

void mips_qs_abort(mips64_ctx_t *ctx)
{
    qs_end(ctx, 0);
}

void mips_qs_register(mips64_ctx_t *ctx)
{
    qs_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    (void)pthread_once(&qs_once, qs_install);
    s = qs_slot_for(ctx, 1);
    if (s != NULL) {
        qs_touch(s);
    }
}

void mips_qs_unregister(mips64_ctx_t *ctx)
{
    qs_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    s = qs_slot_for(ctx, 0);
    if (s == NULL) {
        return;
    }
    if (atomic_exchange_explicit(&s->used, QS_SLOT_INIT,
                                 memory_order_acq_rel) != QS_SLOT_LIVE) {
        return;
    }
    /* Release any lease the exiting thread still held so a dead
     * worker never blocks a future mutation's drain. */
    {
        int held = atomic_exchange(&s->leases, 0);

        if (held > 0) {
            atomic_fetch_sub(&qs_leases, held);
        }
    }
    s->saved_leases = 0;
    s->depth = 0;
    atomic_store_explicit(&s->state, MIPS_QS_RUNNING, memory_order_relaxed);
    atomic_store_explicit(&s->key, NULL, memory_order_relaxed);
    atomic_fetch_sub_explicit(&qs_worker_count, 1, memory_order_relaxed);
    atomic_store_explicit(&s->used, QS_SLOT_FREE, memory_order_release);
}

void mips_qs_atfork_child(mips64_ctx_t *ctx)
{
    pthread_mutex_t fresh = PTHREAD_MUTEX_INITIALIZER;
    size_t i;

    (void)memcpy(&qs_mu, &fresh, sizeof qs_mu);
    atomic_store_explicit(&qs_mutating, 0, memory_order_relaxed);
    for (i = 0u; i < QS_MAX_SLOTS; i++) {
        atomic_store_explicit(&qs_slots[i].used, QS_SLOT_FREE,
                              memory_order_relaxed);
        atomic_store_explicit(&qs_slots[i].key, NULL, memory_order_relaxed);
        atomic_store_explicit(&qs_slots[i].tid, 0L, memory_order_relaxed);
        atomic_store_explicit(&qs_slots[i].pid, 0L, memory_order_relaxed);
        atomic_store_explicit(&qs_slots[i].state, MIPS_QS_RUNNING,
                              memory_order_relaxed);
        atomic_store_explicit(&qs_slots[i].leases, 0, memory_order_relaxed);
        qs_slots[i].saved_leases = 0;
        qs_slots[i].depth = 0;
    }
    if (ctx == NULL) {
        atomic_store_explicit(&qs_leases, 0, memory_order_relaxed);
        atomic_store_explicit(&qs_worker_count, 0, memory_order_release);
        return;
    }
    atomic_store_explicit(&qs_slots[0].key, ctx, memory_order_relaxed);
    qs_slots[0].pthread = pthread_self();
#if defined(__linux__)
    atomic_store_explicit(&qs_slots[0].tid, syscall(SYS_gettid),
                          memory_order_relaxed);
#else
    atomic_store_explicit(&qs_slots[0].tid, 0L, memory_order_relaxed);
#endif
    atomic_store_explicit(&qs_slots[0].pid, (long)getpid(),
                          memory_order_relaxed);
    atomic_store_explicit(&qs_slots[0].state, MIPS_QS_LEASE,
                          memory_order_relaxed);
    atomic_store_explicit(&qs_slots[0].leases, 1, memory_order_relaxed);
    atomic_store_explicit(&qs_leases, 1, memory_order_relaxed);
    atomic_store_explicit(&qs_worker_count, 1, memory_order_relaxed);
    atomic_store_explicit(&qs_slots[0].used, QS_SLOT_LIVE,
                          memory_order_release);
}
