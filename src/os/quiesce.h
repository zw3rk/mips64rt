/*
 * src/os/quiesce.h — Lane U12 VM-mutation quiescence transaction.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Six-step transaction over guest-physical mutations (map, unmap,
 * protect, remap, file-size changes):
 *
 *   1. The mutator parks itself (marks MUTATING under the mutation
 *      lock) and bumps the sequence.
 *   2. Every worker enters a syscall memory lease (Dekker
 *      handshake): a lease entered during a mutation parks until
 *      the mutation commits, and the mutator waits for outstanding
 *      leases to drain.
 *   3. The mutator preempts RUNNING workers with the reserved
 *      signal (Linux tgkill / Darwin pthread_kill) after publishing
 *      its intent; the handler rewinds a host pc caught inside a
 *      JIT sequence prefix to the sequence start, marks PARKED,
 *      and spins until the mutation clears.
 *   4. The host operation runs; on failure it returns -errno with
 *      zero mutation (abort path).
 *   5. On success the mutator publishes (region metadata, SMC
 *      epoch) and invalidates every worker's soft TLB.
 *   6. The mutator clears the sequence and resumes the workers.
 *
 * Single-threaded runs take the same path with no peers (the park
 * and preempt steps are vacuous but ordered), so the fast path is
 * the degenerate case of the general protocol, not a separate one.
 */

#ifndef MIPS64RT_OS_QUIESCE_H
#define MIPS64RT_OS_QUIESCE_H

#include "core/cpu.h"

#include <pthread.h>
#include <signal.h>

/* Worker states (see the transaction above). */
#define MIPS_QS_RUNNING 0
#define MIPS_QS_LEASE 1
#define MIPS_QS_PARKED 2
#define MIPS_QS_MUTATING 3

/* Reserved preemption signal: a real-time slot clear of NPTL's own
 * (32, 33) on Linux, SIGUSR2 where no RT range exists. Blocked
 * nowhere; the translator owns it on both hosts. */
#if defined(__linux__)
#define QS_PREEMPT_SIG (SIGRTMIN + 3)
#else
#define QS_PREEMPT_SIG SIGUSR2
#endif

/* Block the preempt signal around short critical sections whose
 * locks the mutator needs (mem_table, backend registry, page
 * table). A peer parked while holding one of those would deadlock
 * the transaction: the mutator blocks on the lock while the holder
 * spins for the commit. Save/restore pairs nest properly. */
static inline void mips_qs_block_preempt(sigset_t *old)
{
    sigset_t set;

    (void)sigemptyset(&set);
    (void)sigaddset(&set, QS_PREEMPT_SIG);
    (void)pthread_sigmask(SIG_BLOCK, &set, old);
}

static inline void mips_qs_unblock_preempt(const sigset_t *old)
{
    (void)pthread_sigmask(SIG_SETMASK, old, NULL);
}

/* Lease a syscall's memory accesses (wraps mips_syscall; recursive
 * lease depth is per worker). NULL ctx is a no-op. */
void mips_qs_lease_enter(mips64_ctx_t *ctx);
void mips_qs_lease_exit(mips64_ctx_t *ctx);

/* Begin a VM mutation (steps 1-3). Recursive per worker; only the
 * outermost begin preempts and waits. NULL ctx is a no-op. */
void mips_qs_begin(mips64_ctx_t *ctx);

/* Commit a VM mutation (steps 5-6): invalidate every worker's soft
 * TLB, clear the sequence, resume. Only the outermost commit acts. */
void mips_qs_commit(mips64_ctx_t *ctx);

/* Abort a VM mutation (step 4 failure): like commit but without any
 * publication. Metadata is untouched on this path by construction. */
void mips_qs_abort(mips64_ctx_t *ctx);

/* Drop a dead worker's slot (thread teardown; also releases any
 * lease the exiting thread still held). NULL ctx is a no-op. */
void mips_qs_unregister(mips64_ctx_t *ctx);

/* Claim the calling thread's slot eagerly (worker start, thread
 * entry) so pure-compute workers that never syscall are still
 * visible to preemption. Idempotent; NULL ctx is a no-op. */
void mips_qs_register(mips64_ctx_t *ctx);

#endif /* MIPS64RT_OS_QUIESCE_H */
