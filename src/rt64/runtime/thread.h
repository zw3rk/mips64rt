/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 lane L4b: thread-runtime contract (`clone`/`futex`/TLS).
 * Additive `src/rt64/` wiring only: declarations + guest ABI constants.
 * The implementation lives in `src/os/clone.c` (new, owned by this lane);
 * the coordinator wires dispatch (`MIPS64_NR_CLONE`/`MIPS64_NR_FUTEX`) and the
 * `Makefile` source entry at `RC4` (see the recipe in `src/os/clone.c`).
 */

#ifndef MIPS64RT_RT64_RUNTIME_THREAD_H
#define MIPS64RT_RT64_RUNTIME_THREAD_H

#include "core/cpu.h"

#include <stdint.h>

/* Guest `clone(2)` flags (Linux asm-generic values, shared by MIPS64). Only
 * the `CLONE_VM` family is served here; fork/vfork (no `CLONE_VM`) belong
 * to lane L4c and return `-ENOSYS` from `mips64_sys_clone`. */
#define MIPS64_CLONE_VM UINT64_C(0x00000100)
#define MIPS64_CLONE_FS UINT64_C(0x00000200)
#define MIPS64_CLONE_FILES UINT64_C(0x00000400)
#define MIPS64_CLONE_SIGHAND UINT64_C(0x00000800)
#define MIPS64_CLONE_THREAD UINT64_C(0x00010000)
#define MIPS64_CLONE_SYSVSEM UINT64_C(0x00040000)
#define MIPS64_CLONE_SETTLS UINT64_C(0x00080000)
#define MIPS64_CLONE_PARENT_SETTID UINT64_C(0x00100000)
#define MIPS64_CLONE_CHILD_CLEARTID UINT64_C(0x00200000)
#define MIPS64_CLONE_DETACHED UINT64_C(0x00400000)
#define MIPS64_CLONE_CHILD_SETTID UINT64_C(0x01000000)

/* Guest `futex(2)` op numbers (Linux values shared by MIPS64). Bit 7
 * (`FUTEX_PRIVATE_FLAG`) selects process-private fast hashing; bit 8
 * (`FUTEX_CLOCK_REALTIME`) selects `CLOCK_REALTIME` absolute timeouts. */
#define MIPS64_FUTEX_WAIT 0u
#define MIPS64_FUTEX_WAKE 1u
#define MIPS64_FUTEX_REQUEUE 3u
#define MIPS64_FUTEX_CMP_REQUEUE 4u
#define MIPS64_FUTEX_WAKE_OP 5u
#define MIPS64_FUTEX_WAIT_BITSET 9u
#define MIPS64_FUTEX_WAKE_BITSET 10u
#define MIPS64_FUTEX_PRIVATE_FLAG 128u
#define MIPS64_FUTEX_CLOCK_REALTIME 256u

/* Cap on live guest threads (host pthreads). Past it `clone` fails with
 * `-EAGAIN`, matching the kernel under thread exhaustion. */
#define MIPS64_CLONE_MAX_THREADS 128u

/* Store-atomicity lock (recursive): serializes a guest store (or
 * read-modify-write) against every other thread's `LL`/`SC` check and
 * `AM*` op so updates are never lost to host-thread interleaving. The
 * store path holds it across (invalidate + bytes); `SC` holds it
 * across (check + store); `AMCAS`/`AM*` hold it across
 * (load + modify + store); invalidation itself takes it, so lock order
 * stays store-then-registry everywhere. Nesting is safe; every return
 * path must release exactly as often as it acquired. */
void mips64_clone_store_lock(void);
void mips64_clone_store_unlock(void);

/* Handle the raw `clone` syscall. `ctx` is the calling (parent) thread
 * (passed through exactly like `mips64_syscall_extra` receives it);
 * `stack_va` is the child stack top (required with `CLONE_VM`).
 * Raw MIPS64 order (musl `src/thread/mips64/clone.s`, kernel
 * `SYSCALL_DEFINE5(clone, ..., parent_tidptr, child_tidptr, tls)`):
 * `a0` = flags, `a1` = stack, `a2` = parent_tid, `a3` = child_tid,
 * `a4` = tls (the new thread pointer, `ulr` via RDHWR 29, under
 * `CLONE_SETTLS`; x86 order has `tls`/`ctid` swapped — do not "fix"
 * this). Returns the
 * child guest tid, or a negative Linux errno (`-ENOSYS` without
 * `CLONE_VM`, `-EINVAL` on bad flag/address combinations, `-EAGAIN`
 * when full). */
long mips64_sys_clone(mips64_ctx_t *ctx, uint64_t flags, uint64_t stack_va,
                    uint64_t parent_tid_va, uint64_t child_tid_va,
                    uint64_t tls_va);

/* Full `futex` handler replacing the Phase-2 subset at `RC4`. `tmo_va`
 * is a guest timespec pointer for `WAIT`/`WAIT_BITSET` and an integer
 * requeue count for `REQUEUE`/`CMP_REQUEUE`/`WAKE_OP`. Returns the wake
 * count (or 0), or a negative Linux errno (`-EAGAIN` on value mismatch,
 * `-ETIMEDOUT` on expiry, `-EINVAL`/`-EFAULT` on bad args/addresses). */
long mips64_sys_futex_full(uint64_t uaddr, uint64_t op, uint64_t val,
                         uint64_t tmo_va, uint64_t uaddr2, uint64_t val3);

/* Calling thread's `CLONE_CHILD_CLEARTID` guest VA (0 on the main thread
 * or when the flag was absent). Used by the exit path and `join`. */
uint64_t mips64_clone_child_tid(void);

/* True when the caller runs on a `clone`-created worker thread. The
 * thread-aware `exit(2)` routing (lane L4c/coordinator, `minsys.c`)
 * calls `mips64_clone_thread_exit` in that case and process-exits
 * otherwise; `exit_group` always process-exits. */
int mips64_clone_is_worker(void);

/* Fork-lineage mute for `--difftest` lockstep (lane L6b): a fork child
 * opts its whole lineage out of tracing/verifying (its steps would
 * otherwise interleave nondeterministically into the single-stream
 * trace). The parent lineage stays fully traced and deterministic. */
void mips64_trace_mute(void);
int mips64_trace_muted(void);

/* Terminate the calling worker: store 0 to its clear-tid word, issue the
 * joining `FUTEX_WAKE`, drop its table slot, and end the host thread.
 * Never returns on a worker; returns 0 immediately on a non-worker so
 * the caller can fall back to process exit. */
long mips64_clone_thread_exit(long status);

/* Clear every live LL/SC reservation overlapping `[va, va+len)` except
 * the caller's (`self` may be NULL to clear all). The store path
 * (`interp_mem.h`/`interp_amo.c`, coordinator hook) calls this before
 * performing any guest store so a concurrent `SC` cannot spuriously
 * succeed; signal delivery and thread switches call
 * `mips64_clone_clear_ll` below. */
void mips64_clone_invalidate_ll(const mips64_ctx_t *self, uint64_t va,
                              uint64_t len);

/* Clear one context's reservation (signal delivery / thread switch /
 * `clone` child setup entry point). */
void mips64_clone_clear_ll(mips64_ctx_t *ctx);

/* Drop every stale DBT translation (calls `dbt_invalidate_all`). The
 * `munmap`/`mprotect` path (coordinator hook) calls this after changing
 * guest mappings; DBT block dispatch already revalidates the epoch
 * before entering translated code and ends blocks at syscalls, so a
 * thread switch or signal inside a block falls back to `interp`. */
void mips64_clone_mem_changed(void);

#endif /* MIPS64RT_RT64_RUNTIME_THREAD_H */
