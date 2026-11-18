/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 signal core: guest signal trampoline placement and LL/SC
 * reservation discipline. Full `rt_sigframe` construction/restoration lands
 * in Phase 4 (lane L4a); this module fixes the address contract now so later
 * lanes build on a frozen constant.
 */
#ifndef MIPS64RT_OS_SIGNAL_CORE_H
#define MIPS64RT_OS_SIGNAL_CORE_H

#include "core/cpu.h"

/* Signal trampoline: one reserved page at the frozen per-ABI placement
 * (SPEC 2.1): `MIPS64_N64_SIGTRAMP` below `MIPS64_N64_TASK_SIZE`,
 * `MIPS64_N32_SIGTRAMP` below `MIPS64_N32_TASK_SIZE`. */
uint64_t mips64_signal_trampoline_addr(int is_n32);
void mips64_ctx_clear_ll(mips64_ctx_t *ctx);
int mips64_sigpend_enqueue(mips64_ctx_t *ctx, uint32_t signo, int32_t code,
                           int32_t errnum, uint64_t addr);
/* MIPS SIGCHLD (asm/signal.h) and CLD_EXITED si_code. */
#define MIPS64_SIGCHLD 18
#define MIPS64_CLD_EXITED 1
/* MIPS SA_NOCLDSTOP/SA_RESTART (asm/signal.h): the guest SIGCHLD flags
 * driving the host bridge (waitid report set + SA_NOCLDSTOP install;
 * SA_RESTART never reaches the host) and guest syscall restart. */
#define MIPS64_SA_NOCLDSTOP UINT64_C(0x00000001)
#define MIPS64_SA_RESTART UINT64_C(0x10000000)
void mips64_sig_defer_restore(const uint64_t old[2]);
int mips64_sig_take_saved(uint64_t out[2]);
void mips64_sig_restore_saved(mips64_ctx_t *ctx);
void mips64_host_sigchld_arm(uint64_t guest_flags);
int mips64_host_sigchld_armed(void);
void mips64_host_sigchld_disarm(void);
void mips64_host_sigchld_fork_child(void);
void mips64_host_sigchld_poll(mips64_ctx_t *ctx);
int mips64_sigchld_info(uint32_t *pid, uint32_t *uid, int32_t *status,
                        int32_t *code);
int mips64_host_eintr_retry(mips64_ctx_t *ctx);
int mips64_sig_deliverable(const mips64_ctx_t *ctx, const uint64_t mask[2]);
/* 1 when nr names a restartable guest syscall for SA_RESTART. */
int mips64_syscall_restartable(uint64_t nr, int is_n32);
/* Syscall-exit sweep: deliver the first unblocked handled signal,
 * restarting a -EINTR restartable syscall under SA_RESTART. */
void mips64_sc_deliver_pending(mips64_ctx_t *ctx, uint64_t orig_v0,
                               uint64_t orig_a3, int64_t raw_rc);
void mips_trap_code(mips64_ctx_t *ctx, int signo, int32_t code, uint64_t addr);
void mips_insn_trap_code(mips64_ctx_t *ctx, int signo, int32_t code,
                         uint64_t addr);

#endif
