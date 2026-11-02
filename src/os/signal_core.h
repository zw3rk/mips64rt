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
void mips_trap_code(mips64_ctx_t *ctx, int signo, int32_t code, uint64_t addr);
void mips_insn_trap_code(mips64_ctx_t *ctx, int signo, int32_t code,
                         uint64_t addr);

#endif
