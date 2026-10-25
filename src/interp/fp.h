/*
 * src/interp/fp.h — COP1 scalar FPU entry point (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MIPS64RT_INTERP_FP_H
#define MIPS64RT_INTERP_FP_H

#include <stdint.h>

#include "core/cpu.h"

/* Branch completed with ctx->pc already final. Same contract as the
 * dispatcher-moved-pc path in interp.c: the caller must NOT advance pc
 * itself and must set next_pc = pc + 4. */
#define FP_RC_BRANCH 2

/* Execute one COP1 word: DMFC1/DMTC1, S/D arithmetic (ADD/SUB/MUL/DIV/
 * SQRT/ABS/NEG/MOV), the CVT/ROUND/TRUNC/CEIL/FLOOR family, C.cond, or
 * BC1T/BC1F/BC1TL/BC1FL. cur_pc must equal ctx->pc (the word's own
 * address). Returns 0 (advance pc by 4), MIPS_FAULT (fault recorded by
 * the caller), 1 (run stopped, exit_reason set), or FP_RC_BRANCH. */
int fp_cop1(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d);

#endif /* MIPS64RT_INTERP_FP_H */
