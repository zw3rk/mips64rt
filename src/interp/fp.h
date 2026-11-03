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

/* FCSR exception indices for fp_raise: cause bit (12 + e), sticky flag
 * bit (2 + e). Matches the MIPS R2 layout the P3 suite checks
 * (V: 0x10040, Z: 0x8020, O: 0x40010, I: 0x1004): */
#define FP_EXC_I 0
#define FP_EXC_U 1
#define FP_EXC_O 2
#define FP_EXC_Z 3
#define FP_EXC_V 4

/* Execute one COP1 word: DMFC1/DMTC1, S/D arithmetic (ADD/SUB/MUL/DIV/
 * SQRT/ABS/NEG/MOV), the CVT/ROUND/TRUNC/CEIL/FLOOR family, C.cond, or
 * BC1T/BC1F/BC1TL/BC1FL. cur_pc must equal ctx->pc (the word's own
 * address). Returns 0 (advance pc by 4), MIPS_FAULT (fault recorded by
 * the caller), 1 (run stopped, exit_reason set), or FP_RC_BRANCH. */
int fp_cop1(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d);

/* Execute one COP1X word (MADD/MSUB/NMADD/NMSUB .S/.D only; everything
 * else faults). Same return contract as fp_cop1. */
int fp_cop1x(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d);

/* Legacy default quiet NaNs (E04-observed 0.0/0.0 results). */
#define FP_DEFNAN_S 0x7FBFFFFFu
#define FP_DEFNAN_D UINT64_C(0x7FF7FFFFFFFFFFFF)

/* FCSR flush-to-zero control bit (R7-15). */
#define FP_FS_BIT 24u

/* Default quiet NaN for the mode selected by ctx->nan2008 (R7-6):
 * legacy 0x7FBFFFFF/0x7FF7FFFFFFFFFFFF, 2008 0x7FC00000/0x7FF8.... */
uint32_t fp_defnan_s(const mips64_ctx_t *ctx);
uint64_t fp_defnan_d(const mips64_ctx_t *ctx);

/* Nonzero iff the raw bits are a signalling NaN under the selected
 * NaN mode (fp.c): legacy quiet bit is clear, 2008 quiet bit is set. */
int fp_issn_s(const mips64_ctx_t *ctx, uint32_t u);
int fp_issn_d(const mips64_ctx_t *ctx, uint64_t u);

/* Bit-cast and lane helpers shared by fp.c, fp_cvt.c and fp_ps.c: */
uint64_t fp_d_bits(double x);
double fp_bits_d(uint64_t u);
uint32_t fp_f_bits(float x);
float fp_bits_f(uint32_t u);
void fp_put_s(mips64_ctx_t *ctx, unsigned fd, uint32_t v);
void fp_put_d(mips64_ctx_t *ctx, unsigned fd, uint64_t v);
unsigned fp_rm(const mips64_ctx_t *ctx);
unsigned fp_get_cc(const mips64_ctx_t *ctx, unsigned cc);
float fp_adj_f(const mips64_ctx_t *ctx, float r, long double q,
    unsigned rm);
float fp_sqrt_adj_f(const mips64_ctx_t *ctx, float r, float x,
    unsigned rm);
int fp_cmp_sign(double x);
long double fp_rne_q(long double q);

/* Set FCSR cause + sticky flag for exception e (FP_EXC_*), or arm an
 * enabled IEEE exception trap (SIGFPE) when FCSR enable bit (7 + e) is set. */
void fp_raise(mips64_ctx_t *ctx, unsigned e);
void fp_clear_trap(void);
/* Start one arithmetic op (R7-12): clear trap state and replace the
 * Cause field; sticky Flags commit at fp_finish_trap (R7-13). */
void fp_begin_op(mips64_ctx_t *ctx);
int32_t fp_fcsr_sicode(uint32_t fcsr);
int fp_finish_trap(mips64_ctx_t *ctx, uint64_t cur_pc, unsigned fd,
    uint64_t saved_fpr, uint32_t saved_cc, int rc);
double fp_round_d(mips64_ctx_t *ctx, double r, int cmp, unsigned rm);

/* Flag a finished single-precision result: O (+I) on overflow,
 * U (+I) on tiny inexact (or trapped tiny), I when inexact. */
void fp_inexact(mips64_ctx_t *ctx, long double rf, long double q);

/* Shared single-precision exception bits for scalar and paired-single
 * lanes (defined in fp.c; the lane accumulates and raises per bit). */
unsigned fp_inexact_exc(mips64_ctx_t *ctx, long double rf, long double q);

/* MIPS CVT/round funct field values (destination selectors): */
#define FP_FN_ROUND_L 0x08u
#define FP_FN_TRUNC_L 0x09u
#define FP_FN_CEIL_L  0x0Au
#define FP_FN_FLOOR_L 0x0Bu
#define FP_FN_ROUND_W 0x0Cu
#define FP_FN_TRUNC_W 0x0Du
#define FP_FN_CEIL_W  0x0Eu
#define FP_FN_FLOOR_W 0x0Fu
#define FP_FN_CVT_S   0x20u
#define FP_FN_CVT_D   0x21u
#define FP_FN_CVT_W   0x24u
#define FP_FN_CVT_L   0x25u

/* Conversions (defined in fp_cvt.c): */
int fp_to_int(mips64_ctx_t *ctx, unsigned fd, long double q,
    unsigned funct);
int fp_cvt_sd(mips64_ctx_t *ctx, const mips_dec_t *d, unsigned is_s);
int fp_cvt_wl(mips64_ctx_t *ctx, const mips_dec_t *d, unsigned is_l);

/* Paired-single + COP1X (defined in fp_ps.c): */
int fp_ps_cop1(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d);

/* Conditional FPR moves MOVF/MOVT/MOVZ/MOVN .S/.D (fpmove.c, R7-18):
 * FCC/GPR predicate, full lane copy, no arithmetic side effects. */
int fp_cond_move(mips64_ctx_t *ctx, const mips_dec_t *d);

#endif /* MIPS64RT_INTERP_FP_H */
