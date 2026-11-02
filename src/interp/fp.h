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

/* Nonzero iff the raw bits are a signalling NaN (fp.c): */
int fp_issn_s(uint32_t u);
int fp_issn_d(uint64_t u);

/* Bit-cast and lane helpers shared by fp.c, fp_cvt.c and fp_ps.c: */
uint64_t fp_d_bits(double x);
double fp_bits_d(uint64_t u);
uint32_t fp_f_bits(float x);
float fp_bits_f(uint32_t u);
void fp_put_s(mips64_ctx_t *ctx, unsigned fd, uint32_t v);
void fp_put_d(mips64_ctx_t *ctx, unsigned fd, uint64_t v);
unsigned fp_rm(const mips64_ctx_t *ctx);
double fp_adj_d(double r, long double q, unsigned rm);
float fp_adj_f(float r, long double q, unsigned rm);
long double fp_rne_q(long double q);

/* Set FCSR cause + sticky flag for exception e (FP_EXC_*), or arm an
 * enabled IEEE exception trap (SIGFPE) when FCSR enable bit (7 + e) is set. */
void fp_raise(mips64_ctx_t *ctx, unsigned e);
void fp_clear_trap(void);
int fp_finish_trap(mips64_ctx_t *ctx, uint64_t cur_pc, unsigned fd,
    uint64_t saved_fpr, uint32_t saved_cc, int rc);

/* Flag a finished finite result: O (+I) on overflow to infinity,
 * I when the final value differs from the exact one. U is never set
 * (RC3 limitation, same in both engines). */
void fp_inexact(mips64_ctx_t *ctx, long double rf, long double q);

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

#endif /* MIPS64RT_INTERP_FP_H */
