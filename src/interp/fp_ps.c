/*
 * src/interp/fp_ps.c -- paired-single + COP1X fused multiply-add (RC3).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PS (fmt 0x16) scalar-lane ADD/SUB/MUL/ABS/NEG/MOV and COP1X MADD/MSUB/
 * NMADD/NMSUB (.S/.D). Per-lane IEEE semantics with MIPS R2 FCSR
 * accounting shared with fp.c (V on invalid lanes, I on inexact,
 * O (+I) on overflow to infinity; U never set). DIV.PS/SQRT.PS/CVT.PS/
 * C.cond.PS and the indexed COP1X memory ops fault (untested by the
 * RC3 suite; DBT falls back to interp_step for every word here).
 */

#include <math.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"

static int fp_cop1x_mem(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    uint64_t addr = ctx->gpr[d->rs] + ctx->gpr[d->rt];
    unsigned fd = d->sa & 31u;
    unsigned fs = d->rd & 31u;
    int be = mips_is_be(ctx);
    unsigned i;

    if (d->funct == 0x0Fu) { /* PREFX */
        return 0;
    }
    if (d->funct == 0x05u || d->funct == 0x0Du) { /* LUXC1 / SUXC1 */
        addr &= ~UINT64_C(7);
    } else if (d->funct == 0x00u || d->funct == 0x08u) { /* LWXC1 / SWXC1 */
        if ((addr & 3u) != 0u) {
            mips_fault(ctx, addr);
            return MIPS_FAULT;
        }
    } else if (d->funct == 0x01u || d->funct == 0x09u) { /* LDXC1 / SDXC1 */
        if ((addr & 7u) != 0u) {
            mips_fault(ctx, addr);
            return MIPS_FAULT;
        }
    } else {
        return MIPS_FAULT;
    }
    if (d->funct == 0x00u) { /* LWXC1 */
        uint32_t w = 0u;

        for (i = 0u; i < 4u; i++) {
            uint64_t b = 0u;

            if (guest_ld8(ctx, addr + i, &b) != 0)
                return MIPS_FAULT;
            w |= (uint32_t)(b & 0xFFu) << (8u * (be ? (3u - i) : i));
        }
        ctx->fpr[fd] = (ctx->fpr[fd] & UINT64_C(0xFFFFFFFF00000000)) | w;
        return 0;
    }
    if (d->funct == 0x08u) { /* SWXC1 */
        uint32_t w = (uint32_t)ctx->fpr[fs];

        for (i = 0u; i < 4u; i++) {
            unsigned p = be ? (3u - i) : i;

            if (guest_st8(ctx, addr + i, (w >> (8u * p)) & 0xFFu) != 0)
                return MIPS_FAULT;
        }
        return 0;
    }
    if (d->funct == 0x01u || d->funct == 0x05u) { /* LDXC1 / LUXC1 */
        uint64_t v = 0u;

        for (i = 0u; i < 8u; i++) {
            uint64_t b = 0u;

            if (guest_ld8(ctx, addr + i, &b) != 0)
                return MIPS_FAULT;
            v |= (b & 0xFFu) << (8u * (be ? (7u - i) : i));
        }
        ctx->fpr[fd] = v;
        return 0;
    }
    { /* SDXC1 / SUXC1 */
        uint64_t v = ctx->fpr[fs];

        for (i = 0u; i < 8u; i++) {
            unsigned p = be ? (7u - i) : i;

            if (guest_st8(ctx, addr + i,
                          (uint32_t)((v >> (8u * p)) & 0xFFu)) != 0)
                return MIPS_FAULT;
        }
        return 0;
    }
}

/* One PS lane: op selects ADD/SUB/MUL on raw 32-bit lanes au/bu.
 * Returns the result lane; *exc accumulates FP_EXC_* bits (bit e set
 * when exception e fires on this lane). */
static uint32_t fp_ps_lane(unsigned op, uint32_t au, uint32_t bu,
    unsigned *exc)
{
    float a = fp_bits_f(au);
    float b = fp_bits_f(bu);
    float r = 0.0f;
    long double q = 0.0L;

    if (isnan(a) || isnan(b)) {
        if (fp_issn_s(au) != 0 || fp_issn_s(bu) != 0) {
            *exc |= 1u << (unsigned)FP_EXC_V;
        }
        return FP_DEFNAN_S;
    }
    switch (op) {
    case 0x00u: /* ADD.PS */
        if (isinf(a) && isinf(b) &&
            ((signbit(a) != 0) != (signbit(b) != 0))) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return FP_DEFNAN_S;
        }
        r = a + b;
        q = (long double)a + (long double)b;
        break;
    case 0x01u: /* SUB.PS */
        if (isinf(a) && isinf(b) &&
            ((signbit(a) != 0) == (signbit(b) != 0))) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return FP_DEFNAN_S;
        }
        r = a - b;
        q = (long double)a - (long double)b;
        break;
    default: /* MUL.PS */
        if ((a == 0.0f && isinf(b)) || (isinf(a) && b == 0.0f)) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return FP_DEFNAN_S;
        }
        r = a * b;
        q = (long double)a * (long double)b;
        break;
    }
    if ((isinf((double)r) != 0) && (isinf(q) == 0)) {
        *exc |= (1u << (unsigned)FP_EXC_O) | (1u << (unsigned)FP_EXC_I);
    } else if ((long double)r != q) {
        *exc |= 1u << (unsigned)FP_EXC_I;
    }
    return fp_f_bits(r);
}

/* Paired-single arithmetic (fmt 0x16 in d->rs). */
int fp_ps_cop1(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    unsigned fs = d->rd & 31u;
    unsigned ft = d->rt & 31u;
    unsigned fd = d->sa & 31u;
    unsigned exc = 0u;
    uint32_t hi;
    uint32_t lo;
    unsigned e;

    (void)cur_pc;
    if (d->rs != 0x16u) {
        return MIPS_FAULT;
    }
    if (fs >= 32u || ft >= 32u || fd >= 32u) {
        return MIPS_FAULT;
    }
    switch (d->funct) {
    case 0x00u: /* ADD.PS */
    case 0x01u: /* SUB.PS */
    case 0x02u: /* MUL.PS */
        hi = fp_ps_lane(d->funct, (uint32_t)(ctx->fpr[fs] >> 32u),
            (uint32_t)(ctx->fpr[ft] >> 32u), &exc);
        lo = fp_ps_lane(d->funct, (uint32_t)ctx->fpr[fs],
            (uint32_t)ctx->fpr[ft], &exc);
        ctx->fpr[fd] = ((uint64_t)hi << 32u) | lo;
        break;
    case 0x05u: /* ABS.PS: bitwise per lane */
        ctx->fpr[fd] = ctx->fpr[fs] & UINT64_C(0x7FFFFFFF7FFFFFFF);
        return 0;
    case 0x06u: /* MOV.PS: full 64-bit lane copy */
        ctx->fpr[fd] = ctx->fpr[fs];
        return 0;
    case 0x07u: /* NEG.PS: bitwise per lane */
        ctx->fpr[fd] = ctx->fpr[fs] ^ UINT64_C(0x8000000080000000);
        return 0;
    default:
        return MIPS_FAULT;
    }
    for (e = 0u; e <= (unsigned)FP_EXC_V; e++) {
        if ((exc & (1u << e)) != 0u) {
            fp_raise(ctx, e);
        }
    }
    return 0;
}

/* COP1X fused multiply-add (op 0x13): fd = +/-(fr +/- fs * ft) with a
 * single rounding. NaN inputs raise V and yield the default NaN. */
int fp_cop1x(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    unsigned fr = d->rs & 31u;
    unsigned ft = d->rt & 31u;
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    unsigned is_d = 0u;

    (void)cur_pc;
    if (d->op != 0x13u) {
        return MIPS_FAULT;
    }
    switch (d->funct) {
    case 0x00u: /* LWXC1 */
    case 0x01u: /* LDXC1 */
    case 0x05u: /* LUXC1 */
    case 0x08u: /* SWXC1 */
    case 0x09u: /* SDXC1 */
    case 0x0Du: /* SUXC1 */
    case 0x0Fu: /* PREFX */
        return fp_cop1x_mem(ctx, d);
    case 0x20u: /* MADD.S */
    case 0x28u: /* MSUB.S */
    case 0x30u: /* NMADD.S */
    case 0x38u: /* NMSUB.S */
        is_d = 0u;
        break;
    case 0x21u: /* MADD.D */
    case 0x29u: /* MSUB.D */
    case 0x31u: /* NMADD.D */
    case 0x39u: /* NMSUB.D */
        is_d = 1u;
        break;
    default:
        return MIPS_FAULT;
    }
    if (fr >= 32u || ft >= 32u || fs >= 32u || fd >= 32u) {
        return MIPS_FAULT;
    }
    if (is_d == 0u) {
        float a = fp_bits_f((uint32_t)ctx->fpr[fr]);
        float b = fp_bits_f((uint32_t)ctx->fpr[fs]);
        float c = fp_bits_f((uint32_t)ctx->fpr[ft]);
        float r;
        long double q;

        if (isnan(a) || isnan(b) || isnan(c)) {
            fp_put_s(ctx, fd, FP_DEFNAN_S);
            if (fp_issn_s((uint32_t)ctx->fpr[fr]) != 0 ||
                fp_issn_s((uint32_t)ctx->fpr[fs]) != 0 ||
                fp_issn_s((uint32_t)ctx->fpr[ft]) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return 0;
        }
        if ((isinf(b) && c == 0.0f) || (b == 0.0f && isinf(c))) {
            fp_put_s(ctx, fd, FP_DEFNAN_S);
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        if (d->funct == 0x20u) { /* MADD.S: fr + fs*ft */
            r = fmaf(b, c, a);
            q = (long double)a + (long double)b * (long double)c;
        } else if (d->funct == 0x28u) { /* MSUB.S: fs*ft - fr */
            r = fmaf(b, c, -a);
            q = (long double)b * (long double)c - (long double)a;
        } else if (d->funct == 0x30u) { /* NMADD.S */
            r = -fmaf(b, c, a);
            q = -((long double)a + (long double)b * (long double)c);
        } else { /* NMSUB.S: fr - fs*ft */
            r = fmaf(-b, c, a);
            q = (long double)a - (long double)b * (long double)c;
        }
        if (isnan(r)) {
            fp_put_s(ctx, fd, FP_DEFNAN_S);
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        fp_put_s(ctx, fd, fp_f_bits(r));
        fp_inexact(ctx, (long double)r, q);
        return 0;
    }
    {
        double a = fp_bits_d(ctx->fpr[fr]);
        double b = fp_bits_d(ctx->fpr[fs]);
        double c = fp_bits_d(ctx->fpr[ft]);
        double r;
        long double q;

        if (isnan(a) || isnan(b) || isnan(c)) {
            fp_put_d(ctx, fd, FP_DEFNAN_D);
            if (fp_issn_d(ctx->fpr[fr]) != 0 ||
                fp_issn_d(ctx->fpr[fs]) != 0 ||
                fp_issn_d(ctx->fpr[ft]) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return 0;
        }
        if ((isinf(b) && c == 0.0) || (b == 0.0 && isinf(c))) {
            fp_put_d(ctx, fd, FP_DEFNAN_D);
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        if (d->funct == 0x21u) { /* MADD.D: fr + fs*ft */
            r = fma(b, c, a);
            q = (long double)a + (long double)b * (long double)c;
        } else if (d->funct == 0x29u) { /* MSUB.D: fs*ft - fr */
            r = fma(b, c, -a);
            q = (long double)b * (long double)c - (long double)a;
        } else if (d->funct == 0x31u) { /* NMADD.D */
            r = -fma(b, c, a);
            q = -((long double)a + (long double)b * (long double)c);
        } else { /* NMSUB.D: fr - fs*ft */
            r = fma(-b, c, a);
            q = (long double)a - (long double)b * (long double)c;
        }
        if (isnan(r)) {
            fp_put_d(ctx, fd, FP_DEFNAN_D);
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        fp_put_d(ctx, fd, fp_d_bits(r));
        fp_inexact(ctx, (long double)r, q);
        return 0;
    }
}
