/*
 * src/interp/fp_ps.c -- paired-single + COP1X fused multiply-add (RC3).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PS (fmt 0x16) scalar-lane ADD/SUB/MUL/ABS/NEG/MOV and COP1X MADD/MSUB/
 * NMADD/NMSUB (.S/.D, product rounded first, then the sum, both in
 * guest RM; NMSUB negates after rounding). Per-lane IEEE semantics
 * with MIPS R2 FCSR accounting shared with fp.c (V on invalid lanes,
 * I on inexact, U (+I) on FS-flushed tiny results, O (+I) on overflow
 * to infinity). DIV.PS/SQRT.PS/CVT.PS/
 * C.cond.PS and the indexed COP1X memory ops fault (untested by the
 * RC3 suite; DBT falls back to interp_step for every word here).
 */

#include <float.h>
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
 * when exception e fires on this lane). Rounding follows the guest
 * FCSR mode via the exact single-precision path shared with scalar
 * ADD.S/SUB.S/MUL.S (fp_adj_f + fp_inexact_exc), including the
 * symmetric absorbed-operand residual (R4-5/R4-6). */
static uint32_t fp_ps_lane(mips64_ctx_t *ctx, unsigned op, uint32_t au,
    uint32_t bu, unsigned *exc)
{
    float a = fp_bits_f(au);
    float b = fp_bits_f(bu);
    float r = 0.0f;
    long double q = 0.0L;
    unsigned rm = fp_rm(ctx);

    if (isnan(a) || isnan(b)) {
        if (fp_issn_s(ctx, au) != 0 || fp_issn_s(ctx, bu) != 0) {
            *exc |= 1u << (unsigned)FP_EXC_V;
        }
        return (ctx->nan2008 != 0u) ? FP_DEFNAN_S_2008 : FP_DEFNAN_S;
    }
    switch (op) {
    case 0x00u: /* ADD.PS */
        if (isinf(a) && isinf(b) &&
            ((signbit(a) != 0) != (signbit(b) != 0))) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return (ctx->nan2008 != 0u) ? FP_DEFNAN_S_2008 : FP_DEFNAN_S;
        }
        r = a + b;
        q = (long double)((double)a + (double)b);
        break;
    case 0x01u: /* SUB.PS */
        if (isinf(a) && isinf(b) &&
            ((signbit(a) != 0) == (signbit(b) != 0))) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return (ctx->nan2008 != 0u) ? FP_DEFNAN_S_2008 : FP_DEFNAN_S;
        }
        r = a - b;
        q = (long double)((double)a - (double)b);
        break;
    default: /* MUL.PS */
        if ((a == 0.0f && isinf(b)) || (isinf(a) && b == 0.0f)) {
            *exc |= 1u << (unsigned)FP_EXC_V;
            return (ctx->nan2008 != 0u) ? FP_DEFNAN_S_2008 : FP_DEFNAN_S;
        }
        r = a * b;
        q = (long double)a * (long double)b;
        break;
    }
    if ((op == 0x00u || op == 0x01u) && q == 0.0L && rm == 3u) {
        /* R7-16: exact cancellation under round-down yields -0,
         * like scalar ADD.S/SUB.S (fp_adj_f would keep +0). */
        int cancel = (op == 0x00u) ?
            ((signbit(a) != 0) != (signbit(b) != 0)) :
            ((signbit(a) != 0) == (signbit(b) != 0));

        if (cancel) {
            return fp_f_bits(-0.0f);
        }
    }
    if (op == 0x00u || op == 0x01u) {
        /* Absorbed-operand residual shared with scalar ADD.S/SUB.S:
         * either effective operand may vanish into the other, and the
         * lost sign steers directed rounding and Inexact. */
        double sb = (op == 0x01u) ? -(double)b : (double)b;
        double qd = (double)a + sb;
        double da = (double)a;

        if (isfinite(qd) != 0 && qd == da && sb != 0.0) {
            q = nextafterl((long double)r,
                           sb > 0.0 ? INFINITY : -INFINITY);
        } else if (isfinite(qd) != 0 && qd == sb && a != 0.0f) {
            q = nextafterl((long double)r,
                           a > 0.0f ? INFINITY : -INFINITY);
        }
    }
    {
        float rf = fp_adj_f(ctx, r, q, rm);

        *exc |= fp_inexact_exc(ctx, (long double)rf, q);
        return fp_f_bits(rf);
    }
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
        hi = fp_ps_lane(ctx, d->funct, (uint32_t)(ctx->fpr[fs] >> 32u),
            (uint32_t)(ctx->fpr[ft] >> 32u), &exc);
        lo = fp_ps_lane(ctx, d->funct, (uint32_t)ctx->fpr[fs],
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

/* COP1X multiply-add (op 0x13): fd = +/-(fr +/- fs * ft) with the
 * product rounded first, then the sum, both in guest RM (R7-8).
 * NaN inputs raise V and yield the default NaN. */
int fp_cop1x(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    unsigned fr = d->rs & 31u;
    unsigned ft = d->rt & 31u;
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    unsigned is_d = 0u;
    uint64_t saved_fpr;
    uint32_t saved_cc;

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
    saved_fpr = ctx->fpr[fd];
    saved_cc = ctx->fcsr & 0xFE800000u;
    fp_begin_op(ctx);
    if (is_d == 0u) {
        /* Snapshot sources before writeback (R7-7): fd may alias. */
        uint32_t au = (uint32_t)ctx->fpr[fr];
        uint32_t bu = (uint32_t)ctx->fpr[fs];
        uint32_t cu = (uint32_t)ctx->fpr[ft];
        float a = fp_bits_f(au);
        float b = fp_bits_f(bu);
        float c = fp_bits_f(cu);
        float rp;
        long double qp;
        float s1;
        float s2;
        float hs;
        long double q;
        float rs;
        unsigned rm = fp_rm(ctx);

        if (isnan(a) || isnan(b) || isnan(c)) {
            fp_put_s(ctx, fd, fp_defnan_s(ctx));
            if (fp_issn_s(ctx, au) != 0 || fp_issn_s(ctx, bu) != 0 ||
                fp_issn_s(ctx, cu) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        if ((isinf(b) && c == 0.0f) || (b == 0.0f && isinf(c))) {
            fp_put_s(ctx, fd, fp_defnan_s(ctx));
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        /* R7-8: R2 rounds the product first, then the sum, both in
         * guest RM; both steps contribute exceptions. */
        qp = (long double)b * (long double)c;
        rp = fp_adj_f(ctx, b * c, qp, rm);
        fp_inexact(ctx, (long double)rp, qp);
        if (d->funct == 0x20u) { /* MADD.S: fr + fs*ft */
            s1 = a;
            s2 = rp;
        } else if (d->funct == 0x28u) { /* MSUB.S: fs*ft - fr */
            s1 = rp;
            s2 = -a;
        } else if (d->funct == 0x30u) { /* NMADD.S: -(fr + fs*ft) */
            s1 = a;
            s2 = rp;
        } else { /* NMSUB.S: -(fs*ft - fr): round p - fr, then negate,
                  * so directed rounding (RP/RM) matches MIPS64r2. */
            s1 = rp;
            s2 = -a;
        }
        hs = s1 + s2;
        if (isnan(hs)) {
            fp_put_s(ctx, fd, fp_defnan_s(ctx));
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        q = (long double)s1 + (long double)s2;
        if (q == 0.0L && rm == 3u &&
            ((signbit(s1) != 0) != (signbit(s2) != 0))) {
            rs = -0.0f;
        } else {
            double ds1 = (double)s1;
            double ds2 = (double)s2;
            double qd = ds1 + ds2;
            long double qq = q;

            if (isfinite(qd) != 0 && qd == ds1 && ds2 != 0.0) {
                qq = nextafterl((long double)hs,
                    ds2 > 0.0 ? INFINITY : -INFINITY);
            } else if (isfinite(qd) != 0 && qd == ds2 && s1 != 0.0f) {
                qq = nextafterl((long double)hs,
                    s1 > 0.0f ? INFINITY : -INFINITY);
            } else {
                qq = (long double)qd;
            }
            rs = fp_adj_f(ctx, hs, qq, rm);
        }
        if (d->funct == 0x30u || d->funct == 0x38u) {
            rs = -rs;
            q = -q;
        }
        fp_put_s(ctx, fd, fp_f_bits(rs));
        fp_inexact(ctx, (long double)rs, q);
        return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
    }
    {
        /* Snapshot sources before writeback (R7-7): fd may alias. */
        uint64_t au = ctx->fpr[fr];
        uint64_t bu = ctx->fpr[fs];
        uint64_t cu = ctx->fpr[ft];
        double a = fp_bits_d(au);
        double b = fp_bits_d(bu);
        double c = fp_bits_d(cu);
        double rp;
        double s1;
        double s2;
        double hs;
        unsigned rm = fp_rm(ctx);

        if (isnan(a) || isnan(b) || isnan(c)) {
            fp_put_d(ctx, fd, fp_defnan_d(ctx));
            if (fp_issn_d(ctx, au) != 0 || fp_issn_d(ctx, bu) != 0 ||
                fp_issn_d(ctx, cu) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        if ((isinf(b) && c == 0.0) || (b == 0.0 && isinf(c))) {
            fp_put_d(ctx, fd, fp_defnan_d(ctx));
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        /* R7-8: R2 rounds the product first, then the sum, both in
         * guest RM; both steps contribute exceptions. */
        if (b == 0.0 || c == 0.0 || isinf(b) || isinf(c)) {
            rp = b * c; /* exact signed zero or infinity */
        } else {
            int eb;
            int ec;
            double mb = frexp(b, &eb);
            double mc = frexp(c, &ec);
            double hp = b * c;
            double mr = ldexp(hp, -(eb + ec));

            rp = fp_round_d(ctx, hp, fp_cmp_sign(fma(mb, mc, -mr)), rm);
        }
        if (d->funct == 0x21u) { /* MADD.D: fr + fs*ft */
            s1 = a;
            s2 = rp;
        } else if (d->funct == 0x29u) { /* MSUB.D: fs*ft - fr */
            s1 = rp;
            s2 = -a;
        } else if (d->funct == 0x31u) { /* NMADD.D: -(fr + fs*ft) */
            s1 = a;
            s2 = rp;
        } else { /* NMSUB.D: -(fs*ft - fr): round p - fr, then negate,
                  * so directed rounding (RP/RM) matches MIPS64r2. */
            s1 = rp;
            s2 = -a;
        }
        if (isinf(s1) && isinf(s2) &&
            ((signbit(s1) != 0) != (signbit(s2) != 0))) {
            fp_put_d(ctx, fd, fp_defnan_d(ctx));
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        hs = s1 + s2;
        if (isinf(s1) || isinf(s2)) {
            if (d->funct == 0x31u || d->funct == 0x39u) {
                hs = -hs;
            }
            fp_put_d(ctx, fd, fp_d_bits(hs));
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        if (hs == 0.0) {
            int cancel = (signbit(s1) != 0) != (signbit(s2) != 0);

            hs = (rm == 3u && cancel) ? -0.0 : hs;
            if (d->funct == 0x31u || d->funct == 0x39u) {
                hs = -hs;
            }
            fp_put_d(ctx, fd, fp_d_bits(hs));
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        if (!isfinite(hs)) {
            hs = fp_round_d(ctx, hs, (hs > 0.0) ? -1 : 1, rm);
            if (d->funct == 0x31u || d->funct == 0x39u) {
                hs = -hs;
            }
            fp_put_d(ctx, fd, fp_d_bits(hs));
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
        {
            double a1 = hs - s2;
            double b1 = hs - a1;
            double err = (s1 - a1) + (s2 - b1);

            hs = fp_round_d(ctx, hs, fp_cmp_sign(err), rm);
            if (d->funct == 0x31u || d->funct == 0x39u) {
                hs = -hs;
            }
            fp_put_d(ctx, fd, fp_d_bits(hs));
            return fp_finish_trap(ctx, cur_pc, fd, saved_fpr, saved_cc, 0);
        }
    }
}
