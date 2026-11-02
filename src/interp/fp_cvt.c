/*
 * src/interp/fp_cvt.c -- COP1 conversions (lane L3a split of fp.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CVT.S/D and CVT.W/L plus fixed ROUND/TRUNC/CEIL/FLOOR, with MIPS R2
 * FCSR cause/flag accounting (V on invalid, I on inexact narrowing or
 * dropped fraction).
 */

#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/fp.h"

/* Integer-destination conversion: CVT.W/L (current FCSR RM) and
 * ROUND/TRUNC/CEIL/FLOOR.W/L (fixed modes). q is the exact source value.
 * Out-of-range/NaN/Inf saturate to the MIPS indefinite values and raise
 * V; a dropped fraction raises I. */
int fp_to_int(mips64_ctx_t *ctx, unsigned fd, long double q,
                     unsigned funct)
{
    int is64 = (funct == FP_FN_ROUND_L || funct == FP_FN_TRUNC_L ||
                funct == FP_FN_CEIL_L || funct == FP_FN_FLOOR_L ||
                funct == FP_FN_CVT_L);
    long double t;
    unsigned mode = fp_rm(ctx);

    if (isnan(q) || isinf(q)) {
        if (is64) {
            fp_put_d(ctx, fd, UINT64_C(0x7FFFFFFFFFFFFFFF));
        } else {
            fp_put_s(ctx, fd, 0x7FFFFFFFu);
        }
        fp_raise(ctx, (unsigned)FP_EXC_V);
        return 0;
    }
    switch (funct) {
    case FP_FN_ROUND_W:
    case FP_FN_ROUND_L:
        t = fp_rne_q(q);
        break;
    case FP_FN_TRUNC_W:
    case FP_FN_TRUNC_L:
        t = truncl(q);
        break;
    case FP_FN_CEIL_W:
    case FP_FN_CEIL_L:
        t = ceill(q);
        break;
    case FP_FN_FLOOR_W:
    case FP_FN_FLOOR_L:
        t = floorl(q);
        break;
    default: /* CVT.W / CVT.L: current rounding mode */
        switch (mode) {
        case 1u:
            t = truncl(q);
            break;
        case 2u:
            t = ceill(q);
            break;
        case 3u:
            t = floorl(q);
            break;
        default:
            t = fp_rne_q(q);
            break;
        }
        break;
    }
    if (is64) {
        if (t >= 0x1p63L || t < -0x1p63L) {
            fp_put_d(ctx, fd, UINT64_C(0x7FFFFFFFFFFFFFFF));
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        fp_put_d(ctx, fd, (uint64_t)(int64_t)t);
        if (t != q) {
            fp_raise(ctx, (unsigned)FP_EXC_I);
        }
        return 0;
    }
    if (t >= 0x1p31L || t < -0x1p31L) {
        fp_put_s(ctx, fd, 0x7FFFFFFFu);
        fp_raise(ctx, (unsigned)FP_EXC_V);
        return 0;
    }
    fp_put_s(ctx, fd, (uint32_t)(int32_t)t);
    if (t != q) {
        fp_raise(ctx, (unsigned)FP_EXC_I);
    }
    return 0;
}

/* CVT.S/D destination from an S/D/W/L source lane. NaN sources yield the
 * default quiet NaN of the destination format. */
int fp_cvt_sd(mips64_ctx_t *ctx, const mips_dec_t *d, unsigned is_s)
{
    unsigned fd = d->sa;
    unsigned fs = d->rd;
    unsigned rm = fp_rm(ctx);

    if (d->funct == FP_FN_CVT_S) {
        if (is_s) { /* CVT.S.S: lane copy */
            fp_put_d(ctx, fd, ctx->fpr[fs]);
            return 0;
        }
        {
            double x = fp_bits_d(ctx->fpr[fs]);
            float r = (float)x;

            if (isnan(x)) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                return 0;
            }
            {
                float rf = fp_adj_f(r, (long double)x, rm);

                fp_put_s(ctx, fd, fp_f_bits(rf));
                fp_inexact(ctx, (long double)rf, (long double)x);
                return 0;
            }
        }
    }
    if (d->funct == FP_FN_CVT_D) {
        if (is_s) {
            float x = fp_bits_f((uint32_t)ctx->fpr[fs]);

            if (isnan(x)) {
                fp_put_d(ctx, fd, FP_DEFNAN_D);
                return 0;
            }
            fp_put_d(ctx, fd, fp_d_bits((double)x));
            return 0;
        }
        fp_put_d(ctx, fd, ctx->fpr[fs]);
        return 0;
    }
    if (d->funct == FP_FN_CVT_W || d->funct == FP_FN_CVT_L) {
        long double q;

        if (is_s) {
            float x = fp_bits_f((uint32_t)ctx->fpr[fs]);

            if (isnan(x)) {
                if (d->funct == FP_FN_CVT_L) {
                    fp_put_d(ctx, fd, UINT64_C(0x7FFFFFFFFFFFFFFF));
                } else {
                    fp_put_s(ctx, fd, 0x7FFFFFFFu);
                }
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            q = (long double)x;
        } else {
            double x = fp_bits_d(ctx->fpr[fs]);

            if (isnan(x)) {
                if (d->funct == FP_FN_CVT_L) {
                    fp_put_d(ctx, fd, UINT64_C(0x7FFFFFFFFFFFFFFF));
                } else {
                    fp_put_s(ctx, fd, 0x7FFFFFFFu);
                }
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            q = (long double)x;
        }
        return fp_to_int(ctx, fd, q, d->funct);
    }
    return MIPS_FAULT;
}

/* Exact signed-integer-to-FP conversion with host-independent 64-bit
 * mantissa rounding (prec = 24 for S, 53 for D) and FCSR Inexact (I)
 * accounting. */
static double fp_int_to_fp(mips64_ctx_t *ctx, int64_t v, unsigned prec,
                           unsigned rm)
{
    int neg = (v < 0);
    uint64_t mag = neg ? (UINT64_C(0) - (uint64_t)v) : (uint64_t)v;
    unsigned bw = 0u;
    uint64_t tmp = mag;
    double res;

    if (mag == 0u) {
        return 0.0;
    }
    while (tmp != 0u) {
        bw++;
        tmp >>= 1u;
    }
    if (bw <= prec) {
        res = (double)mag;
        return neg ? -res : res;
    }
    {
        unsigned shift = bw - prec;
        uint64_t sig = mag >> shift;
        uint64_t rem = mag & ((UINT64_C(1) << shift) - 1u);
        uint64_t half = UINT64_C(1) << (shift - 1u);
        uint64_t inc = 0u;

        if (rem != 0u) {
            fp_raise(ctx, (unsigned)FP_EXC_I);
            switch (rm) {
            case 0u:
                if (rem > half || (rem == half && (sig & 1u) != 0u)) {
                    inc = 1u;
                }
                break;
            case 2u:
                if (!neg) {
                    inc = 1u;
                }
                break;
            case 3u:
                if (neg) {
                    inc = 1u;
                }
                break;
            default:
                break;
            }
        }
        res = ldexp((double)(sig + inc), (int)shift);
        return neg ? -res : res;
    }
}

/* CVT.S/D destination from a W/L integer source lane. */
int fp_cvt_wl(mips64_ctx_t *ctx, const mips_dec_t *d, unsigned is_l)
{
    unsigned fd = d->sa;
    unsigned fs = d->rd;
    unsigned rm = fp_rm(ctx);
    int64_t v = is_l ? (int64_t)ctx->fpr[fs] : (int64_t)(int32_t)ctx->fpr[fs];

    if (d->funct == FP_FN_CVT_S) {
        float rf = (float)fp_int_to_fp(ctx, v, 24u, rm);

        fp_put_s(ctx, fd, fp_f_bits(rf));
        return 0;
    }
    if (d->funct == FP_FN_CVT_D) {
        double rf = fp_int_to_fp(ctx, v, 53u, rm);

        fp_put_d(ctx, fd, fp_d_bits(rf));
        return 0;
    }
    return MIPS_FAULT;
}
