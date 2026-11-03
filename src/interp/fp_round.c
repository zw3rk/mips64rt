/*
 * src/interp/fp_round.c -- directed rounding + FCSR accounting (R7-15).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from fp.c so every TU stays <= 900 lines: single-precision
 * O/U/I bits, directed binary64 rounding, FPR lane writeback, the RNE
 * quad helper, and the FS flush-to-zero control (FCSR bit 24). With
 * FS set, a subnormal result flushes to signed zero: the operation is
 * still inexact (I), but no underflow (U) is reported.
 */

#include <float.h>
#include <math.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/fp.h"

/* Single-precision O/U/I bits for rf vs exact q (R4-6 shared path). */
unsigned fp_inexact_exc(mips64_ctx_t *ctx, long double rf, long double q)
{
    unsigned exc = 0u;

    if (ctx != NULL && (ctx->fcsr & (1u << FP_FS_BIT)) != 0u &&
        rf == 0.0L && q != 0.0L && fabsl(q) < (long double)FLT_MIN) {
        /* FS-flushed tiny result (fp_adj_f zeroed it): the operation
         * is inexact, but flushing suppresses underflow. */
        return 1u << (unsigned)FP_EXC_I;
    }
    if (((isinf(rf) != 0) || (isinf((float)q) != 0)) &&
        (isinf(q) == 0)) {
        return (1u << (unsigned)FP_EXC_O) | (1u << (unsigned)FP_EXC_I);
    }
    if (q != 0.0L && fabsl(q) < (long double)FLT_MIN) {
        if (rf != q ||
            (ctx->fcsr & (1u << (7u + (unsigned)FP_EXC_U))) != 0u) {
            exc |= 1u << (unsigned)FP_EXC_U;
        }
    }
    if (rf != q) {
        exc |= 1u << (unsigned)FP_EXC_I;
    }
    return exc;
}

/* Raise O/U/I for finished single result rf vs exact q. */
void fp_inexact(mips64_ctx_t *ctx, long double rf, long double q)
{
    unsigned exc = fp_inexact_exc(ctx, rf, q);
    unsigned e;

    for (e = 0u; e <= (unsigned)FP_EXC_V; e++) {
        if ((exc & (1u << e)) != 0u) {
            fp_raise(ctx, e);
        }
    }
}

/* Directed binary64 rounding of RNE r by residual sign cmp. */
double fp_round_d(mips64_ctx_t *ctx, double r, int cmp, unsigned rm)
{
    double rf = r;
    int is_tiny;

    if (!isfinite(r)) {
        if (rm == 1u) {
            rf = (r > 0.0) ? DBL_MAX : -DBL_MAX;
        } else if (rm == 2u) {
            rf = (r > 0.0) ? INFINITY : -DBL_MAX;
        } else if (rm == 3u) {
            rf = (r > 0.0) ? DBL_MAX : -INFINITY;
        }
        fp_raise(ctx, (unsigned)FP_EXC_O);
        fp_raise(ctx, (unsigned)FP_EXC_I);
        return rf;
    }
    if (cmp != 0) {
        if (rm == 1u) {
            if ((r > 0.0 && cmp < 0) || (r < 0.0 && cmp > 0)) {
                rf = nextafter(r, 0.0);
            }
        } else if (rm == 2u) {
            if (cmp > 0) {
                rf = nextafter(r, INFINITY);
            }
        } else if (rm == 3u) {
            if (cmp < 0) {
                rf = nextafter(r, -INFINITY);
            }
        }
    }
    if (!isfinite(rf)) {
        fp_raise(ctx, (unsigned)FP_EXC_O);
        fp_raise(ctx, (unsigned)FP_EXC_I);
        return rf;
    }
    if (ctx != NULL && (ctx->fcsr & (1u << FP_FS_BIT)) != 0u &&
        rf != 0.0 && isfinite(rf) != 0 && isnormal(rf) == 0) {
        /* FS flush (R7-15): subnormal result becomes signed zero;
         * inexact, but no underflow is reported. */
        rf = signbit(rf) != 0 ? -0.0 : 0.0;
        fp_raise(ctx, (unsigned)FP_EXC_I);
        return rf;
    }
    is_tiny = (fabs(r) < DBL_MIN && (r != 0.0 || cmp != 0)) ||
              (fabs(r) == DBL_MIN &&
               ((r > 0.0 && cmp < 0) || (r < 0.0 && cmp > 0)));
    if (is_tiny &&
        (cmp != 0 ||
         (ctx->fcsr & (1u << (7u + (unsigned)FP_EXC_U))) != 0u)) {
        fp_raise(ctx, (unsigned)FP_EXC_U);
    }
    if (cmp != 0) {
        fp_raise(ctx, (unsigned)FP_EXC_I);
    }
    return rf;
}

/* S write: low lane replaced, upper preserved (FR=1). */
void fp_put_s(mips64_ctx_t *ctx, unsigned fd, uint32_t v)
{
    ctx->fpr[fd] = (ctx->fpr[fd] & UINT64_C(0xFFFFFFFF00000000)) | v;
}

void fp_put_d(mips64_ctx_t *ctx, unsigned fd, uint64_t v)
{
    ctx->fpr[fd] = v;
}

float fp_adj_f(const mips64_ctx_t *ctx, float r, long double q, unsigned rm)
{
    long double lr;
    float rf = r;

    if (rm != 0u) {
        lr = (long double)r;
        if (lr != q) {
            switch (rm) {
            case 1u:
                rf = (fabsl(q) < fabsl(lr)) ? nextafterf(r, 0.0f) : r;
                break;
            case 2u:
                rf = (q > lr) ? nextafterf(r, INFINITY) : r;
                break;
            default:
                rf = (q < lr) ? nextafterf(r, -INFINITY) : r;
                break;
            }
        }
    }
    if (ctx != NULL && (ctx->fcsr & (1u << FP_FS_BIT)) != 0u &&
        rf != 0.0f && isfinite(rf) != 0 && isnormal(rf) == 0) {
        /* FS flush (R7-15): subnormal result becomes signed zero. */
        rf = signbit(rf) != 0 ? -0.0f : 0.0f;
    }
    return rf;
}

/* Directed sqrt fixup: r*r is exact in quad; compare vs x. */
float fp_sqrt_adj_f(const mips64_ctx_t *ctx, float r, float x, unsigned rm)
{
    long double sq;
    float rf = r;

    if (rm != 0u) {
        sq = (long double)r * (long double)r;
        if (rm == 2u) {
            rf = (sq < (long double)x) ? nextafterf(r, INFINITY) : r;
        } else {
            rf = (sq > (long double)x) ? nextafterf(r, 0.0f) : r;
        }
    }
    if (ctx != NULL && (ctx->fcsr & (1u << FP_FS_BIT)) != 0u &&
        rf != 0.0f && isfinite(rf) != 0 && isnormal(rf) == 0) {
        /* FS flush (R7-15): subnormal result becomes signed zero. */
        rf = signbit(rf) != 0 ? -0.0f : 0.0f;
    }
    return rf;
}

/* Round quad q to integer, ties to even. */
long double fp_rne_q(long double q)
{
    long double lo = truncl(q);
    long double d = q - lo;
    long double ad = fabsl(d);
    long double half;

    if (ad < 0.5L) {
        return lo;
    }
    if (ad > 0.5L) {
        return lo + ((q > 0.0L) ? 1.0L : -1.0L);
    }
    half = lo * 0.5L;
    if (half == truncl(half)) {
        return lo;
    }
    return lo + ((q > 0.0L) ? 1.0L : -1.0L);
}

int fp_cmp_sign(double x)
{
    return (x > 0.0) ? 1 : ((x < 0.0) ? -1 : 0);
}
