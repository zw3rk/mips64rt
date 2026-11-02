/*
 * src/interp/fp.c — COP1 scalar S/D FPU for the reference interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 3 lane L3a: scalar single/double COP1 — ADD/SUB/MUL/DIV/SQRT/
 * ABS/NEG/MOV, the CVT/ROUND/TRUNC/CEIL/FLOOR family, C.cond compares +
 * FCC condition bits, BC1T/BC1F/BC1TL/BC1FL with RC1 delay-slot/annul
 * rules, and DMFC1/DMTC1. FR=1 64-bit FPR lanes; S-format results occupy
 * the low 32 bits with the upper lane preserved (the fpmove.c LWC1/MTC1
 * discipline). COP1X/MSA (paired-single, MSA) keep faulting; see the
 * lane commit for the SIMD adjudication.
 *
 * Oracle model (qemu-mips64el/qemu-mips64 user 10.0.13 per E04, legacy
 * NaN toolchain default EF_MIPS_NAN2008==0, qemu master fpu_helper.c for
 * value-level details):
 * - Any NaN operand (quiet or signalling shapes) or invalid combination
 *   (0/0, Inf-Inf, 0*Inf, Inf/Inf, sqrt of a negative) yields the legacy
 *   default quiet NaN (S 0x7FBFFFFF, D 0x7FF7FFFFFFFFFFFF, E04-observed)
 *   with NO FCSR Cause/Flag update (E04: qemu leaves FCSR zero across
 *   the whole NaN run, including 0.0/0.0). Cause/Flag fields are
 *   otherwise preserved untouched (sticky).
 * - ABS/NEG are bitwise (sign-bit clear/flip, payloads bit-exact).
 * - ROUND.W/L round to nearest-even (qemu float_round_* uses
 *   float_round_nearest_even); TRUNC/CEIL/FLOOR use their fixed mode
 *   and CVT.W/L use the current FCSR RM. Out-of-range/NaN/Inf integer
 *   results saturate to the MIPS indefinite values (W 0x7FFFFFFF,
 *   L 0x7FFFFFFFFFFFFFFF, qemu FP_TO_INT{32,64}_OVERFLOW).
 * - FCSR RM (bits 1:0) is honoured in software via exact quad-precision
 *   references (all quad intermediate results are exactly
 *   representable for our operand widths); the host FP control word is
 *   never touched. Default RNE.
 * - C.cond sets FCC[cc] (FCSR bit 23 for cc 0, bits 31:25 for cc 1..7)
 *   with the MIPS predicate table; unordered inputs clear the ordered
 *   predicates. No Cause/Flag update.
 */

#include <float.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"

extern void mips_insn_trap(mips64_ctx_t *ctx, int signo, uint64_t addr);
extern void mips_insn_trap_code(mips64_ctx_t *ctx, int signo, int32_t code,
                                uint64_t addr);

/* FCSR: FCC0 at bit 23, FCC1..7 at bits 31:25 (matches the MOVCI mask in
 * interp.c). RM at bits 1:0. Cause/Flag fields are never written here. */
#define FP_FCC0_BIT 23u
#define FP_RM_MASK  3u

uint64_t fp_d_bits(double x)
{
    uint64_t u = 0u;
    memcpy(&u, &x, sizeof(u));
    return u;
}

double fp_bits_d(uint64_t u)
{
    double x = 0.0;
    memcpy(&x, &u, sizeof(x));
    return x;
}

uint32_t fp_f_bits(float x)
{
    uint32_t u = 0u;
    memcpy(&u, &x, sizeof(u));
    return u;
}

float fp_bits_f(uint32_t u)
{
    float x = 0.0f;
    memcpy(&x, &u, sizeof(x));
    return x;
}

unsigned fp_rm(const mips64_ctx_t *ctx)
{
    return ctx->fcsr & FP_RM_MASK;
}

static unsigned fp_get_cc(const mips64_ctx_t *ctx, unsigned cc)
{
    if (cc == 0u) {
        return (ctx->fcsr >> FP_FCC0_BIT) & 1u;
    }
    return (ctx->fcsr >> (24u + cc)) & 1u;
}

static void fp_set_cc(mips64_ctx_t *ctx, unsigned cc, unsigned v)
{
    if (cc == 0u) {
        if (v != 0u) {
            ctx->fcsr |= (1u << FP_FCC0_BIT);
        } else {
            ctx->fcsr &= ~(1u << FP_FCC0_BIT);
        }
    } else if (v != 0u) {
        ctx->fcsr |= (1u << (24u + cc));
    } else {
        ctx->fcsr &= ~(1u << (24u + cc));
    }
}

/* Nonzero iff the raw lane bits are a signalling NaN under the legacy
 * MIPS (pre-nan2008) convention: all-ones exponent, nonzero mantissa,
 * top mantissa bit SET. 0x7FC00000 signals (crafted P3 case, V set);
 * the default 0x7FBFFFFF is quiet and propagates flag-free. Only SNaN
 * inputs raise V on quiet propagation (P3 suite, qemu-blessed). */
int fp_issn_s(uint32_t u)
{
    return ((u & 0x7F800000u) == 0x7F800000u) &&
        ((u & 0x007FFFFFu) != 0u) && ((u & 0x00400000u) != 0u);
}

int fp_issn_d(uint64_t u)
{
    return ((u & UINT64_C(0x7FF0000000000000)) ==
            UINT64_C(0x7FF0000000000000)) &&
        ((u & UINT64_C(0x000FFFFFFFFFFFFF)) != 0u) &&
        ((u & UINT64_C(0x0008000000000000)) != 0u);
}

static _Thread_local int fp_trapped;

void fp_clear_trap(void)
{
    fp_trapped = 0;
}

/* Set FCSR cause + sticky flag for exception e (FP_EXC_*). When the
 * corresponding FCSR enable bit (7 + e) is set, record an enabled trap
 * (suppressing sticky flag and destination writeback) so fp_finish_trap
 * delivers SIGFPE synchronously. */
void fp_raise(mips64_ctx_t *ctx, unsigned e)
{
    if (e > (unsigned)FP_EXC_V) {
        return;
    }
    ctx->fcsr |= (1u << (12u + e));
    if ((ctx->fcsr & (1u << (7u + e))) != 0u) {
        fp_trapped = 1;
    } else {
        ctx->fcsr |= (1u << (2u + e));
    }
}

int32_t fp_fcsr_sicode(uint32_t fcsr)
{
    uint32_t active = (fcsr >> 12u) & (fcsr >> 7u) & 0x1Fu;

    if ((active & (1u << (unsigned)FP_EXC_V)) != 0u) {
        return 7; /* FPE_FLTINV */
    }
    if ((active & (1u << (unsigned)FP_EXC_Z)) != 0u) {
        return 3; /* FPE_FLTDIV */
    }
    if ((active & (1u << (unsigned)FP_EXC_O)) != 0u) {
        return 4; /* FPE_FLTOVF */
    }
    if ((active & (1u << (unsigned)FP_EXC_U)) != 0u) {
        return 5; /* FPE_FLTUND */
    }
    if ((active & (1u << (unsigned)FP_EXC_I)) != 0u) {
        return 6; /* FPE_FLTRES */
    }
    return 7;
}

int fp_finish_trap(mips64_ctx_t *ctx, uint64_t cur_pc, unsigned fd,
                   uint64_t saved_fpr, uint32_t saved_cc, int rc)
{
    if (rc == 0 && fp_trapped != 0) {
        fp_trapped = 0;
        ctx->fpr[fd & 31u] = saved_fpr;
        ctx->fcsr = (ctx->fcsr & ~0xFE800000u) | (saved_cc & 0xFE800000u);
        mips_insn_trap_code(ctx, 8, fp_fcsr_sicode(ctx->fcsr), cur_pc);
        return (ctx->exit_reason == MIPS64_EXIT_NONE) ?
            FP_RC_BRANCH : MIPS_FAULT;
    }
    fp_trapped = 0;
    return rc;
}

/* Flag a finished single-precision result rf against its exact value q
 * (exact in double/long double for all S operands): O (+I) on overflow,
 * U (+I) on tiny inexact (or trapped tininess), and I on inexact. */
void fp_inexact(mips64_ctx_t *ctx, long double rf, long double q)
{
    if (((isinf(rf) != 0) || (isinf((float)q) != 0)) &&
        (isinf(q) == 0)) {
        fp_raise(ctx, (unsigned)FP_EXC_O);
        fp_raise(ctx, (unsigned)FP_EXC_I);
        return;
    }
    if (q != 0.0L && fabsl(q) < (long double)FLT_MIN) {
        if (rf != q ||
            (ctx->fcsr & (1u << (7u + (unsigned)FP_EXC_U))) != 0u) {
            fp_raise(ctx, (unsigned)FP_EXC_U);
        }
    }
    if (rf != q) {
        fp_raise(ctx, (unsigned)FP_EXC_I);
    }
}

/* Host-independent binary64 directed rounding and O/U/I flag accounting
 * from an RNE result r and exact residual sign cmp = sign(exact - r). */
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

/* S-format FPR write: low 32 bits replaced, upper lane preserved (FR=1,
 * the fpmove.c LWC1/MTC1 discipline). */
void fp_put_s(mips64_ctx_t *ctx, unsigned fd, uint32_t v)
{
    ctx->fpr[fd] = (ctx->fpr[fd] & UINT64_C(0xFFFFFFFF00000000)) | v;
}

void fp_put_d(mips64_ctx_t *ctx, unsigned fd, uint64_t v)
{
    ctx->fpr[fd] = v;
}

float fp_adj_f(float r, long double q, unsigned rm)
{
    long double lr;

    if (rm == 0u) {
        return r;
    }
    lr = (long double)r;
    if (lr == q) {
        return r;
    }
    switch (rm) {
    case 1u:
        return (fabsl(q) < fabsl(lr)) ? nextafterf(r, 0.0f) : r;
    case 2u:
        return (q > lr) ? nextafterf(r, INFINITY) : r;
    default:
        return (q < lr) ? nextafterf(r, -INFINITY) : r;
    }
}

/* Directed-mode correction for sqrt: the square of the RNE result is
 * exact in quad (53x53 / 24x24 bits), so the comparison against x is
 * exact. Toward-zero and toward -inf coincide for non-negative roots. */
static float fp_sqrt_adj_f(float r, float x, unsigned rm)
{
    long double sq;

    if (rm == 0u) {
        return r;
    }
    sq = (long double)r * (long double)r;
    if (rm == 2u) {
        return (sq < (long double)x) ? nextafterf(r, INFINITY) : r;
    }
    return (sq > (long double)x) ? nextafterf(r, 0.0f) : r;
}

/* Round quad q to an integer, ties to even. The caller range-checks
 * first, so q - truncl(q) is exact and the halfway case is detectable. */
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

static int fp_cmp_sign(double x)
{
    return (x > 0.0) ? 1 : ((x < 0.0) ? -1 : 0);
}

/* S/D ADD/SUB/MUL/DIV/SQRT/ABS/NEG/MOV. NaN operands and invalid
 * combinations yield the default quiet NaN; infinities follow the IEEE
 * sign rules. Returns 0, or MIPS_FAULT for an unknown funct (the caller
 * records the fault). */
static int fp_arith(mips64_ctx_t *ctx, const mips_dec_t *d, unsigned is_s)
{
    unsigned fd = d->sa;
    unsigned fs = d->rd;
    unsigned ft = d->rt;
    unsigned rm = fp_rm(ctx);

    if (!is_s) {
        double a = fp_bits_d(ctx->fpr[fs]);
        double b = fp_bits_d(ctx->fpr[ft]);
        double r;

        switch (d->funct) {
        case 0x06u: /* MOV.D: full 64-bit lane copy (FR=1) */
            fp_put_d(ctx, fd, ctx->fpr[fs]);
            return 0;
        case 0x05u: /* ABS.D: bitwise */
            fp_put_d(ctx, fd, ctx->fpr[fs] & ~(UINT64_C(1) << 63));
            return 0;
        case 0x07u: /* NEG.D: bitwise */
            fp_put_d(ctx, fd, ctx->fpr[fs] ^ (UINT64_C(1) << 63));
            return 0;
        case 0x04u: /* SQRT.D */
            if (isnan(a)) {
                fp_put_d(ctx, fd, FP_DEFNAN_D);
                if (fp_issn_d(ctx->fpr[fs]) != 0) {
                    fp_raise(ctx, (unsigned)FP_EXC_V);
                }
                return 0;
            }
            if (a < 0.0) {
                fp_put_d(ctx, fd, FP_DEFNAN_D);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            if (a == 0.0 || isinf(a)) {
                fp_put_d(ctx, fd, fp_d_bits(a));
                return 0;
            }
            r = sqrt(a);
            {
                int ea;
                double ma;
                double mr;
                double rf;

                (void)frexp(a, &ea);
                ea &= ~1;
                ma = ldexp(a, -ea);
                mr = ldexp(r, -(ea / 2));
                rf = fp_round_d(ctx, r, fp_cmp_sign(fma(-mr, mr, ma)), rm);
                fp_put_d(ctx, fd, fp_d_bits(rf));
                return 0;
            }
        case 0x00u: /* ADD.D */
        case 0x01u: /* SUB.D */
        case 0x02u: /* MUL.D */
        case 0x03u: /* DIV.D */
            break;
        default:
            return MIPS_FAULT;
        }
        if (isnan(a) || isnan(b)) {
            fp_put_d(ctx, fd, FP_DEFNAN_D);
            if (fp_issn_d(ctx->fpr[fs]) != 0 ||
                fp_issn_d(ctx->fpr[ft]) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return 0;
        }
        if (d->funct == 0x00u || d->funct == 0x01u) {
            double bb = (d->funct == 0x01u) ? -b : b;

            if (isinf(a) && isinf(bb) &&
                ((signbit(a) != 0) != (signbit(bb) != 0))) {
                fp_put_d(ctx, fd, FP_DEFNAN_D);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = a + bb;
            if (isinf(a) || isinf(bb)) {
                fp_put_d(ctx, fd, fp_d_bits(r));
                return 0;
            }
            if (r == 0.0) {
                int cancel = (signbit(a) != 0) != (signbit(bb) != 0);

                fp_put_d(ctx, fd, fp_d_bits((rm == 3u && cancel) ? -0.0 : r));
                return 0;
            }
            if (!isfinite(r)) {
                fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r,
                    (r > 0.0) ? -1 : 1, rm)));
                return 0;
            }
            {
                double a1 = r - bb;
                double b1 = r - a1;
                double err = (a - a1) + (bb - b1);

                fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r,
                    fp_cmp_sign(err), rm)));
                return 0;
            }
        }
        if (d->funct == 0x02u) {
            if ((a == 0.0 && isinf(b)) || (isinf(a) && b == 0.0)) {
                fp_put_d(ctx, fd, FP_DEFNAN_D);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = a * b;
            if (a == 0.0 || b == 0.0 || isinf(a) || isinf(b)) {
                fp_put_d(ctx, fd, fp_d_bits(r));
                return 0;
            }
            if (!isfinite(r)) {
                fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r,
                    (r > 0.0) ? -1 : 1, rm)));
                return 0;
            }
            {
                int ea;
                int eb;
                double ma = frexp(a, &ea);
                double mb = frexp(b, &eb);
                double mr = ldexp(r, -(ea + eb));

                fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r,
                    fp_cmp_sign(fma(ma, mb, -mr)), rm)));
                return 0;
            }
        }
        if ((a == 0.0 && b == 0.0) || (isinf(a) && isinf(b))) {
            fp_put_d(ctx, fd, FP_DEFNAN_D);
            fp_raise(ctx, (unsigned)FP_EXC_V);
            return 0;
        }
        if (b == 0.0) {
            int sx = (signbit(a) != 0) != (signbit(b) != 0);

            fp_put_d(ctx, fd, fp_d_bits(sx ? -INFINITY : INFINITY));
            fp_raise(ctx, (unsigned)FP_EXC_Z);
            return 0;
        }
        r = a / b;
        if (a == 0.0 || isinf(a) || isinf(b)) {
            fp_put_d(ctx, fd, fp_d_bits(r));
            return 0;
        }
        if (!isfinite(r)) {
            fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r,
                (r > 0.0) ? -1 : 1, rm)));
            return 0;
        }
        {
            int ea;
            int eb;
            double ma = frexp(a, &ea);
            double mb = frexp(b, &eb);
            double mr = ldexp(r, eb - ea);
            int cmp = fp_cmp_sign(fma(-mr, mb, ma));

            if (mb < 0.0) {
                cmp = -cmp;
            }
            fp_put_d(ctx, fd, fp_d_bits(fp_round_d(ctx, r, cmp, rm)));
            return 0;
        }
    }
    {
        float a = fp_bits_f((uint32_t)ctx->fpr[fs]);
        float b = fp_bits_f((uint32_t)ctx->fpr[ft]);
        float r;
        long double q;

        switch (d->funct) {
        case 0x06u: /* MOV.S: full 64-bit lane copy (FR=1) */
            fp_put_d(ctx, fd, ctx->fpr[fs]);
            return 0;
        case 0x05u: /* ABS.S: bitwise on the low lane, upper preserved */
            fp_put_s(ctx, fd, ((uint32_t)ctx->fpr[fs]) & 0x7FFFFFFFu);
            return 0;
        case 0x07u: /* NEG.S: bitwise on the low lane, upper preserved */
            fp_put_s(ctx, fd, ((uint32_t)ctx->fpr[fs]) ^ 0x80000000u);
            return 0;
        case 0x04u: /* SQRT.S */
            if (isnan(a)) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                if (fp_issn_s((uint32_t)ctx->fpr[fs]) != 0) {
                    fp_raise(ctx, (unsigned)FP_EXC_V);
                }
                return 0;
            }
            if (a < 0.0f) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = sqrtf(a);
            {
                float rf = fp_sqrt_adj_f(r, a, rm);

                fp_put_s(ctx, fd, fp_f_bits(rf));
                if ((long double)rf * (long double)rf != (long double)a) {
                    fp_raise(ctx, (unsigned)FP_EXC_I);
                }
                return 0;
            }
        case 0x00u:
        case 0x01u:
        case 0x02u:
        case 0x03u:
            break;
        default:
            return MIPS_FAULT;
        }
        if (isnan(a) || isnan(b)) {
            fp_put_s(ctx, fd, FP_DEFNAN_S);
            if (fp_issn_s((uint32_t)ctx->fpr[fs]) != 0 ||
                fp_issn_s((uint32_t)ctx->fpr[ft]) != 0) {
                fp_raise(ctx, (unsigned)FP_EXC_V);
            }
            return 0;
        }
        switch (d->funct) {
        case 0x00u:
            if (isinf(a) && isinf(b) &&
                ((signbit(a) != 0) != (signbit(b) != 0))) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = a + b;
            q = (long double)a + (long double)b;
            break;
        case 0x01u:
            if (isinf(a) && isinf(b) &&
                ((signbit(a) != 0) == (signbit(b) != 0))) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = a - b;
            q = (long double)a - (long double)b;
            break;
        case 0x02u:
            if ((a == 0.0f && isinf(b)) || (isinf(a) && b == 0.0f)) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            r = a * b;
            q = (long double)a * (long double)b;
            break;
        default:
            r = 0.0f;
            q = 0.0L;
            break;
        }
        if (d->funct == 0x03u) {
            if ((a == 0.0f && b == 0.0f) || (isinf(a) && isinf(b))) {
                fp_put_s(ctx, fd, FP_DEFNAN_S);
                fp_raise(ctx, (unsigned)FP_EXC_V);
                return 0;
            }
            if (b == 0.0f) {
                int sx = (signbit(a) != 0) != (signbit(b) != 0);

                fp_put_s(ctx, fd, fp_f_bits(sx ? -INFINITY : INFINITY));
                fp_raise(ctx, (unsigned)FP_EXC_Z);
                return 0;
            }
            r = a / b;
            {
                long double m = (long double)r * (long double)b;
                long double la = (long double)a;
                int err;

                if (m == la) {
                    fp_put_s(ctx, fd, fp_f_bits(r));
                    return 0;
                }
                err = (m > la) ? 1 : -1;
                if (b < 0.0f) {
                    err = -err;
                }
                {
                    float rf = r;

                    if (rm == 1u) {
                        rf = (((r > 0.0f) && err > 0) ||
                            ((r < 0.0f) && err < 0)) ?
                            nextafterf(r, 0.0f) : r;
                    } else if (rm == 2u) {
                        rf = (err < 0) ? nextafterf(r, INFINITY) : r;
                    } else if (rm == 3u) {
                        rf = (err > 0) ? nextafterf(r, -INFINITY) : r;
                    }
                    fp_put_s(ctx, fd, fp_f_bits(rf));
                    fp_inexact(ctx, (long double)rf,
                        (long double)a / (long double)b);
                    return 0;
                }
            }
        }
        if (q == 0.0L && rm == 3u) {
            int cancel;

            if (d->funct == 0x00u) {
                cancel = (signbit(a) != 0) != (signbit(b) != 0);
            } else if (d->funct == 0x01u) {
                cancel = (signbit(a) != 0) == (signbit(b) != 0);
            } else {
                cancel = 0;
            }
            if (cancel) {
                fp_put_s(ctx, fd, fp_f_bits(-0.0f));
                return 0;
            }
        }
        if (d->funct == 0x00u || d->funct == 0x01u) {
            /* ADD.S/SUB.S exact residual (R3-2): the binary64 sum is
             * the exact reference, except when the small operand is
             * absorbed (qd == da, b != 0) — then the residual carries
             * the small operand's sign, one long-double ulp past r. */
            double sb = (d->funct == 0x01u) ? -(double)b : (double)b;
            double qd = (double)a + sb;

            q = (isfinite(qd) && qd == (double)a && sb != 0.0) ?
                nextafterl((long double)r,
                           sb > 0.0 ? INFINITY : -INFINITY) :
                (long double)qd;
        }
        {
            float rf = fp_adj_f(r, q, rm);

            fp_put_s(ctx, fd, fp_f_bits(rf));
            fp_inexact(ctx, (long double)rf, q);
            return 0;
        }
    }
}

/* S/D arithmetic + conversion dispatch (fmt S/D in d->rs). */
static int fp_fmt_sd(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    switch (d->funct) {
    case 0x00u:
    case 0x01u:
    case 0x02u:
    case 0x03u:
    case 0x04u:
    case 0x05u:
    case 0x06u:
    case 0x07u:
        return fp_arith(ctx, d, d->rs == 0x10u);
    case FP_FN_ROUND_W:
    case FP_FN_TRUNC_W:
    case FP_FN_CEIL_W:
    case FP_FN_FLOOR_W:
    case FP_FN_ROUND_L:
    case FP_FN_TRUNC_L:
    case FP_FN_CEIL_L:
    case FP_FN_FLOOR_L:
        /* NaN/Inf/out-of-range saturate inside fp_to_int. */
        if (d->rs == 0x10u) {
            return fp_to_int(ctx, d->sa,
                             (long double)fp_bits_f(
                                 (uint32_t)ctx->fpr[d->rd]), d->funct);
        }
        return fp_to_int(ctx, d->sa,
                         (long double)fp_bits_d(ctx->fpr[d->rd]), d->funct);
    case FP_FN_CVT_S:
    case FP_FN_CVT_D:
    case FP_FN_CVT_W:
    case FP_FN_CVT_L:
        return fp_cvt_sd(ctx, d, d->rs == 0x10u);
    default:
        break;
    }
    if ((d->funct & 0x30u) == 0x30u) {
        unsigned cond = d->funct & 0xFu;
        unsigned cc = (d->word >> 8) & 7u;
        unsigned l;
        unsigned e;
        unsigned u;
        unsigned res = 0u;

        if (d->rs == 0x10u) {
            float a = fp_bits_f((uint32_t)ctx->fpr[d->rd]);
            float b = fp_bits_f((uint32_t)ctx->fpr[d->rt]);

            l = (a < b) ? 1u : 0u;
            e = (a == b) ? 1u : 0u;
            u = (isnan(a) || isnan(b)) ? 1u : 0u;
        } else {
            double a = fp_bits_d(ctx->fpr[d->rd]);
            double b = fp_bits_d(ctx->fpr[d->rt]);

            l = (a < b) ? 1u : 0u;
            e = (a == b) ? 1u : 0u;
            u = (isnan(a) || isnan(b)) ? 1u : 0u;
        }
        switch (cond) {
        case 0x00u: /* F */
        case 0x08u: /* SF */
            res = 0u;
            break;
        case 0x01u: /* UN */
        case 0x09u: /* NGLE */
            res = u;
            break;
        case 0x02u: /* EQ */
        case 0x0Au: /* SEQ */
            res = e;
            break;
        case 0x0Cu: /* LT (signalling; same boolean as OLT) */
            res = l;
            break;
        case 0x03u: /* UEQ */
        case 0x0Bu: /* NGL */
            res = (u != 0u || e != 0u) ? 1u : 0u;
            break;
        case 0x04u: /* OLT */
            res = (u == 0u && l != 0u) ? 1u : 0u;
            break;
        case 0x05u: /* ULT */
        case 0x0Du: /* NGE */
            res = (u != 0u || l != 0u) ? 1u : 0u;
            break;
        case 0x06u: /* OLE */
        case 0x0Eu: /* LE */
            res = (u == 0u && (l != 0u || e != 0u)) ? 1u : 0u;
            break;
        case 0x07u: /* ULE */
        case 0x0Fu: /* NGT */
            res = (u != 0u || l != 0u || e != 0u) ? 1u : 0u;
            break;
        default:
            break;
        }
        if ((u != 0u) && ((cond & 8u) != 0u)) {
            fp_raise(ctx, (unsigned)FP_EXC_V);
        }
        fp_set_cc(ctx, cc, res);
        return 0;
    }
    return MIPS_FAULT;
}

/* W/L-source dispatch (CVT.S.W, CVT.D.W, CVT.S.L, CVT.D.L). */
static int fp_fmt_wl(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    if (d->funct == FP_FN_CVT_S || d->funct == FP_FN_CVT_D) {
        return fp_cvt_wl(ctx, d, d->rs == 0x15u);
    }
    return MIPS_FAULT;
}

/* BC1F/BC1FL/BC1T/BC1TL (any cc): RC1 delay-slot/annul rules. The slot
 * runs via interp_step with in_delay_slot set, so a fault there keeps
 * pc at the slot and records branch_pc; likely-not-taken annuls the
 * slot with no fetch at all. Returns FP_RC_BRANCH with pc final. */
static int fp_branch(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    unsigned cc = ((unsigned)d->rt >> 2u) & 7u;
    unsigned likely = ((unsigned)d->rt >> 1u) & 1u;
    unsigned tf = (unsigned)d->rt & 1u;
    uint64_t off = (uint64_t)((int64_t)d->simm * 4);
    uint64_t target = cur_pc + 4u + off;
    int taken = (fp_get_cc(ctx, cc) == tf);
    int rc;

    if (likely && !taken) {
        ctx->in_delay_slot = 0;
        ctx->pc = cur_pc + 8u;
        ctx->next_pc = cur_pc + 12u;
        return FP_RC_BRANCH;
    }
    ctx->in_delay_slot = 1;
    ctx->pc = cur_pc + 4u;
    rc = interp_step(ctx);
    if (rc == 0) {
        ctx->in_delay_slot = 0;
        ctx->pc = taken ? target : cur_pc + 8u;
        ctx->next_pc = ctx->pc + 4u;
        return FP_RC_BRANCH;
    }
    if (rc == 2) {
        /* The slot moved pc itself (dispatcher-owned pc): keep it. */
        ctx->in_delay_slot = 0;
        return FP_RC_BRANCH;
    }
    return rc;
}

int fp_cop1(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    uint64_t saved_fpr;
    uint32_t saved_cc;
    int rc = MIPS_FAULT;

    if (ctx == NULL || d == NULL) {
        return MIPS_FAULT;
    }
    if (d->rs == 0x08u) { /* BC1F/BC1FL/BC1T/BC1TL */
        return fp_branch(ctx, cur_pc, d);
    }
    saved_fpr = ctx->fpr[d->sa & 31u];
    saved_cc = ctx->fcsr & 0xFE800000u;
    fp_clear_trap();
    switch (d->rs) {
    case 0x01u: /* DMFC1: full 64-bit lane to GPR ($0 stays 0) */
        interp_set_reg(ctx, d->rt, ctx->fpr[d->rd]);
        return 0;
    case 0x05u: /* DMTC1: full 64-bit lane from GPR */
        ctx->fpr[d->rd] = ctx->gpr[d->rt];
        return 0;
    case 0x16u: /* PS: paired-single lanes */
        rc = fp_ps_cop1(ctx, cur_pc, d);
        break;
    case 0x10u: /* S */
    case 0x11u: /* D */
        rc = fp_fmt_sd(ctx, d);
        break;
    case 0x14u: /* W (CVT.S.W / CVT.D.W source) */
    case 0x15u: /* L (CVT.S.L / CVT.D.L source) */
        rc = fp_fmt_wl(ctx, d);
        break;
    default:
        break;
    }
    return fp_finish_trap(ctx, cur_pc, d->sa & 31u, saved_fpr, saved_cc, rc);
}
