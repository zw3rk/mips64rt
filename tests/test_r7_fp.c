/*
 * tests/test_r7_fp.c — Round-7 FP interpreter regression gate.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sibling of test_r7_defects.c (kept separate so every TU stays
 * <= 900 lines): drives the real FP TUs directly, no guest needed.
 *
 * - R7-6: NAN2008 polarity honored.
 * - R7-7: aliased fd==fs SQRT/ADD still raise Invalid for sNaN.
 * - R7-8: MADD.S/MADD.D round product then sum in guest RM.
 * - R7-12: FCSR Cause is replaced per op, Flags stay cumulative.
 * - R7-13: a trapped op leaves sticky Flags untouched.
 * - R7-14: DIV.S/DIV.D resolve infinities before residual rounding.
 * - R7-15: FS flushes tiny results to signed zero with U and I.
 * - R7-16: PS cancellation under round-down yields -0 per lane.
 * - R7-17: FCCR/FEXR/FENR alias packing, masks, trap checks.
 * - R7-18: MOVF/MOVT/MOVZ/MOVN move lanes with no FCSR effects.
 *
 * Protocol: "R7-PASS <name>", "R7-FAIL <name> ...", final
 * "R7-RESULT: PASS|FAIL" plus summary. Exit 0 iff zero failures.
 */

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define R7_CHECK(name, cond) do { \
        if (cond) { \
            g_pass++; \
            (void)printf("R7-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R7-FAIL %s\n", name); \
        } \
    } while (0)

#define R7_CHECK64(name, got, want) do { \
        uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
        if (_g == _w) { \
            g_pass++; \
            (void)printf("R7-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R7-FAIL %s got=0x%llx want=0x%llx\n", \
                name, (unsigned long long)_g, \
                (unsigned long long)_w); \
        } \
    } while (0)

/* ---- recording seams ---- */

static int g_trap_count;
static int g_trap_signo;
static uint64_t g_trap_addr;

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    g_trap_count++;
    g_trap_signo = signo;
    g_trap_addr = addr;
}

int mips_signal_has_handler(int signo)
{
    (void)signo;
    return 0;
}

int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr)
{
    (void)ctx;
    (void)signo;
    (void)fault_addr;
    return 1;
}

void mips_hostfault_install(const void *pool, size_t len)
{
    (void)pool;
    (void)len;
}

int mips_hostfault_run(mips64_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    (void)ctx;
    (void)code;
    if (reasonp != NULL) {
        *reasonp = (uint32_t)MIPS64_EXIT_UNDEF;
    }
    return 0;
}

void mips_hostfault_disarm(void)
{
}

int64_t mips_syscall(mips64_ctx_t *ctx)
{
    ctx->llbit = 0;
    return 0;
}

static void r7_reset_traps(void)
{
    g_trap_count = 0;
    g_trap_signo = 0;
    g_trap_addr = 0u;
}

/* Fresh zeroed FP context (legacy NaN mode unless set after). */
static void r7_fp_init(mips64_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof *ctx);
    ctx->is_be = 0U;
    ctx->is_n32 = 0U;
}
/* Build an S/D arithmetic word: fd = sa, fs = rd, ft = rt. */
static void r7_arith_d(mips_dec_t *d, unsigned fmt, unsigned funct,
    unsigned fd, unsigned fs, unsigned ft)
{
    (void)memset(d, 0, sizeof *d);
    d->rs = (uint8_t)fmt;
    d->funct = (uint8_t)funct;
    d->sa = (uint8_t)fd;
    d->rd = (uint8_t)fs;
    d->rt = (uint8_t)ft;
}

/* R7-12: Cause is replaced per op; Flags stay cumulative. */
static void t_fcsr_cause(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fpr[4] = (uint64_t)0x3F800000u; /* 1.0f */
    ctx.fpr[6] = 0u; /* 0.0f */
    r7_arith_d(&d, 0x10u, 0x03u, 2u, 4u, 6u); /* DIV.S */
    R7_CHECK("cause-div-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("cause-div", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x8000)); /* Cause.Z */
    ctx.fpr[4] = (uint64_t)0x3F800000u;
    ctx.fpr[6] = (uint64_t)0x3F800000u;
    r7_arith_d(&d, 0x10u, 0x00u, 2u, 4u, 6u); /* ADD.S exact */
    R7_CHECK("cause-add-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("cause-add-clear", (uint64_t)(ctx.fcsr & 0x3F000u), 0u);
    R7_CHECK64("cause-flag-sticky", (uint64_t)(ctx.fcsr & 0x7Cu),
        UINT64_C(0x20)); /* Flag.Z */
    /* Issue 4: DMFC1/DMTC1 moves leave FCSR Cause untouched. */
    ctx.fcsr |= UINT64_C(0x10000); /* Cause.V */
    r7_arith_d(&d, 0x01u, 0x00u, 0u, 4u, 6u); /* DMFC1 $f4 -> $6 */
    R7_CHECK("cause-dmfc1-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("cause-dmfc1-keep", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x10000));
    r7_arith_d(&d, 0x05u, 0x00u, 0u, 4u, 6u); /* DMTC1 $6 -> $f4 */
    R7_CHECK("cause-dmtc1-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("cause-dmtc1-keep", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x10000));
}

/* R7-13: a trapped op leaves sticky Flags untouched. */
static void t_fcsr_trapped(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fpr[4] = (uint64_t)0x7F7FFFFFu; /* FLT_MAX */
    ctx.fpr[6] = (uint64_t)0x7F7FFFFFu;
    ctx.fcsr = 1u << 9; /* Enable.O only */
    r7_arith_d(&d, 0x10u, 0x00u, 2u, 4u, 6u); /* ADD.S overflows */
    ctx.fpr[2] = UINT64_C(0xDEADBEEFDEADBEEF);
    R7_CHECK("trap-add-rc", fp_cop1(&ctx, 0u, &d) == MIPS_FAULT);
    R7_CHECK64("trap-dst-restored", ctx.fpr[2],
        UINT64_C(0xDEADBEEFDEADBEEF));
    R7_CHECK64("trap-flags-clear", (uint64_t)(ctx.fcsr & 0x7Cu), 0u);
}

/* R7-14: division resolves infinities before residual rounding. */
static void t_div_inf(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fcsr = 2u; /* RM=+inf */
    ctx.fpr[4] = (uint64_t)0x3F800000u; /* 1.0f */
    ctx.fpr[6] = (uint64_t)0x7F800000u; /* +inf */
    r7_arith_d(&d, 0x10u, 0x03u, 2u, 4u, 6u);
    R7_CHECK("div-s-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("div-s-zero", (uint64_t)(uint32_t)ctx.fpr[2], 0u);
    R7_CHECK64("div-s-fcsr", (uint64_t)ctx.fcsr, 2u);
    r7_fp_init(&ctx);
    ctx.fpr[4] = (uint64_t)0x7F800000u;
    ctx.fpr[6] = 0u;
    r7_arith_d(&d, 0x10u, 0x03u, 2u, 4u, 6u);
    R7_CHECK("div-s-inf-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("div-s-inf", (uint64_t)(uint32_t)ctx.fpr[2],
        UINT64_C(0x7F800000));
    R7_CHECK64("div-s-inf-fcsr", (uint64_t)(ctx.fcsr & 0x3F07Cu), 0u);
    r7_fp_init(&ctx);
    ctx.fpr[4] = UINT64_C(0x7FF0000000000000);
    ctx.fpr[6] = 0u;
    r7_arith_d(&d, 0x11u, 0x03u, 2u, 4u, 6u); /* DIV.D */
    R7_CHECK("div-d-inf-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("div-d-inf", ctx.fpr[2],
        UINT64_C(0x7FF0000000000000));
    R7_CHECK64("div-d-inf-fcsr", (uint64_t)(ctx.fcsr & 0x3F07Cu), 0u);
}

/* R7-6: NAN2008 polarity honored. */
static void t_nan2008(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.nan2008 = 1u;
    ctx.fpr[4] = (uint64_t)0x7FC00000u; /* 2008 quiet NaN */
    ctx.fpr[6] = (uint64_t)0x3F800000u;
    r7_arith_d(&d, 0x10u, 0x00u, 2u, 4u, 6u); /* ADD.S */
    R7_CHECK("nan2008-qnan-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("nan2008-qnan-cause", (uint64_t)(ctx.fcsr & 0x3F000u),
        0u);
    R7_CHECK64("nan2008-qnan-def", (uint64_t)(uint32_t)ctx.fpr[2],
        UINT64_C(0x7FC00000));
    r7_fp_init(&ctx);
    ctx.nan2008 = 1u;
    ctx.fpr[4] = (uint64_t)0x7F800001u; /* 2008 signalling NaN */
    ctx.fpr[6] = (uint64_t)0x3F800000u;
    r7_arith_d(&d, 0x10u, 0x00u, 2u, 4u, 6u);
    R7_CHECK("nan2008-snan-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("nan2008-snan-cause",
        (uint64_t)(ctx.fcsr & 0x3F000u), UINT64_C(0x10000));
    r7_fp_init(&ctx);
    ctx.nan2008 = 1u;
    ctx.fpr[4] = 0u;
    ctx.fpr[6] = 0u;
    r7_arith_d(&d, 0x10u, 0x03u, 2u, 4u, 6u); /* DIV.S 0/0 */
    R7_CHECK("nan2008-div-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("nan2008-div-def", (uint64_t)(uint32_t)ctx.fpr[2],
        UINT64_C(0x7FC00000));
}

/* R7-7: aliased fd==fs still classifies the sNaN input. */
static void t_alias_snan(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fpr[0] = (uint64_t)0x7FC00000u; /* legacy sNaN */
    r7_arith_d(&d, 0x10u, 0x04u, 0u, 0u, 0u); /* SQRT.S $f0,$f0 */
    R7_CHECK("alias-sqrt-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("alias-sqrt-cause", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x10000));
    r7_fp_init(&ctx);
    ctx.fpr[0] = (uint64_t)0x7FC00000u;
    ctx.fpr[1] = (uint64_t)0x3F800000u;
    r7_arith_d(&d, 0x10u, 0x00u, 0u, 0u, 1u); /* ADD.S $f0,$f0,$f1 */
    R7_CHECK("alias-add-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("alias-add-cause", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x10000));
    r7_fp_init(&ctx);
    ctx.fpr[2] = UINT64_C(0x7FF8000000000000); /* legacy D sNaN */
    r7_arith_d(&d, 0x11u, 0x04u, 2u, 2u, 2u); /* SQRT.D $f2,$f2 */
    R7_CHECK("alias-sqrtd-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("alias-sqrtd-cause", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x10000));
}

/* Build a COP1X word: fd = sa, fs = rd, ft = rt, fr = rs. */
static void r7_cop1x_d(mips_dec_t *d, unsigned funct, unsigned fd,
    unsigned fs, unsigned ft, unsigned fr)
{
    (void)memset(d, 0, sizeof *d);
    d->op = 0x13u;
    d->funct = (uint8_t)funct;
    d->sa = (uint8_t)fd;
    d->rd = (uint8_t)fs;
    d->rt = (uint8_t)ft;
    d->rs = (uint8_t)fr;
}

/* R7-8: MADD rounds product then sum in guest RM. */
static void t_madd(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    /* Finding's case: (-1) + (1+2^-23)(1-2^-23) -> +0, not -2^-46. */
    r7_fp_init(&ctx);
    ctx.fpr[4] = (uint64_t)0xBF800000u; /* fr = -1.0 */
    ctx.fpr[6] = (uint64_t)0x3F800001u; /* fs = 1+2^-23 */
    ctx.fpr[8] = (uint64_t)0x3F7FFFFFu; /* ft = 1-2^-23 */
    r7_cop1x_d(&d, 0x20u, 2u, 6u, 8u, 4u); /* MADD.S $f2,$f6,$f8,$f4 */
    R7_CHECK("madd-s-rc", fp_cop1x(&ctx, 0u, &d) == 0);
    R7_CHECK64("madd-s-zero", (uint64_t)(uint32_t)ctx.fpr[2], 0u);
    /* Directed zero signs: RM=0 -> +0, RM=3 -> -0. */
    r7_fp_init(&ctx);
    ctx.fpr[4] = (uint64_t)0xBF800002u; /* -(1+2^-22) */
    ctx.fpr[6] = (uint64_t)0x3F800001u;
    ctx.fpr[8] = (uint64_t)0x3F800001u;
    r7_cop1x_d(&d, 0x20u, 2u, 6u, 8u, 4u);
    R7_CHECK("madd-s-rm0-rc", fp_cop1x(&ctx, 0u, &d) == 0);
    R7_CHECK64("madd-s-rm0", (uint64_t)(uint32_t)ctx.fpr[2], 0u);
    r7_fp_init(&ctx);
    ctx.fcsr = 3u; /* RM=-inf */
    ctx.fpr[4] = (uint64_t)0xBF800002u;
    ctx.fpr[6] = (uint64_t)0x3F800001u;
    ctx.fpr[8] = (uint64_t)0x3F800001u;
    r7_cop1x_d(&d, 0x20u, 2u, 6u, 8u, 4u);
    R7_CHECK("madd-s-rm3-rc", fp_cop1x(&ctx, 0u, &d) == 0);
    R7_CHECK64("madd-s-rm3", (uint64_t)(uint32_t)ctx.fpr[2],
        UINT64_C(0x80000000));
    /* Double: (-1) + (1+2^-27)(1-2^-27) -> +0. */
    r7_fp_init(&ctx);
    ctx.fpr[4] = UINT64_C(0xBFF0000000000000);
    ctx.fpr[6] = UINT64_C(0x3FF0000000000001);
    ctx.fpr[8] = UINT64_C(0x3FEFFFFFFFFFFFFF);
    r7_cop1x_d(&d, 0x21u, 2u, 6u, 8u, 4u); /* MADD.D */
    R7_CHECK("madd-d-rc", fp_cop1x(&ctx, 0u, &d) == 0);
    R7_CHECK64("madd-d-zero", ctx.fpr[2], 0u);
}

/* R7-15: FS flushes tiny results to signed zero with U and I. */
static void t_fs_flush(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 24; /* FS */
    ctx.fpr[4] = (uint64_t)0x00800000u; /* 2^-126 */
    ctx.fpr[6] = (uint64_t)0x3F000000u; /* 0.5f */
    r7_arith_d(&d, 0x10u, 0x02u, 2u, 4u, 6u); /* MUL.S */
    R7_CHECK("fs-mul-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("fs-mul-zero", (uint64_t)(uint32_t)ctx.fpr[2], 0u);
    R7_CHECK("fs-mul-u", (ctx.fcsr & (1u << 3)) != 0u);
    R7_CHECK("fs-mul-i", (ctx.fcsr & (1u << 2)) != 0u);
    /* Double path (fp_round_d): subnormal MUL.D flushes with U and I. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 24; /* FS */
    ctx.fpr[4] = UINT64_C(0x0008000000000000); /* 2^-1023, subnormal */
    ctx.fpr[6] = UINT64_C(0x3FF0000000000000); /* 1.0 */
    r7_arith_d(&d, 0x11u, 0x02u, 2u, 4u, 6u); /* MUL.D */
    R7_CHECK("fs-muld-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("fs-muld-zero", ctx.fpr[2], 0u);
    R7_CHECK("fs-muld-u", (ctx.fcsr & (1u << 3)) != 0u);
    R7_CHECK("fs-muld-i", (ctx.fcsr & (1u << 2)) != 0u);
    /* Paired-single lanes flush independently. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 24;
    ctx.fpr[4] = ((uint64_t)0x00800000u << 32) | 0x00800000u;
    ctx.fpr[6] = ((uint64_t)0x3F000000u << 32) | 0x3F000000u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x16u;
    d.funct = 0x02u; /* MUL.PS */
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 6u;
    R7_CHECK("fs-ps-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("fs-ps-zero", ctx.fpr[2], 0u);
    /* MADD.S with a tiny intermediate flushes before the sum. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 24;
    ctx.fpr[4] = 0u; /* fr = +0 */
    ctx.fpr[6] = (uint64_t)0x00800000u;
    ctx.fpr[8] = (uint64_t)0x3F000000u;
    r7_cop1x_d(&d, 0x20u, 2u, 6u, 8u, 4u);
    R7_CHECK("fs-madd-rc", fp_cop1x(&ctx, 0u, &d) == 0);
    R7_CHECK64("fs-madd-zero", (uint64_t)(uint32_t)ctx.fpr[2], 0u);
}

/* R7-16: PS cancellation under round-down yields -0 per lane. */
static void t_ps_zero(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.fcsr = 3u; /* RM=-inf */
    ctx.fpr[4] = ((uint64_t)0x3F800000u << 32) | 0x3F800000u;
    ctx.fpr[6] = ((uint64_t)0xBF800000u << 32) | 0xBF800000u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x16u;
    d.funct = 0x00u; /* ADD.PS (+1)+(-1) */
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 6u;
    R7_CHECK("ps-add-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("ps-add-zero", ctx.fpr[2],
        UINT64_C(0x8000000080000000));
    r7_fp_init(&ctx);
    ctx.fcsr = 3u;
    ctx.fpr[4] = ((uint64_t)0x3F800000u << 32) | 0x3F800000u;
    ctx.fpr[6] = ((uint64_t)0x3F800000u << 32) | 0x3F800000u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x16u;
    d.funct = 0x01u; /* SUB.PS (+1)-(+1) */
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 6u;
    R7_CHECK("ps-sub-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("ps-sub-zero", ctx.fpr[2],
        UINT64_C(0x8000000080000000));
}

/* Build a CFC1/CTC1 word: op rs=2/6, fs = rd, rt = GPR. */
static void r7_cfc_d(mips_dec_t *d, unsigned op, unsigned fs, unsigned rt)
{
    (void)memset(d, 0, sizeof *d);
    d->op = 0x11u;
    d->rs = (uint8_t)op;
    d->rd = (uint8_t)fs;
    d->rt = (uint8_t)rt;
}

/* R7-17: FCCR/FEXR/FENR alias packing, masks, trap checks. */
static void t_fcsr_alias(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    r7_fp_init(&ctx);
    ctx.gpr[4] = 0u;
    ctx.fcsr = (1u << 23) | (1u << 27); /* FCC0 + FCC3 */
    r7_cfc_d(&d, 0x02u, 25u, 4u); /* CFC1 $25 */
    R7_CHECK("fccr-read-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fccr-read", ctx.gpr[4], 0x9u);
    r7_fp_init(&ctx);
    ctx.gpr[4] = 0x82u; /* FCC7 + FCC1 */
    r7_cfc_d(&d, 0x06u, 25u, 4u); /* CTC1 $25 */
    R7_CHECK("fccr-write-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fccr-write", (uint64_t)ctx.fcsr, UINT64_C(0x82000000));
    r7_cfc_d(&d, 0x02u, 25u, 4u);
    R7_CHECK("fccr-reread-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fccr-reread", ctx.gpr[4], 0x82u);
    /* FEXR carries Cause + Flags at FCSR positions. */
    r7_fp_init(&ctx);
    ctx.gpr[4] = 0u;
    ctx.fcsr = 0x10000u | 0x20u; /* Cause.V + Flag.Z */
    r7_cfc_d(&d, 0x02u, 26u, 4u);
    R7_CHECK("fexr-read-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fexr-read", ctx.gpr[4], UINT64_C(0x10020));
    r7_fp_init(&ctx);
    ctx.gpr[4] = 0x18000u; /* Cause V|Z */
    r7_cfc_d(&d, 0x06u, 26u, 4u);
    R7_CHECK("fexr-write-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fexr-write", (uint64_t)(ctx.fcsr & 0x3F000u),
        UINT64_C(0x18000));
    /* Enabled Cause on an alias write traps like CTC1 $31. */
    r7_fp_init(&ctx);
    ctx.gpr[4] = 0x10000u; /* Cause.V */
    ctx.fcsr = 1u << 11; /* Enable.V */
    r7_reset_traps();
    r7_cfc_d(&d, 0x06u, 26u, 4u);
    R7_CHECK("fexr-trap-rc", fpmove_cop1(&ctx, &d) == MIPS_FAULT);
    R7_CHECK64("fexr-trap-signo", (uint64_t)g_trap_signo, 8u);
    /* FENR: FS at bit 2, Enables, RM. */
    r7_fp_init(&ctx);
    ctx.gpr[4] = (1u << 2) | 0xF80u | 2u;
    r7_cfc_d(&d, 0x06u, 28u, 4u);
    R7_CHECK("fenr-write-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fenr-write", (uint64_t)ctx.fcsr, UINT64_C(0x1000F82));
    ctx.gpr[4] = 0u;
    r7_cfc_d(&d, 0x02u, 28u, 4u);
    R7_CHECK("fenr-read-rc", fpmove_cop1(&ctx, &d) == 0);
    R7_CHECK64("fenr-read", ctx.gpr[4], (1u << 2) | 0xF80u | 2u);
    /* Unknown control register still faults. */
    r7_cfc_d(&d, 0x02u, 27u, 4u);
    R7_CHECK("fcc-bad-rc", fpmove_cop1(&ctx, &d) == MIPS_FAULT);
}

/* R7-18: conditional FPR moves with no arithmetic side effects. */
static void t_cond_move(void)
{
    mips64_ctx_t ctx;
    mips_dec_t d;

    /* MOVT $fcc0 true: full 64-bit lane copy, FCSR untouched. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 23;
    ctx.fpr[4] = UINT64_C(0x1122334455667788);
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x10u;
    d.funct = 0x11u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 1u; /* cc=0, tf=1 */
    R7_CHECK("movt-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movt-lane", ctx.fpr[2], UINT64_C(0x1122334455667788));
    R7_CHECK64("movt-fcsr", (uint64_t)ctx.fcsr, 1u << 23);
    /* MOVF $fcc0 with FCC0 true: no move. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 23;
    ctx.fpr[4] = UINT64_C(0x1122334455667788);
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x10u;
    d.funct = 0x11u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 0u; /* cc=0, tf=0 */
    R7_CHECK("movf-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movf-nomove", ctx.fpr[2], 0u);
    /* MOVT $fcc1 true via bit 25. */
    r7_fp_init(&ctx);
    ctx.fcsr = 1u << 25;
    ctx.fpr[4] = UINT64_C(0xA5A5A5A5A5A5A5A5);
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x11u;
    d.funct = 0x11u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = (1u << 2) | 1u; /* cc=1, tf=1 */
    R7_CHECK("movt-d-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movt-d-lane", ctx.fpr[2],
        UINT64_C(0xA5A5A5A5A5A5A5A5));
    /* MOVZ/MOVN on GPR zero/nonzero. */
    r7_fp_init(&ctx);
    ctx.gpr[5] = 0u;
    ctx.fpr[4] = UINT64_C(0x0102030405060708);
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x10u;
    d.funct = 0x12u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 5u;
    R7_CHECK("movz-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movz-move", ctx.fpr[2], UINT64_C(0x0102030405060708));
    R7_CHECK64("movz-fcsr", (uint64_t)ctx.fcsr, 0u);
    r7_fp_init(&ctx);
    ctx.gpr[5] = 7u;
    ctx.fpr[4] = UINT64_C(0x0102030405060708);
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x10u;
    d.funct = 0x13u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 5u;
    R7_CHECK("movn-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movn-move", ctx.fpr[2], UINT64_C(0x0102030405060708));
    r7_fp_init(&ctx);
    ctx.gpr[5] = 0u;
    ctx.fpr[2] = 0u;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x10u;
    d.funct = 0x13u;
    d.sa = 2u;
    d.rd = 4u;
    d.rt = 5u;
    R7_CHECK("movn-nomove-rc", fp_cop1(&ctx, 0u, &d) == 0);
    R7_CHECK64("movn-nomove", ctx.fpr[2], 0u);
}

int main(void)
{
    t_fcsr_cause();
    t_fcsr_trapped();
    t_div_inf();
    t_nan2008();
    t_alias_snan();
    t_madd();
    t_fs_flush();
    t_ps_zero();
    t_fcsr_alias();
    t_cond_move();
    (void)printf("R7-RESULT: %s (%d pass, %d fail)\n",
        (g_fail == 0) ? "PASS" : "FAIL", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
