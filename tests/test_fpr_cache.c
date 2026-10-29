/*
 * tests/test_fpr_cache.c — Wave P13 scalar FPR cache regression test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Structural assertions over the d8..d15 write-through cache
 * (src/dbt/emit_fpmem.c, never executed): a first fill must miss
 * (ctx LDR plus FMOV populate), a second fill must hit (one FMOV,
 * no LDR), spills must stay write-through (STR plus FMOV), .S reads
 * take either precision tag while .D reads need a .D tag, MTC1-style
 * invalidation must force a reload, and the GPR alias (d(8+s) shares
 * x(8+s) with x9..x15) must invalidate in both directions. No guest
 * memory is mapped (only register-pure words are emitted).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/emit_int.h"

static int fails = 0;

#define CHECK(c)                                                           \
    do {                                                                   \
        if (!(c)) {                                                        \
            (void)printf("FAIL line %u: %s\n", (unsigned)__LINE__, #c);    \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static uint32_t g_buf[64];

/* ---- stubs: trap/hostfault/interp are not exercised natively ---- */

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    (void)signo;
    (void)addr;
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
    (void)reasonp;
    return (int)MIPS_FAULT;
}

int interp_step(mips64_ctx_t *ctx)
{
    (void)ctx;
    return 1;
}

/* ---- expected-word constructors (bases match the emitters) ---- */

#define FPR_OFF(fs) (MIPS64_CTX_FPR_OFFSET + (uint32_t)(fs) * 8u)
#define LDR_D(rt, fs)                                                      \
    (0xFD400000u | ((FPR_OFF(fs) / 8u) << 10) | (19u << 5) | (uint32_t)(rt))
#define STR_D(rt, fs)                                                      \
    (0xFD000000u | ((FPR_OFF(fs) / 8u) << 10) | (19u << 5) | (uint32_t)(rt))
#define LDR_S(rt, fs)                                                      \
    (0xBD400000u | ((FPR_OFF(fs) / 4u) << 10) | (19u << 5) | (uint32_t)(rt))
#define FMOV_DD(rd, rn) (0x1E604000u | ((uint32_t)(rn) << 5) | (uint32_t)(rd))
#define FMOV_SS(rd, rn) (0x1E204000u | ((uint32_t)(rn) << 5) | (uint32_t)(rd))
#define FMOV_WS(wd, sn) (0x1E260000u | ((uint32_t)(sn) << 5) | (uint32_t)(wd))
#define FMOV_XD(xd, dn) (0x9E660000u | ((uint32_t)(dn) << 5) | (uint32_t)(xd))
#define FMOV_DX(dd, xn) (0x9E670000u | ((uint32_t)(xn) << 5) | (uint32_t)(dd))

static void fresh(a64_emit_t *e)
{
    (void)memset(g_buf, 0, sizeof g_buf);
    a64e_init(e, g_buf, 64u);
}

static void test_init_zeroes(void)
{
    a64_emit_t e;
    size_t i;

    (void)memset(&e, 0xA5, sizeof e);
    a64e_init(&e, g_buf, 64u);
    CHECK(e.fpr_valid == 0u);
    CHECK(e.fpr_is_d == 0u);
    for (i = 0u; i < 8u; i++) {
        CHECK(e.fpr_slot_reg[i] == 0u);
    }
}

static void test_fill_miss_then_hit(void)
{
    a64_emit_t e;

    fresh(&e);
    /* Miss: ctx load plus FMOV populate into d13 (slot 5). */
    ef_fill(&e, 1, 2u, 5u);
    CHECK(e.err == 0);
    CHECK(e.len == 2u);
    CHECK(g_buf[0] == LDR_D(2u, 5u));
    CHECK(g_buf[1] == FMOV_DD(13u, 2u));
    CHECK(e.fpr_valid == (uint8_t)(1u << 5));
    CHECK(e.fpr_slot_reg[5] == 5u);
    CHECK(e.fpr_is_d == (uint8_t)(1u << 5));
    /* Hit: one FMOV, no second load. */
    ef_fill(&e, 1, 2u, 5u);
    CHECK(e.len == 3u);
    CHECK(g_buf[2] == FMOV_DD(2u, 13u));
}

static void test_spill_write_through(void)
{
    a64_emit_t e;

    fresh(&e);
    /* Spill stores the ctx lane AND the cache reg. */
    ef_spill(&e, 1, 3u, 6u);
    CHECK(e.err == 0);
    CHECK(e.len == 2u);
    CHECK(g_buf[0] == STR_D(3u, 6u));
    CHECK(g_buf[1] == FMOV_DD(14u, 3u));
    CHECK(e.fpr_valid == (uint8_t)(1u << 6));
    CHECK(e.fpr_is_d == (uint8_t)(1u << 6));
    /* The spilled lane reads back with one FMOV. */
    ef_fill(&e, 1, 3u, 6u);
    CHECK(e.len == 3u);
    CHECK(g_buf[2] == FMOV_DD(3u, 14u));
}

static void test_precision_tags(void)
{
    a64_emit_t e;

    fresh(&e);
    ef_fill(&e, 1, 2u, 7u);
    CHECK(e.len == 2u);
    /* .S reads take either tag (low 32 shared); the .D tag survives. */
    ef_fill(&e, 0, 1u, 7u);
    CHECK(e.len == 3u);
    CHECK(g_buf[2] == FMOV_SS(1u, 15u));
    CHECK(e.fpr_is_d == (uint8_t)(1u << 7));
    ef_fill(&e, 1, 2u, 7u);
    CHECK(e.len == 4u);
    CHECK(g_buf[3] == FMOV_DD(2u, 15u));
    /* An .S populate tags .S: a later .D read must miss. */
    ef_fpr_invalidate(&e, 7u);
    ef_fill(&e, 0, 1u, 7u);
    CHECK(e.len == 6u);
    CHECK(g_buf[4] == LDR_S(1u, 7u));
    CHECK(e.fpr_is_d == 0u);
    ef_fill(&e, 1, 2u, 7u);
    CHECK(e.len == 8u);
    CHECK(g_buf[6] == LDR_D(2u, 7u));
    CHECK(e.fpr_is_d == (uint8_t)(1u << 7));
}

static void test_invalidate(void)
{
    a64_emit_t e;
    size_t n;

    fresh(&e);
    ef_fill(&e, 1, 2u, 1u);
    CHECK(e.len == 2u);
    /* MTC1/DMTC1-style raw write: the next fill reloads. */
    ef_fpr_invalidate(&e, 1u);
    ef_fill(&e, 1, 2u, 1u);
    CHECK(e.len == 4u);
    CHECK(g_buf[2] == LDR_D(2u, 1u));
    /* Invalidating an untracked lane is a no-op. */
    n = e.len;
    ef_fpr_invalidate(&e, 3u);
    CHECK(e.len == n);
    CHECK(e.fpr_valid == (uint8_t)(1u << 1));
}

static void test_gpr_alias(void)
{
    a64_emit_t e;

    fresh(&e);
    /* x13 fill (guest r12, GPR slot 4), then d13 populate (FP slot 5):
     * the GPR copy dies with the FMOV. */
    ei_gld(&e, EI_A, 12u);
    CHECK(((e.gpr_cache_valid >> 4) & 1u) != 0u);
    ef_fill(&e, 1, 2u, 5u);
    CHECK(e.len == 4u);
    CHECK(((e.fpr_valid >> 5) & 1u) != 0u);
    CHECK(((e.gpr_cache_valid >> 4) & 1u) == 0u);
    /* Reverse: FP slot 2 lives in d10/x10; a GPR store to x10
     * (guest r9, GPR slot 1) drops it, forcing a reload. */
    ef_fill(&e, 1, 2u, 2u);
    CHECK(((e.fpr_valid >> 2) & 1u) != 0u);
    ei_gst(&e, EI_C, 9u);
    CHECK(((e.fpr_valid >> 2) & 1u) == 0u);
    ef_fill(&e, 1, 2u, 2u);
    CHECK(g_buf[e.len - 2u] == LDR_D(2u, 2u));
    CHECK(g_buf[e.len - 1u] == FMOV_DD(10u, 2u));
}

static void test_cache_rw_helpers(void)
{
    a64_emit_t e;
    int hit;

    fresh(&e);
    /* Full-lane producer write-through from an integer reg. */
    ef_cache_write_d(&e, 4u, EI_B);
    CHECK(e.err == 0);
    CHECK(e.len == 1u);
    CHECK(g_buf[0] == FMOV_DX(12u, EI_B));
    CHECK(e.fpr_valid == (uint8_t)(1u << 4));
    CHECK(e.fpr_is_d == (uint8_t)(1u << 4));
    /* Integer-side reads hit without touching ctx. */
    hit = ef_cache_read_d(&e, 4u, EI_A);
    CHECK(hit == 1);
    CHECK(e.len == 2u);
    CHECK(g_buf[1] == FMOV_XD(EI_A, 12u));
    hit = ef_cache_read_s(&e, 4u, EI_A);
    CHECK(hit == 1);
    CHECK(e.len == 3u);
    CHECK(g_buf[2] == FMOV_WS(EI_A, 12u));
    /* An untracked lane misses cleanly. */
    hit = ef_cache_read_d(&e, 5u, EI_A);
    CHECK(hit == 0);
    CHECK(e.len == 3u);
}

static void test_no_v18(void)
{
    a64_emit_t e;
    size_t i;

    fresh(&e);
    ef_fill(&e, 1, 2u, 5u);
    ef_fill(&e, 0, 1u, 5u);
    ef_spill(&e, 1, 3u, 6u);
    ef_cache_write_d(&e, 4u, EI_B);
    (void)ef_cache_read_d(&e, 4u, EI_A);
    /* v18 overlaps the forbidden x18: no emitted FP or integer
     * register field may name it. */
    for (i = 0u; i < e.len; i++) {
        uint32_t w = g_buf[i];
        uint32_t fp0 = 0u;
        uint32_t fp1 = 0u;

        if ((w & 0xFFC00000u) == 0xFD400000u ||
            (w & 0xFFC00000u) == 0xFD000000u ||
            (w & 0xFFC00000u) == 0xBD400000u ||
            (w & 0xFFC00000u) == 0xBD000000u) {
            fp0 = w & 31u;
            fp1 = (w >> 5) & 31u;
        } else if ((w & 0xFFE00000u) == 0x1E200000u ||
            (w & 0xFFE00000u) == 0x1E600000u) {
            fp0 = w & 31u;
            fp1 = (w >> 5) & 31u;
        } else if ((w & 0xFFFF0000u) == 0x9E660000u ||
            (w & 0xFFFF0000u) == 0x9E670000u) {
            fp0 = w & 31u;
            fp1 = (w >> 5) & 31u;
        }
        CHECK(fp0 != 18u);
        CHECK(fp1 != 18u);
    }
}

int main(void)
{
    test_init_zeroes();
    test_fill_miss_then_hit();
    test_spill_write_through();
    test_precision_tags();
    test_invalidate();
    test_gpr_alias();
    test_cache_rw_helpers();
    test_no_v18();
    if (fails == 0) {
        (void)printf("test_fpr_cache: PASS\n");
    } else {
        (void)printf("test_fpr_cache: %d FAILURES\n", fails);
    }
    return fails != 0;
}