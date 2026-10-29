/*
 * tests/test_gpr_cache.c — Wave P12 direct GPR cache regression test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Structural assertions over `dbt_emit_int` output (never executed):
 * a repeated guest load must hit the x9..x16 cache (orr-mov instead
 * of a second ldr), `$0` must never touch memory, every store must
 * stay write-through, and the MOVZ conditional-skip merge must
 * invalidate the cache. No guest memory is mapped (only register-
 * pure words are emitted), so `mips_fetch` is never reached.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/a64_emit.h"

static int fails = 0;

#define CHECK(c)                                                           \
    do {                                                                   \
        if (!(c)) {                                                        \
            (void)printf("FAIL line %u: %s\n", (unsigned)__LINE__, #c);    \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static mips64_ctx_t g_ctx;
static uint32_t g_out[2048];

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

static int is_ldr_x(uint32_t w)
{
    return (w & 0xFFC00000u) == 0xF9400000u;
}

static int is_str_x(uint32_t w)
{
    return (w & 0xFFC00000u) == 0xF9000000u;
}

static int is_orr_mov(uint32_t w)
{
    return (w & 0xFF000000u) == 0xAA000000u && ((w >> 5) & 31u) == 31u;
}

static unsigned fld_rd(uint32_t w)
{
    return w & 31u;
}

static unsigned fld_rn(uint32_t w)
{
    return (w >> 5) & 31u;
}

static unsigned fld_rm(uint32_t w)
{
    return (w >> 16) & 31u;
}

static uint32_t mem_off(uint32_t w)
{
    return ((w >> 10) & 0xFFFu) * 8u;
}

/* GPR fills: ldr x?, [x19, #off] with off inside ctx->r[] (< 0x100). */
static size_t count_gpr_ldrs(const uint32_t *words, size_t n)
{
    size_t i;
    size_t c = 0u;

    for (i = 0u; i < n; i++) {
        if (is_ldr_x(words[i]) && fld_rn(words[i]) == 19u &&
            mem_off(words[i]) < 0x100u) {
            c++;
        }
    }
    return c;
}

/* Write-through stores: str x?, [x19, #off] with off inside r[]. */
static size_t count_gpr_strs(const uint32_t *words, size_t n)
{
    size_t i;
    size_t c = 0u;

    for (i = 0u; i < n; i++) {
        if (is_str_x(words[i]) && fld_rn(words[i]) == 19u &&
            mem_off(words[i]) < 0x100u) {
            c++;
        }
    }
    return c;
}

/* orr Xd, XZR, Xm word (the ei_mov shape). */
#define ORR_W(rd, rm) (0xAA0003E0u | ((uint32_t)(rm) << 16) | (uint32_t)(rd))

/* x18 must never appear as Rd/Rn/Rm in the shapes this emitter uses. */
static int uses_x18(uint32_t w)
{
    if (is_ldr_x(w) || is_str_x(w)) {
        return fld_rd(w) == 18u || fld_rn(w) == 18u;
    }
    if (is_orr_mov(w)) {
        return fld_rd(w) == 18u || fld_rm(w) == 18u;
    }
    if ((w & 0xFF000000u) == 0x0B000000u) { /* add Wd, Wn, Wm */
        return fld_rd(w) == 18u || fld_rn(w) == 18u || fld_rm(w) == 18u;
    }
    if ((w & ~0x3FFu) == 0x93407C00u) { /* sxtw Xd, Wn */
        return fld_rd(w) == 18u || fld_rn(w) == 18u;
    }
    if ((w & 0xFF000000u) == 0xB4000000u ||
        (w & 0xFF000000u) == 0xB5000000u) { /* cbz/cbnz Xt */
        return fld_rd(w) == 18u;
    }
    if ((w & 0xFF000000u) == 0xD2000000u ||
        (w & 0xFF000000u) == 0xF2000000u ||
        (w & 0xFF000000u) == 0x52000000u ||
        (w & 0xFF000000u) == 0x72000000u) { /* movz/movk */
        return fld_rd(w) == 18u;
    }
    return 0;
}

static void check_no_x18(const uint32_t *words, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        if (uses_x18(words[i])) {
            (void)printf("FAIL line %u: word %lu is %08x (x18)\n",
                         (unsigned)__LINE__, (unsigned long)i, words[i]);
            fails++;
        }
    }
}

static mips_dec_t mk_r(unsigned funct, unsigned rs, unsigned rt, unsigned rd)
{
    mips_dec_t d;

    (void)memset(&d, 0, sizeof d);
    d.op = 0x00u;
    d.rs = (uint8_t)rs;
    d.rt = (uint8_t)rt;
    d.rd = (uint8_t)rd;
    d.funct = (uint8_t)funct;
    d.word = ((uint32_t)rs << 21) | ((uint32_t)rt << 16) |
        ((uint32_t)rd << 11) | (uint32_t)funct;
    return d;
}

static size_t emit_block(const mips_dec_t *insns, unsigned count)
{
    size_t out_len = 0u;
    uint64_t out_end = 0u;
    int rc;

    (void)memset(g_out, 0, sizeof g_out);
    rc = dbt_emit_int(&g_ctx, 0x10000u, insns, count, (uint8_t *)g_out,
                      sizeof g_out, &out_len, &out_end);
    CHECK(rc == 0);
    CHECK(out_len > 0u && (out_len & 3u) == 0u);
    CHECK(out_end == 0x10000u + (uint64_t)count * 4u);
    return out_len / 4u;
}

static void test_init_zeroes(void)
{
    a64_emit_t e;
    static uint32_t buf[8];
    size_t i;

    (void)memset(&e, 0xA5, sizeof e);
    a64e_init(&e, buf, 8u);
    CHECK(e.buf == buf && e.cap == 8u && e.len == 0u && e.err == 0);
    CHECK(e.gpr_cache_valid == 0u);
    for (i = 0u; i < 8u; i++) {
        CHECK(e.gpr_cache_reg[i] == 0u);
    }
    /* Wave P13 FPR cache starts empty too. */
    CHECK(e.fpr_valid == 0u);
    CHECK(e.fpr_is_d == 0u);
    for (i = 0u; i < 8u; i++) {
        CHECK(e.fpr_slot_reg[i] == 0u);
    }
}

static void test_hit(void)
{
    mips_dec_t insns[2];
    size_t n;

    /* ADDU $8,$4,$5; ADDU $9,$4,$5: the second pair of loads hits. */
    insns[0] = mk_r(0x21u, 4u, 5u, 8u);
    insns[1] = mk_r(0x21u, 4u, 5u, 9u);
    n = emit_block(insns, 2u);
    CHECK(count_gpr_ldrs(g_out, n) == 2u);
    CHECK(count_gpr_strs(g_out, n) == 2u);
    /* The second ADDU reuses $4/$5 from x13/x14 (no fresh fills). */
    CHECK(n > 9u);
    CHECK(g_out[8] == ORR_W(21u, 13u));
    CHECK(g_out[9] == ORR_W(22u, 14u));
    check_no_x18(g_out, n);
}

static void test_zero(void)
{
    mips_dec_t one;
    size_t n;
    size_t i;

    /* ADDU $8,$0,$5: $0 reads as xzr, only $5 is loaded. */
    one = mk_r(0x21u, 0u, 5u, 8u);
    n = emit_block(&one, 1u);
    CHECK(count_gpr_ldrs(g_out, n) == 1u);
    for (i = 0u; i < n; i++) {
        if (is_ldr_x(g_out[i]) && fld_rn(g_out[i]) == 19u) {
            CHECK(mem_off(g_out[i]) != 0u);
        }
    }
    /* ADDU $0,$4,$5: the $0 write is dropped, never stored. */
    one = mk_r(0x21u, 4u, 5u, 0u);
    n = emit_block(&one, 1u);
    CHECK(count_gpr_ldrs(g_out, n) == 2u);
    CHECK(count_gpr_strs(g_out, n) == 0u);
    for (i = 0u; i < n; i++) {
        if (is_str_x(g_out[i]) && fld_rn(g_out[i]) == 19u) {
            CHECK(mem_off(g_out[i]) != 0u);
        }
    }
    check_no_x18(g_out, n);
}

static void test_movz_invalidate(void)
{
    mips_dec_t insns[3];
    size_t n;

    /* The MOVZ skip merges cold: the trailing ADDU reloads $4/$5
     * (5 fills total); a stale cache would show only 3. Stores stay
     * write-through throughout (3 GPR stores). */
    insns[0] = mk_r(0x21u, 4u, 5u, 8u);
    insns[1] = mk_r(0x0Au, 6u, 0u, 9u);
    insns[2] = mk_r(0x21u, 4u, 5u, 10u);
    n = emit_block(insns, 3u);
    CHECK(count_gpr_ldrs(g_out, n) == 5u);
    CHECK(count_gpr_strs(g_out, n) == 3u);
    check_no_x18(g_out, n);
}

int main(void)
{
    (void)memset(&g_ctx, 0, sizeof g_ctx);
    test_init_zeroes();
    test_hit();
    test_zero();
    test_movz_invalidate();
    if (fails == 0) {
        (void)printf("test_gpr_cache: PASS\n");
    } else {
        (void)printf("test_gpr_cache: %d FAILURES\n", fails);
    }
    return fails != 0;
}
