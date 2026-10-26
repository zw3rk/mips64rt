/*
 * tests/test_u0_fill_retry.c — fill-and-retry regression gate.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression test for the --dbt first-touch data fault: the inlined
 * soft-TLB probe misses every cold data page, and without a
 * fill-and-retry step dbt_run delivered a spurious guest SIGSEGV
 * (the first N64 startup stack load aborted the whole run). Covers
 * dbt_u0_fill_retry: mapped-cold fills (load, store, span-crossing
 * LWL), already-filled loop guard, unmapped genuine fault, non-memory
 * word, NULL ctx, and store-vs-read-only permission.
 *
 * Host-portable (same pattern as tests/test_u0_delay_tlb.c): builds
 * with the host C compiler, no Docker, no guest toolchain.
 *
 * Curated C11 only: no VLA, no Annex K, no <threads.h>, no _Generic,
 * no sprintf/strcpy/strcat.
 */

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "interp/decode.h"
#include "os/backend.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
static int passes = 0;

#define CHECK(cond) do { \
        if (cond) { \
            passes++; \
        } else { \
            (void)printf("FAIL line %u: %s\n", (unsigned)__LINE__, #cond); \
            fails++; \
        } \
    } while (0)

/* ---- stubs: trap/hostfault/interp are not exercised natively ---- */

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    (void)signo;
    (void)addr;
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
    (void)reasonp;
    return (int)MIPS_FAULT;
}

int interp_step(mips64_ctx_t *ctx)
{
    (void)ctx;
    return 1;
}

/* ---- fixture ---- */

#define FILL_PAGE UINT64_C(0x10000)
#define FILL_CODE (FILL_PAGE + UINT64_C(0x000))
#define FILL_LD (FILL_PAGE + UINT64_C(0x800))
#define FILL_ST (FILL_PAGE + UINT64_C(0x900))
#define FILL_SPAN (FILL_PAGE + UINT64_C(0xD00))

static uint32_t lw_word(unsigned rs, unsigned rt, uint32_t simm)
{
    return (uint32_t)((0x23u << 26) | ((rs & 31u) << 21) |
                      ((rt & 31u) << 16) | (simm & 0xFFFFu));
}

static uint32_t sw_word(unsigned rs, unsigned rt, uint32_t simm)
{
    return (uint32_t)((0x2Bu << 26) | ((rs & 31u) << 21) |
                      ((rt & 31u) << 16) | (simm & 0xFFFFu));
}

static uint32_t lwl_word(unsigned rs, unsigned rt, uint32_t simm)
{
    return (uint32_t)((0x22u << 26) | ((rs & 31u) << 21) |
                      ((rt & 31u) << 16) | (simm & 0xFFFFu));
}

/* One 8 KiB R|W|X mapping holds code and every data scratch
 * address: the macOS sandbox only admits a single MAP_FIXED sub-map
 * per reservation (see tests/check_host_contract.c), so the fixture
 * never maps twice. */
static void setup_fill_ctx(mips64_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof *ctx);
    ctx->is_n32 = 0U;
    ctx->is_be = 0U;
    mips_backend_state_reset(ctx);
    if (guest_mem_init(ctx) != 0) {
        (void)printf("FAIL line %u: guest_mem_init\n",
                     (unsigned)__LINE__);
        fails++;
        return;
    }
    if (mips_mem_map(ctx, FILL_PAGE, UINT64_C(0x2000),
                     (uint32_t)(1u | 2u | 4u), "fill-page") != 0) {
        (void)printf("FAIL line %u: mips_mem_map errno=%d\n",
                     (unsigned)__LINE__, errno);
        fails++;
    }
}

int main(void)
{
    static mips64_ctx_t ctx;
    static mips64_region_t saved[8];
    static mips64_region_t two[2];
    size_t saved_n = 0u;

    setup_fill_ctx(&ctx);

    /* Plant every code word up front: later cases narrow the page
     * read-only, after which planting would fault. */
    CHECK(guest_st32(&ctx, FILL_CODE, (uint64_t)lw_word(5u, 6u, 0x10u)) == 0);
    CHECK(guest_st32(&ctx, FILL_CODE + 8u,
                     (uint64_t)sw_word(5u, 6u, 0u)) == 0);
    CHECK(guest_st32(&ctx, FILL_CODE + 16u,
                     (uint64_t)lw_word(5u, 6u, 0u)) == 0);
    CHECK(guest_st32(&ctx, FILL_CODE + 24u,
                     (uint64_t)lwl_word(5u, 6u, 0x00u)) == 0);
    CHECK(guest_st32(&ctx, FILL_CODE + 28u, UINT64_C(0)) == 0);
    CHECK(guest_st32(&ctx, FILL_CODE + 32u,
                     (uint32_t)((0x21u << 26) | (5u << 21) |
                                (6u << 16) | 0x0FFFu)) == 0);

    /* NULL and non-memory edges never fill. */
    CHECK(dbt_u0_fill_retry(NULL, FILL_CODE) == 0);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 28u) == 0);

    /* Cold mapped load fills once, then the loop guard stops. */
    ctx.gpr[5] = FILL_LD;
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE) == 1);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE) == 0);

    /* Cold mapped store fills once on a writable page. Each fresh
     * expectation resets the registry so the loop guard cannot leak
     * state between cases. */
    mips_backend_state_reset(&ctx);
    ctx.gpr[5] = FILL_ST;
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 8u) == 1);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 8u) == 0);

    /* Aligned span op (LWL) fills its word span; a second call hits
     * the loop guard. */
    mips_backend_state_reset(&ctx);
    ctx.gpr[5] = FILL_SPAN;
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 24u) == 1);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 24u) == 0);

    /* Span op over an unmapped page is genuine. */
    ctx.gpr[5] = UINT64_C(0x30000);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 24u) == 0);

    /* Narrow the whole page read-only (fetch keeps EXEC so decoding
     * still works): a store there is genuine (no fill) while a load
     * still fills. */
    mips_backend_state_reset(&ctx);
    CHECK(mips_mem_protect(&ctx, FILL_PAGE, UINT64_C(0x1000),
                           (uint32_t)(1u | 4u)) == 0);
    ctx.gpr[5] = FILL_LD;
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 8u) == 0);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 16u) == 1);

    /* Two-byte load straddling the 4 KiB boundary fills both pages.
     * The sandbox maps a single sub-page per reservation, so the
     * second page exists only as a table record (fabricated via a
     * snapshot/restore pair, restored afterwards): the helper never
     * touches data host pages, only the table and the registry. */
    saved_n = mips_mem_snapshot(saved, 8u);
    CHECK(saved_n == 2u);
    CHECK(saved[0].start == FILL_PAGE);
    CHECK(saved[0].end == FILL_PAGE + UINT64_C(0x1000));
    two[0] = saved[0];
    two[1].start = saved[0].end;
    two[1].end = saved[0].end + UINT64_C(0x1000);
    two[1].prot = (uint32_t)(1u | 2u);
    two[1].flags = 0u;
    two[1].name[0] = 'f';
    two[1].name[1] = '2';
    two[1].name[2] = '\0';
    mips_mem_restore(two, 2u);
    mips_backend_state_reset(&ctx);
    ctx.gpr[5] = FILL_PAGE;
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 32u) == 1);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE + 32u) == 0);
    mips_mem_restore(saved, saved_n);

    /* Unmapped data page is genuine. */
    ctx.gpr[5] = UINT64_C(0x30000);
    CHECK(dbt_u0_fill_retry(&ctx, FILL_CODE) == 0);

    (void)printf("FILLRETRY: %d passed, %d failed\n", passes, fails);
    return fails == 0 ? 0 : 1;
}
