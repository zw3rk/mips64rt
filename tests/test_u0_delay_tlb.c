/*
 * tests/test_u0_delay_tlb.c — U0 delay-slot + TIF_FIXADE prototype gate.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned, native-compilable (pure C plus structural DBT
 * word assertions; emitted code is never executed):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc ...
 * via `make build-darwin`.
 *
 * Covers the exclusive-ownership surface: fixade emulation on/off
 * through src/os/mem.c (default 1, SIGBUS/BUS_ADRALN never SIGSEGV,
 * sysmips MIPS_FIXADE hook), the delay-target/npc_mode gate and
 * dbt_npc_resume, the 64-entry soft-TLB registry and x20 binding
 * shape, the 7-instruction ei_tlb_probe words plus the aligned-word
 * structure (legacy direct map gone, x4 host address, x0 preserved,
 * no x18, BE rev16/rev/rev64), and the vm64/Provider A 6-step
 * contract over both providers.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "core/cpu.h"
#include "dbt/a64_emit.h"
#include "dbt/dbt.h"
#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"
#include "os/backend.h"
#include "vm/vm64.h"
#include "vm/vm_file.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* ---- trap spy: replaces the frozen mips_trap for this gate ---- */

static int spy_count;
static int spy_signo;
static uint64_t spy_addr;

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    spy_count++;
    spy_signo = signo;
    spy_addr = addr;
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

/* Host-fault guard + interp fallback: not exercised natively. */
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

void mips_hostfault_disarm(void)
{
}

int interp_step(mips64_ctx_t *ctx)
{
    (void)ctx;
    return 1;
}

static void spy_reset(void)
{
    spy_count = 0;
    spy_signo = 0;
    spy_addr = 0U;
}

/* ---- fixade emulation through the real mem.c accessors ---- */

#define U0_PAGE UINT64_C(0x10000)

static void setup_ctx(mips64_ctx_t *ctx, int be)
{
    (void)memset(ctx, 0, sizeof *ctx);
    ctx->is_n32 = 0U;
    ctx->is_be = (be != 0) ? 1U : 0U;
    ctx->pc = U0_PAGE;
    mips_backend_state_reset(ctx);
    if (guest_mem_init(ctx) != 0) {
        (void)printf("FAIL line %u: guest_mem_init\n",
                     (unsigned)__LINE__);
        fails++;
        return;
    }
    if (mips_mem_map(ctx, U0_PAGE, UINT64_C(0x1000),
                     (uint32_t)(1u | 2u), "u0") != 0) {
        (void)printf("FAIL line %u: mips_mem_map\n",
                     (unsigned)__LINE__);
        fails++;
    }
    spy_reset();
}

static void test_fixade_emulation(void)
{
    static mips64_ctx_t ctx;
    uint64_t v = 0U;

    /* Default is emulate-on with no prior state. */
    (void)memset(&ctx, 0, sizeof ctx);
    CHECK(mips_fixade_enabled(&ctx) == 1);
    CHECK(mips_fixade_enabled(NULL) == 1);

    /* LE round trips at every width and offset. */
    setup_ctx(&ctx, 0);
    CHECK(guest_st32(&ctx, U0_PAGE + 1u, UINT64_C(0xAABBCCDD)) == 0);
    CHECK(guest_ld32(&ctx, U0_PAGE + 1u, &v) == 0 &&
          v == UINT64_C(0xAABBCCDD));
    CHECK(guest_st16(&ctx, U0_PAGE + 3u, UINT64_C(0x1234)) == 0);
    CHECK(guest_ld16(&ctx, U0_PAGE + 3u, &v) == 0 && v == UINT64_C(0x1234));
    CHECK(guest_st64(&ctx, U0_PAGE + 5u, UINT64_C(0x1122334455667788)) == 0);
    CHECK(guest_ld64(&ctx, U0_PAGE + 5u, &v) == 0 &&
          v == UINT64_C(0x1122334455667788));
    CHECK(spy_count == 0);

    /* Emulated stores clear the reservation like ordinary stores. */
    ctx.llbit = 1U;
    CHECK(guest_st32(&ctx, U0_PAGE + 1u, UINT64_C(1)) == 0);
    CHECK(ctx.llbit == 0U);

    /* Aligned access is untouched by the gate. */
    CHECK(guest_st32(&ctx, U0_PAGE + 8u, UINT64_C(0xDEADBEEF)) == 0);
    CHECK(guest_ld32(&ctx, U0_PAGE + 8u, &v) == 0 &&
          v == UINT64_C(0xDEADBEEF));

    /* BE round trips assemble MSB-first. */
    setup_ctx(&ctx, 1);
    CHECK(guest_st32(&ctx, U0_PAGE + 1u, UINT64_C(0x11223344)) == 0);
    CHECK(guest_ld32(&ctx, U0_PAGE + 1u, &v) == 0 &&
          v == UINT64_C(0x11223344));
    CHECK(guest_st16(&ctx, U0_PAGE + 7u, UINT64_C(0xABCD)) == 0);
    CHECK(guest_ld16(&ctx, U0_PAGE + 7u, &v) == 0 && v == UINT64_C(0xABCD));
    CHECK(guest_st64(&ctx, U0_PAGE + 9u, UINT64_C(0x102030405060708)) == 0);
    CHECK(guest_ld64(&ctx, U0_PAGE + 9u, &v) == 0 &&
          v == UINT64_C(0x102030405060708));
    CHECK(spy_count == 0);

    /* A span crossing into an unmapped page faults on the missing
     * byte as a page fault (SIGSEGV), not an alignment fault. */
    spy_reset();
    CHECK(guest_st32(&ctx, U0_PAGE + UINT64_C(0xFFE), 1U) == MIPS_FAULT);
    CHECK(spy_signo == 11 && ctx.exit_reason == MIPS64_EXIT_FAULT);
}

static void test_fixade_disabled(void)
{
    static mips64_ctx_t ctx;
    uint64_t v = 0U;

    setup_ctx(&ctx, 0);
    CHECK(mips_fixade_ctl(&ctx, (unsigned long)MIPS_SYS_MIPS_FIXADE, 0UL) == 0);
    CHECK(mips_fixade_enabled(&ctx) == 0);

    /* Misaligned integer access: SIGBUS/BUS_ADRALN, never SIGSEGV. */
    spy_reset();
    CHECK(guest_ld32(&ctx, U0_PAGE + 1u, &v) == MIPS_FAULT);
    CHECK(spy_signo == (int)MIPS64_SIGBUS);
    CHECK(spy_signo != 11);
    CHECK(ctx.exit_reason == MIPS64_EXIT_FAULT);
    CHECK(ctx.exit_info == (uint32_t)(U0_PAGE + 1u));
    CHECK(spy_addr == U0_PAGE + 1u);
    CHECK(mips_fixade_ctl(&ctx, (unsigned long)MIPS_SYS_MIPS_FIXADE, 1UL) == 0);
    CHECK(mips_fixade_enabled(&ctx) == 1);

    /* Aligned access still works while disabled. */
    mips_fixade_set(&ctx, 0);
    CHECK(guest_st32(&ctx, U0_PAGE + 8u, UINT64_C(7)) == 0);
    CHECK(guest_ld32(&ctx, U0_PAGE + 8u, &v) == 0 && v == UINT64_C(7));
    CHECK(spy_count == 1);

    /* Bad sysmips commands and NULL ctx fail the hook. */
    CHECK(mips_fixade_ctl(&ctx, (unsigned long)MIPS_SYS_FLUSH_CACHE, 1UL) ==
          MIPS_FAULT);
    CHECK(mips_fixade_ctl(NULL, (unsigned long)MIPS_SYS_MIPS_FIXADE, 1UL) ==
          MIPS_FAULT);
    mips_fixade_set(NULL, 1);
    CHECK(mips_fixade_enabled(&ctx) == 0);
    mips_backend_state_reset(&ctx);
    CHECK(mips_fixade_enabled(&ctx) == 1);
    mips_backend_state_reset(NULL);
}

/* ---- delay slot: target, npc_mode, dispatcher resume ---- */

static void test_delay_target(void)
{
    static mips64_ctx_t ctx;
    uint64_t va = 0U;
    uint64_t applied = 0U;

    (void)memset(&ctx, 0, sizeof ctx);
    mips_backend_state_reset(&ctx);
    CHECK(mips_npc_mode(&ctx) == (int)MIPS_NPC_STATIC);
    CHECK(mips_npc_mode(NULL) == (int)MIPS_NPC_STATIC);
    CHECK(mips_delay_target_get(&ctx, &va) == 0);
    CHECK(mips_delay_target_get(NULL, &va) == 0);
    CHECK(mips_delay_target_get(&ctx, NULL) == 0);

    mips_delay_target_set(&ctx, UINT64_C(0x4000));
    CHECK(mips_npc_mode(&ctx) == (int)MIPS_NPC_DYNAMIC_CTX);
    CHECK(mips_delay_target_get(&ctx, &va) == 1 && va == UINT64_C(0x4000));

    /* The shared resume step (also used by dbt_npc_resume) moves the
     * pending x25-carried target into pc/next_pc and drops it. */
    ctx.in_delay_slot = 1U;
    ctx.pc = UINT64_C(0x3000);
    ctx.next_pc = UINT64_C(0x3004);
    CHECK(mips_npc_resume_step(&ctx, &applied) == 1);
    CHECK(applied == UINT64_C(0x4000));
    CHECK(ctx.pc == UINT64_C(0x4000));
    CHECK(ctx.next_pc == UINT64_C(0x4004));
    CHECK(ctx.in_delay_slot == 0U);
    CHECK(mips_npc_mode(&ctx) == (int)MIPS_NPC_STATIC);
    CHECK(mips_npc_resume_step(&ctx, NULL) == 0);
    CHECK(mips_npc_resume_step(NULL, NULL) == 0);

    /* Dispatcher entry point shares the same path. */
    mips_delay_target_set(&ctx, UINT64_C(0x8000));
    CHECK(dbt_npc_resume(&ctx) == 1);
    CHECK(ctx.pc == UINT64_C(0x8000));
    CHECK(ctx.next_pc == UINT64_C(0x8004));
    CHECK(dbt_npc_resume(&ctx) == 0);
    CHECK(dbt_npc_resume(NULL) == 0);
    mips_delay_target_clear(&ctx);
    mips_delay_target_set(NULL, 1U);
    mips_delay_target_clear(NULL);
}

/* ---- soft-TLB registry and x20 binding shape ---- */

static void test_soft_tlb(void)
{
    static mips64_ctx_t ctx;
    mips_soft_tlb_entry_t *base;
    size_t idx;

    setup_ctx(&ctx, 0);
    base = (mips_soft_tlb_entry_t *)mips_soft_tlb_base(&ctx);
    CHECK(base != NULL);
    CHECK((((uintptr_t)base) & 7u) == 0u);
    CHECK(sizeof(mips_soft_tlb_entry_t) == 32u);
    CHECK(mips_soft_tlb_base(NULL) == NULL);

    /* Entries start invalid; fill derives the split tags plus the
     * uniform addend (read for readable, write for writable). */
    CHECK(sizeof(mips_soft_tlb_entry_t) == 32u);
    CHECK(base[0x345u].read_tag == UINT64_MAX);
    CHECK(base[0x345u].write_tag == UINT64_MAX);
    mips_soft_tlb_fill(&ctx, U0_PAGE + 0x500u);
    idx = (size_t)(((U0_PAGE + 0x500u) >> 12) & MIPS64_SOFT_TLB_INDEX_MASK);
    CHECK(idx == (size_t)((U0_PAGE >> 12) & 0xFFFu));
    CHECK(base[idx].read_tag == (U0_PAGE & ~(uint64_t)0xFFFu));
    CHECK(base[idx].write_tag == (U0_PAGE & ~(uint64_t)0xFFFu));
    CHECK(base[idx].addend == (uintptr_t)ctx.guest_base);
    CHECK(base[idx].flags_reserved == 0u);
    mips_soft_tlb_fill(NULL, 1U);
    mips_soft_tlb_invalidate(NULL);

    /* A read-only remap closes the write gate but keeps reads. */
    mips_mem_protect(&ctx, U0_PAGE, 0x1000u, (uint32_t)MIPS_PROT_READ);
    mips_soft_tlb_invalidate(&ctx);
    mips_soft_tlb_fill(&ctx, U0_PAGE + 8u);
    CHECK(base[(size_t)((U0_PAGE >> 12) & 0xFFFu)].read_tag ==
          (U0_PAGE & ~(uint64_t)0xFFFu));
    CHECK(base[(size_t)((U0_PAGE >> 12) & 0xFFFu)].write_tag ==
          UINT64_MAX);
    mips_mem_protect(&ctx, U0_PAGE, 0x1000u,
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE));

    /* Prefill covers every page of the span. */
    mips_soft_tlb_invalidate(&ctx);
    CHECK(base[idx].read_tag == UINT64_MAX);
    dbt_u0_prefill(&ctx, U0_PAGE, U0_PAGE + UINT64_C(0x1000));
    CHECK(base[(size_t)((U0_PAGE >> 12) & 0xFFFu)].read_tag ==
          (U0_PAGE & ~(uint64_t)0xFFFu));
    /* Unmapped span pages are skipped, never stamped readable. */
    dbt_u0_prefill(&ctx, U0_PAGE, U0_PAGE + UINT64_C(0x2000));
    CHECK(base[(size_t)(((U0_PAGE + 0x1000u) >> 12) & 0xFFFu)].read_tag ==
          UINT64_MAX);
    dbt_u0_prefill(NULL, 0U, 4096U);
    dbt_u0_prefill(&ctx, 8U, 8U);

    CHECK(MIPS64RT_BACKEND_REV == 5u);
    CHECK(mips_backend_name() != NULL);
    CHECK(MIPS64_BUS_ADRALN == 1u);
    CHECK(MIPS64_SIGBUS == 10u);
}

/* ---- DBT word structure (never executed) ---- */

static a64_emit_t u0e;
static uint32_t u0buf[512];

static void u0_begin(void)
{
    u0e.buf = u0buf;
    u0e.cap = 512u;
    u0e.len = 0u;
    u0e.err = 0;
    u0e.gpr_cache_valid = 0;
}

static int u0_has_masked(uint32_t mask, uint32_t want)
{
    size_t i;

    for (i = 0; i < u0e.len; i++) {
        if ((u0buf[i] & mask) == want) {
            return 1;
        }
    }
    return 0;
}

static void test_probe_words(void)
{
    /* Rev4 load probe (mask 0xFFC): ubfx, scaled add, tag/addend
     * ldp, masked bic, folded subtract, miss cbnz. Every word is
     * assembler-verified (see the /tmp/enc_probe captures). */
    u0_begin();
    (void)ei_tlb_probe(&u0e, 0xFFCu, 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 6u);
    CHECK(u0buf[0] == UINT32_C(0xD34C5EB6)); /* ubfx x22, x21, #12, #12 */
    CHECK(u0buf[1] == UINT32_C(0x8B161696)); /* add x22, x20, x22, lsl #5 */
    CHECK(u0buf[2] == UINT32_C(0xA94012D8)); /* ldp x24, x4, [x22] */
    CHECK(u0buf[3] == UINT32_C(0x9274D6B6)); /* bic x22, x21, #0xFFC */
    CHECK(u0buf[4] == UINT32_C(0xCB1802D6)); /* sub x22, x22, x24 */
    CHECK(u0buf[5] == UINT32_C(0xB5000016)); /* cbnz x22 (unpatched) */

    /* Store probe (mask 0xFF8): the ldp swaps to (addend, tag). */
    u0_begin();
    (void)ei_tlb_probe(&u0e, 0xFF8u, 1);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 6u);
    CHECK(u0buf[0] == UINT32_C(0xD34C5EB6));
    CHECK(u0buf[1] == UINT32_C(0x8B161696));
    CHECK(u0buf[2] == UINT32_C(0xA940E2C4)); /* ldp x4, x24, [x22, #8] */
    CHECK(u0buf[3] == UINT32_C(0x9274DAB6)); /* bic x22, x21, #0xFF8 */
    CHECK(u0buf[4] == UINT32_C(0xCB1802D6));
    CHECK(u0buf[5] == UINT32_C(0xB5000016));

    /* Bad widths are an emitter error, never a silent miscompile. */
    u0_begin();
    (void)ei_tlb_probe(&u0e, 0xFF7u, 0);
    CHECK(u0e.err != 0);
}

/* Exact Rev4 memory-word shapes (rs=4, rt=5, simm=16). The address
 * triple is shared: ldr x21,[x19,#0x40]; movz x24,#16;
 * add x21,x21,x24. The 6-insn probe follows, then the single
 * register-offset memory word on [x21, x4]. No alignment tst, no
 * scratch pc store, no x0 anywhere, never x18. */
static void test_aligned_words(void)
{
    mips_dec_t d;

    (void)memset(&d, 0, sizeof d);
    d.op = 0x23u; /* LW */
    d.rs = 4u;
    d.rt = 5u;
    d.simm = 16;

    /* LE LW: 12 words, ends with ldrsw + sxtw + guest store. */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 0, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 12u);
    CHECK(u0buf[0] == UINT32_C(0xF9401275));
    CHECK(u0buf[1] == UINT32_C(0xD2800218));
    CHECK(u0buf[2] == UINT32_C(0x8B1802B5));
    CHECK(u0buf[3] == UINT32_C(0xD34C5EB6));
    CHECK(u0buf[4] == UINT32_C(0x8B161696));
    CHECK(u0buf[5] == UINT32_C(0xA94012D8));
    CHECK(u0buf[6] == UINT32_C(0x9274D6B6));
    CHECK(u0buf[7] == UINT32_C(0xCB1802D6));
    CHECK(u0buf[8] == UINT32_C(0xB5000016));
    CHECK(u0buf[9] == UINT32_C(0xB8A46AB7)); /* ldrsw x23, [x21, x4] */
    CHECK(u0buf[10] == UINT32_C(0x93407EF7)); /* sxtw x23, x23 */
    CHECK(u0buf[11] == UINT32_C(0xF9001677)); /* str x23, [x19, #0x28] */
    CHECK(u0_has_masked(UINT32_C(0xFFC00000), UINT32_C(0x5AC00000)) == 0);

    /* BE LW: same plus the word rev before the sign extension. */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 1, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 13u);
    CHECK(u0buf[9] == UINT32_C(0xB8A46AB7));
    CHECK(u0buf[10] == UINT32_C(0x5AC00AF7)); /* rev w23, w23 */
    CHECK(u0buf[11] == UINT32_C(0x93407EF7));
    CHECK(u0buf[12] == UINT32_C(0xF9001677));

    /* BE LD: doubleword load + rev64 + X-form store. */
    d.op = 0x37u; /* LD */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 1, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 12u);
    CHECK(u0buf[6] == UINT32_C(0x9274DAB6)); /* bic x22, x21, #0xFF8 */
    CHECK(u0buf[9] == UINT32_C(0xF8646AB7)); /* ldr x23, [x21, x4] */
    CHECK(u0buf[10] == UINT32_C(0xDAC00EF7)); /* rev x23, x23 */
    CHECK(u0buf[11] == UINT32_C(0xF9001677)); /* str x23, [x19, #0x28] */

    /* BE LH: halfword load + rev16 + sign extension. */
    d.op = 0x21u; /* LH */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 1, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 13u);
    CHECK(u0buf[6] == UINT32_C(0x9274D2B6)); /* bic x22, x21, #0xFFE */
    CHECK(u0buf[9] == UINT32_C(0x78A46AB7)); /* ldrsh x23, [x21, x4] */
    CHECK(u0buf[10] == UINT32_C(0x5AC006F7)); /* rev16 w23, w23 */
    CHECK(u0buf[11] == UINT32_C(0x93403EF7)); /* sxth x23, x23 */
    CHECK(u0buf[12] == UINT32_C(0xF9001677));

    /* LE SB: byte store path with the llbit clear. */
    d.op = 0x28u; /* SB */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 0, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 12u);
    CHECK(u0buf[5] == UINT32_C(0xA940E2C4)); /* ldp x4, x24, [x22, #8] */
    CHECK(u0buf[6] == UINT32_C(0x9274CEB6)); /* bic x22, x21, #0xFFF */
    CHECK(u0buf[9] == UINT32_C(0xF9401677)); /* ldr x23, [x19, #0x28] */
    CHECK(u0buf[10] == UINT32_C(0x38246AB7)); /* strb w23, [x21, x4] */
    CHECK(u0buf[11] == UINT32_C(0x3904BA7F)); /* llbit clear */

    /* BE SW: the rev lands in x22 (dead past the compare), never x0. */
    d.op = 0x2Bu; /* SW */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 1, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 13u);
    CHECK(u0buf[9] == UINT32_C(0xF9401677));
    CHECK(u0buf[10] == UINT32_C(0x5AC00AF6)); /* rev w22, w23 */
    CHECK(u0buf[11] == UINT32_C(0xB8246AB6)); /* str w22, [x21, x4] */
    CHECK(u0buf[12] == UINT32_C(0x3904BA7F));

    /* LB never revs (either endianness): a rev64 would exile the
     * byte to the top halfword and the sign extension would read
     * back zero for every positive byte. */
    d.op = 0x20u; /* LB */
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 0, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 12u);
    CHECK(u0buf[6] == UINT32_C(0x9274CEB6)); /* bic x22, x21, #0xFFF */
    CHECK(u0buf[9] == UINT32_C(0x38A46AB7)); /* ldrsb x23, [x21, x4] */
    CHECK(u0buf[10] == UINT32_C(0x93401EF7)); /* sxtb x23, x23 */
    CHECK(u0buf[11] == UINT32_C(0xF9001677));
    u0_begin();
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 1, 0) == 0);
    CHECK(u0e.err == 0);
    CHECK(u0e.len == 12u);
    CHECK(u0buf[9] == UINT32_C(0x38A46AB7));
    CHECK(u0buf[10] == UINT32_C(0x93401EF7));
    CHECK(u0buf[11] == UINT32_C(0xF9001677));

    /* Slot words record a delay-slot site (emitted inside a block). */
    ei_mem_block_begin(UINT64_C(0x1000));
    u0_begin();
    ei_mem_branch_note(UINT64_C(0xFFC), (unsigned)RT_NPC_STATIC_TARGET,
                       (int32_t)8);
    CHECK(ei_mem_aligned(&u0e, &d, UINT64_C(0x1000), 0, 1) == 0);
    CHECK(u0e.err == 0);
    ei_mem_branch_clear();
    {
        const struct dbt_mem_site *sites;
        size_t count;

        ei_mem_block_end(&u0e);
        CHECK(u0e.err == 0);
        ei_mem_take_sites(&sites, &count);
        CHECK(count == 1u);
    }
}

/* ---- vm64 / Provider A 6-step contract over both providers ---- */

static void test_vm64_anon(void)
{
    mips_vm64_t vm;
    mips_vm_region_t r;
    uint8_t *h;
    uint64_t ps = (uint64_t)sysconf(_SC_PAGESIZE);
    uint64_t va;
    uint64_t len;

    if (ps < 4096u) {
        ps = 4096u;
    }
    va = 2u * ps;
    len = 2u * ps;
    (void)memset(&vm, 0, sizeof vm);
    CHECK(mips_vm64_reserve(NULL, &mips_provider_a, 4096U) == MIPS_FAULT);
    CHECK(mips_vm64_reserve(&vm, NULL, 4096U) == MIPS_FAULT);
    CHECK(mips_vm64_reserve(&vm, &mips_provider_a, 0U) == MIPS_FAULT);
    CHECK(mips_vm64_reserve(&vm, &mips_provider_a,
                            UINT64_C(0x1000000)) == 0);
    CHECK(vm.base != 0U && vm.size == UINT64_C(0x1000000));

    /* Map two pages, write through the host pointer, query back. */
    CHECK(mips_vm64_map(&vm, va, len, (uint32_t)(1u | 2u),
                        MIPS_VM_TAG_ANON) == 0);
    h = (uint8_t *)mips_vm64_host(&vm, va);
    CHECK(h != NULL);
    h[0] = 0xA5u;
    h[len - 1u] = 0x5Au;
    CHECK(mips_vm64_query(&vm, va, &r) == 0);
    CHECK(r.start == va && r.end == va + len);
    CHECK(r.tag == MIPS_VM_TAG_ANON);
    CHECK(mips_vm64_query(&vm, va - 1u, &r) == MIPS_FAULT);
    CHECK(mips_vm64_query(&vm, vm.size, NULL) == MIPS_FAULT);
    CHECK(mips_vm64_host(&vm, vm.size) == NULL);
    CHECK(mips_vm64_host(NULL, 0U) == NULL);

    /* Reject EXEC maps (W^X) and out-of-range spans. */
    CHECK(mips_vm64_map(&vm, va + len, ps, (uint32_t)(1u | 2u | 4u),
                        MIPS_VM_TAG_ANON) == MIPS_FAULT);
    CHECK(mips_vm64_map(&vm, vm.size, ps, (uint32_t)1u,
                        MIPS_VM_TAG_ANON) == MIPS_FAULT);

    /* Protect drops write; unmap drops the record; release ends it. */
    CHECK(mips_vm64_protect(&vm, va, len, (uint32_t)1u) == 0);
    CHECK(mips_vm64_query(&vm, va + len - 1u, &r) == 0);
    CHECK((r.prot & (uint32_t)2u) == 0u);
    CHECK(mips_vm64_unmap(&vm, va + ps, ps) == 0);
    CHECK(mips_vm64_query(&vm, va + ps, &r) == MIPS_FAULT);
    CHECK(mips_vm64_query(&vm, va, &r) == 0);
    CHECK(mips_vm64_release(&vm) == 0);
    CHECK(vm.base == 0U && vm.ops == NULL);
    CHECK(mips_vm64_release(&vm) == MIPS_FAULT);
    CHECK(mips_vm64_map(NULL, 0U, 4096U, 1u, 0u) == MIPS_FAULT);
}

static void test_vmfile(void)
{
    mips_vm64_t vm;
    mips_vm_region_t r;
    char path[] = "/tmp/u0vmfileXXXXXX";
    int fd;
    uint64_t ps = (uint64_t)sysconf(_SC_PAGESIZE);
    uint64_t fsz;
    uint64_t va;
    uint64_t len;
    uint8_t *h;
    uint64_t i;

    if (ps < 4096u) {
        ps = 4096u;
    }
    fsz = 4u * ps;
    va = 2u * ps;
    len = 2u * ps;
    fd = mkstemp(path);
    CHECK(fd >= 0);
    for (i = 0; i < fsz; i++) {
        uint8_t byte = (uint8_t)(i & 0xFFu);

        CHECK(write(fd, &byte, 1u) == 1);
    }

    (void)memset(&vm, 0, sizeof vm);
    CHECK(mips_vm64_reserve(&vm, &mips_provider_f,
                            UINT64_C(0x1000000)) == 0);
    CHECK(mips_vmfile_map(&vm, fd, 0U, va, len, (uint32_t)1u) == 0);
    h = (uint8_t *)mips_vm64_host(&vm, va);
    CHECK(h != NULL);
    CHECK(h[0] == (uint8_t)0u && h[len - 1u] == (uint8_t)((len - 1u) & 0xFFu));
    CHECK(mips_vm64_query(&vm, va + ps, &r) == 0);
    CHECK(r.tag == MIPS_VM_TAG_FILE && r.prot == (uint32_t)1u);
    CHECK(mips_vm64_map(&vm, va + len, ps, (uint32_t)1u,
                        MIPS_VM_TAG_FILE) == MIPS_FAULT);
    CHECK(mips_vmfile_map(&vm, fd, 0U, va + 1u, ps,
                          (uint32_t)1u) == MIPS_FAULT);
    CHECK(mips_vmfile_map(NULL, fd, 0U, va, ps,
                          (uint32_t)1u) == MIPS_FAULT);
    CHECK(mips_vm64_unmap(&vm, va, len) == 0);
    CHECK(mips_vm64_query(&vm, va, &r) == MIPS_FAULT);
    CHECK(mips_vm64_release(&vm) == 0);

    (void)close(fd);
    (void)unlink(path);
}

/* ---- M64 Round-8 DBT/JIT defects (decline codes + JR ordering) ---- */

static uint32_t r8out[512];

static void r8_make(mips_dec_t *d, unsigned op, unsigned rs, unsigned rt,
                    unsigned rd, unsigned funct, int32_t simm,
                    uint32_t target)
{
    (void)memset(d, 0, sizeof *d);
    d->op = (uint8_t)op;
    d->rs = (uint8_t)rs;
    d->rt = (uint8_t)rt;
    d->rd = (uint8_t)rd;
    d->funct = (uint8_t)funct;
    d->simm = simm;
    d->uimm = (uint32_t)simm;
    d->target = target;
}

/* R8-2: trapping words decline in delay slots, neighbours still emit. */
static void test_r8_trapping_slots(void)
{
    static const unsigned trap_f[] = { 0x20u, 0x22u, 0x2Cu, 0x2Eu };
    static const unsigned plain_f[] = { 0x21u, 0x23u, 0x2Du, 0x2Fu };
    static const unsigned tcond_f[] = { 0x30u, 0x31u, 0x32u, 0x33u,
                                        0x34u, 0x36u };
    static const unsigned rts[] = { 0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu,
                                    0x0Eu };
    mips_dec_t d;
    size_t i;

    for (i = 0u; i < sizeof trap_f / sizeof trap_f[0]; i++) {
        r8_make(&d, 0x00u, 4u, 5u, 6u, trap_f[i], 0, 0u);
        u0_begin();
        CHECK(ei_special(&u0e, &d, UINT64_C(0x1000), 1) == 1);
        CHECK(u0e.len == 0u);
    }
    for (i = 0u; i < sizeof plain_f / sizeof plain_f[0]; i++) {
        r8_make(&d, 0x00u, 4u, 5u, 6u, plain_f[i], 0, 0u);
        u0_begin();
        CHECK(ei_special(&u0e, &d, UINT64_C(0x1000), 1) == 0);
    }
    for (i = 0u; i < sizeof tcond_f / sizeof tcond_f[0]; i++) {
        r8_make(&d, 0x00u, 4u, 5u, 6u, tcond_f[i], 0, 0u);
        u0_begin();
        CHECK(ei_special(&u0e, &d, UINT64_C(0x1000), 1) == 1);
        CHECK(u0e.len == 0u);
    }
    r8_make(&d, 0x08u, 4u, 5u, 0u, 0u, 1, 0u);
    u0_begin();
    CHECK(ei_imm(&u0e, &d, UINT64_C(0x1000), 1) == 1);
    CHECK(u0e.len == 0u);
    r8_make(&d, 0x18u, 4u, 5u, 0u, 0u, 1, 0u);
    u0_begin();
    CHECK(ei_imm(&u0e, &d, UINT64_C(0x1000), 1) == 1);
    CHECK(u0e.len == 0u);
    r8_make(&d, 0x09u, 4u, 5u, 0u, 0u, 1, 0u);
    u0_begin();
    CHECK(ei_imm(&u0e, &d, UINT64_C(0x1000), 1) == 0);
    r8_make(&d, 0x19u, 4u, 5u, 0u, 0u, 1, 0u);
    u0_begin();
    CHECK(ei_imm(&u0e, &d, UINT64_C(0x1000), 1) == 0);
    for (i = 0u; i < sizeof rts / sizeof rts[0]; i++) {
        r8_make(&d, 0x01u, 4u, rts[i], 0u, 0u, 1, 0u);
        u0_begin();
        CHECK(ei_regimm_trap(&u0e, &d, UINT64_C(0x1000), 1) == 1);
        CHECK(u0e.len == 0u);
    }
    /* SYNCI has no trap and still emits in a slot. */
    r8_make(&d, 0x01u, 4u, 0x1Fu, 0u, 0u, 1, 0u);
    u0_begin();
    CHECK(ei_regimm_trap(&u0e, &d, UINT64_C(0x1000), 1) == 0);
}

static int r8_emit_branch(mips64_ctx_t *ctx, const mips_dec_t *b,
                         const mips_dec_t *s, size_t *nwords)
{
    mips_dec_t insns[2];
    size_t out_len = 0u;
    uint64_t out_end = 0u;
    int rc;

    insns[0] = *b;
    insns[1] = *s;
    rc = dbt_emit_int(ctx, U0_PAGE, insns, 2u, (uint8_t *)r8out,
                      sizeof r8out, &out_len, &out_end);
    *nwords = out_len / 4u;
    return rc;
}

/* R8-3/R8-4/R8-2 at block level: the whole branch+slot declines. */
static void test_r8_branch_declines(void)
{
    static mips64_ctx_t ctx;
    mips_dec_t b;
    mips_dec_t s;
    mips_dec_t t;
    size_t n = 0u;

    setup_ctx(&ctx, 0);
    r8_make(&s, 0x09u, 9u, 12u, 0u, 0u, 1, 0u); /* ADDIU slot */

    /* R8-3: JAL with a COP1/COP1X slot declines; GPR slot emits. */
    r8_make(&b, 0x03u, 0u, 0u, 0u, 0u, 0, 0u);
    r8_make(&t, 0x11u, 0u, 0u, 0u, 0u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &t, &n) != 0);
    r8_make(&t, 0x13u, 0u, 0u, 0u, 0u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &t, &n) != 0);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);

    /* R8-3: a linking conditional with a COP1 slot declines too. */
    r8_make(&b, 0x01u, 4u, 0x11u, 0u, 0u, 4, 0u); /* BGEZAL */
    r8_make(&t, 0x11u, 0u, 0u, 0u, 0u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &t, &n) != 0);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);

    /* R8-4: JALR rd == rs declines; rd != rs and rd == 0 emit. */
    r8_make(&b, 0x00u, 8u, 0u, 8u, 0x09u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) != 0);
    r8_make(&b, 0x00u, 8u, 0u, 9u, 0x09u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);
    r8_make(&b, 0x00u, 8u, 0u, 0u, 0x09u, 0, 0u);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);

    /* R8-2 at block level: a trapping slot declines the branch. */
    r8_make(&b, 0x04u, 4u, 5u, 0u, 0u, 4, 0u); /* BEQ */
    r8_make(&t, 0x00u, 4u, 5u, 6u, 0x20u, 0, 0u); /* ADD */
    CHECK(r8_emit_branch(&ctx, &b, &t, &n) != 0);
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);
}

static size_t r8_find_word(uint32_t w, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        if (r8out[i] == w) {
            return i;
        }
    }
    return n;
}

static size_t r8_find_tbnz(size_t n, unsigned rt, unsigned bit)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        uint32_t w = r8out[i];

        if (((w & 0xFF000000u) == 0x37000000u) && ((w & 31u) == rt) &&
            (((w >> 19) & 31u) == bit)) {
            return i;
        }
    }
    return n;
}

/* R8-1: JR parks the target in x25, runs link + slot, then checks. */
static void test_r8_jr_order(void)
{
    static mips64_ctx_t ctx;
    mips_dec_t b;
    mips_dec_t s;
    size_t n = 0u;
    size_t park;
    size_t store;
    size_t chk0;
    size_t chk1;
    size_t dyn;
    size_t i;
    unsigned found;

    setup_ctx(&ctx, 0);
    r8_make(&b, 0x00u, 8u, 0u, 0u, 0x08u, 0, 0u); /* JR $t0 */
    r8_make(&s, 0x09u, 9u, 12u, 0u, 0u, 1, 0u); /* ADDIU slot */
    CHECK(r8_emit_branch(&ctx, &b, &s, &n) == 0);
    CHECK(n > 0u);

    /* Target parks in x25 before the slot store ... */
    park = r8_find_word(0xAA1503F9u, n); /* mov x25, x21 */
    store = r8_find_word(0xF9003277u, n); /* str x23, [x19, #96] */
    /* ... and both TBNZ checks on x25 come after the slot. */
    chk0 = r8_find_tbnz(n, 25u, 0u);
    chk1 = r8_find_tbnz(n, 25u, 1u);
    CHECK(park < n && store < n && chk0 < n && chk1 < n);
    CHECK(park < chk0 && store < chk0);
    CHECK(park < chk1 && store < chk1);
    /* No alignment check fires on the pre-slot input register. */
    for (i = 0u; i < n; i++) {
        uint32_t w = r8out[i];
        unsigned is_tb = ((w & 0xFF000000u) == 0x36000000u) ||
            ((w & 0xFF000000u) == 0x37000000u);

        CHECK(is_tb == 0u || (w & 31u) != 21u);
    }
    /* The fault epilogue reports the parked target: x24 carries x25
     * and the exit_info store reads x25, both after the checks. */
    dyn = r8_find_word(0xAA1903F8u, n); /* mov x24, x25 */
    CHECK(dyn < n && chk0 < dyn && chk1 < dyn);
    found = 0u;
    for (i = 0u; i < n; i++) {
        if ((r8out[i] & 0xFFC0001Fu) == 0xB9000019u) { /* str w25 */
            found = 1u;
            CHECK(chk0 < i && chk1 < i);
        }
    }
    CHECK(found != 0u);
}

int main(void)
{
    test_fixade_emulation();
    test_fixade_disabled();
    test_delay_target();
    test_soft_tlb();
    test_probe_words();
    test_aligned_words();
    test_r8_trapping_slots();
    test_r8_branch_declines();
    test_r8_jr_order();
    test_vm64_anon();
    test_vmfile();
    (void)printf("U0: %d passed, %d failed\n", passes, fails);
    return (fails == 0) ? 0 : 1;
}
