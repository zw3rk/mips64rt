/*
 * tests/test_dbt_emit.c — Unit assertions for `src/dbt/a64_emit.c`.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2b-owned, native-compilable (pure C, no guest state):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc \
 *     tests/test_dbt_emit.c src/dbt/a64_emit.c -o /tmp/test_dbt_emit
 * Every expected word was verified against
 * `aarch64-unknown-linux-musl-as` (`/tmp/enc_probe.s`,
 * `/tmp/enc_probe2.s` ground-truth dumps).
 */

#include <stdint.h>
#include <stdio.h>

#include "dbt/a64_emit.h"

static int fails = 0;
static uint32_t buf[64];
static a64_emit_t e;

static void begin(void)
{
    e.buf = buf;
    e.cap = 64;
    e.len = 0;
    e.err = 0;
    e.gpr_cache_valid = 0;
}

static void expect(unsigned slot, uint32_t want, unsigned line)
{
    if (e.err != 0 || e.len <= slot || buf[slot] != want) {
        (void)printf("FAIL line %u: slot %u got %08x want %08x"
                     " (err=%d len=%lu)\n",
                     line, slot,
                     (e.len > slot) ? buf[slot] : 0u, want, e.err,
                     (unsigned long)e.len);
        fails++;
    }
}

static void expect_err(unsigned line)
{
    if (e.err == 0) {
        (void)printf("FAIL line %u: expected err, got err=0\n", line);
        fails++;
    }
}

#define EXPECT(slot, want) expect(slot, want, __LINE__)
#define EXPECT_ERR() expect_err(__LINE__)

int main(void)
{
    size_t s;

    begin();
    a64e_movz_x(&e, 0, 0x1234, 1);
    EXPECT(0, 0xd2a24680u);
    begin();
    a64e_movk_x(&e, 5, 0xabcd, 2);
    EXPECT(0, 0xf2d579a5u);
    begin();
    a64e_movn_x(&e, 7, 1, 0);
    EXPECT(0, 0x92800027u);
    begin();
    a64e_movz_w(&e, 3, 0xbeef, 1);
    EXPECT(0, 0x52b7dde3u);
    begin();
    a64e_movk_w(&e, 0, 0x1234, 1);
    EXPECT(0, 0x72a24680u);
    begin();
    a64e_mov_imm64(&e, 0, UINT64_C(0x123456789abcdef0));
    EXPECT(0, 0xd29bde00u);
    EXPECT(1, 0xf2b35780u);
    EXPECT(2, 0xf2cacf00u);
    EXPECT(3, 0xf2e24680u);
    begin();
    a64e_mov_imm32(&e, 0, 0xbeff1234u);
    EXPECT(0, 0x52824680u);
    EXPECT(1, 0x72b7dfe0u);
    begin();
    a64e_mov_imm32(&e, 2, 0x42u);
    EXPECT(0, 0x52800842u);
    begin();
    a64e_mov_rr(&e, 9, 10);
    EXPECT(0, 0xaa0a03e9u);

    begin();
    a64e_add_rr(&e, 0, 1, 2);
    EXPECT(0, 0x8b020020u);
    begin();
    a64e_sub_rr(&e, 3, 4, 5);
    EXPECT(0, 0xcb050083u);
    begin();
    a64e_add_ww(&e, 0, 1, 2);
    EXPECT(0, 0x0b020020u);
    begin();
    a64e_sub_ww(&e, 3, 4, 5);
    EXPECT(0, 0x4b050083u);
    begin();
    a64e_add_ir(&e, 0, 1, 0xfff, 0);
    EXPECT(0, 0x913ffc20u);
    begin();
    a64e_add_ir(&e, 0, 1, 0x123, 12);
    EXPECT(0, 0x91448c20u);
    begin();
    a64e_sub_ir(&e, 2, 3, 1, 0);
    EXPECT(0, 0xd1000462u);
    begin();
    a64e_add_ir_w(&e, 4, 5, 7, 0);
    EXPECT(0, 0x11001ca4u);
    begin();
    a64e_sub_ir_w(&e, 6, 7, 0xfff, 0);
    EXPECT(0, 0x513ffce6u);

    begin();
    a64e_logic_x(&e, 0, 0, 1, 2);
    EXPECT(0, 0x8a020020u);
    begin();
    a64e_logic_x(&e, 1, 3, 4, 5);
    EXPECT(0, 0xaa050083u);
    begin();
    a64e_logic_x(&e, 2, 6, 7, 8);
    EXPECT(0, 0xca0800e6u);
    begin();
    a64e_logic_w(&e, 0, 0, 1, 2);
    EXPECT(0, 0x0a020020u);
    begin();
    a64e_logic_w(&e, 1, 3, 4, 5);
    EXPECT(0, 0x2a050083u);
    begin();
    a64e_logic_w(&e, 2, 6, 7, 8);
    EXPECT(0, 0x4a0800e6u);

    begin();
    a64e_shift_reg_x(&e, 0, 0, 1, 2);
    EXPECT(0, 0x9ac22020u);
    begin();
    a64e_shift_reg_x(&e, 1, 3, 4, 5);
    EXPECT(0, 0x9ac52483u);
    begin();
    a64e_shift_reg_x(&e, 2, 6, 7, 8);
    EXPECT(0, 0x9ac828e6u);
    begin();
    a64e_shift_reg_x(&e, 3, 9, 10, 11);
    EXPECT(0, 0x9acb2d49u);
    begin();
    a64e_shift_reg_w(&e, 0, 0, 1, 2);
    EXPECT(0, 0x1ac22020u);
    begin();
    a64e_shift_reg_w(&e, 1, 3, 4, 5);
    EXPECT(0, 0x1ac52483u);
    begin();
    a64e_shift_reg_w(&e, 2, 6, 7, 8);
    EXPECT(0, 0x1ac828e6u);
    begin();
    a64e_shift_reg_w(&e, 3, 9, 10, 11);
    EXPECT(0, 0x1acb2d49u);

    begin();
    a64e_shift_imm_x(&e, 0, 0, 1, 8);
    EXPECT(0, 0xd378dc20u);
    begin();
    a64e_shift_imm_x(&e, 1, 2, 3, 10);
    EXPECT(0, 0xd34afc62u);
    begin();
    a64e_shift_imm_x(&e, 2, 4, 5, 3);
    EXPECT(0, 0x9343fca4u);
    begin();
    a64e_shift_imm_w(&e, 0, 6, 7, 5);
    EXPECT(0, 0x531b68e6u);
    begin();
    a64e_shift_imm_w(&e, 1, 8, 9, 1);
    EXPECT(0, 0x53017d28u);
    begin();
    a64e_shift_imm_w(&e, 2, 10, 11, 31);
    EXPECT(0, 0x131f7d6au);
    begin();
    a64e_shift_imm_w(&e, 0, 0, 1, 31);
    EXPECT(0, 0x53010020u);
    begin();
    a64e_ubfm_x(&e, 0, 1, 2, 9);
    EXPECT(0, 0xd3422420u);

    begin();
    a64e_sxtw(&e, 0, 1);
    EXPECT(0, 0x93407c20u);
    begin();
    a64e_sxth_x(&e, 2, 3);
    EXPECT(0, 0x93403c62u);
    begin();
    a64e_sxtb_x(&e, 4, 5);
    EXPECT(0, 0x93401ca4u);

    begin();
    a64e_mul_x(&e, 0, 1, 2);
    EXPECT(0, 0x9b027c20u);
    begin();
    a64e_mul_w(&e, 3, 4, 5);
    EXPECT(0, 0x1b057c83u);
    begin();
    a64e_sdiv_x(&e, 0, 1, 2);
    EXPECT(0, 0x9ac20c20u);
    begin();
    a64e_udiv_x(&e, 3, 4, 5);
    EXPECT(0, 0x9ac50883u);
    begin();
    a64e_sdiv_w(&e, 6, 7, 8);
    EXPECT(0, 0x1ac80ce6u);
    begin();
    a64e_udiv_w(&e, 9, 10, 11);
    EXPECT(0, 0x1acb0949u);
    begin();
    a64e_cmp_x(&e, 0, 1);
    EXPECT(0, 0xeb01001fu);
    begin();
    a64e_csel_x(&e, 0, 1, 2, A64_EQ);
    EXPECT(0, 0x9a820020u);
    begin();
    a64e_cset_x(&e, 3, A64_NE);
    EXPECT(0, 0x9a9f07e3u);

    begin();
    a64e_ldr_x(&e, 0, 1, 8);
    EXPECT(0, 0xf9400420u);
    begin();
    a64e_str_x(&e, 2, 3, 248);
    EXPECT(0, 0xf9007c62u);
    begin();
    a64e_ldr_w(&e, 4, 5, 12);
    EXPECT(0, 0xb9400ca4u);
    begin();
    a64e_str_w(&e, 6, 7, 16);
    EXPECT(0, 0xb90010e6u);
    begin();
    a64e_ldrb(&e, 8, 9, 7);
    EXPECT(0, 0x39401d28u);
    begin();
    a64e_strb(&e, 10, 11, 255);
    EXPECT(0, 0x3903fd6au);
    begin();
    a64e_ldrh(&e, 12, 13, 6);
    EXPECT(0, 0x79400dacu);
    begin();
    a64e_strh(&e, 14, 15, 10);
    EXPECT(0, 0x790015eeu);
    begin();
    a64e_ldrsb_x(&e, 0, 1, 3);
    EXPECT(0, 0x39800c20u);
    begin();
    a64e_ldrsh_x(&e, 2, 3, 4);
    EXPECT(0, 0x79800862u);
    begin();
    a64e_ldrsw_x(&e, 4, 5, 8);
    EXPECT(0, 0xb98008a4u);
    begin();
    a64e_ldxr_x(&e, 0, 1);
    EXPECT(0, 0xc85f7c20u);
    begin();
    a64e_stxr_x(&e, 2, 3, 4);
    EXPECT(0, 0xc8027c83u);
    begin();
    a64e_ldxr_w(&e, 5, 6);
    EXPECT(0, 0x885f7cc5u);
    begin();
    a64e_stxr_w(&e, 7, 8, 9);
    EXPECT(0, 0x88077d28u);
    begin();
    a64e_dmb_ish(&e);
    EXPECT(0, 0xd5033bbfu);

    begin();
    a64e_b_off(&e, 16);
    EXPECT(0, 0x14000010u);
    begin();
    a64e_bl_off(&e, 32);
    EXPECT(0, 0x94000020u);
    begin();
    a64e_b_off(&e, -2);
    EXPECT(0, 0x17fffffeu);
    begin();
    a64e_bcond(&e, A64_EQ, 8);
    EXPECT(0, 0x54000100u);
    begin();
    a64e_cbz_x(&e, 0, 6);
    EXPECT(0, 0xb40000c0u);
    begin();
    a64e_cbnz_w(&e, 1, 5);
    EXPECT(0, 0x350000a1u);
    begin();
    a64e_cbz_w(&e, 2, 4);
    EXPECT(0, 0x34000082u);
    begin();
    a64e_cbnz_x(&e, 3, 3);
    EXPECT(0, 0xb5000063u);
    begin();
    a64e_br_reg(&e, 5);
    EXPECT(0, 0xd61f00a0u);
    begin();
    a64e_ret(&e);
    EXPECT(0, 0xd65f03c0u);
    begin();
    a64e_ret_reg(&e, 6);
    EXPECT(0, 0xd65f00c0u);
    begin();
    a64e_nop(&e);
    EXPECT(0, 0xd503201fu);

    begin();
    a64e_nop(&e);
    s = a64e_reserve(&e);
    a64e_nop(&e);
    a64e_patch(&e, s, 0xd65f03c0u);
    EXPECT(0, 0xd503201fu);
    EXPECT(1, 0xd65f03c0u);
    EXPECT(2, 0xd503201fu);

    /* Register gate: x18/x29/x30 never encode. */
    begin();
    a64e_mov_rr(&e, 18, 21);
    EXPECT_ERR();
    begin();
    a64e_mov_rr(&e, 21, 18);
    EXPECT_ERR();
    begin();
    a64e_add_rr(&e, 29, 21, 22);
    EXPECT_ERR();
    begin();
    a64e_ldr_x(&e, 21, 30, 0);
    EXPECT_ERR();
    begin();
    a64e_br_reg(&e, 18);
    EXPECT_ERR();
    begin();
    a64e_ret_reg(&e, 30);
    EXPECT(0, 0xd65f03c0u);
    begin();
    a64e_ret_reg(&e, 18);
    EXPECT_ERR();
    begin();
    a64e_add_ir(&e, 0, 1, 4096, 0);
    EXPECT_ERR();
    begin();
    a64e_shift_imm_x(&e, 0, 0, 1, 64);
    EXPECT_ERR();
    begin();
    a64e_b_off(&e, 1 << 25);
    EXPECT_ERR();
    begin();
    a64e_bcond(&e, 16, 0);
    EXPECT_ERR();
    begin();
    e.cap = 1;
    a64e_nop(&e);
    a64e_nop(&e);
    EXPECT_ERR();
    begin();
    a64e_patch(&e, 99, 0);
    EXPECT_ERR();
    a64e_nop(NULL);
    a64e_u32(NULL, 0);

    if (fails == 0)
        (void)printf("test_dbt_emit: all assertions passed\n");
    return fails != 0;
}
