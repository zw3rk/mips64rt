/*
 * src/dbt/a64_emit.c — Direct AArch64 integer instruction encoder.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bodies for `src/dbt/a64_emit.h`. Curated C11 only. Every word below
 * was verified against `aarch64-unknown-linux-musl-as` (see the
 * `/tmp/enc_probe.s` ground-truth dump) and is pinned by
 * `tests/test_dbt_emit.c`. The register gate rejects `x18` (platform
 * register) and `x29`/`x30` (host fp/lr, owned by the trampoline);
 * `x19` (ctx) and `x20` (guest base) stay addressable as bases.
 */

#include "dbt/a64_emit.h"

void a64e_u32(a64_emit_t *e, uint32_t w)
{
    if (e == NULL || e->buf == NULL || e->len >= e->cap) {
        if (e != NULL)
            e->err = 1;
        return;
    }
    e->buf[e->len++] = w;
}

void a64e_init(a64_emit_t *e, uint32_t *buf, size_t cap)
{
    size_t i;

    if (e == NULL) {
        return;
    }
    e->buf = buf;
    e->cap = cap;
    e->len = 0u;
    e->err = 0;
    e->gpr_cache_valid = 0u;
    for (i = 0u; i < 8u; i++) {
        e->gpr_cache_reg[i] = 0u;
    }
    /* Fresh block: the Wave P13 FPR cache starts empty (a64e_init zeroes
     * fpr_valid); each ei_branch slot copy re-invalidates. */
    e->fpr_valid = 0u;
    e->fpr_is_d = 0u;
    for (i = 0u; i < 8u; i++) {
        e->fpr_slot_reg[i] = 0u;
    }
}

/* Register gate: `x18`, `x29`, `x30` are never scratch-encodable.
 * `xzr` (31) is fine (dropped writes, comparisons). */
static int reg_ok(a64_emit_t *e, unsigned r)
{
    if (r == 18u || r == 29u || r == 30u || r > 31u) {
        e->err = 1;
        return 0;
    }
    return 1;
}

static int two_regs_ok(a64_emit_t *e, unsigned a, unsigned b)
{
    return reg_ok(e, a) && reg_ok(e, b);
}

static int three_regs_ok(a64_emit_t *e, unsigned a, unsigned b, unsigned c)
{
    return reg_ok(e, a) && reg_ok(e, b) && reg_ok(e, c);
}

void a64e_movz_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd) || hw > 3u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xd2800000u | ((hw & 3u) << 21) |
                    ((imm16 & 0xffffu) << 5) | (rd & 31u));
}

void a64e_movk_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd) || hw > 3u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xf2800000u | ((hw & 3u) << 21) |
                    ((imm16 & 0xffffu) << 5) | (rd & 31u));
}

void a64e_movn_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd) || hw > 3u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x92800000u | ((hw & 3u) << 21) |
                    ((imm16 & 0xffffu) << 5) | (rd & 31u));
}

void a64e_movz_w(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd) || hw > 1u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x52800000u | ((hw & 1u) << 21) |
                    ((imm16 & 0xffffu) << 5) | (rd & 31u));
}

void a64e_movk_w(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd) || hw > 1u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x72800000u | ((hw & 1u) << 21) |
                    ((imm16 & 0xffffu) << 5) | (rd & 31u));
}

void a64e_mov_imm64(a64_emit_t *e, unsigned rd, uint64_t v)
{
    unsigned hw;

    if (e == NULL)
        return;
    if (!reg_ok(e, rd)) {
        e->err = 1;
        return;
    }
    a64e_movz_x(e, rd, (uint32_t)(v & 0xffffu), 0);
    for (hw = 1; hw < 4; hw++) {
        uint32_t part = (uint32_t)((v >> (hw * 16)) & 0xffffu);

        if (part != 0u)
            a64e_movk_x(e, rd, part, hw);
    }
}

void a64e_mov_imm32(a64_emit_t *e, unsigned rd, uint32_t v)
{
    if (e == NULL)
        return;
    if (!reg_ok(e, rd)) {
        e->err = 1;
        return;
    }
    if (v <= 0xffffu) {
        a64e_movz_w(e, rd, v, 0);
        return;
    }
    a64e_movz_w(e, rd, v & 0xffffu, 0);
    a64e_movk_w(e, rd, (v >> 16) & 0xffffu, 1);
}

void a64e_mov_rr(a64_emit_t *e, unsigned rd, unsigned rm)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rd, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xaa0003e0u | ((rm & 31u) << 16) | (rd & 31u));
}

void a64e_add_rr(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    if (!three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x8b000000u | ((rm & 31u) << 16) |
                    ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_sub_rr(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    if (!three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xcb000000u | ((rm & 31u) << 16) |
                    ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_add_ww(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    if (!three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x0b000000u | ((rm & 31u) << 16) |
                    ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_sub_ww(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    if (!three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x4b000000u | ((rm & 31u) << 16) |
                    ((rn & 31u) << 5) | (rd & 31u));
}

static void addsub_ir(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                      uint32_t imm12, unsigned sh)
{
    if (!two_regs_ok(e, rd, rn) || imm12 > 4095u || (sh != 0u && sh != 12u)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((sh == 12u ? 1u : 0u) << 22) |
                    ((imm12 & 0xfffu) << 10) | ((rn & 31u) << 5) |
                    (rd & 31u));
}

void a64e_add_ir(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                 unsigned sh)
{
    if (e == NULL)
        return;
    addsub_ir(e, (uint32_t)0x91000000u, rd, rn, imm12, sh);
}

void a64e_sub_ir(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                 unsigned sh)
{
    if (e == NULL)
        return;
    addsub_ir(e, (uint32_t)0xd1000000u, rd, rn, imm12, sh);
}

void a64e_add_ir_w(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                   unsigned sh)
{
    if (e == NULL)
        return;
    addsub_ir(e, (uint32_t)0x11000000u, rd, rn, imm12, sh);
}

void a64e_sub_ir_w(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                   unsigned sh)
{
    if (e == NULL)
        return;
    addsub_ir(e, (uint32_t)0x51000000u, rd, rn, imm12, sh);
}

static void logic3(a64_emit_t *e, uint32_t base, unsigned op, unsigned rd,
                   unsigned rn, unsigned rm)
{
    /* `opc` lives in bits 30:29 (`and` = 0, `orr` = 1, `eor` = 2). */
    static const uint32_t sub[3] = { 0x00000000u, 0x20000000u, 0x40000000u };

    if (op > 2u || !three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | sub[op] | ((rm & 31u) << 16) | ((rn & 31u) << 5) |
                    (rd & 31u));
}

void a64e_logic_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                  unsigned rm)
{
    if (e == NULL)
        return;
    logic3(e, (uint32_t)0x8a000000u, op, rd, rn, rm);
}

void a64e_logic_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                  unsigned rm)
{
    if (e == NULL)
        return;
    logic3(e, (uint32_t)0x0a000000u, op, rd, rn, rm);
}

static void shift_reg(a64_emit_t *e, uint32_t base, unsigned op, unsigned rd,
                      unsigned rn, unsigned rm)
{
    /* `op2` lives in bits 13:12 (`lsl` = 1, `lsr` = 2, ...): the
     * probe words pin `lsl` = 0x2000, `lsr` = 0x2400, `asr` = 0x2800,
     * `ror` = 0x2c00. */
    static const uint32_t sub[4] = { 0x00002000u, 0x00002400u, 0x00002800u,
        0x00002c00u };

    if (op > 3u || !three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | sub[op] | ((rm & 31u) << 16) | ((rn & 31u) << 5) |
                    (rd & 31u));
}

void a64e_shift_reg_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned rm)
{
    if (e == NULL)
        return;
    shift_reg(e, (uint32_t)0x9ac00000u, op, rd, rn, rm);
}

void a64e_shift_reg_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned rm)
{
    if (e == NULL)
        return;
    shift_reg(e, (uint32_t)0x1ac00000u, op, rd, rn, rm);
}

void a64e_ubfm_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned immr,
                 unsigned imms)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rd, rn) || immr > 63u || imms > 63u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xd3400000u | ((immr & 63u) << 16) |
                    ((imms & 63u) << 10) | ((rn & 31u) << 5) | (rd & 31u));
}

static void shift_imm(a64_emit_t *e, unsigned is_w, unsigned op, unsigned rd,
                      unsigned rn, unsigned amount)
{
    unsigned width = is_w != 0u ? 32u : 64u;
    uint32_t base;

    if (op > 2u || !two_regs_ok(e, rd, rn) || amount >= width) {
        e->err = 1;
        return;
    }
    if (op == 2u) {
        /* `asr` is the signed bitfield move. */
        base = is_w != 0u ? (uint32_t)0x13000000u : (uint32_t)0x93400000u;
        a64e_u32(e, base | ((amount & 63u) << 16) |
                        (((width - 1u) & 63u) << 10) | ((rn & 31u) << 5) |
                        (rd & 31u));
        return;
    }
    base = is_w != 0u ? (uint32_t)0x53000000u : (uint32_t)0xd3400000u;
    if (op == 0u) {
        /* `lsl #a` is `ubfm #(w-a)%w, #(w-1-a)`. */
        unsigned immr = (width - amount) & (width - 1u);
        unsigned imms = width - 1u - amount;

        a64e_u32(e, base | ((immr & 63u) << 16) | ((imms & 63u) << 10) |
                        ((rn & 31u) << 5) | (rd & 31u));
        return;
    }
    a64e_u32(e, base | ((amount & 63u) << 16) |
                    (((width - 1u) & 63u) << 10) | ((rn & 31u) << 5) |
                    (rd & 31u));
}

void a64e_shift_imm_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned amount)
{
    if (e == NULL)
        return;
    shift_imm(e, 0, op, rd, rn, amount);
}

void a64e_shift_imm_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned amount)
{
    if (e == NULL)
        return;
    shift_imm(e, 1, op, rd, rn, amount);
}

void a64e_sxtw(a64_emit_t *e, unsigned rd, unsigned rn)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rd, rn)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x93407c00u | ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_sxth_x(a64_emit_t *e, unsigned rd, unsigned rn)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rd, rn)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x93403c00u | ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_sxtb_x(a64_emit_t *e, unsigned rd, unsigned rn)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rd, rn)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x93401c00u | ((rn & 31u) << 5) | (rd & 31u));
}

static void mul3(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                 unsigned rm)
{
    if (!three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_mul_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x9b007c00u, rd, rn, rm);
}

void a64e_mul_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x1b007c00u, rd, rn, rm);
}

void a64e_sdiv_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x9ac00c00u, rd, rn, rm);
}

void a64e_udiv_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x9ac00800u, rd, rn, rm);
}

void a64e_sdiv_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x1ac00c00u, rd, rn, rm);
}

void a64e_udiv_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    mul3(e, (uint32_t)0x1ac00800u, rd, rn, rm);
}

void a64e_cmp_x(a64_emit_t *e, unsigned rn, unsigned rm)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xeb000000u | ((rm & 31u) << 16) |
                    ((rn & 31u) << 5) | 31u);
}

void a64e_csel_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm,
                 unsigned cond)
{
    if (e == NULL)
        return;
    if (cond > 15u || !three_regs_ok(e, rd, rn, rm)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x9a800000u | ((rm & 31u) << 16) |
                    ((cond & 15u) << 12) | ((rn & 31u) << 5) | (rd & 31u));
}

void a64e_cset_x(a64_emit_t *e, unsigned rd, unsigned cond)
{
    /* `cset` is the `csinc Xd, XZR, XZR, !cond` alias (bit 10 set,
     * unlike plain `csel`): the probe pins `cset x3, ne`. */
    if (e == NULL)
        return;
    if (cond > 15u || !reg_ok(e, rd)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x9a800400u | (31u << 16) |
                    (((cond ^ 1u) & 15u) << 12) | (31u << 5) | (rd & 31u));
}

static void mem_uo(a64_emit_t *e, uint32_t base, unsigned rt, unsigned rn,
                   uint32_t off, uint32_t align_mask, uint32_t max,
                   unsigned shift)
{
    if (!two_regs_ok(e, rt, rn) || (off & align_mask) != 0u || off > max) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((off >> shift) << 10) | ((rn & 31u) << 5) |
                    (rt & 31u));
}

void a64e_ldr_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0xf9400000u, rt, rn, off, 7u, 32760u, 3);
}

void a64e_str_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0xf9000000u, rt, rn, off, 7u, 32760u, 3);
}

void a64e_ldr_w(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0xb9400000u, rt, rn, off, 3u, 16380u, 2);
}

void a64e_str_w(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0xb9000000u, rt, rn, off, 3u, 16380u, 2);
}

void a64e_ldrb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x39400000u, rt, rn, off, 0u, 4095u, 0);
}

void a64e_strb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x39000000u, rt, rn, off, 0u, 4095u, 0);
}

void a64e_ldrh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x79400000u, rt, rn, off, 1u, 8190u, 1);
}

void a64e_strh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x79000000u, rt, rn, off, 1u, 8190u, 1);
}

void a64e_ldrsb_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x39800000u, rt, rn, off, 0u, 4095u, 0);
}

void a64e_ldrsh_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0x79800000u, rt, rn, off, 1u, 8190u, 1);
}

void a64e_ldrsw_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    if (e == NULL)
        return;
    mem_uo(e, (uint32_t)0xb9800000u, rt, rn, off, 3u, 16380u, 2);
}

static void ex_pair(a64_emit_t *e, uint32_t base, unsigned a, unsigned b,
                    unsigned c)
{
    if (!three_regs_ok(e, a, b, c)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((a & 31u) << 16) | ((c & 31u) << 5) | (b & 31u));
}

void a64e_ldxr_x(a64_emit_t *e, unsigned rt, unsigned rn)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rt, rn)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xc85f7c00u | ((rn & 31u) << 5) | (rt & 31u));
}

void a64e_stxr_x(a64_emit_t *e, unsigned ws, unsigned xt, unsigned xn)
{
    if (e == NULL)
        return;
    ex_pair(e, (uint32_t)0xc8007c00u, ws, xt, xn);
}

void a64e_ldxr_w(a64_emit_t *e, unsigned rt, unsigned rn)
{
    if (e == NULL)
        return;
    if (!two_regs_ok(e, rt, rn)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x885f7c00u | ((rn & 31u) << 5) | (rt & 31u));
}

void a64e_stxr_w(a64_emit_t *e, unsigned ws, unsigned xt, unsigned xn)
{
    if (e == NULL)
        return;
    ex_pair(e, (uint32_t)0x88007c00u, ws, xt, xn);
}

void a64e_dmb_ish(a64_emit_t *e)
{
    if (e == NULL)
        return;
    a64e_u32(e, (uint32_t)0xd5033bbfu);
}

static void branch_off(a64_emit_t *e, uint32_t base, uint32_t mask,
                       int32_t word_off)
{
    int64_t lo = -((int64_t)1 << 25);
    int64_t hi = (int64_t)1 << 25;

    if (mask != 0x03ffffffu) {
        lo = -((int64_t)1 << 18);
        hi = (int64_t)1 << 18;
    }
    if ((int64_t)word_off < lo || (int64_t)word_off >= hi) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((uint32_t)word_off & mask));
}

void a64e_b_off(a64_emit_t *e, int32_t word_off)
{
    if (e == NULL)
        return;
    branch_off(e, (uint32_t)0x14000000u, 0x03ffffffu, word_off);
}

void a64e_bl_off(a64_emit_t *e, int32_t word_off)
{
    if (e == NULL)
        return;
    branch_off(e, (uint32_t)0x94000000u, 0x03ffffffu, word_off);
}

void a64e_bcond(a64_emit_t *e, unsigned cond, int32_t word_off)
{
    int64_t off = (int64_t)word_off;

    if (e == NULL)
        return;
    if (cond > 15u || off < -((int64_t)1 << 18) ||
        off >= ((int64_t)1 << 18)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0x54000000u | (((uint32_t)word_off & 0x7ffffu) << 5) |
                    (cond & 15u));
}

static void cbz_cbnz(a64_emit_t *e, uint32_t base, unsigned rt,
                     int32_t word_off)
{
    int64_t off = (int64_t)word_off;

    if (!reg_ok(e, rt) || off < -((int64_t)1 << 18) ||
        off >= ((int64_t)1 << 18)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | (((uint32_t)word_off & 0x7ffffu) << 5) | (rt & 31u));
}

void a64e_cbz_x(a64_emit_t *e, unsigned rt, int32_t word_off)
{
    if (e == NULL)
        return;
    cbz_cbnz(e, (uint32_t)0xb4000000u, rt, word_off);
}

void a64e_cbnz_x(a64_emit_t *e, unsigned rt, int32_t word_off)
{
    if (e == NULL)
        return;
    cbz_cbnz(e, (uint32_t)0xb5000000u, rt, word_off);
}

void a64e_cbz_w(a64_emit_t *e, unsigned rt, int32_t word_off)
{
    if (e == NULL)
        return;
    cbz_cbnz(e, (uint32_t)0x34000000u, rt, word_off);
}

void a64e_cbnz_w(a64_emit_t *e, unsigned rt, int32_t word_off)
{
    if (e == NULL)
        return;
    cbz_cbnz(e, (uint32_t)0x35000000u, rt, word_off);
}

void a64e_br_reg(a64_emit_t *e, unsigned rn)
{
    /* `br`/`ret` accept any target except `x18` (`x30` is the normal
     * return); the host fp/lr gate does not apply to the branch
     * target itself. */
    if (e == NULL)
        return;
    if (rn == 18u || rn > 31u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xd61f0000u | ((rn & 31u) << 5));
}

void a64e_ret(a64_emit_t *e)
{
    if (e == NULL)
        return;
    a64e_u32(e, (uint32_t)0xd65f03c0u);
}

void a64e_ret_reg(a64_emit_t *e, unsigned rn)
{
    /* Same gate as `br`: only `x18` is forbidden (`ret x30` is the
     * canonical return). */
    if (e == NULL)
        return;
    if (rn == 18u || rn > 31u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, (uint32_t)0xd65f0000u | ((rn & 31u) << 5));
}

void a64e_nop(a64_emit_t *e)
{
    if (e == NULL)
        return;
    a64e_u32(e, (uint32_t)0xd503201fu);
}

size_t a64e_reserve(a64_emit_t *e)
{
    size_t slot;

    if (e == NULL)
        return (size_t)-1;
    slot = e->len;
    a64e_u32(e, (uint32_t)0xd503201fu);
    if (e->err != 0)
        return (size_t)-1;
    return slot;
}

void a64e_patch(a64_emit_t *e, size_t slot, uint32_t w)
{
    if (e == NULL || e->buf == NULL || slot >= e->len) {
        if (e != NULL)
            e->err = 1;
        return;
    }
    e->buf[slot] = w;
}
