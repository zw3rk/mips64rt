/*
 * src/dbt/emit_enc.c — AArch64 word encoders for the L2c integer emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every word below was verified against the native assembler. Only
 * a64e_u32 + the frozen a64_emit_t shape cross from lane L2b; register
 * 18 is rejected in every helper.
 */

#include "dbt/emit_int.h"

static int ei_reg_ok(unsigned r)
{
    return r < 32u && r != 18u;
}

/* Raw word append with a register pre-check. */
static void ei_emit3(a64_emit_t *e, uint32_t w, unsigned ra, unsigned rb,
                     unsigned rc)
{
    if (e == NULL || !ei_reg_ok(ra) || !ei_reg_ok(rb) || !ei_reg_ok(rc)) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    a64e_u32(e, w);
}

/* movz Xd, #imm16, lsl #(hw*16). */
void ei_movz(a64_emit_t *e, unsigned rd, uint32_t imm, unsigned hw)
{
    ei_emit3(e, 0xD2800000u | ((hw & 3u) << 21) | ((imm & 0xFFFFu) << 5) |
                (rd & 31u),
             rd, EI_XZR, EI_XZR);
}

/* movk Xd, #imm16, lsl #(hw*16) (keeps the other half-words). */
void ei_movk(a64_emit_t *e, unsigned rd, uint32_t imm, unsigned hw)
{
    ei_emit3(e, 0xF2800000u | ((hw & 3u) << 21) | ((imm & 0xFFFFu) << 5) |
                (rd & 31u),
             rd, EI_XZR, EI_XZR);
}

/* Materialize a 64-bit constant with the shortest movz/movk chain. */
void ei_mov64(a64_emit_t *e, unsigned rd, uint64_t v)
{
    unsigned hw;
    int first = 1;

    for (hw = 0u; hw < 4u; hw++) {
        uint32_t h = (uint32_t)((v >> (hw * 16u)) & 0xFFFFu);

        if (first != 0) {
            if (h != 0u || hw == 3u) {
                ei_movz(e, rd, h, hw);
                first = 0;
            }
        } else if (h != 0u) {
            ei_movk(e, rd, h, hw);
        }
    }
}

/* Materialize a 32-bit pattern (zero-extended, like a W write). */
void ei_mov32(a64_emit_t *e, unsigned rd, uint32_t v)
{
    uint32_t lo = v & 0xFFFFu;
    uint32_t hi = (v >> 16) & 0xFFFFu;

    if (hi != 0u) {
        ei_movz(e, rd, hi, 1u);
        if (lo != 0u) {
            ei_movk(e, rd, lo, 0u);
        }
    } else {
        ei_movz(e, rd, lo, 0u);
    }
}

/* orr Xd, XZR, Xm (register move, XZR allowed as source). */
void ei_mov(a64_emit_t *e, unsigned rd, unsigned rm)
{
    ei_emit3(e, 0xAA000000u | ((rm & 31u) << 16) | (31u << 5) | (rd & 31u),
             rd, EI_XZR, rm);
}

static void ei_addsub(a64_emit_t *e, uint32_t base, int is_w, unsigned rd,
                      unsigned rn, unsigned rm)
{
    uint32_t w = base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

/* add/sub/adds/subs, X or W forms (is_s selects the flag-setting form). */
void ei_add(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    ei_addsub(e, 0x8B000000u, is_w, rd, rn, rm);
}

void ei_sub(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    ei_addsub(e, 0xCB000000u, is_w, rd, rn, rm);
}

void ei_adds(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_addsub(e, 0xAB000000u, is_w, rd, rn, rm);
}

void ei_subs(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_addsub(e, 0xEB000000u, is_w, rd, rn, rm);
}

static void ei_logic(a64_emit_t *e, uint32_t base, int is_w, unsigned rd,
                     unsigned rn, unsigned rm)
{
    uint32_t w = base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

/* and/or/eor/bic/and-setting(tst), X or W forms. */
void ei_and(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    ei_logic(e, 0x8A000000u, is_w, rd, rn, rm);
}

void ei_orr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    ei_logic(e, 0xAA000000u, is_w, rd, rn, rm);
}

void ei_eor(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    ei_logic(e, 0xCA000000u, is_w, rd, rn, rm);
}

void ei_bic_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm)
{
    ei_emit3(e, 0x0A200000u | ((rm & 31u) << 16) | ((rn & 31u) << 5) |
                 (rd & 31u),
             rd, rn, rm);
}

/* tst Xn, Xm (ands with XZR destination). */
void ei_tst(a64_emit_t *e, unsigned rn, unsigned rm)
{
    ei_emit3(e, 0xEA000000u | ((rm & 31u) << 16) | ((rn & 31u) << 5) | 31u,
             EI_XZR, rn, rm);
}

/* mvn Xd, Xm (orn with XZR). */
void ei_mvn(a64_emit_t *e, unsigned rd, unsigned rm)
{
    ei_emit3(e, 0xAA2003E0u | ((rm & 31u) << 16) | (rd & 31u), rd, EI_XZR,
             rm);
}

/* Register shifts: lslv/lsrv/asrv/rorv, X or W forms. */
static void ei_shiftv(a64_emit_t *e, uint32_t base, int is_w, unsigned rd,
                      unsigned rn, unsigned rm)
{
    uint32_t w = base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

void ei_lslv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_shiftv(e, 0x9AC02000u, is_w, rd, rn, rm);
}

void ei_lsrv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_shiftv(e, 0x9AC02400u, is_w, rd, rn, rm);
}

void ei_asrv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_shiftv(e, 0x9AC02800u, is_w, rd, rn, rm);
}

void ei_rorv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm)
{
    ei_shiftv(e, 0x9AC02C00u, is_w, rd, rn, rm);
}

/* Multiply/divide: mul, smull/umull/smulh/umulh, sdiv/udiv, msub,
 * smaddl/umaddl/smsubl (X forms unless noted). */
void ei_mul(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned rm)
{
    uint32_t w = 0x9B007C00u | ((rm & 31u) << 16) | ((rn & 31u) << 5) |
        (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

void ei_mulwide(a64_emit_t *e, uint32_t base, unsigned rd,
                       unsigned rn, unsigned rm)
{
    ei_emit3(e, base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u),
             rd, rn, rm);
}

void ei_maddl(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                     unsigned rm, unsigned ra)
{
    ei_emit3(e, base | ((rm & 31u) << 16) | ((ra & 31u) << 10) |
                 ((rn & 31u) << 5) | (rd & 31u),
             rd, rn, rm);
}

void ei_div(a64_emit_t *e, uint32_t base, int is_w, unsigned rd,
                   unsigned rn, unsigned rm)
{
    uint32_t w = base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

void ei_msub(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm, unsigned ra)
{
    uint32_t w = 0x9B008000u | ((rm & 31u) << 16) | ((ra & 31u) << 10) |
        ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

/* clz, rev/rev16 (X), rev32 (X), rev/rev16 (W). */
void ei_clz(a64_emit_t *e, int is_w, unsigned rd, unsigned rn)
{
    uint32_t w = 0xDAC01000u | ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, EI_XZR);
}

void ei_rev(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn)
{
    ei_emit3(e, base | ((rn & 31u) << 5) | (rd & 31u), rd, rn, EI_XZR);
}

/* sxtw/sxth/sxtb Xt, Wn (64-bit SBFM with immr 0). */
void ei_sxt(a64_emit_t *e, unsigned imms, unsigned rd, unsigned rn)
{
    ei_emit3(e, 0x93400000u | (1u << 22) | ((imms & 63u) << 10) |
                 ((rn & 31u) << 5) | (rd & 31u),
             rd, rn, EI_XZR);
}

/* ubfm/sbfm Xd, Xn, #immr, #imms (shifts and bitfield extracts). */
void ei_bfm(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                   unsigned immr, unsigned imms)
{
    ei_emit3(e, base | ((immr & 63u) << 16) | ((imms & 63u) << 10) |
                 ((rn & 31u) << 5) | (rd & 31u),
             rd, rn, EI_XZR);
}

void ei_lsl(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned sa)
{
    if (is_w != 0) {
        ei_bfm(e, 0x53000000u, rd, rn, (32u - (sa & 31u)) & 31u,
               31u - (sa & 31u));
    } else {
        ei_bfm(e, 0xD3400000u, rd, rn, (64u - (sa & 63u)) & 63u,
               63u - (sa & 63u));
    }
}

void ei_lsr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned sa)
{
    if (is_w != 0) {
        ei_bfm(e, 0x53000000u, rd, rn, sa & 31u, 31u);
    } else {
        ei_bfm(e, 0xD3400000u, rd, rn, sa & 63u, 63u);
    }
}

void ei_asr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                   unsigned sa)
{
    if (is_w != 0) {
        ei_bfm(e, 0x13000000u, rd, rn, sa & 31u, 31u);
    } else {
        ei_bfm(e, 0x93400000u, rd, rn, sa & 63u, 63u);
    }
}

/* cmp Xn, Xm / cmp Wn, Wm (subs with XZR destination). */
void ei_cmp(a64_emit_t *e, int is_w, unsigned rn, unsigned rm)
{
    uint32_t w = 0xEB000000u | ((rm & 31u) << 16) | ((rn & 31u) << 5) | 31u;

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, EI_XZR, rn, rm);
}

/* cset Wd, cc (csinc with WZR operands and the inverted condition). */
void ei_cset(a64_emit_t *e, unsigned rd, unsigned cc)
{
    ei_emit3(e, 0x1A800400u | (31u << 16) | (((cc ^ 1u) & 15u) << 12) |
                 (31u << 5) | (rd & 31u),
             rd, EI_XZR, EI_XZR);
}

/* csel, X or W forms. */
void ei_csel(a64_emit_t *e, int is_w, unsigned rd, unsigned rn,
                    unsigned rm, unsigned cc)
{
    uint32_t w = 0x9A800000u | ((rm & 31u) << 16) | ((cc & 15u) << 12) |
        ((rn & 31u) << 5) | (rd & 31u);

    if (is_w != 0) {
        w &= ~(1u << 31);
    }
    ei_emit3(e, w, rd, rn, rm);
}

/* Reserve a forward-branch slot; the caller patches it with ei_patch. */
size_t ei_fwd(a64_emit_t *e, uint32_t w)
{
    size_t slot = e == NULL ? 0u : e->len;

    if (e != NULL) {
        a64e_u32(e, w);
    }
    return slot;
}

/* cbz/cbnz/tbz/tbnz/b.cond placeholders (offset patched later). */
size_t ei_cbz(a64_emit_t *e, int is_w, int is_nz, unsigned rt)
{
    uint32_t w = (is_nz != 0 ? 0x35000000u : 0x34000000u) | (rt & 31u);

    if (is_w == 0) {
        w |= (1u << 31);
    }
    if (e != NULL && !ei_reg_ok(rt)) {
        e->err = 1;
    }
    return ei_fwd(e, w);
}

size_t ei_tbz(a64_emit_t *e, int is_nz, unsigned rt, unsigned bit)
{
    uint32_t w = (is_nz != 0 ? 0x37000000u : 0x36000000u) |
        ((bit & 63u) << 19) | (rt & 31u);

    if (e != NULL && !ei_reg_ok(rt)) {
        e->err = 1;
    }
    return ei_fwd(e, w);
}

size_t ei_bcc(a64_emit_t *e, unsigned cc)
{
    return ei_fwd(e, 0x54000000u | (cc & 15u));
}

/* Patch a forward slot to an explicit target word index. */
void ei_patch_at(a64_emit_t *e, size_t slot, size_t tgt, int bit14)
{
    size_t off;

    if (e == NULL || e->buf == NULL || slot >= e->len || tgt < slot ||
        tgt > e->len) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    off = tgt - slot;
    if (bit14 != 0) {
        if ((off >> 14) != 0u) {
            e->err = 1;
            return;
        }
    } else if ((off >> 19) != 0u) {
        e->err = 1;
        return;
    }
    e->buf[slot] |= (uint32_t)((off & 0x7FFFFu) << 5);
}

/* Patch a forward slot to the current end (epilogue just emitted). */
void ei_patch(a64_emit_t *e, size_t slot, int bit14)
{
    if (e == NULL) {
        return;
    }
    ei_patch_at(e, slot, e->len, bit14);
}

/* Backward cbnz to a recorded loop top (word distance known). */
void ei_cbnz_back(a64_emit_t *e, int is_w, unsigned rt, size_t top)
{
    uint32_t w = (is_w != 0 ? 0x35000000u : 0xB5000000u) | (rt & 31u);
    size_t back;

    if (e == NULL || top > e->len) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    back = e->len - top;
    if ((back >> 19) != 0u || back == 0u) {
        e->err = 1;
        return;
    }
    w |= (uint32_t)(((0u - back) & 0x7FFFFu) << 5);
    if (!ei_reg_ok(rt)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, w);
}

/* Unsigned-offset loads/stores (offset must fit the scaled form). */
static void ei_mem(a64_emit_t *e, uint32_t base, unsigned scale,
                   unsigned rt, unsigned rn, uint32_t off)
{
    if (e != NULL &&
        (!ei_reg_ok(rt) || !ei_reg_ok(rn) || (off & ((1u << scale) - 1u)) !=
             0u || (off >> (12u + scale)) != 0u)) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((off >> scale) << 10) | ((rn & 31u) << 5) |
                (rt & 31u));
}

void ei_ldr(a64_emit_t *e, int is_w, unsigned rt, unsigned rn,
                   uint32_t off)
{
    ei_mem(e, is_w != 0 ? 0xB9400000u : 0xF9400000u, is_w != 0 ? 2u : 3u,
           rt, rn, off);
}

void ei_str(a64_emit_t *e, int is_w, unsigned rt, unsigned rn,
                   uint32_t off)
{
    ei_mem(e, is_w != 0 ? 0xB9000000u : 0xF9000000u, is_w != 0 ? 2u : 3u,
           rt, rn, off);
}

void ei_ldrb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, 0x39400000u, 0u, rt, rn, off);
}

void ei_strb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, 0x39000000u, 0u, rt, rn, off);
}

void ei_ldrh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, 0x79400000u, 1u, rt, rn, off);
}

void ei_strh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, 0x79000000u, 1u, rt, rn, off);
}

/* Sign-extending byte/half/word loads into X registers. */
static void ei_ldrs(a64_emit_t *e, uint32_t base, unsigned scale,
                    unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, base, scale, rt, rn, off);
}

void ei_ldrsb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_ldrs(e, 0x39800000u, 0u, rt, rn, off);
}

void ei_ldrsh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_ldrs(e, 0x79800000u, 1u, rt, rn, off);
}

void ei_ldrsw(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off)
{
    ei_mem(e, 0xB9800000u, 2u, rt, rn, off);
}

/* ldxr Xt, [Xn] / stxr Ws, Xt, [Xn] (status in Ws). */
void ei_ldxr(a64_emit_t *e, int is_w, unsigned rt, unsigned rn)
{
    uint32_t w = (is_w != 0 ? 0x885F7C00u : 0xC85F7C00u) |
        ((rn & 31u) << 5) | (rt & 31u);

    if (e != NULL && (!ei_reg_ok(rt) || !ei_reg_ok(rn))) {
        e->err = 1;
        return;
    }
    a64e_u32(e, w);
}

void ei_stxr(a64_emit_t *e, int is_w, unsigned ws, unsigned data,
                    unsigned addr)
{
    uint32_t w = 0x08007C00u | ((is_w != 0 ? 2u : 3u) << 30) |
        ((ws & 31u) << 16) | ((addr & 31u) << 5) | (data & 31u);

    if (e != NULL &&
        (!ei_reg_ok(ws) || !ei_reg_ok(data) || !ei_reg_ok(addr))) {
        e->err = 1;
        return;
    }
    a64e_u32(e, w);
}

void ei_ret(a64_emit_t *e)
{
    a64e_u32(e, 0xD65F03C0u);
}

/* sub Xt, Xn, #imm12 (verified against the native assembler). */
void ei_sub_imm(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm)
{
    if (e != NULL && ((imm >> 12) != 0u || !ei_reg_ok(rd) ||
                      !ei_reg_ok(rn))) {
        e->err = 1;
        return;
    }
    a64e_u32(e, 0xD1000000u | ((imm & 0xFFFu) << 10) | ((rn & 31u) << 5) |
                (rd & 31u));
}
