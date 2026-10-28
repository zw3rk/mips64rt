/*
 * src/dbt/a64_emit.h — Direct AArch64 integer instruction encoder (lane L2b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Buffer plus the small integer encoder set the DBT core needs for
 * block prologues/epilogues and that lane L2c uses for `dbt_emit_int`.
 * Every word was verified against `aarch64-unknown-linux-musl-as`
 * (`/tmp/enc_probe.s`); `tests/test_dbt_emit.c` pins each one.
 *
 * Host register discipline (frozen for L2c, see `src/dbt/dbt.h`):
 * `x19` pins the `mips64_ctx_t *`, `x20` pins the guest window base,
 * `x21..x24` are scratch, `$0` reads as `wzr` (writes dropped), and
 * **`x18` is never encoded** (every helper rejects it via `reg_ok`).
 */

#ifndef MIPS64RT_DBT_A64_EMIT_H
#define MIPS64RT_DBT_A64_EMIT_H

#include <stddef.h>
#include <stdint.h>

/* Emit buffer: a bounds-checked append of one raw A64 instruction
 * word; overflow sets `err` and drops the word. The trailing GPR
 * cache (Wave P12) tracks which guest register each host register
 * `x9..x16` holds: slot `r & 7` pins guest `r` in `x(9 + slot)` while
 * the slot bit in `gpr_cache_valid` is set (write-through, so
 * `ctx->r[]` stays exact for faults and exits). */
typedef struct {
    uint32_t *buf;
    size_t cap;
    size_t len;
    int err;
    uint8_t gpr_cache_valid;
    uint8_t gpr_cache_reg[8];
} a64_emit_t;

/* Bounds-checked append of one raw A64 word. */
void a64e_u32(a64_emit_t *e, uint32_t w);
/* Initialize an emit buffer (zeroes the GPR cache). */
void a64e_init(a64_emit_t *e, uint32_t *buf, size_t cap);

/* Raw AArch64 register ids. `A64_X18` is listed only so emitters can
 * name the forbidden platform register; no helper ever encodes it,
 * nor `x29`/`x30` (host fp/lr stay owned by the trampoline). */
enum {
    A64_X0 = 0,
    A64_X1 = 1,
    A64_X2 = 2,
    A64_X3 = 3,
    A64_X4 = 4,
    A64_X5 = 5,
    A64_X6 = 6,
    A64_X7 = 7,
    A64_X8 = 8,
    A64_X9 = 9,
    A64_X10 = 10,
    A64_X11 = 11,
    A64_X12 = 12,
    A64_X13 = 13,
    A64_X14 = 14,
    A64_X15 = 15,
    A64_X16 = 16,
    A64_X17 = 17,
    A64_X18 = 18,
    A64_X19 = 19,
    A64_X20 = 20,
    A64_X21 = 21,
    A64_X22 = 22,
    A64_X23 = 23,
    A64_X24 = 24,
    A64_X25 = 25,
    A64_X26 = 26,
    A64_X27 = 27,
    A64_X28 = 28,
    A64_X29 = 29,
    A64_X30 = 30,
    A64_XZR = 31
};

/* A64 condition codes for `csel`/`cset`/`b.cond`. */
enum {
    A64_EQ = 0,
    A64_NE = 1,
    A64_CS = 2,
    A64_CC = 3,
    A64_MI = 4,
    A64_PL = 5,
    A64_VS = 6,
    A64_VC = 7,
    A64_HI = 8,
    A64_LS = 9,
    A64_GE = 10,
    A64_LT = 11,
    A64_GT = 12,
    A64_LE = 13,
    A64_AL = 14
};

/* `movz Xd, #imm16, lsl #(hw*16)`; `hw` is 0..3. */
void a64e_movz_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw);
/* `movk Xd, #imm16, lsl #(hw*16)` (keeps the other half-words). */
void a64e_movk_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw);
/* `movn Xd, #imm16, lsl #(hw*16)` (upper bits set). */
void a64e_movn_x(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw);
/* `movz Wd, #imm16, lsl #(hw*16)`; `hw` is 0..1. */
void a64e_movz_w(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw);
/* `movk Wd, #imm16, lsl #(hw*16)`; `hw` is 0..1. */
void a64e_movk_w(a64_emit_t *e, unsigned rd, uint32_t imm16, unsigned hw);
/* Materialize a 64-bit constant with the shortest `movz`/`movk` chain. */
void a64e_mov_imm64(a64_emit_t *e, unsigned rd, uint64_t v);
/* Materialize a 32-bit constant with one `movz` (low half) when small. */
void a64e_mov_imm32(a64_emit_t *e, unsigned rd, uint32_t v);
/* `orr Xd, XZR, Xm` (register move; `rm` may be `xzr`). */
void a64e_mov_rr(a64_emit_t *e, unsigned rd, unsigned rm);
/* `add Xd, Xn, Xm` / `sub Xd, Xn, Xm`. */
void a64e_add_rr(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_sub_rr(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
/* `add Wd, Wn, Wm` / `sub Wd, Wn, Wm`. */
void a64e_add_ww(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_sub_ww(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
/* `add Xd, Xn, #imm12, lsl #(sh ? 12 : 0)` / `sub` (`imm12` <= 4095). */
void a64e_add_ir(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                 unsigned sh);
void a64e_sub_ir(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                 unsigned sh);
/* W-sized `add`/`sub` immediate (same `imm12`/`sh` shape). */
void a64e_add_ir_w(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                   unsigned sh);
void a64e_sub_ir_w(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm12,
                   unsigned sh);
/* Logical shifted-register (`op`: 0 `and`, 1 `orr`, 2 `eor`), X and W. */
void a64e_logic_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                  unsigned rm);
void a64e_logic_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                  unsigned rm);
/* Variable shifts (`op`: 0 `lsl`, 1 `lsr`, 2 `asr`, 3 `ror`), X and W. */
void a64e_shift_reg_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned rm);
void a64e_shift_reg_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned rm);
/* Immediate shifts (`op`: 0 `lsl`, 1 `lsr`, 2 `asr`), X and W. The
 * amount must be below the width (64/32); `#0` is a legal no-op. */
void a64e_shift_imm_x(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned amount);
void a64e_shift_imm_w(a64_emit_t *e, unsigned op, unsigned rd, unsigned rn,
                      unsigned amount);
/* Raw `ubfm Xd, Xn, #immr, #imms` (extract/deposit recipes). */
void a64e_ubfm_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned immr,
                 unsigned imms);
/* `sxtw/sxth/sxtb Xt, Wn` (sign-extend into X). */
void a64e_sxtw(a64_emit_t *e, unsigned rd, unsigned rn);
void a64e_sxth_x(a64_emit_t *e, unsigned rd, unsigned rn);
void a64e_sxtb_x(a64_emit_t *e, unsigned rd, unsigned rn);
/* `mul Xd, Xn, Xm` (low 64 bits) and the W form. */
void a64e_mul_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_mul_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
/* `sdiv`/`udiv` (caller guards the zero divisor), X and W. */
void a64e_sdiv_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_udiv_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_sdiv_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void a64e_udiv_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
/* `cmp Xn, Xm` (`subs xzr, Xn, Xm`). */
void a64e_cmp_x(a64_emit_t *e, unsigned rn, unsigned rm);
/* `csel Xd, Xn, Xm, cond`; `cset Xd, cond` (inverted `csel` on `xzr`). */
void a64e_csel_x(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm,
                 unsigned cond);
void a64e_cset_x(a64_emit_t *e, unsigned rd, unsigned cond);
/* `ldr Xd, [Xn, #off]` / `str Xs, [Xn, #off]`; `off` a multiple of 8
 * within the 15-bit unsigned range. */
void a64e_ldr_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_str_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
/* W loads/stores (`off` multiple of 4, same range). */
void a64e_ldr_w(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_str_w(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
/* Byte/halfword loads/stores (`off` <= 4095 / multiple of 2 <= 8190). */
void a64e_ldrb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_strb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_ldrh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_strh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
/* Signed loads into X (`lb`/`lh`/`lw` with canonical sign-extension). */
void a64e_ldrsb_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_ldrsh_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void a64e_ldrsw_x(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
/* `ldxr Xt, [Xn]` / `stxr Ws, Xt, [Xn]` (LL/SC; `ws` reports status). */
void a64e_ldxr_x(a64_emit_t *e, unsigned rt, unsigned rn);
void a64e_stxr_x(a64_emit_t *e, unsigned ws, unsigned xt, unsigned xn);
void a64e_ldxr_w(a64_emit_t *e, unsigned rt, unsigned rn);
void a64e_stxr_w(a64_emit_t *e, unsigned ws, unsigned xt, unsigned xn);
/* `dmb ish` (LL/SC ordering edge). */
void a64e_dmb_ish(a64_emit_t *e);
/* `b`/`bl` with a signed word offset (bytes/4, +/-128 MiB). */
void a64e_b_off(a64_emit_t *e, int32_t word_off);
void a64e_bl_off(a64_emit_t *e, int32_t word_off);
/* `b.<cond> <off>` with a signed 19-bit word offset (+/-1 MiB). */
void a64e_bcond(a64_emit_t *e, unsigned cond, int32_t word_off);
/* `cbz`/`cbnz` (X and W) with a signed 19-bit word offset. */
void a64e_cbz_x(a64_emit_t *e, unsigned rt, int32_t word_off);
void a64e_cbnz_x(a64_emit_t *e, unsigned rt, int32_t word_off);
void a64e_cbz_w(a64_emit_t *e, unsigned rt, int32_t word_off);
void a64e_cbnz_w(a64_emit_t *e, unsigned rt, int32_t word_off);
/* `br Rn` / `ret` / `ret Rn` / `nop`. `br`/`ret` accept any target
 * except `x18` (`x30` is the canonical return); the `x29`/`x30` gate
 * does not apply to branch targets. */
void a64e_br_reg(a64_emit_t *e, unsigned rn);
void a64e_ret(a64_emit_t *e);
void a64e_ret_reg(a64_emit_t *e, unsigned rn);
void a64e_nop(a64_emit_t *e);

/* Reserve one instruction slot for later patching (direct-chaining
 * fixup); returns the slot index, or `(size_t)-1` on error. */
size_t a64e_reserve(a64_emit_t *e);
/* Overwrite a previously reserved slot with a new word. */
void a64e_patch(a64_emit_t *e, size_t slot, uint32_t w);

#endif /* MIPS64RT_DBT_A64_EMIT_H */
