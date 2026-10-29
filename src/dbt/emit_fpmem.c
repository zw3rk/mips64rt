/*
 * src/dbt/emit_fpmem.c — FPR loads/stores for the L2c emitter (Wave P).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lowers LWC1/SWC1 (word) and LDC1/SDC1 (doubleword) through the same
 * Rev4 soft-TLB probe + miss-site path as integer memory (the probe
 * helpers are shared from emit_mem.c via emit_int.h): the effective
 * address materializes in EI_A, the 6-instruction probe resolves the
 * host page with [EI_A, EI_H] addressing, and the miss stub reaches
 * the shared per-block miss epilogue (the dispatcher replays the word
 * with interp_step, so alignment faults and unmapped spans report
 * exactly like the fpmove_mem oracle).
 *
 * The transfer itself is integer-typed (never x18, x0 preserved):
 * LWC1 loads 4 bytes and stores only the low lane word (the FR=1
 * upper lane is preserved, matching fpmove_mem); LDC1 moves the full
 * 64-bit lane. Big-endian guests byteswap exactly like the integer
 * LW/SW/LD/SD paths (rev after loads, rev before stores). Stores
 * clear the LL reservation like every ordinary store (E05).
 */

#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"

/* FPR lane offset for index r (FR=1 64-bit lanes, cpu.h). */
#define EFPM_OFF_FPR(r) (MIPS64_CTX_FPR_OFFSET + (uint32_t)(r) * 8u)

/* ---- Wave P13: 8-slot write-through scalar FPR cache in d8..d15 ----
 *
 * AAPCS64 callee-saved d8..d15 hold cached guest FPR lanes (slot s =
 * f & 7, tag-checked so f8/f16/f24 alias safely); every write updates
 * the cache reg AND the ctx lane, so ctx->fpr[] stays exact on faults
 * and block exits with zero flush code.  The trampoline saves and
 * restores d8..d15 across mips64_dbt_enter; no mid-block C helper
 * call exists, so nothing clobbers the cache within a block.
 * d(8+s) for s in 1..7 shares its physical register with GPR cache
 * x(8+s), so every cache write drops the aliased GPR slot (and every
 * GPR fill drops the aliased FP slot from emit_int.c). */

/* Raw FMOV register copies (assembler-verified bases, same family as
 * the emit_fp.c ef_f1/ef_fmov_bit words). FP operands cover scratch
 * s0..s4/d0..d3 and cache d8..d15 only (never v18, which overlaps
 * the forbidden x18); integer operands are EI regs, never x18. */
static void ef_fmov_raw(a64_emit_t *e, uint32_t base, unsigned rd,
                        unsigned rn, int fp_rd, int fp_rn)
{
    if (e == NULL) {
        return;
    }
    if (fp_rd != 0 && rd > 15u) {
        e->err = 1;
        return;
    }
    if (fp_rn != 0 && rn > 15u) {
        e->err = 1;
        return;
    }
    if ((fp_rd == 0 && (rd == 18u || rd > 31u)) ||
        (fp_rn == 0 && (rn == 18u || rn > 31u))) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((rn & 31u) << 5) | (rd & 31u));
}

/* FMOV Sd,Sn / Dd,Dn (scalar lane copies). */
static void ef_fmov_ss(a64_emit_t *e, unsigned rd, unsigned rn)
{
    ef_fmov_raw(e, 0x1E204000u, rd, rn, 1, 1);
}

static void ef_fmov_dd(a64_emit_t *e, unsigned rd, unsigned rn)
{
    ef_fmov_raw(e, 0x1E604000u, rd, rn, 1, 1);
}

/* FMOV Wd,Sn (lane low word to integer reg). */
static void ef_fmov_ws(a64_emit_t *e, unsigned wd, unsigned sn)
{
    ef_fmov_raw(e, 0x1E260000u, wd, sn, 0, 1);
}

/* FMOV Sd,Wn (integer word to lane low word; upper lane preserved by
 * the caller-side ctx store pairing every populate). */
static void ef_fmov_sw(a64_emit_t *e, unsigned sd, unsigned wn)
{
    ef_fmov_raw(e, 0x1E270000u, sd, wn, 1, 0);
}

/* FMOV Xd,Dn / Dd,Xn (full-lane bit moves). */
static void ef_fmov_xd(a64_emit_t *e, unsigned xd, unsigned dn)
{
    ef_fmov_raw(e, 0x9E660000u, xd, dn, 0, 1);
}

static void ef_fmov_dx(a64_emit_t *e, unsigned dd, unsigned xn)
{
    ef_fmov_raw(e, 0x9E670000u, dd, xn, 1, 0);
}

#define EF_FSLOT(fs) ((((unsigned)(fs)) & 31u) & 7u)
#define EF_FREG(slot) (8u + (slot))

/* Hit test: a .D read needs a .D tag (an .S entry leaves the cache
 * reg's upper 32 undefined); an .S read takes either tag (the low 32
 * are shared). */
static int ef_fhit(a64_emit_t *e, unsigned fs, int want_d)
{
    unsigned slot;

    if (e == NULL) {
        return 0;
    }
    slot = EF_FSLOT(fs);
    if ((((e->fpr_valid >> slot) & 1u) == 0u) ||
        e->fpr_slot_reg[slot] != (uint8_t)((unsigned)(fs) & 31u)) {
        return 0;
    }
    if (want_d != 0 && (((e->fpr_is_d >> slot) & 1u) == 0u)) {
        return 0;
    }
    return 1;
}

/* Tag slot after a write-through populate (drops the aliased GPR slot
 * for s in 1..7; x8 has no GPR alias). */
static void ef_ftag(a64_emit_t *e, unsigned fs, int is_d)
{
    unsigned slot;

    if (e == NULL) {
        return;
    }
    slot = EF_FSLOT(fs);
    if (slot != 0u) {
        e->gpr_cache_valid &= (uint8_t)~(1u << (slot - 1u));
    }
    e->fpr_valid |= (uint8_t)(1u << slot);
    e->fpr_slot_reg[slot] = (uint8_t)((unsigned)(fs) & 31u);
    if (is_d != 0) {
        e->fpr_is_d |= (uint8_t)(1u << slot);
    } else {
        e->fpr_is_d &= (uint8_t)~(1u << slot);
    }
}

/* MTC1/DMTC1 write raw integer bits: drop the matching slot. */
void ef_fpr_invalidate(a64_emit_t *e, unsigned fs)
{
    unsigned slot;

    if (e == NULL) {
        return;
    }
    slot = EF_FSLOT(fs);
    if (e->fpr_slot_reg[slot] == (uint8_t)((unsigned)(fs) & 31u)) {
        e->fpr_valid &= (uint8_t)~(1u << slot);
    }
}

/* SIMD&FP LDR/STR (unsigned offset): S scales by 4, D by 8.
 * Assembler-verified bases (cf. emit_fp.c): bit 26 selects SIMD&FP
 * lanes (integer STR uses 0xB9000000 / 0xF9000000 and must never
 * appear here). */
static void ef_ldst(a64_emit_t *e, int is_load, int is_d, unsigned rt,
                    unsigned rn, uint32_t off)
{
    uint32_t base;
    uint32_t div;

    if (e == NULL || rt > 15u || rn == 18u || rn > 31u) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    if (is_d != 0) {
        base = is_load != 0 ? 0xFD400000u : 0xFD000000u;
        div = 8u;
    } else {
        base = is_load != 0 ? 0xBD400000u : 0xBD000000u;
        div = 4u;
    }
    if ((off % div) != 0u || (off / div) >= 4096u) {
        e->err = 1;
        return;
    }
    a64e_u32(e, base | ((off / div) << 10) | ((rn & 31u) << 5) |
                (rt & 31u));
}

/* FPR lane spill/fill (FR=1 64-bit lanes; S = low 32 bits), routed
 * through the d8..d15 cache: hits copy between scratch and cache
 * regs with one FMOV, misses load the ctx lane and populate. */
void ef_fill(a64_emit_t *e, int is_d, unsigned fp, unsigned fs)
{
    unsigned slot = EF_FSLOT(fs);

    if (ef_fhit(e, fs, is_d) != 0) {
        if (is_d != 0) {
            ef_fmov_dd(e, fp, EF_FREG(slot));
        } else {
            ef_fmov_ss(e, fp, EF_FREG(slot));
        }
        return;
    }
    ef_ldst(e, 1, is_d, fp, EI_CTX, EFPM_OFF_FPR(fs & 31u));
    if (is_d != 0) {
        ef_fmov_dd(e, EF_FREG(slot), fp);
    } else {
        ef_fmov_ss(e, EF_FREG(slot), fp);
    }
    ef_ftag(e, fs, is_d);
}

void ef_spill(a64_emit_t *e, int is_d, unsigned fp, unsigned fd)
{
    unsigned slot = EF_FSLOT(fd);

    ef_ldst(e, 0, is_d, fp, EI_CTX, EFPM_OFF_FPR(fd & 31u));
    if (is_d != 0) {
        ef_fmov_dd(e, EF_FREG(slot), fp);
    } else {
        ef_fmov_ss(e, EF_FREG(slot), fp);
    }
    ef_ftag(e, fd, is_d);
}

/* Cache read into an integer reg for integer-typed lane consumers
 * (MFC1-style reads, CVT-from-int sources): 1 on hit (FMOV emitted),
 * 0 on miss (caller loads the ctx lane, then populates as usual). */
int ef_cache_read_d(a64_emit_t *e, unsigned fs, unsigned xd)
{
    if (ef_fhit(e, fs, 1) == 0) {
        return 0;
    }
    ef_fmov_xd(e, xd, EF_FREG(EF_FSLOT(fs)));
    return 1;
}

int ef_cache_read_s(a64_emit_t *e, unsigned fs, unsigned wd)
{
    if (ef_fhit(e, fs, 0) == 0) {
        return 0;
    }
    ef_fmov_ws(e, wd, EF_FREG(EF_FSLOT(fs)));
    return 1;
}

/* Cache write-through from an integer reg holding a full 64-bit lane
 * value (DMTC1-class producers, CVT-to-L results, MOV.D/ABS.D/NEG.D):
 * updates d(8+slot) AND tags it (the ctx lane store stays with the
 * caller, which already emitted it). */
void ef_cache_write_d(a64_emit_t *e, unsigned fs, unsigned xn)
{
    if (e == NULL) {
        return;
    }
    ef_fmov_dx(e, EF_FREG(EF_FSLOT(fs)), xn);
    ef_ftag(e, fs, 1);
}

/* Populate the cache from a just-loaded guest word/doubleword sitting
 * in EI_C (called after the ctx lane store, so both copies match). */
static void ef_mempop(a64_emit_t *e, unsigned fs, int is_d)
{
    unsigned slot = EF_FSLOT(fs);

    if (e == NULL) {
        return;
    }
    if (is_d != 0) {
        ef_fmov_dx(e, EF_FREG(slot), EI_C);
    } else {
        ef_fmov_sw(e, EF_FREG(slot), EI_C);
    }
    ef_ftag(e, fs, is_d);
}

int ei_fp_mem(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
              int slot)
{
    unsigned fs = d->rt & 31u;
    uint32_t lane = EFPM_OFF_FPR(fs);
    int is_load = 0;
    unsigned width = 0u;
    unsigned kind = 0u;
    unsigned flags = 0u;
    size_t miss;

    switch (d->op) {
    case 0x31u: /* LWC1 */
        is_load = 1;
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        break;
    case 0x39u: /* SWC1 */
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        break;
    case 0x35u: /* LDC1 */
        is_load = 1;
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        break;
    case 0x3Du: /* SDC1 */
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        break;
    default:
        return 1;
    }
    flags = (is_load != 0 ? 0u : (unsigned)DBT_MEM_F_STORE) |
        (be != 0 ? (unsigned)DBT_MEM_F_BE : 0u) |
        (slot != 0 ? (unsigned)DBT_MEM_F_IN_DELAY_SLOT : 0u);
    ei_mem_addr(e, d);
    miss = ei_probe_open(e, pc, d, width, flags, fs, is_load == 0, slot);
    if (miss == (size_t)-1) {
        return e == NULL ? 1 : 0;
    }
    if (is_load != 0) {
        ei_mem_rx(e, kind, 1, EI_C, EI_A, EI_H);
        if (be != 0) {
            if (kind == (unsigned)EI_RX_U64) {
                ei_rev(e, 0xDAC00C00u, EI_C, EI_C);
            } else {
                ei_rev(e, 0x5AC00800u, EI_C, EI_C);
            }
        }
        /* A 4-byte store preserves the FR=1 upper lane (fpmove_mem). */
        ei_str(e, width == 8u ? 0 : 1, EI_C, EI_CTX, lane);
        /* Wave P13: populate the d8..d15 cache from the loaded value
         * (write-through: both copies now match). */
        ef_mempop(e, fs, width == 8u ? 1 : 0);
        ei_probe_close(e);
        return 0;
    }
    /* Wave P13: a cached lane feeds the store without a ctx load
     * (write-through keeps the ctx copy exact for the miss path). */
    if (width == 8u) {
        if (ef_cache_read_d(e, fs, EI_C) == 0) {
            ei_ldr(e, 0, EI_C, EI_CTX, lane);
        }
    } else if (ef_cache_read_s(e, fs, EI_C) == 0) {
        ei_ldr(e, 1, EI_C, EI_CTX, lane);
    }
    if (be != 0) {
        if (kind == (unsigned)EI_RX_U64) {
            ei_rev(e, 0xDAC00C00u, EI_B, EI_C);
        } else {
            ei_rev(e, 0x5AC00800u, EI_B, EI_C);
        }
        ei_probe_mark_insn(e);
        ei_mem_rx(e, kind, 0, EI_B, EI_A, EI_H);
    } else {
        ei_probe_mark_insn(e);
        ei_mem_rx(e, kind, 0, EI_C, EI_A, EI_H);
    }
    /* E05: any ordinary store clears the reservation. */
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_probe_close(e);
    return 0;
}

/* COP1X indexed FPR loads/stores: LWXC1/LDXC1/SWXC1/SDXC1/PREFX. */
int ei_fp_mem_idx(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
                  int slot)
{
    unsigned freg;
    uint32_t lane;
    int is_load = 0;
    unsigned width = 0u;
    unsigned kind = 0u;
    unsigned flags = 0u;
    size_t miss;

    if (d->op != 0x13u)
        return 1;
    if (d->funct == 0x0Fu) /* PREFX */
        return 0;
    switch (d->funct) {
    case 0x00u: /* LWXC1 */
        is_load = 1;
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        freg = d->sa & 31u;
        break;
    case 0x01u: /* LDXC1 */
        is_load = 1;
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        freg = d->sa & 31u;
        break;
    case 0x08u: /* SWXC1 */
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        freg = d->rd & 31u;
        break;
    case 0x09u: /* SDXC1 */
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        freg = d->rd & 31u;
        break;
    default:
        return 1;
    }
    lane = EFPM_OFF_FPR(freg);
    flags = (is_load != 0 ? 0u : (unsigned)DBT_MEM_F_STORE) |
        (be != 0 ? (unsigned)DBT_MEM_F_BE : 0u) |
        (slot != 0 ? (unsigned)DBT_MEM_F_IN_DELAY_SLOT : 0u);
    ei_gld(e, EI_A, d->rs);
    ei_gld(e, EI_T, d->rt);
    ei_add(e, 0, EI_A, EI_A, EI_T);
    miss = ei_probe_open(e, pc, d, width, flags, freg, is_load == 0, slot);
    if (miss == (size_t)-1)
        return e == NULL ? 1 : 0;
    if (is_load != 0) {
        ei_mem_rx(e, kind, 1, EI_C, EI_A, EI_H);
        if (be != 0)
            ei_rev(e, kind == (unsigned)EI_RX_U64 ? 0xDAC00C00u : 0x5AC00800u,
                   EI_C, EI_C);
        ei_str(e, width == 8u ? 0 : 1, EI_C, EI_CTX, lane);
        /* Wave P13: populate the d8..d15 cache from the loaded value. */
        ef_mempop(e, freg, width == 8u ? 1 : 0);
        ei_probe_close(e);
        return 0;
    }
    /* Wave P13: a cached lane feeds the store without a ctx load. */
    if (width == 8u) {
        if (ef_cache_read_d(e, freg, EI_C) == 0) {
            ei_ldr(e, 0, EI_C, EI_CTX, lane);
        }
    } else if (ef_cache_read_s(e, freg, EI_C) == 0) {
        ei_ldr(e, 1, EI_C, EI_CTX, lane);
    }
    if (be != 0) {
        ei_rev(e, kind == (unsigned)EI_RX_U64 ? 0xDAC00C00u : 0x5AC00800u,
               EI_B, EI_C);
        ei_probe_mark_insn(e);
        ei_mem_rx(e, kind, 0, EI_B, EI_A, EI_H);
    } else {
        ei_probe_mark_insn(e);
        ei_mem_rx(e, kind, 0, EI_C, EI_A, EI_H);
    }
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_probe_close(e);
    return 0;
}
