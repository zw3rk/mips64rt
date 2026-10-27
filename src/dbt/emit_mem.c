/*
 * src/dbt/emit_mem.c — Memory words for the L2c emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * U0 soft-TLB fast path (lane L-U0-C): x20 binds &tlb[0] (never x18)
 * and a 7-instruction probe resolves the host page, materializing the
 * host address into x4 (EI_H) while preserving x0; BE byteswaps use
 * rev16 (halfword), rev (word), rev64 (doubleword) on the hit path.
 * Alignment checks stay inline, the span-checked LWL/LWR/SWL/SWR +
 * LDL/LDR/SDL/SDR keep their RC1 read-modify-write semantics, and
 * LL/SC/LLD/SCD keep LDXR/STXR llbit semantics. Indirect-branch
 * targets still park in x25 across the delay slot; a pending target
 * resumes through ctx->delay_target (npc_mode RT_NPC_DYNAMIC_CTX,
 * backend.h). Same 0/1/2 return shape as emit_alu.c.
 */

#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"

/* Rev4 probe scratch: x4 carries the addend out of the ldp and is
 * dead after the masked compare (entry reuse); x0 is never encoded
 * anywhere in this file (the probe and hit path only name
 * x4/x20/x21/x22/x24/x25); x18 is rejected by the encoders. */
#define EI_H 4u

/* ---- Lane U12 live block-site table (thread-local emission) ---- */

static _Thread_local dbt_mem_sites_t ei_sites;
static _Thread_local size_t ei_miss[DBT_MEM_SITES_MAX];
static _Thread_local size_t ei_span[DBT_MEM_SITES_MAX];
static _Thread_local size_t ei_stubs[DBT_MEM_SITES_MAX];
static _Thread_local uint64_t ei_bpc;
static _Thread_local int ei_active;
static _Thread_local size_t ei_open;
static _Thread_local int ei_branch_valid;
static _Thread_local uint64_t ei_branch_pc;
static _Thread_local unsigned ei_branch_mode;
static _Thread_local int32_t ei_branch_delta;

void ei_mem_block_begin(uint64_t block_pc)
{
    size_t i;

    dbt_mem_sites_init(&ei_sites);
    for (i = 0u; i < DBT_MEM_SITES_MAX; i++) {
        ei_miss[i] = (size_t)-1;
        ei_span[i] = (size_t)-1;
        ei_stubs[i] = (size_t)-1;
    }
    ei_bpc = block_pc;
    ei_active = 1;
    ei_open = (size_t)-1;
    ei_branch_valid = 0;
    ei_branch_pc = 0U;
    ei_branch_mode = (unsigned)RT_NPC_SEQUENTIAL;
    ei_branch_delta = 0;
}

/* Branch context for the next delay-slot word (set by ei_branch in
 * emit_int.c before emitting the slot, cleared after). The slot word
 * inherits the branch pc plus the static/dynamic NPC resolution, so
 * fault recovery never replays the branch. */
void ei_mem_branch_note(uint64_t branch_pc, unsigned npc_mode,
                        int32_t npc_delta)
{
    ei_branch_valid = 1;
    ei_branch_pc = branch_pc;
    ei_branch_mode = npc_mode;
    ei_branch_delta = npc_delta;
}

void ei_mem_branch_clear(void)
{
    ei_branch_valid = 0;
}

void ei_mem_take_sites(const struct dbt_mem_site **sites, size_t *count)
{
    if (sites != NULL) {
        *sites = (const struct dbt_mem_site *)&ei_sites.sites[0];
    }
    if (count != NULL) {
        *count = ei_sites.count;
    }
    /* Drain: the dispatcher copies the rows into the block-cache
     * entry, so the staging table resets for the next block. */
    ei_sites.count = 0u;
    ei_active = 0;
    ei_open = (size_t)-1;
}

/* b . placeholder (unconditional, 26-bit range). */
size_t ei_b(a64_emit_t *e)
{
    return ei_fwd(e, 0x14000000u);
}

void ei_patch26(a64_emit_t *e, size_t slot, size_t tgt)
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
    if ((off >> 26) != 0u) {
        e->err = 1;
        return;
    }
    e->buf[slot] |= (uint32_t)(off & 0x3FFFFFFu);
}
/* ---- Memory: aligned fast path, unaligned RMW, LL/SC ---- */

/* A = rs + sign-extended imm. */
static void ei_mem_addr(a64_emit_t *e, const mips_dec_t *d)
{
    ei_gld(e, EI_A, d->rs);
    ei_mov64(e, EI_T, (uint64_t)(int64_t)d->simm);
    ei_add(e, 0, EI_A, EI_A, EI_T);
}

/* Map a power-of-two access width to the probe mask that keeps the
 * vpn plus the alignment bits: N=1 -> 0xFFF (tag only), N=2 ->
 * 0xFFE, N=4 -> 0xFFC, N=8 -> 0xFF8, N=16 -> 0xFF0. */
static uint32_t ei_probe_mask(unsigned width)
{
    switch (width) {
    case 1u:
        return 0xFFFu;
    case 2u:
        return 0xFFEu;
    case 4u:
        return 0xFFCu;
    case 8u:
        return 0xFF8u;
    default:
        return 0xFF0u;
    }
}

/* Rev4 soft-TLB probe plus site open: exactly 6 instructions. Entry:
 * EI_A holds the guest VA, x20 the TLB base (32-byte entries, 4096
 * of them). Exit on the hit path: EI_H holds the addend, so the
 * memory word uses [EI_A, EI_H] addressing with no materialization;
 * the miss branch (cbnz, slot recorded for the per-site stub)
 * reaches the shared miss epilogue at block end.
 *
 *   ubfx x22, x21, #12, #12   vpn = va >> 12
 *   add  x22, x20, x22, lsl #5 entry = &tlb[vpn & 0xFFF]
 *   ldp  x24, x4, [x22]        (read_tag, addend) [stores: swapped]
 *   bic  x22, x21, #mask       vpn | align_bits
 *   sub  x22, x22, x24         0 iff tag match + aligned
 *   cbnz x22, stub
 *
 * The single subtract folds tag match, alignment, and the aligned
 * no-cross-page proof (an aligned power-of-two access under 4 KiB
 * never straddles a page). Only EI_B/EI_T/EI_H are named: EI_A,
 * EI_C, x0, x25 and NZCV survive, and x18 never appears. The addend
 * is uniform across the arena (Provider A in-place design), so a
 * merge span that crosses into the next 4 KiB page still addresses
 * correctly; a span that reaches an unmapped page traps on the host
 * and recovers through the site table.
 *
 * The caller emits the memory word(s) next, then closes the site
 * (cont offset). Returns the miss slot, or (size_t)-1 on error. */
static size_t ei_probe_open(a64_emit_t *e, uint64_t pc, const mips_dec_t *d,
                            unsigned width, unsigned flags, unsigned val_reg,
                            int is_store, int slot)
{
    uint16_t seq;
    size_t miss;
    dbt_mem_site_t s;
    uint64_t delta;
    int idx;

    if (e == NULL || d == NULL || width == 0u || width > 8u ||
        (width & (width - 1u)) != 0u) {
        if (e != NULL) {
            e->err = 1;
        }
        return (size_t)-1;
    }
    if (ei_active && (ei_sites.count >= DBT_MEM_SITES_MAX ||
                        ei_open != (size_t)-1)) {
        e->err = 1;
        return (size_t)-1;
    }
    seq = (uint16_t)(e->len * 4u);
    ei_bfm(e, 0xD3400000u, EI_B, EI_A, 12u, 23u);
    ei_add_lsl(e, EI_B, EI_BASE, EI_B, 5u);
    if (is_store != 0) {
        ei_ldp(e, EI_H, EI_T, EI_B, 8);
    } else {
        ei_ldp(e, EI_T, EI_H, EI_B, 0);
    }
    ei_bic_imm(e, EI_B, EI_A, ei_probe_mask(width));
    ei_sub(e, 0, EI_B, EI_B, EI_T);
    miss = ei_cbz(e, 0, 1, EI_B);
    if (e->err != 0) {
        return (size_t)-1;
    }
    if (!ei_active) {
        /* Standalone word emission (unit tests, never executed):
         * the miss slot belongs to the caller, no site is kept. */
        return miss;
    }
    delta = pc - ei_bpc;
    if (delta > (uint64_t)0xFFFFu || e->len * 4u > 0xFFFFu) {
        e->err = 1;
        return (size_t)-1;
    }
    s.seq_start_offset = seq;
    s.host_insn_offset = (uint16_t)(e->len * 4u);
    s.cont_insn_offset = 0u;
    s.guest_pc_delta = (uint16_t)delta;
    s.insn_word = d->word;
    s.sp_rollback_delta = 0;
    if ((flags & (unsigned)DBT_MEM_F_IN_DELAY_SLOT) != 0u &&
        slot != 0 && ei_branch_valid != 0) {
        s.npc_mode = (uint8_t)ei_branch_mode;
        s.npc_delta = ei_branch_delta;
    } else {
        if ((flags & (unsigned)DBT_MEM_F_IN_DELAY_SLOT) != 0u &&
            slot != 0) {
            /* A delay-slot word without branch context cannot
             * recover; fail the emission loudly. */
            e->err = 1;
            return (size_t)-1;
        }
        s.npc_mode = (uint8_t)RT_NPC_SEQUENTIAL;
        s.npc_delta = 0;
    }
    (void)val_reg;
    s.width = (uint8_t)width;
    s.flags = (uint8_t)flags;
    s.val_or_dst_reg = (uint8_t)(d->rt & 31u);
    s.addr_base_reg = (uint8_t)(d->rs & 31u);
    s.reserved = 0u;
    idx = dbt_mem_site_bump(&ei_sites, &s);
    if (idx < 0 || (size_t)idx >= DBT_MEM_SITES_MAX) {
        e->err = 1;
        return (size_t)-1;
    }
    ei_miss[idx] = miss;
    ei_span[idx] = (size_t)-1;
    ei_open = (size_t)idx;
    return miss;
}

/* Update the open site's host_insn_offset to the exact word of the
 * first host memory instruction (past register-only setup such as
 * ei_gld/ei_rev) so signal preemption rewinds the entire prefix. */
static void ei_probe_mark_insn(a64_emit_t *e)
{
    if (e == NULL || !ei_active) {
        return;
    }
    if (ei_open == (size_t)-1 || ei_open >= ei_sites.count ||
        e->len * 4u > 0xFFFFu) {
        e->err = 1;
        return;
    }
    ei_sites.sites[ei_open].host_insn_offset = (uint16_t)(e->len * 4u);
}

/* Close the open site: cont is the first word past the memory
 * word(s), so the signal rewind can bracket [seq_start, host_insn]
 * (side-effect-free) against [host_insn, cont) (precise fault). */
static void ei_probe_close(a64_emit_t *e)
{
    if (e == NULL) {
        return;
    }
    if (!ei_active) {
        /* Standalone emission: nothing was opened. */
        return;
    }
    if (ei_open == (size_t)-1 || ei_open >= ei_sites.count ||
        e->len * 4u > 0xFFFFu) {
        e->err = 1;
        return;
    }
    ei_sites.sites[ei_open].cont_insn_offset = (uint16_t)(e->len * 4u);
    ei_open = (size_t)-1;
}

/* Rev4 probe entry used by the word-pinning unit test: the bare
 * 6-instruction sequence (mask + store select) with no site table. */
size_t ei_tlb_probe(a64_emit_t *e, uint32_t mask, int is_store)
{
    size_t miss;

    if (e == NULL) {
        return (size_t)-1;
    }
    ei_bfm(e, 0xD3400000u, EI_B, EI_A, 12u, 23u);
    ei_add_lsl(e, EI_B, EI_BASE, EI_B, 5u);
    if (is_store != 0) {
        ei_ldp(e, EI_H, EI_T, EI_B, 8);
    } else {
        ei_ldp(e, EI_T, EI_H, EI_B, 0);
    }
    ei_bic_imm(e, EI_B, EI_A, mask);
    ei_sub(e, 0, EI_B, EI_B, EI_T);
    miss = ei_cbz(e, 0, 1, EI_B);
    return miss;
}

int ei_mem_aligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                   int be, int slot)
{
    int is_load = 0;
    unsigned width = 0u;
    unsigned kind = 0u;
    unsigned flags;
    unsigned sxt = 0u;
    size_t miss;

    switch (d->op) {
    case 0x20u: /* LB */
        is_load = 1;
        width = 1u;
        kind = (unsigned)EI_RX_S8;
        sxt = 7u;
        break;
    case 0x24u: /* LBU */
        is_load = 1;
        width = 1u;
        kind = (unsigned)EI_RX_U8;
        break;
    case 0x21u: /* LH */
        is_load = 1;
        width = 2u;
        kind = (unsigned)EI_RX_S16;
        sxt = 15u;
        break;
    case 0x25u: /* LHU */
        is_load = 1;
        width = 2u;
        kind = (unsigned)EI_RX_U16;
        break;
    case 0x23u: /* LW */
        is_load = 1;
        width = 4u;
        kind = (unsigned)EI_RX_S32;
        sxt = 31u;
        break;
    case 0x27u: /* LWU */
        is_load = 1;
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        break;
    case 0x28u: /* SB */
        width = 1u;
        kind = (unsigned)EI_RX_U8;
        break;
    case 0x29u: /* SH */
        width = 2u;
        kind = (unsigned)EI_RX_U16;
        break;
    case 0x2Bu: /* SW */
        width = 4u;
        kind = (unsigned)EI_RX_U32;
        break;
    case 0x37u: /* LD */
        is_load = 1;
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        break;
    case 0x3Fu: /* SD */
        width = 8u;
        kind = (unsigned)EI_RX_U64;
        break;
    default:
        return 1;
    }
    flags = (is_load != 0 ? 0u : (unsigned)DBT_MEM_F_STORE) |
        (sxt != 0u ? (unsigned)DBT_MEM_F_SIGNED : 0u) |
        (be != 0 ? (unsigned)DBT_MEM_F_BE : 0u) |
        (slot != 0 ? (unsigned)DBT_MEM_F_IN_DELAY_SLOT : 0u);
    ei_mem_addr(e, d);
    miss = ei_probe_open(e, pc, d, width, flags, d->rt, is_load == 0,
                         slot);
    if (miss == (size_t)-1) {
        return e == NULL ? 1 : 0;
    }
    /* The 7th instruction: register-offset access on [EI_A, EI_H].
     * x0, EI_C (value/dst), x25 and NZCV are untouched by the probe.
     * Single bytes never rev (a rev64 would exile the byte to the
     * top halfword and the sign extension would read back zero). */
    if (is_load != 0) {
        ei_mem_rx(e, kind, 1, EI_C, EI_A, EI_H);
        if (be != 0 && (kind == (unsigned)EI_RX_U16 ||
                        kind == (unsigned)EI_RX_S16)) {
            ei_rev(e, 0x5AC00400u, EI_C, EI_C);
        } else if (be != 0 && (kind == (unsigned)EI_RX_U32 ||
                               kind == (unsigned)EI_RX_S32)) {
            ei_rev(e, 0x5AC00800u, EI_C, EI_C);
        } else if (be != 0 && kind == (unsigned)EI_RX_U64) {
            ei_rev(e, 0xDAC00C00u, EI_C, EI_C);
        }
        if (sxt != 0u) {
            /* BE multi-byte loads arrive zero-extended from the rev;
             * the sign extension still applies afterwards. */
            ei_sxt(e, sxt, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rt);
        ei_probe_close(e);
        return 0;
    }
    ei_gld(e, EI_C, d->rt);
    if (be != 0 && kind != (unsigned)EI_RX_U8) {
        if (kind == (unsigned)EI_RX_U16) {
            ei_rev(e, 0x5AC00400u, EI_B, EI_C);
        } else if (kind == (unsigned)EI_RX_U32) {
            ei_rev(e, 0x5AC00800u, EI_B, EI_C);
        } else {
            ei_rev(e, 0xDAC00C00u, EI_B, EI_C);
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

/* Variable guest-field shift: B holds the exact shift amount (sk for
 * modes 0-1, C - sk for modes 2-3, pre-adjusted by the caller). */
static void ei_vshift(a64_emit_t *e, unsigned dst, unsigned src, int is_w,
                      int mode, unsigned cval)
{
    (void)cval;
    if (mode == 1) {
        ei_lsrv(e, is_w, dst, src, EI_B);
    } else {
        ei_lslv(e, is_w, dst, src, EI_B);
    }
}

/* Load merge: A = R (memory word), C = old rt, B = shift amount. */
static void ei_merge_load(a64_emit_t *e, int is_w, int mode, unsigned cval)
{
    ei_vshift(e, EI_T, EI_A, is_w, mode, cval);
    ei_eor(e, 0, EI_T, EI_C, EI_T);
    if (is_w != 0) {
        ei_mov32(e, EI_A, 0xFFFFFFFFu);
    } else {
        ei_mov64(e, EI_A, UINT64_MAX);
    }
    ei_vshift(e, EI_A, EI_A, is_w, mode, cval);
    ei_and(e, 0, EI_T, EI_T, EI_A);
    ei_eor(e, 0, EI_C, EI_C, EI_T);
}

/* Store merge: A = R (memory word), C = rt. Produces the word in A. */
static void ei_merge_store(a64_emit_t *e, int is_w, int mode, unsigned cval)
{
    ei_vshift(e, EI_T, EI_C, is_w, mode, cval);
    ei_eor(e, 0, EI_T, EI_A, EI_T);
    if (is_w != 0) {
        ei_mov32(e, EI_C, 0xFFFFFFFFu);
    } else {
        ei_mov64(e, EI_C, UINT64_MAX);
    }
    ei_vshift(e, EI_C, EI_C, is_w, mode, cval);
    ei_and(e, 0, EI_T, EI_T, EI_C);
    ei_eor(e, 0, EI_A, EI_A, EI_T);
}

/* Unaligned word/doubleword access with RC1 span semantics. */
int ei_unaligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                 int is_load, int is_d, int be, int mode, int swap, unsigned cval,
                 int slot)
{
    size_t entry = (e == NULL) ? 0u : (e->len * 4u);
    size_t s;
    size_t miss;
    unsigned width = is_d != 0 ? 8u : 4u;
    unsigned flags;
    uint32_t kmask = is_d != 0 ? 7u : 3u;
    int m = (mode == 0) ? (swap != 0 ? 1 : 0) : mode;

    flags = (unsigned)DBT_MEM_F_SPAN |
        (is_load != 0 ? 0u : (unsigned)DBT_MEM_F_STORE) |
        (be != 0 ? (unsigned)DBT_MEM_F_BE : 0u) |
        (slot != 0 ? (unsigned)DBT_MEM_F_IN_DELAY_SLOT : 0u);
    ei_gld(e, EI_A, d->rs);
    ei_mov64(e, EI_T, (uint64_t)(int64_t)d->simm);
    ei_add(e, 0, EI_A, EI_A, EI_T);
    ei_mov32(e, EI_T, kmask);
    ei_and(e, 0, EI_T, EI_A, EI_T);
    ei_sub(e, 0, EI_A, EI_A, EI_T);
    ei_lsl(e, 0, EI_T, EI_T, 3u);
    /* Park the shift: the probe below consumes EI_T as tag scratch. */
    ei_str(e, 0, EI_T, EI_CTX, EI_OFF_SCRATCH);
    ei_mov32(e, EI_C, is_d != 0 ? 7u : 3u);
    ei_add(e, 0, EI_C, EI_A, EI_C);
    ei_ldr(e, 0, EI_B, EI_CTX, EI_OFF_TASK);
    ei_cmp(e, 0, EI_C, EI_B);
    s = ei_bcc(e, EI_HS);
    miss = ei_probe_open(e, pc, d, width, flags, d->rt, is_load == 0,
                         slot);
    if (miss == (size_t)-1) {
        return e == NULL ? 1 : 0;
    }
    ei_add(e, 0, EI_H, EI_A, EI_H);
    ei_ldr(e, 0, EI_T, EI_CTX, EI_OFF_SCRATCH);
    ei_gld(e, EI_C, d->rt);
    if (is_load != 0) {
        ei_probe_mark_insn(e);
    }
    if (is_d != 0) {
        ei_ldr(e, 0, EI_A, EI_H, 0u);
    } else {
        ei_ldr(e, 1, EI_A, EI_H, 0u);
    }
    if (be != 0) {
        ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_A, EI_A);
    }
    if (is_load == 0) {
        ei_str(e, 0, EI_H, EI_CTX, EI_OFF_SCRATCH);
    }
    if (m == 2 || m == 3) {
        ei_sub_imm(e, EI_B, EI_T, cval);
        ei_sub(e, 0, EI_B, EI_XZR, EI_B);
        m = (m == 2) ? 1 : 0;
    } else {
        ei_mov(e, EI_B, EI_T);
    }
    if (is_load != 0) {
        ei_merge_load(e, is_d == 0, m, cval);
        if (is_d == 0) {
            ei_sxt(e, 31u, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rt);
    } else {
        ei_merge_store(e, is_d == 0, m, cval);
        ei_ldr(e, 0, EI_H, EI_CTX, EI_OFF_SCRATCH);
        if (be != 0) {
            ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_A, EI_A);
        }
        ei_probe_mark_insn(e);
        if (is_d != 0) {
            ei_str(e, 0, EI_A, EI_H, 0u);
        } else {
            ei_str(e, 1, EI_A, EI_H, 0u);
        }
        ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    }
    ei_probe_close(e);
    if (e == NULL || ei_sites.count == 0U ||
        ei_sites.count > DBT_MEM_SITES_MAX) {
        if (e != NULL) {
            e->err = 1;
        }
        return 0;
    }
    ei_sites.sites[ei_sites.count - 1u].seq_start_offset = (uint16_t)entry;
    ei_span[ei_sites.count - 1u] = s;
    (void)miss;
    return 0;
}

/* LL/SC/LLD/SCD via LDXR/STXR with llbit semantics. */
int ei_atomic(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
              int slot)
{
    size_t entry = (e == NULL) ? 0u : (e->len * 4u);
    int is_d = (d->op == 0x34u || d->op == 0x3Cu) ? 1 : 0;
    unsigned width = is_d != 0 ? 8u : 4u;
    unsigned flags;
    int is_load = (d->op == 0x30u || d->op == 0x34u) ? 1 : 0;
    size_t miss;
    size_t s1;
    size_t s3;
    size_t dead;
    size_t done;

    flags = (unsigned)DBT_MEM_F_ATOMIC |
        (is_load != 0 ? 0u : (unsigned)DBT_MEM_F_STORE) |
        (be != 0 ? (unsigned)DBT_MEM_F_BE : 0u) |
        (slot != 0 ? (unsigned)DBT_MEM_F_IN_DELAY_SLOT : 0u);
    ei_mem_addr(e, d);
    miss = ei_probe_open(e, pc, d, width, flags, d->rt, is_load == 0,
                         slot);
    if (miss == (size_t)-1) {
        return e == NULL ? 1 : 0;
    }
    ei_add(e, 0, EI_H, EI_A, EI_H);
    if (d->op == 0x30u || d->op == 0x34u) { /* LL / LLD */
        ei_probe_mark_insn(e);
        ei_ldxr(e, is_d == 0, EI_C, EI_H);
        ei_mov32(e, EI_T, 1u);
        ei_strb(e, EI_T, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
        ei_str(e, 0, EI_A, EI_CTX, MIPS64_CTX_LLADDR_OFFSET);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LLVAL_OFFSET);
        if (is_d == 0) {
            if (be != 0) {
                ei_rev(e, 0x5AC00800u, EI_C, EI_C);
            }
            ei_sxt(e, 31u, EI_C, EI_C);
        } else if (be != 0) {
            ei_rev(e, 0xDAC00C00u, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rt);
        ei_probe_close(e);
        if (ei_sites.count > 0u && ei_sites.count <= DBT_MEM_SITES_MAX) {
            ei_sites.sites[ei_sites.count - 1u].seq_start_offset =
                (uint16_t)entry;
        }
        return 0;
    }
    ei_gld(e, EI_B, d->rt);
    ei_ldrb(e, EI_C, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    dead = ei_cbz(e, 0, 0, EI_C);
    ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_LLADDR_OFFSET);
    ei_cmp(e, 0, EI_C, EI_A);
    s1 = ei_bcc(e, EI_NE);
    if (be != 0) {
        ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_B, EI_B);
    }
    ei_ldxr(e, is_d == 0, EI_C, EI_H);
    ei_ldr(e, 0, EI_A, EI_CTX, MIPS64_CTX_LLVAL_OFFSET);
    ei_cmp(e, 0, EI_C, EI_A);
    s3 = ei_bcc(e, EI_NE);
    ei_probe_mark_insn(e);
    ei_stxr(e, is_d == 0, EI_C, EI_B, EI_H);
    ei_cbnz_back(e, 1, EI_C, entry / 4u);
    ei_mov32(e, EI_B, 1u);
    ei_gst(e, EI_B, d->rt);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    done = ei_b(e);
    ei_patch_at(e, dead, e == NULL ? 0u : e->len, 0);
    ei_patch_at(e, s1, e == NULL ? 0u : e->len, 0);
    ei_patch_at(e, s3, e == NULL ? 0u : e->len, 0);
    ei_mov(e, EI_B, EI_XZR);
    ei_gst(e, EI_B, d->rt);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_patch26(e, done, e == NULL ? 0u : e->len);
    ei_probe_close(e);
    if (ei_sites.count > 0u && ei_sites.count <= DBT_MEM_SITES_MAX) {
        ei_sites.sites[ei_sites.count - 1u].seq_start_offset =
            (uint16_t)entry;
    }
    return 0;
}

/* ---- Lane U12: relative 24-byte miss-site table + stubs ---- */

void dbt_mem_sites_init(dbt_mem_sites_t *t)
{
    size_t i;

    if (t == NULL)
        return;
    for (i = 0u; i < DBT_MEM_SITES_MAX; i++) {
        t->sites[i].seq_start_offset = 0u;
        t->sites[i].host_insn_offset = 0u;
        t->sites[i].cont_insn_offset = 0u;
        t->sites[i].guest_pc_delta = 0u;
        t->sites[i].npc_delta = 0;
        t->sites[i].insn_word = 0u;
        t->sites[i].sp_rollback_delta = 0;
        t->sites[i].npc_mode = 0u;
        t->sites[i].width = 0u;
        t->sites[i].flags = 0u;
        t->sites[i].val_or_dst_reg = 0u;
        t->sites[i].addr_base_reg = 0u;
        t->sites[i].reserved = 0u;
    }
    t->count = 0u;
}

int dbt_mem_site_bump(dbt_mem_sites_t *t, const dbt_mem_site_t *s)
{
    size_t at;

    if (t == NULL || s == NULL || t->count >= DBT_MEM_SITES_MAX)
        return -1;
    at = t->count;
    t->sites[at] = *s;
    t->count = at + 1u;
    return (int)at;
}

static void put_u16le(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void put_u32le(uint8_t *out, uint32_t v)
{
    unsigned i;

    for (i = 0u; i < 4u; i++)
        out[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
}

static uint16_t get_u16le(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t get_u32le(const uint8_t *in)
{
    uint32_t v = 0u;
    unsigned i;

    for (i = 0u; i < 4u; i++)
        v |= (uint32_t)in[i] << (8u * i);
    return v;
}

size_t dbt_mem_sites_serialize(const dbt_mem_sites_t *t, uint8_t *out,
                               size_t cap)
{
    size_t need;
    size_t i;

    if (t == NULL)
        return 0u;
    need = t->count * sizeof(dbt_mem_site_t);
    if (need == 0u)
        return 0u;
    if (out == NULL || cap < need)
        return 0u;
    for (i = 0u; i < t->count; i++) {
        uint8_t *row = out + i * sizeof(dbt_mem_site_t);
        const dbt_mem_site_t *s = &t->sites[i];

        put_u16le(row, s->seq_start_offset);
        put_u16le(row + 2u, s->host_insn_offset);
        put_u16le(row + 4u, s->cont_insn_offset);
        put_u16le(row + 6u, s->guest_pc_delta);
        put_u32le(row + 8u, (uint32_t)s->npc_delta);
        put_u32le(row + 12u, s->insn_word);
        put_u16le(row + 16u, (uint16_t)s->sp_rollback_delta);
        row[18] = s->npc_mode;
        row[19] = s->width;
        row[20] = s->flags;
        row[21] = s->val_or_dst_reg;
        row[22] = s->addr_base_reg;
        row[23] = s->reserved;
    }
    return need;
}

size_t dbt_mem_sites_deserialize(dbt_mem_sites_t *t, const uint8_t *in,
                                 size_t len)
{
    size_t rows;
    size_t i;

    if (t == NULL || in == NULL || len % sizeof(dbt_mem_site_t) != 0u)
        return 0u;
    rows = len / sizeof(dbt_mem_site_t);
    if (rows == 0u || rows > DBT_MEM_SITES_MAX - t->count)
        return 0u;
    for (i = 0u; i < rows; i++) {
        const uint8_t *row = in + i * sizeof(dbt_mem_site_t);
        dbt_mem_site_t *s = &t->sites[t->count + i];

        s->seq_start_offset = get_u16le(row);
        s->host_insn_offset = get_u16le(row + 2u);
        s->cont_insn_offset = get_u16le(row + 4u);
        s->guest_pc_delta = get_u16le(row + 6u);
        s->npc_delta = (int32_t)get_u32le(row + 8u);
        s->insn_word = get_u32le(row + 12u);
        s->sp_rollback_delta = (int16_t)get_u16le(row + 16u);
        s->npc_mode = row[18];
        s->width = row[19];
        s->flags = row[20];
        s->val_or_dst_reg = row[21];
        s->addr_base_reg = row[22];
        s->reserved = row[23];
        if (s->reserved != 0u)
            return 0u;
    }
    t->count += rows;
    return rows;
}

size_t ei_mem_miss_stub(a64_emit_t *e, unsigned site)
{
    size_t at;

    if (e == NULL || e->buf == NULL || site > 0xFFFFu) {
        if (e != NULL)
            e->err = 1;
        return (size_t)-1;
    }
    if (site >= DBT_MEM_SITES_MAX) {
        e->err = 1;
        return (size_t)-1;
    }
    at = e->len;
    /* `movz w4, #site`: only w4 is written, x18 never appears. The
     * following `b` carries a zero offset until block end patches it
     * to the shared miss epilogue. */
    ei_fwd(e, 0x52800000u | (((uint32_t)site & 0xFFFFu) << 5u) | 4u);
    ei_fwd(e, 0x14000000u);
    return at;
}

/* Emit the shared per-block miss epilogue: the stub's site index in
 * w4 lands in exit_info, the reason is TRAP (never FAULT, which
 * carries a fault address instead), llbit clears like mips_fault,
 * and control returns to the dispatcher for fill/retry or precise
 * fault delivery. The faulting pc is NOT materialized here: the
 * dispatcher derives it from the block base plus the site's
 * guest_pc_delta. */
static void ei_miss_epilogue(a64_emit_t *e)
{
    ei_str(e, 1, 4u, EI_CTX, (uint32_t)MIPS64_CTX_EXIT_REASON_OFFSET + 4u);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_mov32(e, 0u, (uint32_t)MIPS64_EXIT_TRAP);
    ei_str(e, 1, 0u, EI_CTX, (uint32_t)MIPS64_CTX_EXIT_REASON_OFFSET);
    ei_ret(e);
}

void ei_mem_block_end(a64_emit_t *e)
{
    size_t i;
    size_t epi;

    if (e == NULL) {
        return;
    }
    if (!ei_active) {
        e->err = 1;
        return;
    }
    ei_active = 0;
    if (ei_open != (size_t)-1) {
        /* A word left its site open: the emission is unbalanced. */
        e->err = 1;
        return;
    }
    if (ei_sites.count == 0u) {
        return;
    }
    /* One 2-insn stub per site; patch every recorded miss (and span)
     * slot to its stub. Stubs lay out in site order, two words each;
     * the branch word (stub + 1) is patched to the shared epilogue
     * after it is emitted. */
    for (i = 0u; i < ei_sites.count; i++) {
        size_t stub;

        if (ei_miss[i] == (size_t)-1) {
            e->err = 1;
            return;
        }
        stub = ei_mem_miss_stub(e, (unsigned)i);
        if (stub == (size_t)-1) {
            return;
        }
        ei_stubs[i] = stub;
        ei_patch_at(e, ei_miss[i], stub, 0);
        if (ei_span[i] != (size_t)-1) {
            ei_patch_at(e, ei_span[i], stub, 0);
        }
    }
    epi = e->len;
    ei_miss_epilogue(e);
    /* Point every stub at the shared epilogue. */
    for (i = 0u; i < ei_sites.count; i++) {
        ei_patch26(e, ei_stubs[i] + 1u, epi);
    }
}
