/*
 * src/dbt/emit_mem.c — Memory words for the L2c emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aligned fast path via x20 + guest base (alignment + task_size bounds
 * checks), LWL/LWR/SWL/SWR + LDL/LDR/SDL/SDR with the RC1 span
 * semantics (read-modify-write of the aligned word), LL/SC/LLD/SCD via
 * LDXR/STXR with llbit semantics. Same 0/1/2 return shape as emit_alu.c.
 */

#include "dbt/emit_int.h"

/* Shared fault epilogue for one memory word: the alignment and
 * bounds checks branch here with the address in EI_A. Slots holding
 * (size_t)-1 are skipped. An unconditional jump skips the epilogue so
 * the fast path continues inline. */
static void ei_mem_fault(a64_emit_t *e, uint64_t pc, size_t s1, size_t s2)
{
    size_t over;
    size_t tgt;

    if (e == NULL) {
        return;
    }
    over = ei_b(e);
    tgt = e->len;
    ei_exit_fault_reg(e, pc, EI_A);
    if (s1 != (size_t)-1) {
        ei_patch_at(e, s1, tgt, 0);
    }
    if (s2 != (size_t)-1) {
        ei_patch_at(e, s2, tgt, 0);
    }
    ei_patch26(e, over, e->len);
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

/* Record this word's guest pc in the scratch slot for the host-fault
 * guard: a captured fault reports precise sc_pc even though compiled
 * blocks do not advance ctx->pc per instruction. `reg` must be dead at
 * the call site (callers place this after the host address is
 * finalised); the transient spill users overwrite-then-read their own
 * value in program order, so the record always wins at capture time. */
static void ei_mem_pc_reg(a64_emit_t *e, uint64_t pc, unsigned reg)
{
    ei_mov64(e, reg, pc);
    ei_str(e, 0, reg, EI_CTX, EI_OFF_SCRATCH);
}

/* Alignment (align = 1/2/4/8, 0 skips) + task_size bounds checks with
 * the address in EI_A. Falls through with B = x20 + A; faults share
 * one epilogue per word. */
static void ei_mem_checked(a64_emit_t *e, uint64_t pc, unsigned align)
{
    size_t s1 = (size_t)-1;
    size_t s2;

    if (align == 1u) {
        s1 = ei_tbz(e, 1, EI_A, 0u);
    } else if (align > 1u) {
        ei_mov32(e, EI_T, align - 1u);
        ei_tst(e, EI_A, EI_T);
        s1 = ei_bcc(e, EI_NE);
    }
    ei_ldr(e, 0, EI_T, EI_CTX, EI_OFF_TASK);
    ei_cmp(e, 0, EI_A, EI_T);
    s2 = ei_bcc(e, EI_HS);
    ei_add(e, 0, EI_B, EI_BASE, EI_A);
    ei_mem_fault(e, pc, s1, s2);
}

int ei_mem_aligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                          int be)
{
    int is_load = 0;
    unsigned align = 0u;

    switch (d->op) {
    case 0x20u: /* LB */
        is_load = 1;
        break;
    case 0x21u: /* LH */
        is_load = 1;
        align = 1u;
        break;
    case 0x23u: /* LW */
    case 0x27u: /* LWU */
        is_load = 1;
        align = 2u;
        break;
    case 0x24u: /* LBU */
        is_load = 1;
        break;
    case 0x25u: /* LHU */
        is_load = 1;
        align = 1u;
        break;
    case 0x28u: /* SB */
        break;
    case 0x29u: /* SH */
        align = 1u;
        break;
    case 0x2Bu: /* SW */
        align = 2u;
        break;
    case 0x37u: /* LD */
        is_load = 1;
        align = 3u;
        break;
    case 0x3Fu: /* SD */
        align = 3u;
        break;
    default:
        return 1;
    }
    if (align == 2u) {
        align = 4u;
    } else if (align == 3u) {
        align = 8u;
    }
    ei_mem_addr(e, d);
    ei_mem_checked(e, pc, align);
    /* EI_A is dead past the host-address computation (the fault
     * epilogue already branched away); record before the access. */
    ei_mem_pc_reg(e, pc, EI_A);
    if (is_load != 0) {
        switch (d->op) {
        case 0x20u: /* LB */
            ei_ldrsb(e, EI_C, EI_B, 0u);
            ei_sxt(e, 7u, EI_C, EI_C);
            break;
        case 0x24u: /* LBU */
            ei_ldrb(e, EI_C, EI_B, 0u);
            break;
        case 0x21u: /* LH */
            ei_ldrh(e, EI_C, EI_B, 0u);
            if (be != 0) {
                ei_rev(e, 0x5AC00400u, EI_C, EI_C);
            }
            ei_sxt(e, 15u, EI_C, EI_C);
            break;
        case 0x25u: /* LHU */
            ei_ldrh(e, EI_C, EI_B, 0u);
            if (be != 0) {
                ei_rev(e, 0x5AC00400u, EI_C, EI_C);
            }
            break;
        case 0x23u: /* LW */
            if (be != 0) {
                ei_ldr(e, 1, EI_C, EI_B, 0u);
                ei_rev(e, 0x5AC00800u, EI_C, EI_C);
                ei_sxt(e, 31u, EI_C, EI_C);
            } else {
                ei_ldrsw(e, EI_C, EI_B, 0u);
            }
            break;
        case 0x27u: /* LWU */
            ei_ldr(e, 1, EI_C, EI_B, 0u);
            if (be != 0) {
                ei_rev(e, 0x5AC00800u, EI_C, EI_C);
            }
            break;
        default: /* LD */
            ei_ldr(e, 0, EI_C, EI_B, 0u);
            if (be != 0) {
                ei_rev(e, 0xDAC00C00u, EI_C, EI_C);
            }
            break;
        }
        ei_gst(e, EI_C, d->rt);
        return 0;
    }
    ei_gld(e, EI_C, d->rt);
    switch (d->op) {
    case 0x28u: /* SB */
        ei_strb(e, EI_C, EI_B, 0u);
        break;
    case 0x29u: /* SH */
        if (be != 0) {
            ei_rev(e, 0x5AC00400u, EI_C, EI_C);
        }
        ei_strh(e, EI_C, EI_B, 0u);
        break;
    case 0x2Bu: /* SW */
        if (be != 0) {
            ei_rev(e, 0x5AC00800u, EI_C, EI_C);
        }
        ei_str(e, 1, EI_C, EI_B, 0u);
        break;
    default: /* SD */
        if (be != 0) {
            ei_rev(e, 0xDAC00C00u, EI_C, EI_C);
        }
        ei_str(e, 0, EI_C, EI_B, 0u);
        break;
    }
    /* E05: any ordinary store clears the reservation. */
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    return 0;
}

/* Variable guest-field shift: B holds the exact shift amount (sk for
 * modes 0-1, C - sk for modes 2-3, pre-adjusted by the caller). C is 24
 * for 32-bit, 56 for 64-bit (unused here). */
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

/* Load merge: A = R (memory word), C = old rt, B = shift amount.
 * Produces the merged value in C. */
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

/* Store merge: A = R (memory word), C = rt. Produces the word in A.
 * The mask lives in C so R survives for the final XOR. */
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

/* Unaligned word/doubleword access with RC1 span semantics.
 * is_load selects the merge direction, is_d the width, mode the shift
 * shape (0 = <<sk/>>sk per dir, 2 = >>(C-sk), 3 = <<(C-sk)), cval the
 * 24/56 constant, dir the mode-0 direction (0 left, 1 right). */
int ei_unaligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                        int is_load, int is_d, int be, int mode, int dir,
                        unsigned cval)
{
    size_t s;
    uint32_t kmask = is_d != 0 ? 7u : 3u;
    int m = (mode == 0) ? (dir != 0 ? 1 : 0) : mode;

    ei_gld(e, EI_A, d->rs);
    ei_mov64(e, EI_T, (uint64_t)(int64_t)d->simm);
    ei_add(e, 0, EI_A, EI_A, EI_T);
    ei_mov32(e, EI_T, kmask);
    ei_and(e, 0, EI_T, EI_A, EI_T);
    ei_sub(e, 0, EI_A, EI_A, EI_T);
    ei_lsl(e, 0, EI_T, EI_T, 3u);
    ei_mov32(e, EI_C, is_d != 0 ? 7u : 3u);
    ei_add(e, 0, EI_C, EI_A, EI_C);
    ei_ldr(e, 0, EI_B, EI_CTX, EI_OFF_TASK);
    ei_cmp(e, 0, EI_C, EI_B);
    s = ei_bcc(e, EI_HS);
    ei_add(e, 0, EI_B, EI_BASE, EI_A);
    ei_gld(e, EI_C, d->rt);
    /* EI_A is the load destination below, so its address value is dead;
     * record before the first host access. */
    ei_mem_pc_reg(e, pc, EI_A);
    if (is_d != 0) {
        ei_ldr(e, 0, EI_A, EI_B, 0u);
    } else {
        ei_ldr(e, 1, EI_A, EI_B, 0u);
    }
    if (be != 0) {
        ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_A, EI_A);
    }
    if (is_load == 0) {
        /* Spill the host address: B becomes the shift amount below and
         * is reloaded for the final store. The spill lifetime holds no
         * exits, so the padding slot is invisible elsewhere. */
        ei_str(e, 0, EI_B, EI_CTX, EI_OFF_SCRATCH);
    }
    if (m == 2 || m == 3) {
        /* B = C - sk so a plain register shift does the whole job. */
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
        ei_ldr(e, 0, EI_B, EI_CTX, EI_OFF_SCRATCH);
        /* EI_C died with the merge (value now in A); record before the
         * final host store. */
        ei_mem_pc_reg(e, pc, EI_C);
        if (be != 0) {
            ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_A, EI_A);
        }
        if (is_d != 0) {
            ei_str(e, 0, EI_A, EI_B, 0u);
        } else {
            ei_str(e, 1, EI_A, EI_B, 0u);
        }
        /* E05: any ordinary store clears the reservation. */
        ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    }
    ei_mem_fault(e, pc, s, (size_t)-1);
    return 0;
}

/* LL/SC/LLD/SCD via LDXR/STXR with llbit semantics. */
int ei_atomic(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be)
{
    int is_d = (d->op == 0x34u || d->op == 0x3Cu) ? 1 : 0;
    size_t s1;
    size_t s2;
    size_t s3;
    size_t dead;
    size_t done;
    size_t top;

    ei_mem_addr(e, d);
    if (is_d != 0) {
        ei_mov32(e, EI_T, 7u);
    } else {
        ei_mov32(e, EI_T, 3u);
    }
    ei_tst(e, EI_A, EI_T);
    s1 = ei_bcc(e, EI_NE);
    ei_ldr(e, 0, EI_T, EI_CTX, EI_OFF_TASK);
    ei_cmp(e, 0, EI_A, EI_T);
    s2 = ei_bcc(e, EI_HS);
    ei_mem_fault(e, pc, s1, s2);
    if (d->op == 0x30u || d->op == 0x34u) { /* LL / LLD */
        ei_add(e, 0, EI_B, EI_BASE, EI_A);
        /* EI_T held task_size for the bounds check above and is dead
         * now; EI_A still carries the guest address for the LLADDR
         * store below, so the pc record must not use EI_A here. */
        ei_mem_pc_reg(e, pc, EI_T);
        /* Width flag is "is word": LL needs the W form, LLD the X. */
        ei_ldxr(e, is_d == 0, EI_C, EI_B);
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
        return 0;
    }
    /* SC / SCD: the host address is needed on the dead path too, so
     * compute it before the reservation check. */
    ei_add(e, 0, EI_T, EI_BASE, EI_A);
    ei_gld(e, EI_B, d->rt);
    /* EI_C is dead here (overwritten by the load below); the record
     * must precede the reservation check because the llbit==0 path
     * skips the second record yet still faults on the fail-path
     * load. */
    ei_mem_pc_reg(e, pc, EI_C);
    ei_ldrb(e, EI_C, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    dead = ei_cbz(e, 0, 0, EI_C);
    ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_LLADDR_OFFSET);
    ei_cmp(e, 0, EI_C, EI_A);
    s1 = ei_bcc(e, EI_NE);
    if (be != 0) {
        ei_rev(e, is_d != 0 ? 0xDAC00C00u : 0x5AC00800u, EI_B, EI_B);
    }
    /* The LL block exited to the dispatcher, which need not preserve
     * the host exclusive monitor, so a bare STXR here can never
     * succeed. Re-arm with LDXR in this block. RC4: commit only when
     * the lane still holds the LL-observed value — per-ctx llbit
     * cannot see foreign stores, and two host threads share no
     * monitor. EI_A is dead past the lladdr check, so it carries
     * llval (raw host order on both sides, like the LL store). Width
     * flag is "is word", matching the fail-path load below. */
    top = e == NULL ? 0u : e->len;
    ei_mem_pc_reg(e, pc, EI_A);
    ei_ldxr(e, is_d == 0, EI_C, EI_T);
    ei_ldr(e, 0, EI_A, EI_CTX, MIPS64_CTX_LLVAL_OFFSET);
    ei_cmp(e, 0, EI_C, EI_A);
    s3 = ei_bcc(e, EI_NE);
    ei_stxr(e, is_d == 0, EI_C, EI_B, EI_T);
    ei_cbnz_back(e, 0, EI_C, top);
    ei_mov32(e, EI_B, 1u);
    ei_gst(e, EI_B, d->rt);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    done = ei_b(e);
    ei_patch_at(e, dead, e == NULL ? 0u : e->len, 0);
    ei_patch_at(e, s1, e == NULL ? 0u : e->len, 0);
    ei_patch_at(e, s3, e == NULL ? 0u : e->len, 0);
    ei_ldr(e, is_d == 0, EI_T, EI_T, 0u);
    ei_mov(e, EI_B, EI_XZR);
    ei_gst(e, EI_B, d->rt);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_patch26(e, done, e == NULL ? 0u : e->len);
    return 0;
}
