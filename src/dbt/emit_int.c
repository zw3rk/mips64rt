/*
 * src/dbt/emit_int.c — AArch64 integer instruction emitter (Phase 2, lane L2c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the frozen `dbt_emit_int` contract from src/core/cpu.h using
 * only the lane L2b headers src/dbt/dbt.h (host register map) and
 * src/dbt/a64_emit.h (emission buffer). Word encoders live in
 * emit_enc.c, register-pure words in emit_alu.c, memory words in
 * emit_mem.c; shared declarations are in emit_int.h (lane-private).
 *
 * Host register map (card text, frozen by lane L2b): x19 = ctx, x20 =
 * guest window base, $0 reads as xzr/wzr (writes dropped), every other
 * guest register is memory-backed in [x19, #off], x21..x24 are scratch.
 * x18 is never read or written.
 *
 * Exit convention: every emitted block ends in one epilogue that stores
 * the resume guest pc to ctx->pc (plus pc + 4 to ctx->next_pc for
 * non-fault exits), the exit code to ctx->exit_reason, moves the code to
 * w0, and returns. Fault exits also store the fault address low half to
 * ctx->exit_info and clear llbit, matching mips_fault; the dispatcher
 * re-executes the faulting word via interp_step for exact state.
 *
 * Returns 0 when the block was emitted (length/end valid), 1 when
 * the dispatcher must fall back (untranslatable word, branch in a delay
 * slot, missing slot fetch, bad arguments). A block ends at the first
 * control transfer, SYSCALL/BREAK/trap exit, or the end of the decoded
 * window; a fault inside a delay slot reports the slot pc.
 */

#include "dbt/emit_int.h"

/* Lane L3b FP entry point (src/dbt/emit_fp.c): 0 emitted, nonzero for
 * unknown words (dispatcher falls back to interp_step). */
int ef_emit_fp(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);

/* ---- Guest state access ($0 reads as XZR, writes are dropped) ---- */

void ei_gld(a64_emit_t *e, unsigned tmp, unsigned r)
{
    if (r == MIPS64_REG_ZERO) {
        ei_mov(e, tmp, EI_XZR);
    } else {
        ei_ldr(e, 0, tmp, EI_CTX, EI_OFF_GPR(r));
    }
}

void ei_gst(a64_emit_t *e, unsigned tmp, unsigned r)
{
    if (r != MIPS64_REG_ZERO) {
        ei_str(e, 0, tmp, EI_CTX, EI_OFF_GPR(r));
    }
}

/* ---- Block terminators ---- */

/* Store an immediate guest pc to ctx->pc. */
void ei_set_pc(a64_emit_t *e, uint64_t pc)
{
    ei_mov64(e, EI_T, pc);
    ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_PC_OFFSET);
}

/* Reason tail shared by non-fault exits: next_pc, exit_reason, w0, ret. */
void ei_exit_tail(a64_emit_t *e, uint64_t next_pc, uint32_t reason)
{
    ei_mov64(e, EI_T, next_pc);
    ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_NEXT_PC_OFFSET);
    ei_mov32(e, 0u, reason);
    ei_str(e, 1, 0u, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET);
    ei_ret(e);
}

/* Normal resume at an immediate pc (fallthrough, taken branches, jumps). */
void ei_exit_at(a64_emit_t *e, uint64_t pc, uint32_t reason)
{
    ei_set_pc(e, pc);
    ei_exit_tail(e, pc + 4u, reason);
}

/* Fault exit with an immediate fault pc: info holds the pc low half,
 * llbit is cleared like mips_fault, next_pc is left alone (interp
 * parity: a faulting step never advances next_pc). */
void ei_exit_fault_pc(a64_emit_t *e, uint64_t pc)
{
    ei_mov64(e, EI_T, pc);
    ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_PC_OFFSET);
    ei_mov32(e, EI_A, (uint32_t)pc);
    ei_str(e, 1, EI_A, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET + 4u);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_mov32(e, 0u, MIPS64_EXIT_FAULT);
    ei_str(e, 1, 0u, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET);
    ei_ret(e);
}

/* Fault exit with the fault address in a register (low half stored).
 * The scratch slot is refreshed with pc as well: the miss branches
 * skip the hit-path pc record, so without this store the dispatcher's
 * pad150 would name a previous word and fault recovery (fill-and-retry
 * decode, si_addr recomputation) would inspect the wrong instruction.
 * EI_T is dead at every epilogue (terminal block exit). */
void ei_exit_fault_reg(a64_emit_t *e, uint64_t pc, unsigned areg)
{
    ei_mov64(e, EI_T, pc);
    ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_PC_OFFSET);
    ei_str(e, 0, EI_T, EI_CTX, EI_OFF_SCRATCH);
    ei_str(e, 1, areg, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET + 4u);
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_mov32(e, 0u, MIPS64_EXIT_FAULT);
    ei_str(e, 1, 0u, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET);
    ei_ret(e);
}

/* SYSCALL exit: llbit cleared (interp parity), dispatcher re-executes
 * the word via interp_step, so pc points at the syscall itself. */
void ei_exit_syscall(a64_emit_t *e, uint64_t pc)
{
    ei_strb(e, EI_XZR, EI_CTX, MIPS64_CTX_LLBIT_OFFSET);
    ei_set_pc(e, pc);
    ei_exit_tail(e, pc + 4u, MIPS64_EXIT_SYSCALL);
}

/* EXIT_UNDEF exit for FP/COP1/COP2/unknown words. */
void ei_exit_undef(a64_emit_t *e, uint64_t pc)
{
    ei_exit_at(e, pc, MIPS64_EXIT_UNDEF);
}

/* Emit an immediate fault exit for a just-recorded forward slot. The
 * epilogue is skipped by a jump so execution continues inline. */
void ei_bfault(a64_emit_t *e, uint64_t pc, size_t slot)
{
    size_t over;
    size_t tgt;

    if (e == NULL) {
        return;
    }
    over = ei_b(e);
    tgt = e->len;
    ei_exit_fault_pc(e, pc);
    ei_patch_at(e, slot, tgt, 0);
    ei_patch26(e, over, e->len);
}

/* ---- Block driver (0 continue, 1 fallback, 2 block ended) ---- */

/* True for words that transfer control with a delay slot (mirrors
 * interp_is_control; interp.h is lane-internal and not included here). */
static int ei_is_control(const mips_dec_t *d)
{
    switch (d->op) {
    case 0x02u: /* J */
    case 0x03u: /* JAL */
    case 0x04u: /* BEQ */
    case 0x05u: /* BNE */
    case 0x06u: /* BLEZ */
    case 0x07u: /* BGTZ */
    case 0x14u: /* BEQL */
    case 0x15u: /* BNEL */
    case 0x16u: /* BLEZL */
    case 0x17u: /* BGTZL */
        return 1;
    case 0x01u: /* REGIMM */
        switch (d->rt) {
        case 0x00u: /* BLTZ */
        case 0x01u: /* BGEZ */
        case 0x02u: /* BLTZL */
        case 0x03u: /* BGEZL */
        case 0x10u: /* BLTZAL */
        case 0x11u: /* BGEZAL */
        case 0x12u: /* BLTZALL */
        case 0x13u: /* BGEZALL */
            return 1;
        default:
            return 0;
        }
    case 0x00u: /* JR / JALR */
        return d->funct == 0x08u || d->funct == 0x09u;
    case 0x11u: /* COP1 BC1T/BC1F/likely (lane L3b; no other COP1 moves) */
        return d->rs == 0x08u ? 1 : 0;
    default:
        return 0;
    }
}

static int ei_one(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
                  int slot);

static int ei_branch(a64_emit_t *e, const mips_dec_t *d, const mips_dec_t *s,
                     uint64_t pc, int be)
{
    int64_t off = (int64_t)d->simm * 4;
    uint64_t tgt = pc + 4u + (uint64_t)off;
    unsigned cc = EI_EQ;
    int likely = 0;
    int link = 0;
    int indirect = 0;
    int has_cond = 1;
    /* Lane L3b: BC1 sources the condition from the FCSR FCC bit instead
     * of a GPR compare (rt = cc<<2 | likely<<1 | tf). */
    int fpcond = 0;
    unsigned fccbit = 23u;
    unsigned tf = 0u;
    size_t t;

    switch (d->op) {
    case 0x02u: /* J */
    case 0x03u: /* JAL */
        link = (d->op == 0x03u) ? 1 : 0;
        tgt = ((pc + 4u) & ~UINT64_C(0xFFFFFF)) | ((uint64_t)d->target << 2);
        has_cond = 0;
        break;
    case 0x04u: /* BEQ */
        cc = EI_EQ;
        break;
    case 0x05u: /* BNE */
        cc = EI_NE;
        break;
    case 0x06u: /* BLEZ */
        cc = EI_LE;
        break;
    case 0x07u: /* BGTZ */
        cc = EI_GT;
        break;
    case 0x14u: /* BEQL */
        cc = EI_EQ;
        likely = 1;
        break;
    case 0x15u: /* BNEL */
        cc = EI_NE;
        likely = 1;
        break;
    case 0x16u: /* BLEZL */
        cc = EI_LE;
        likely = 1;
        break;
    case 0x17u: /* BGTZL */
        cc = EI_GT;
        likely = 1;
        break;
    case 0x01u: /* REGIMM */
        switch (d->rt) {
        case 0x00u: /* BLTZ */
            cc = EI_LT;
            break;
        case 0x01u: /* BGEZ */
            cc = EI_GE;
            break;
        case 0x02u: /* BLTZL */
            cc = EI_LT;
            likely = 1;
            break;
        case 0x03u: /* BGEZL */
            cc = EI_GE;
            likely = 1;
            break;
        case 0x10u: /* BLTZAL */
            cc = EI_LT;
            link = 1;
            break;
        case 0x11u: /* BGEZAL */
            cc = EI_GE;
            link = 1;
            break;
        case 0x12u: /* BLTZALL */
            cc = EI_LT;
            link = 1;
            likely = 1;
            break;
        case 0x13u: /* BGEZALL */
            cc = EI_GE;
            link = 1;
            likely = 1;
            break;
        default:
            return 1;
        }
        break;
    case 0x00u: /* JR / JALR */
        if (d->funct != 0x08u && d->funct != 0x09u) {
            return 1;
        }
        link = (d->funct == 0x09u) ? 1 : 0;
        indirect = 1;
        has_cond = 0;
        break;
    case 0x11u: /* COP1 BC1T/BC1F/BC1TL/BC1FL (lane L3b) */
        if (d->rs != 0x08u) {
            return 1;
        }
        tf = d->rt & 1u;
        likely = (int)((d->rt >> 1) & 1u);
        fpcond = 1;
        if (((d->rt >> 2) & 7u) == 0u) {
            fccbit = 23u;
        } else {
            fccbit = 24u + ((d->rt >> 2) & 7u);
        }
        break;
    default:
        return 1;
    }
    if (indirect != 0) {
        size_t s1;
        size_t s2;
        size_t ft;

        ei_gld(e, EI_A, d->rs);
        s1 = ei_tbz(e, 1, EI_A, 0u);
        s2 = ei_tbz(e, 1, EI_A, 1u);
        if (link != 0) {
            ei_mov64(e, EI_T, pc + 8u);
            ei_gst(e, EI_T, d->rd);
        }
        /* The delay slot owns x21..x24, so park the target in x25
         * (trampoline-preserved, emitter-unused) across it. */
        ei_mov(e, EI_S, EI_A);
        if (ei_one(e, s, pc + 4u, be, 1) != 0) {
            return 1;
        }
        ei_mov(e, EI_A, EI_S);
        ei_str(e, 0, EI_A, EI_CTX, MIPS64_CTX_PC_OFFSET);
        ei_mov32(e, EI_T, 4u);
        ei_add(e, 0, EI_T, EI_A, EI_T);
        ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_NEXT_PC_OFFSET);
        ei_mov32(e, 0u, MIPS64_EXIT_BRANCH);
        ei_str(e, 1, 0u, EI_CTX, MIPS64_CTX_EXIT_REASON_OFFSET);
        ei_ret(e);
        ft = e == NULL ? 0u : e->len;
        ei_exit_fault_reg(e, pc, EI_A);
        ei_patch_at(e, s1, ft, 0);
        ei_patch_at(e, s2, ft, 0);
        return 0;
    }
    if (has_cond != 0) {
        if (fpcond != 0) {
            /* BC1: condition is the FCSR FCC bit (lane L3b). */
            ei_ldr(e, 1, EI_A, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
        } else {
            ei_gld(e, EI_A, d->rs);
            if (d->op == 0x04u || d->op == 0x05u || d->op == 0x14u ||
                d->op == 0x15u) {
                ei_gld(e, EI_B, d->rt);
                ei_cmp(e, 0, EI_A, EI_B);
            } else {
                ei_cmp(e, 0, EI_A, EI_XZR);
            }
        }
    }
    if (link != 0) {
        ei_mov64(e, EI_T, pc + 8u);
        ei_gst(e, EI_T, MIPS64_REG_RA);
    }
    if (has_cond != 0 && fpcond != 0) {
        /* BC1T: taken when the FCC bit is set (tbnz); BC1F: taken
         * when clear (tbz). Same 19-bit patch shape as b.cond. */
        t = ei_tbz(e, (int)tf, EI_A, fccbit);
    } else {
        t = has_cond != 0 ? ei_bcc(e, cc) : (size_t)-1;
    }
    if (likely != 0) {
        /* Not-taken likely: skip the slot with no fetch. */
        ei_exit_at(e, pc + 8u, MIPS64_EXIT_BRANCH);
        ei_patch_at(e, t, e == NULL ? 0u : e->len, 0);
        if (ei_one(e, s, pc + 4u, be, 1) != 0) {
            return 1;
        }
        ei_exit_at(e, tgt, MIPS64_EXIT_BRANCH);
        return 0;
    }
    if (has_cond == 0) {
        /* Unconditional: the slot runs, then the target (no link to
         * the fallthrough, which is unreachable). */
        if (ei_one(e, s, pc + 4u, be, 1) != 0) {
            return 1;
        }
    } else {
        if (ei_one(e, s, pc + 4u, be, 1) != 0) {
            return 1;
        }
        ei_exit_at(e, pc + 8u, MIPS64_EXIT_BRANCH);
        ei_patch_at(e, t, e == NULL ? 0u : e->len, 0);
        if (ei_one(e, s, pc + 4u, be, 1) != 0) {
            return 1;
        }
    }
    ei_exit_at(e, tgt, MIPS64_EXIT_BRANCH);
    return 0;
}

static int ei_one(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
                  int slot)
{
    int r = 1;

    switch (d->op) {
    case 0x00u: /* SPECIAL */
        r = ei_special(e, d, pc, slot);
        break;
    case 0x01u: /* REGIMM */
        switch (d->rt) {
        case 0x00u: /* BLTZ */
        case 0x01u: /* BGEZ */
        case 0x02u: /* BLTZL */
        case 0x03u: /* BGEZL */
        case 0x10u: /* BLTZAL */
        case 0x11u: /* BGEZAL */
        case 0x12u: /* BLTZALL */
        case 0x13u: /* BGEZALL */
            r = 1;
            break;
        default:
            r = ei_regimm_trap(e, d, pc, slot);
            break;
        }
        break;
    case 0x08u: /* ADDI */
    case 0x09u: /* ADDIU */
    case 0x0Au: /* SLTI */
    case 0x0Bu: /* SLTIU */
    case 0x0Cu: /* ANDI */
    case 0x0Du: /* ORI */
    case 0x0Eu: /* XORI */
    case 0x0Fu: /* LUI */
    case 0x18u: /* DADDI */
    case 0x19u: /* DADDIU */
        r = ei_imm(e, d, pc, slot);
        break;
    case 0x1Cu: /* SPECIAL2 */
        r = ei_special2(e, d, pc, slot);
        break;
    case 0x1Fu: /* SPECIAL3 */
        r = ei_special3(e, d, pc, slot);
        break;
    case 0x10u: /* COP0 */
        r = ei_cop(e, d, pc, slot);
        break;
    case 0x11u: /* COP1 (lane L3b): arithmetic/CVT/compare via emit_fp.c */
        r = ef_emit_fp(e, d, pc, slot);
        break;
    case 0x1Au: /* LDL */
        r = ei_unaligned(e, d, pc, 1, 1, be, be != 0 ? 0 : 3, 0, 56u);
        break;
    case 0x1Bu: /* LDR */
        r = ei_unaligned(e, d, pc, 1, 1, be, be != 0 ? 2 : 0, 1, 56u);
        break;
    case 0x22u: /* LWL */
        r = ei_unaligned(e, d, pc, 1, 0, be, be != 0 ? 0 : 3, 0, 24u);
        break;
    case 0x26u: /* LWR */
        r = ei_unaligned(e, d, pc, 1, 0, be, be != 0 ? 2 : 0, 1, 24u);
        break;
    case 0x2Au: /* SWL */
        r = ei_unaligned(e, d, pc, 0, 0, be, be != 0 ? 0 : 2, 1, 24u);
        break;
    case 0x2Eu: /* SWR */
        r = ei_unaligned(e, d, pc, 0, 0, be, be != 0 ? 3 : 0, 0, 24u);
        break;
    case 0x2Cu: /* SDL */
        /* BE stores mirror the 32-bit BE store modes (SWL/SWR), not
         * the load modes: SDL needs LSR-by-sk (m=1), SDR LSL-by-56-sk
         * (m=3 after adjust). Matches do_sdl/do_sdr in interp. */
        r = ei_unaligned(e, d, pc, 0, 1, be, be != 0 ? 1 : 2, 0, 56u);
        break;
    case 0x2Du: /* SDR */
        r = ei_unaligned(e, d, pc, 0, 1, be, be != 0 ? 3 : 0, 0, 56u);
        break;
    case 0x30u: /* LL */
    case 0x34u: /* LLD */
    case 0x38u: /* SC */
    case 0x3Cu: /* SCD */
        r = ei_atomic(e, d, pc, be);
        break;
    case 0x20u: /* LB */
    case 0x21u: /* LH */
    case 0x23u: /* LW */
    case 0x24u: /* LBU */
    case 0x25u: /* LHU */
    case 0x27u: /* LWU */
    case 0x28u: /* SB */
    case 0x29u: /* SH */
    case 0x2Bu: /* SW */
    case 0x37u: /* LD */
    case 0x3Fu: /* SD */
        r = ei_mem_aligned(e, d, pc, be);
        break;
    case 0x2Fu: /* CACHE */
    case 0x33u: /* PREF */
        r = 0;
        break;
    default: /* COP1X/COP2/JALX/FP memory/unknown: EXIT_UNDEF
                * (COP1 has its own case above and never reaches here). */
        if (slot == 0) {
            ei_exit_undef(e, pc);
            r = 2;
        } else {
            r = 1;
        }
        break;
    }
    if (r == 2 && slot != 0) {
        return 1;
    }
    return r;
}

int dbt_emit_int(mips64_ctx_t *ctx, uint64_t pc, const mips_dec_t *insns,
                 unsigned count, uint8_t *out, size_t cap, size_t *out_len,
                 uint64_t *out_end)
{
    a64_emit_t e;
    unsigned i;
    int be;

    if (ctx == NULL || insns == NULL || out == NULL || out_len == NULL ||
        out_end == NULL) {
        return 1;
    }
    if (count == 0u || count > MIPS64_DBT_MAX_INSNS) {
        return 1;
    }
    if (cap < 4u || ((uintptr_t)out & 3u) != 0u) {
        return 1;
    }
    e.buf = (uint32_t *)(void *)out;
    e.cap = cap / 4u;
    e.len = 0u;
    e.err = 0;
    be = ctx->is_be != 0u ? 1 : 0;
    for (i = 0u; i < count; i++) {
        uint64_t cur = pc + (uint64_t)i * 4u;
        const mips_dec_t *d = &insns[i];
        int r;

        if (ei_is_control(d) != 0) {
            mips_dec_t s;
            const mips_dec_t *sp;

            if (i + 1u < count) {
                sp = &insns[i + 1u];
            } else {
                uint32_t w;

                if (mips_fetch(ctx, cur + 4u, &w) != 0) {
                    *out_len = 0u;
                    return 1;
                }
                mips_decode(w, &s);
                sp = &s;
            }
            if (ei_is_control(sp) != 0) {
                *out_len = 0u;
                return 1;
            }
            if (ei_branch(&e, d, sp, cur, be) != 0 || e.err != 0) {
                *out_len = 0u;
                return 1;
            }
            *out_len = e.len * 4u;
            *out_end = cur + 8u;
            return 0;
        }
        r = ei_one(&e, d, cur, be, 0);
        if (r == 1 || e.err != 0) {
            *out_len = 0u;
            return 1;
        }
        if (r == 2) {
            *out_len = e.len * 4u;
            *out_end = cur + 4u;
            return 0;
        }
    }
    ei_exit_at(&e, pc + (uint64_t)count * 4u, MIPS64_EXIT_BRANCH);
    if (e.err != 0) {
        *out_len = 0u;
        return 1;
    }
    *out_len = e.len * 4u;
    *out_end = pc + (uint64_t)count * 4u;
    return 0;
}
