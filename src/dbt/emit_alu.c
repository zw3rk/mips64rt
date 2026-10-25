/*
 * src/dbt/emit_alu.c — Register-pure integer words for the L2c emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPECIAL/SPECIAL2/SPECIAL3, immediates, REGIMM traps, and the COP0
 * ulr-alias move. Semantics mirror src/interp/interp.c (RC1-corrected:
 * funct 0x24 sa 2/5, DINSM pos = sa). Returns 0 (continue), 1
 * (dispatcher fallback), 2 (block ended with an exit).
 */

#include "dbt/emit_int.h"

/* Conditional store: skip the gst when skip_if_nz matches the test. */
static void ei_skip_st(a64_emit_t *e, unsigned test, int is_w, int is_nz,
                       unsigned src, unsigned rd)
{
    size_t s = ei_cbz(e, is_w, is_nz, test);

    ei_gst(e, src, rd);
    ei_patch_at(e, s, e == NULL ? 0u : e->len, 0);
}

int ei_special(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                      int slot)
{
    switch (d->funct) {
    case 0x00u: /* SLL */
        ei_gld(e, EI_B, d->rt);
        ei_lsl(e, 1, EI_C, EI_B, d->sa & 31u);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x01u: { /* MOVCI: FCSR cc selects, tf inverts */
        unsigned cc = ((unsigned)d->rt >> 2u) & 7u;
        unsigned tf = (unsigned)d->rt & 1u;
        uint32_t mask = (cc == 0u) ? 0x00800000u : (1u << (24u + cc));

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rd);
        ei_ldr(e, 1, EI_C, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
        ei_mov32(e, EI_T, mask);
        ei_tst(e, EI_C, EI_T);
        ei_csel(e, 0, EI_C, EI_A, EI_B, tf != 0u ? EI_NE : EI_EQ);
        ei_gst(e, EI_C, d->rd);
        return 0;
    }
    case 0x02u: /* SRL / ROTR (rs == 1) */
        ei_gld(e, EI_B, d->rt);
        if (d->rs == 1u) {
            ei_mov32(e, EI_T, d->sa & 31u);
            ei_rorv(e, 1, EI_C, EI_B, EI_T);
        } else {
            ei_lsr(e, 1, EI_C, EI_B, d->sa & 31u);
        }
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x03u: /* SRA */
        ei_gld(e, EI_B, d->rt);
        ei_asr(e, 1, EI_C, EI_B, d->sa & 31u);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x04u: /* SLLV */
    case 0x06u: /* SRLV / RORV (sa == 1) */
    case 0x07u: /* SRAV */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        if (d->funct != 0x06u || d->sa != 1u) {
            ei_mov32(e, EI_T, 31u);
            ei_and(e, 1, EI_T, EI_A, EI_T);
        }
        if (d->funct == 0x04u) {
            ei_lslv(e, 1, EI_C, EI_B, EI_T);
        } else if (d->funct == 0x07u) {
            ei_asrv(e, 1, EI_C, EI_B, EI_T);
        } else if (d->sa == 1u) {
            ei_rorv(e, 1, EI_C, EI_B, EI_A);
        } else {
            ei_lsrv(e, 1, EI_C, EI_B, EI_T);
        }
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x08u: /* JR */
    case 0x09u: /* JALR */
        return 1;
    case 0x0Au: /* MOVZ: store only when rt == 0 */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_skip_st(e, EI_B, 0, 1, EI_A, d->rd);
        return 0;
    case 0x0Bu: /* MOVN: store only when rt != 0 */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_skip_st(e, EI_B, 0, 0, EI_A, d->rd);
        return 0;
    case 0x0Cu: /* SYSCALL */
        if (slot != 0) {
            return 1;
        }
        ei_exit_syscall(e, pc);
        return 2;
    case 0x0Du: /* BREAK */
        if (slot != 0) {
            return 1;
        }
        ei_exit_fault_pc(e, pc);
        return 2;
    case 0x0Fu: /* SYNC */
        return 0;
    case 0x10u: /* MFHI */
        ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_HI_OFFSET);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x11u: /* MTHI */
        ei_gld(e, EI_C, d->rs);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_HI_OFFSET);
        return 0;
    case 0x12u: /* MFLO */
        ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x13u: /* MTLO */
        ei_gld(e, EI_C, d->rs);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
        return 0;
    case 0x14u: /* DSLLV */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_lslv(e, 0, EI_C, EI_B, EI_A);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x16u: /* DSRLV / DROTRV (sa == 1) */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        if (d->sa == 1u) {
            ei_rorv(e, 0, EI_C, EI_B, EI_A);
        } else {
            ei_lsrv(e, 0, EI_C, EI_B, EI_A);
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x17u: /* DSRAV */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_asrv(e, 0, EI_C, EI_B, EI_A);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x18u: /* MULT: signed 32-bit halves, sign-extended */
    case 0x19u: { /* MULTU: unsigned 32-bit halves, sign-extended */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_mul(e, 1, EI_C, EI_A, EI_B);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
        if (d->funct == 0x18u) {
            ei_mulwide(e, 0x9B207C00u, EI_T, EI_A, EI_B);
        } else {
            ei_mulwide(e, 0x9BA07C00u, EI_T, EI_A, EI_B);
        }
        ei_lsr(e, 0, EI_T, EI_T, 32u);
        ei_sxt(e, 31u, EI_T, EI_T);
        ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_HI_OFFSET);
        return 0;
    }
    case 0x1Au: /* DIV: zero divisor leaves hi/lo unchanged */
    case 0x1Bu: { /* DIVU */
        size_t s;

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        s = ei_cbz(e, 1, 0, EI_B);
        if (d->funct == 0x1Au) {
            ei_div(e, 0x1AC00C00u, 1, EI_C, EI_A, EI_B);
        } else {
            ei_div(e, 0x1AC00800u, 1, EI_C, EI_A, EI_B);
        }
        ei_msub(e, 1, EI_T, EI_C, EI_B, EI_A);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
        ei_sxt(e, 31u, EI_T, EI_T);
        ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_HI_OFFSET);
        ei_patch_at(e, s, e == NULL ? 0u : e->len, 0);
        return 0;
    }
    case 0x1Cu: /* DMULT: signed 128-bit product */
    case 0x1Du: { /* DMULTU: unsigned 128-bit product */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_mul(e, 0, EI_C, EI_A, EI_B);
        ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
        if (d->funct == 0x1Cu) {
            ei_mulwide(e, 0x9B407C00u, EI_T, EI_A, EI_B);
        } else {
            ei_mulwide(e, 0x9BC07C00u, EI_T, EI_A, EI_B);
        }
        ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_HI_OFFSET);
        return 0;
    }
    case 0x1Eu: /* DDIV: zero or INT64_MIN/-1 leaves hi/lo unchanged */
    case 0x1Fu: { /* DDIVU: zero divisor leaves hi/lo unchanged */
        size_t s;

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        s = ei_cbz(e, 0, 0, EI_B);
        if (d->funct == 0x1Eu) {
            size_t no;
            size_t yes;

            ei_mov64(e, EI_T, UINT64_C(1) << 63);
            ei_cmp(e, 0, EI_A, EI_T);
            no = ei_bcc(e, EI_NE);
            ei_mov64(e, EI_T, UINT64_MAX);
            ei_cmp(e, 0, EI_B, EI_T);
            yes = ei_bcc(e, EI_EQ);
            ei_patch_at(e, no, e == NULL ? 0u : e->len, 0);
            ei_div(e, 0x9AC00C00u, 0, EI_C, EI_A, EI_B);
            ei_msub(e, 0, EI_T, EI_C, EI_B, EI_A);
            ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
            ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_HI_OFFSET);
            ei_patch_at(e, yes, e == NULL ? 0u : e->len, 0);
        } else {
            ei_div(e, 0x9AC00800u, 0, EI_C, EI_A, EI_B);
            ei_msub(e, 0, EI_T, EI_C, EI_B, EI_A);
            ei_str(e, 0, EI_C, EI_CTX, MIPS64_CTX_LO_OFFSET);
            ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_HI_OFFSET);
        }
        ei_patch_at(e, s, e == NULL ? 0u : e->len, 0);
        return 0;
    }
    case 0x20u: /* ADD (trapping) */
    case 0x21u: /* ADDU */
    case 0x22u: /* SUB (trapping) */
    case 0x23u: /* SUBU */
    case 0x2Cu: /* DADD (trapping) */
    case 0x2Du: /* DADDU */
    case 0x2Eu: /* DSUB (trapping) */
    case 0x2Fu: /* DSUBU */ {
        int is_d = (d->funct & 0x0Cu) == 0x0Cu;
        int trapping = d->funct == 0x20u || d->funct == 0x22u ||
            d->funct == 0x2Cu || d->funct == 0x2Eu;
        int is_sub = (d->funct & 0x02u) != 0u;

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        if (is_sub != 0) {
            if (trapping != 0) {
                ei_subs(e, is_d == 0, EI_C, EI_A, EI_B);
            } else {
                ei_sub(e, is_d == 0, EI_C, EI_A, EI_B);
            }
        } else if (trapping != 0) {
            ei_adds(e, is_d == 0, EI_C, EI_A, EI_B);
        } else {
            ei_add(e, is_d == 0, EI_C, EI_A, EI_B);
        }
        if (trapping != 0) {
            ei_bfault(e, pc, ei_bcc(e, EI_VS));
        }
        if (is_d == 0) {
            ei_sxt(e, 31u, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    }
    case 0x24u: /* AND */
    case 0x25u: /* OR */
    case 0x26u: /* XOR */
    case 0x27u: /* NOR */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        if (d->funct == 0x24u) {
            ei_and(e, 0, EI_C, EI_A, EI_B);
        } else if (d->funct == 0x25u) {
            ei_orr(e, 0, EI_C, EI_A, EI_B);
        } else if (d->funct == 0x26u) {
            ei_eor(e, 0, EI_C, EI_A, EI_B);
        } else {
            ei_orr(e, 0, EI_C, EI_A, EI_B);
            ei_mvn(e, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x2Au: /* SLT */
    case 0x2Bu: /* SLTU */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_cmp(e, 0, EI_A, EI_B);
        ei_cset(e, EI_C, d->funct == 0x2Au ? EI_LT : EI_LO);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x30u: /* TGE */
    case 0x31u: /* TGEU */
    case 0x32u: /* TLT */
    case 0x33u: /* TLTU */
    case 0x34u: /* TEQ */
    case 0x36u: { /* TNE */
        unsigned cc = EI_EQ;

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_cmp(e, 0, EI_A, EI_B);
        if (d->funct == 0x30u) {
            cc = EI_GE;
        } else if (d->funct == 0x31u) {
            cc = EI_HS;
        } else if (d->funct == 0x32u) {
            cc = EI_LT;
        } else if (d->funct == 0x33u) {
            cc = EI_LO;
        } else if (d->funct == 0x36u) {
            cc = EI_NE;
        }
        ei_bfault(e, pc, ei_bcc(e, cc));
        return 0;
    }
    case 0x38u: /* DSLL */
        ei_gld(e, EI_B, d->rt);
        ei_lsl(e, 0, EI_C, EI_B, d->sa & 31u);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Au: /* DSRL / DROTR (rs == 1) */
        ei_gld(e, EI_B, d->rt);
        if (d->rs == 1u) {
            ei_mov32(e, EI_T, d->sa & 31u);
            ei_rorv(e, 0, EI_C, EI_B, EI_T);
        } else {
            ei_lsr(e, 0, EI_C, EI_B, d->sa & 31u);
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Bu: /* DSRA */
        ei_gld(e, EI_B, d->rt);
        ei_asr(e, 0, EI_C, EI_B, d->sa & 31u);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Cu: /* DSLL32 */
        ei_gld(e, EI_B, d->rt);
        ei_lsl(e, 0, EI_C, EI_B, 32u + (d->sa & 31u));
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Eu: /* DSRL32 / DROTR32 (rs == 1) */
        ei_gld(e, EI_B, d->rt);
        if (d->rs == 1u) {
            ei_mov32(e, EI_T, 32u + (d->sa & 31u));
            ei_rorv(e, 0, EI_C, EI_B, EI_T);
        } else {
            ei_lsr(e, 0, EI_C, EI_B, 32u + (d->sa & 31u));
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Fu: /* DSRA32, or all-zero SDBBP breakpoint */
        if (d->rs == 0u && d->rt == 0u && d->rd == 0u && d->sa == 0u) {
            if (slot != 0) {
                return 1;
            }
            ei_exit_fault_pc(e, pc);
            return 2;
        }
        ei_gld(e, EI_B, d->rt);
        ei_asr(e, 0, EI_C, EI_B, 32u + (d->sa & 31u));
        ei_gst(e, EI_C, d->rd);
        return 0;
    default:
        break;
    }
    return 1;
}

int ei_special2(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                       int slot)
{
    (void)pc;
    (void)slot;
    switch (d->funct) {
    case 0x00u: /* MADD */
    case 0x01u: /* MADDU */
    case 0x04u: /* MSUB */
    case 0x05u: { /* MSUBU */
        uint32_t base = 0x9B200000u;

        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_HI_OFFSET);
        ei_ldr(e, 0, EI_T, EI_CTX, MIPS64_CTX_LO_OFFSET);
        ei_lsl(e, 0, EI_C, EI_C, 32u);
        ei_lsl(e, 0, EI_T, EI_T, 32u);
        ei_lsr(e, 0, EI_T, EI_T, 32u);
        ei_orr(e, 0, EI_C, EI_C, EI_T);
        if (d->funct == 0x01u) {
            base = 0x9BA00000u;
        } else if (d->funct == 0x04u) {
            base = 0x9B208000u;
        } else if (d->funct == 0x05u) {
            base = 0x9BA08000u;
        }
        ei_maddl(e, base, EI_C, EI_A, EI_B, EI_C);
        ei_lsl(e, 0, EI_T, EI_C, 32u);
        ei_asr(e, 0, EI_T, EI_T, 32u);
        ei_str(e, 0, EI_T, EI_CTX, MIPS64_CTX_LO_OFFSET);
        ei_lsr(e, 0, EI_A, EI_C, 32u);
        ei_lsl(e, 0, EI_A, EI_A, 32u);
        ei_asr(e, 0, EI_A, EI_A, 32u);
        ei_str(e, 0, EI_A, EI_CTX, MIPS64_CTX_HI_OFFSET);
        return 0;
    }
    case 0x02u: /* MUL */
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_mul(e, 1, EI_C, EI_A, EI_B);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x20u: /* CLZ */
    case 0x21u: /* CLO */
        ei_gld(e, EI_A, d->rs);
        if (d->funct == 0x21u) {
            ei_mvn(e, EI_A, EI_A);
        }
        ei_clz(e, 1, EI_C, EI_A);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x24u: /* DCLZ */
    case 0x25u: /* DCLO */
        ei_gld(e, EI_A, d->rs);
        if (d->funct == 0x25u) {
            ei_mvn(e, EI_A, EI_A);
        }
        ei_clz(e, 0, EI_C, EI_A);
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Fu: /* SDBBP */
        if (slot != 0) {
            return 1;
        }
        ei_exit_fault_pc(e, pc);
        return 2;
    default:
        break;
    }
    return 1;
}

int ei_special3(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                       int slot)
{
    (void)slot;
    switch (d->funct) {
    case 0x00u: { /* EXT rt, rs, pos, size (size = rd + 1) */
        unsigned pos = d->sa & 31u;
        unsigned size = (unsigned)d->rd + 1u;

        ei_gld(e, EI_A, d->rs);
        ei_bfm(e, 0x53000000u, EI_C, EI_A, pos, pos + size - 1u);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rt);
        return 0;
    }
    case 0x01u: /* DEXTM: pos = sa, size = rd + 33 */
    case 0x02u: /* DEXTU: pos = sa + 32, size = rd + 1 */
    case 0x03u: { /* DEXT: pos = sa, size = rd + 1 */
        unsigned pos = (d->sa & 31u) + ((d->funct == 0x02u) ? 32u : 0u);
        unsigned size = (unsigned)d->rd + 1u +
            ((d->funct == 0x01u) ? 32u : 0u);

        ei_gld(e, EI_A, d->rs);
        ei_bfm(e, 0xD3400000u, EI_C, EI_A, pos, pos + size - 1u);
        ei_gst(e, EI_C, d->rt);
        return 0;
    }
    case 0x04u: { /* INS rt, rs, pos, msb (result sign-extended) */
        unsigned pos = d->sa & 31u;
        unsigned msb = d->rd & 31u;
        unsigned size;
        uint32_t m;

        if (msb < pos) {
            ei_exit_fault_pc(e, pc);
            return slot != 0 ? 1 : 2;
        }
        size = msb - pos + 1u;
        m = (size >= 32u) ? 0xFFFFFFFFu : (uint32_t)(((1u << size) - 1u)
                                                    << pos);
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_mov32(e, EI_T, m);
        ei_bic_w(e, EI_B, EI_B, EI_T);
        ei_lsl(e, 1, EI_C, EI_A, pos);
        ei_and(e, 1, EI_C, EI_C, EI_T);
        ei_orr(e, 1, EI_B, EI_B, EI_C);
        ei_sxt(e, 31u, EI_B, EI_B);
        ei_gst(e, EI_B, d->rt);
        return 0;
    }
    case 0x05u: /* DINSM: pos = sa, msb = rd + 32 */
    case 0x06u: /* DINSU: pos = sa + 32, msb = rd + 32 */
    case 0x07u: { /* DINS: pos = sa, msb = rd */
        unsigned pos = (d->sa & 31u) + ((d->funct == 0x06u) ? 32u : 0u);
        unsigned msb = (d->rd & 31u) + ((d->funct == 0x07u) ? 0u : 32u);
        unsigned size;
        uint64_t m;

        if (msb < pos) {
            ei_exit_fault_pc(e, pc);
            return slot != 0 ? 1 : 2;
        }
        size = msb - pos + 1u;
        m = (size >= 64u) ? UINT64_MAX :
                             (((UINT64_C(1) << size) - 1u) << pos);
        ei_gld(e, EI_A, d->rs);
        ei_gld(e, EI_B, d->rt);
        ei_mov64(e, EI_T, m);
        ei_mvn(e, EI_T, EI_T);
        ei_and(e, 0, EI_B, EI_B, EI_T);
        ei_lsl(e, 0, EI_C, EI_A, pos);
        ei_mov64(e, EI_T, m);
        ei_and(e, 0, EI_C, EI_C, EI_T);
        ei_orr(e, 0, EI_B, EI_B, EI_C);
        ei_gst(e, EI_B, d->rt);
        return 0;
    }
    case 0x20u: /* BSHFL: WSBH (sa 2), SEB (sa 16), SEH (sa 24) */
        ei_gld(e, EI_A, d->rt);
        if (d->sa == 2u) {
            ei_rev(e, 0x5AC00400u, EI_C, EI_A);
            ei_sxt(e, 31u, EI_C, EI_C);
        } else if (d->sa == 16u) {
            ei_sxt(e, 7u, EI_C, EI_A);
        } else if (d->sa == 24u) {
            ei_sxt(e, 15u, EI_C, EI_A);
        } else {
            return 1;
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x24u: /* DSBH (sa 2) / DSHD (sa 5) */
        ei_gld(e, EI_A, d->rt);
        if (d->sa == 2u) {
            ei_rev(e, 0xDAC00400u, EI_C, EI_A);
        } else if (d->sa == 5u) {
            ei_rev(e, 0xDAC00C00u, EI_C, EI_A);
            ei_rev(e, 0xDAC00400u, EI_C, EI_C);
        } else {
            return 1;
        }
        ei_gst(e, EI_C, d->rd);
        return 0;
    case 0x3Bu: /* RDHWR rt, rd (rd 29 selects ulr) */
        if (d->rd != MIPS64_RDHWR_ULR) {
            return 1;
        }
        ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_ULR_OFFSET);
        ei_gst(e, EI_C, d->rt);
        return 0;
    default:
        break;
    }
    return 1;
}

int ei_imm(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot)
{
    (void)slot;
    switch (d->op) {
    case 0x08u: /* ADDI (trapping) */
        ei_gld(e, EI_A, d->rs);
        ei_mov32(e, EI_B, (uint32_t)d->simm);
        ei_adds(e, 1, EI_C, EI_A, EI_B);
        ei_bfault(e, pc, ei_bcc(e, EI_VS));
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x09u: /* ADDIU */
        ei_gld(e, EI_A, d->rs);
        ei_mov32(e, EI_B, (uint32_t)d->simm);
        ei_add(e, 1, EI_C, EI_A, EI_B);
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x0Au: /* SLTI (signed) */
    case 0x0Bu: /* SLTIU (unsigned vs sign-extended imm) */
        ei_gld(e, EI_A, d->rs);
        ei_mov64(e, EI_B, (uint64_t)(int64_t)d->simm);
        ei_cmp(e, 0, EI_A, EI_B);
        ei_cset(e, EI_C, d->op == 0x0Au ? EI_LT : EI_LO);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x0Cu: /* ANDI (zero-extended imm clears high bits) */
        ei_gld(e, EI_A, d->rs);
        ei_mov32(e, EI_B, d->uimm);
        ei_and(e, 0, EI_C, EI_A, EI_B);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x0Du: /* ORI */
        ei_gld(e, EI_A, d->rs);
        ei_mov32(e, EI_B, d->uimm);
        ei_orr(e, 0, EI_C, EI_A, EI_B);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x0Eu: /* XORI */
        ei_gld(e, EI_A, d->rs);
        ei_mov32(e, EI_B, d->uimm);
        ei_eor(e, 0, EI_C, EI_A, EI_B);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x0Fu: /* LUI */
        ei_mov32(e, EI_C, (uint32_t)(d->uimm << 16));
        ei_sxt(e, 31u, EI_C, EI_C);
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x18u: /* DADDI (trapping) */
        ei_gld(e, EI_A, d->rs);
        ei_mov64(e, EI_B, (uint64_t)(int64_t)d->simm);
        ei_adds(e, 0, EI_C, EI_A, EI_B);
        ei_bfault(e, pc, ei_bcc(e, EI_VS));
        ei_gst(e, EI_C, d->rt);
        return 0;
    case 0x19u: /* DADDIU */
        ei_gld(e, EI_A, d->rs);
        ei_mov64(e, EI_B, (uint64_t)(int64_t)d->simm);
        ei_add(e, 0, EI_C, EI_A, EI_B);
        ei_gst(e, EI_C, d->rt);
        return 0;
    default:
        break;
    }
    return 1;
}

int ei_regimm_trap(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                          int slot)
{
    unsigned cc = EI_EQ;

    (void)slot;
    switch (d->rt) {
    case 0x08u: /* TGEI */
        cc = EI_GE;
        break;
    case 0x09u: /* TGEIU */
        cc = EI_HS;
        break;
    case 0x0Au: /* TLTI */
        cc = EI_LT;
        break;
    case 0x0Bu: /* TLTIU */
        cc = EI_LO;
        break;
    case 0x0Cu: /* TEQI */
        cc = EI_EQ;
        break;
    case 0x0Eu: /* TNEI */
        cc = EI_NE;
        break;
    case 0x1Fu: /* SYNCI */
        return 0;
    default:
        return 1;
    }
    ei_gld(e, EI_A, d->rs);
    ei_mov64(e, EI_B, (uint64_t)(int64_t)d->simm);
    ei_cmp(e, 0, EI_A, EI_B);
    ei_bfault(e, pc, ei_bcc(e, cc));
    return 0;
}
int ei_cop(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot)
{
    (void)pc;
    (void)slot;
    if (d->op == 0x10u && (d->rs == 0u || d->rs == 1u) && d->rd == 4u &&
        (d->funct & 7u) == 2u) {
        /* MFC0/DMFC0 of the ulr alias (rd 4, sel 2). */
        ei_ldr(e, 0, EI_C, EI_CTX, MIPS64_CTX_ULR_OFFSET);
        if (d->rs == 0u) {
            ei_sxt(e, 31u, EI_C, EI_C);
        }
        ei_gst(e, EI_C, d->rt);
        return 0;
    }
    return 1;
}
