/*
 * src/interp/decode.h — MIPS64r2 instruction decoder interface (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Re-exports the frozen decoder contract from src/core/cpu.h
 * (mips_dec_t, mips_decode, mips_fetch) and adds pure instruction
 * classifiers used by the interpreter (lane L1b) and later the DBT.
 * All classifiers are pure: they inspect only the decoded fields.
 *
 * Opcode tables follow the MIPS64r2 Volume II instruction encoding
 * (major opcodes 0x00..0x3F; SPECIAL/SPECIAL2/SPECIAL3/REGIMM minor
 * selectors). COP1X (0x13) and COP2 (0x12) have no integer role in
 * Phase 1 and are decoded but left unclassified so lane L1b faults
 * on them; full COP1 arithmetic and COP2 land in Phase 3.
 */

#ifndef MIPS64RT_INTERP_DECODE_H
#define MIPS64RT_INTERP_DECODE_H

#include "core/cpu.h"

/* Major opcodes (bits 31..26). */
#define MIPS64_OP_SPECIAL  0x00U
#define MIPS64_OP_REGIMM   0x01U
#define MIPS64_OP_J        0x02U
#define MIPS64_OP_JAL      0x03U
#define MIPS64_OP_BEQ      0x04U
#define MIPS64_OP_BNE      0x05U
#define MIPS64_OP_BLEZ     0x06U
#define MIPS64_OP_BGTZ     0x07U
#define MIPS64_OP_ADDI     0x08U
#define MIPS64_OP_ADDIU    0x09U
#define MIPS64_OP_SLTI     0x0aU
#define MIPS64_OP_SLTIU    0x0bU
#define MIPS64_OP_ANDI     0x0cU
#define MIPS64_OP_ORI      0x0dU
#define MIPS64_OP_XORI     0x0eU
#define MIPS64_OP_LUI      0x0fU
#define MIPS64_OP_COP0     0x10U
#define MIPS64_OP_COP1     0x11U
#define MIPS64_OP_COP2     0x12U /* Phase 3: decoded, never classified here */
#define MIPS64_OP_COP1X    0x13U /* Phase 3: decoded, never classified here */
#define MIPS64_OP_BEQL     0x14U
#define MIPS64_OP_BNEL     0x15U
#define MIPS64_OP_BLEZL    0x16U
#define MIPS64_OP_BGTZL    0x17U
#define MIPS64_OP_DADDI    0x18U
#define MIPS64_OP_DADDIU   0x19U
#define MIPS64_OP_LDL      0x1aU
#define MIPS64_OP_LDR      0x1bU
#define MIPS64_OP_SPECIAL2 0x1cU
#define MIPS64_OP_JALX     0x1dU /* MIPS16 execution: L1b faults, not jumped */
#define MIPS64_OP_SPECIAL3 0x1fU /* RDHWR lives here (funct 0x3b) */
#define MIPS64_OP_LB       0x20U
#define MIPS64_OP_LH       0x21U
#define MIPS64_OP_LWL      0x22U
#define MIPS64_OP_LW       0x23U
#define MIPS64_OP_LBU      0x24U
#define MIPS64_OP_LHU      0x25U
#define MIPS64_OP_LWR      0x26U
#define MIPS64_OP_LWU      0x27U
#define MIPS64_OP_SB       0x28U
#define MIPS64_OP_SH       0x29U
#define MIPS64_OP_SWL      0x2aU
#define MIPS64_OP_SW       0x2bU
#define MIPS64_OP_SDL      0x2cU
#define MIPS64_OP_SDR      0x2dU
#define MIPS64_OP_SWR      0x2eU
#define MIPS64_OP_CACHE    0x2fU /* Phase 1: NOP (lane L1b) */
#define MIPS64_OP_LL       0x30U
#define MIPS64_OP_LWC1     0x31U
#define MIPS64_OP_LWC2     0x32U /* Phase 3: decoded, never classified here */
#define MIPS64_OP_PREF     0x33U /* Phase 1: NOP (lane L1b) */
#define MIPS64_OP_LLD      0x34U
#define MIPS64_OP_LDC1     0x35U
#define MIPS64_OP_LDC2     0x36U /* Phase 3: decoded, never classified here */
#define MIPS64_OP_LD       0x37U
#define MIPS64_OP_SC       0x38U
#define MIPS64_OP_SWC1     0x39U
#define MIPS64_OP_SWC2     0x3aU /* Phase 3: decoded, never classified here */
#define MIPS64_OP_SCD      0x3cU
#define MIPS64_OP_SDC1     0x3dU
#define MIPS64_OP_SDC2     0x3eU /* Phase 3: decoded, never classified here */
#define MIPS64_OP_SD       0x3fU

/* REGIMM selectors (op == MIPS64_OP_REGIMM, rt field). */
#define MIPS64_REGIMM_BLTZ    0x00U
#define MIPS64_REGIMM_BGEZ    0x01U
#define MIPS64_REGIMM_BLTZL   0x02U
#define MIPS64_REGIMM_BGEZL   0x03U
#define MIPS64_REGIMM_TGEI    0x08U
#define MIPS64_REGIMM_TGEIU   0x09U
#define MIPS64_REGIMM_TLTI    0x0aU
#define MIPS64_REGIMM_TLTIU   0x0bU
#define MIPS64_REGIMM_TEQI    0x0cU
#define MIPS64_REGIMM_TNEI    0x0eU
#define MIPS64_REGIMM_BLTZAL  0x10U
#define MIPS64_REGIMM_BGEZAL  0x11U
#define MIPS64_REGIMM_BLTZALL 0x12U
#define MIPS64_REGIMM_BGEZALL 0x13U

/* SPECIAL selectors (op == MIPS64_OP_SPECIAL, funct field). */
#define MIPS64_FUNCT_SLL   0x00U
#define MIPS64_FUNCT_SRL   0x02U
#define MIPS64_FUNCT_SRA   0x03U
#define MIPS64_FUNCT_SLLV  0x04U
#define MIPS64_FUNCT_SRLV  0x06U
#define MIPS64_FUNCT_SRAV  0x07U
#define MIPS64_FUNCT_JR    0x08U
#define MIPS64_FUNCT_JALR  0x09U
#define MIPS64_FUNCT_MOVZ  0x0aU
#define MIPS64_FUNCT_MOVN  0x0bU
#define MIPS64_FUNCT_SYSCALL 0x0cU
#define MIPS64_FUNCT_BREAK 0x0dU
#define MIPS64_FUNCT_SYNC  0x0fU
#define MIPS64_FUNCT_MFHI  0x10U
#define MIPS64_FUNCT_MTHI  0x11U
#define MIPS64_FUNCT_MFLO  0x12U
#define MIPS64_FUNCT_MTLO  0x13U
#define MIPS64_FUNCT_DSLLV 0x14U
#define MIPS64_FUNCT_DSRLV 0x16U
#define MIPS64_FUNCT_DSRAV 0x17U
#define MIPS64_FUNCT_MULT  0x18U
#define MIPS64_FUNCT_MULTU 0x19U
#define MIPS64_FUNCT_DIV   0x1aU
#define MIPS64_FUNCT_DIVU  0x1bU
#define MIPS64_FUNCT_DMULT 0x1cU
#define MIPS64_FUNCT_DMULTU 0x1dU
#define MIPS64_FUNCT_DDIV  0x1eU
#define MIPS64_FUNCT_DDIVU 0x1fU
#define MIPS64_FUNCT_ADD   0x20U
#define MIPS64_FUNCT_ADDU  0x21U
#define MIPS64_FUNCT_SUB   0x22U
#define MIPS64_FUNCT_SUBU  0x23U
#define MIPS64_FUNCT_AND   0x24U
#define MIPS64_FUNCT_OR    0x25U
#define MIPS64_FUNCT_XOR   0x26U
#define MIPS64_FUNCT_NOR   0x27U
#define MIPS64_FUNCT_SLT   0x2aU
#define MIPS64_FUNCT_SLTU  0x2bU
#define MIPS64_FUNCT_DADD  0x2cU
#define MIPS64_FUNCT_DADDU 0x2dU
#define MIPS64_FUNCT_DSUB  0x2eU
#define MIPS64_FUNCT_DSUBU 0x2fU
#define MIPS64_FUNCT_TGE   0x30U
#define MIPS64_FUNCT_TGEU  0x31U
#define MIPS64_FUNCT_TLT   0x32U
#define MIPS64_FUNCT_TLTU  0x33U
#define MIPS64_FUNCT_TEQ   0x34U
#define MIPS64_FUNCT_TNE   0x36U
#define MIPS64_FUNCT_DSLL  0x38U
#define MIPS64_FUNCT_DSRL  0x3aU
#define MIPS64_FUNCT_DSRA  0x3bU
#define MIPS64_FUNCT_DSLL32 0x3cU
#define MIPS64_FUNCT_DSRL32 0x3eU
#define MIPS64_FUNCT_DSRA32 0x3fU

/* SPECIAL2 selectors (op == MIPS64_OP_SPECIAL2, funct field). */
#define MIPS64_S2_MADD  0x00U
#define MIPS64_S2_MADDU 0x01U
#define MIPS64_S2_MUL   0x02U
#define MIPS64_S2_MSUB  0x04U
#define MIPS64_S2_MSUBU 0x05U
#define MIPS64_S2_CLZ   0x20U
#define MIPS64_S2_CLO   0x21U
#define MIPS64_S2_DCLZ  0x24U
#define MIPS64_S2_DCLO  0x25U
#define MIPS64_S2_SDBBP 0x3fU

/* SPECIAL3 selectors (op == MIPS64_OP_SPECIAL3, funct field). */
#define MIPS64_S3_EXT   0x00U
#define MIPS64_S3_DEXM  0x01U
#define MIPS64_S3_DEXTU 0x02U
#define MIPS64_S3_DEXT  0x03U
#define MIPS64_S3_INS   0x04U
#define MIPS64_S3_DINSM 0x05U
#define MIPS64_S3_DINSU 0x06U
#define MIPS64_S3_DINS  0x07U
#define MIPS64_S3_BSHFL 0x20U /* sa picks WSBH/SEB/SEH (L1b) */
#define MIPS64_S3_DSBH  0x24U /* sa 2 = DSBH, sa 5 = DSHD (L1b) */
#define MIPS64_S3_RDHWR 0x3bU

/* COP0 selectors (op == MIPS64_OP_COP0, rs field; rs == 16 uses funct). */
#define MIPS64_COP0_MFC0  0x00U
#define MIPS64_COP0_DMFC0 0x01U
#define MIPS64_COP0_MTC0  0x04U
#define MIPS64_COP0_DMTC0 0x05U
#define MIPS64_COP0_BC    0x08U
#define MIPS64_COP0_COFN  0x10U
#define MIPS64_COP0F_TLBR  0x01U
#define MIPS64_COP0F_TLBWI 0x02U
#define MIPS64_COP0F_TLBWR 0x06U
#define MIPS64_COP0F_TLBP  0x08U
#define MIPS64_COP0F_ERET  0x18U
#define MIPS64_COP0F_WAIT  0x20U

/* COP1 selectors (op == MIPS64_OP_COP1, rs field; BC uses rt). */
#define MIPS64_COP1_MFC1  0x00U
#define MIPS64_COP1_DMFC1 0x01U
#define MIPS64_COP1_CFC1  0x02U
#define MIPS64_COP1_MTC1  0x04U
#define MIPS64_COP1_DMTC1 0x05U
#define MIPS64_COP1_CTC1  0x06U
#define MIPS64_COP1_BC    0x08U
#define MIPS64_COP1_BC1F  0x00U
#define MIPS64_COP1_BC1T  0x01U
#define MIPS64_COP1_BC1FL 0x02U
#define MIPS64_COP1_BC1TL 0x03U

/* COP0/COP1 branch sub-opcodes share the BC numbering. */
#define MIPS64_BC_F  0x00U
#define MIPS64_BC_T  0x01U
#define MIPS64_BC_FL 0x02U
#define MIPS64_BC_TL 0x03U

/*
 * Pure classifiers. Each returns nonzero when the decoded instruction
 * belongs to the named class, zero otherwise (including a null
 * pointer). mips_is_trap reports instructions that trap or need a
 * trap-condition check (SYSCALL/BREAK unconditionally; TEQ/TNE/TGE/
 * TLT/TEQI/... conditionally; SDBBP): lane L1b evaluates the
 * condition and routes to the syscall dispatcher or mips_fault.
 */
int mips_is_branch(const mips_dec_t *d);
int mips_is_branch_likely(const mips_dec_t *d);
int mips_is_jump(const mips_dec_t *d);
int mips_is_link(const mips_dec_t *d);
int mips_has_delay_slot(const mips_dec_t *d);
int mips_is_load(const mips_dec_t *d);
int mips_is_store(const mips_dec_t *d);
int mips_is_trap(const mips_dec_t *d);

#endif /* MIPS64RT_INTERP_DECODE_H */
