/*
 * src/interp/decode.c — MIPS64r2 instruction decoder (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * mips_decode is a pure field splitter: it fills every mips_dec_t field
 * from the raw word and touches no other state. mips_fetch loads the
 * 4-byte word at guest pc through the Phase 1 reservation window
 * (ctx->guest_base + pc, SPEC 2.1) and assembles it explicitly so the
 * result is host-endian independent (mips_is_be selects the guest byte
 * order). It reports MIPS_FAULT on a null context, a misaligned pc, a
 * pc outside TASK_SIZE, or a pc not covered by any recorded region
 * with execute permission (when lane L1c has recorded regions; with
 * no regions — e.g. unit tests over a scratch window — only the
 * TASK_SIZE bound applies).
 */

#include "interp/decode.h"

#include <string.h>

void mips_decode(uint32_t word, mips_dec_t *d)
{
    uint16_t imm;

    if (d == NULL) {
        return;
    }
    imm = (uint16_t)(word & 0xffffU);
    d->word = word;
    d->op = (uint8_t)((word >> 26) & 0x3fU);
    d->rs = (uint8_t)((word >> 21) & 0x1fU);
    d->rt = (uint8_t)((word >> 16) & 0x1fU);
    d->rd = (uint8_t)((word >> 11) & 0x1fU);
    d->sa = (uint8_t)((word >> 6) & 0x1fU);
    d->funct = (uint8_t)(word & 0x3fU);
    d->imm = imm;
    d->target = word & 0x03ffffffU;
    d->simm = (int32_t)(int16_t)imm;
    d->uimm = (uint32_t)imm;
}

/*
 * True when [pc, pc+4) lies inside a recorded guest region with
 * execute permission. With no regions recorded (region_count == 0,
 * e.g. a scratch window in a unit test) every in-range pc is
 * fetchable; lane L1c records the mapped regions at RC1 and gaps
 * then fault here instead of trapping the host. The EXEC check is
 * load-bearing: fetching a PROT_NONE page (branch-likely pageend
 * probe) must report MIPS_FAULT before the host memcpy touches a
 * host-PROT_NONE mapping and delivers a host SIGSEGV to the
 * translator itself.
 */
static int fetch_covered(const mips64_ctx_t *ctx, uint64_t pc)
{
    size_t i;

    if (ctx->region_count == 0U) {
        return 1;
    }
    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].start <= pc && pc + 4U <= ctx->regions[i].end) {
            return (ctx->regions[i].prot & MIPS_PROT_EXEC) != 0U;
        }
    }
    return 0;
}

int mips_fetch(mips64_ctx_t *ctx, uint64_t pc, uint32_t *word)
{
    uint64_t limit;
    uint8_t b[4];

    if (ctx == NULL || word == NULL) {
        return MIPS_FAULT;
    }
    if ((pc & 3ULL) != 0ULL) {
        return MIPS_FAULT;
    }
    /* Ordered so pc + 4 never wraps: the first check rejects every
     * pc >= limit (including values near UINT64_MAX), so the second
     * addition runs only for pc < limit <= 2^40 (SPEC 2.1). */
    limit = mips_task_size(ctx);
    if (pc >= limit || pc + 4U > limit) {
        return MIPS_FAULT;
    }
    if (!fetch_covered(ctx, pc)) {
        return MIPS_FAULT;
    }
    /* W^X: the host never executes guest bytes; fetch only reads them.
     * memcpy keeps this safe for any host alignment; the byte assembly
     * below keeps it correct for any host endianness. */
    memcpy(b, mips64_guest_ptr(ctx, pc), 4U);
    if (mips_is_be(ctx) != 0) {
        *word = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
            ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    } else {
        *word = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
            ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    }
    return 0;
}

static int is_regimm_branch(uint8_t rt)
{
    return rt == MIPS64_REGIMM_BLTZ || rt == MIPS64_REGIMM_BGEZ ||
        rt == MIPS64_REGIMM_BLTZL || rt == MIPS64_REGIMM_BGEZL ||
        rt == MIPS64_REGIMM_BLTZAL || rt == MIPS64_REGIMM_BGEZAL ||
        rt == MIPS64_REGIMM_BLTZALL || rt == MIPS64_REGIMM_BGEZALL;
}

static int is_regimm_link(uint8_t rt)
{
    return rt == MIPS64_REGIMM_BLTZAL || rt == MIPS64_REGIMM_BGEZAL ||
        rt == MIPS64_REGIMM_BLTZALL || rt == MIPS64_REGIMM_BGEZALL;
}

static int is_regimm_likely(uint8_t rt)
{
    return rt == MIPS64_REGIMM_BLTZL || rt == MIPS64_REGIMM_BGEZL ||
        rt == MIPS64_REGIMM_BLTZALL || rt == MIPS64_REGIMM_BGEZALL;
}

static int is_regimm_trap(uint8_t rt)
{
    return rt == MIPS64_REGIMM_TGEI || rt == MIPS64_REGIMM_TGEIU ||
        rt == MIPS64_REGIMM_TLTI || rt == MIPS64_REGIMM_TLTIU ||
        rt == MIPS64_REGIMM_TEQI || rt == MIPS64_REGIMM_TNEI;
}

static int is_bc(uint8_t op, const mips_dec_t *d)
{
    if (op != MIPS64_OP_COP0 && op != MIPS64_OP_COP1) {
        return 0;
    }
    if (op == MIPS64_OP_COP0) {
        return d->rs == MIPS64_COP0_BC && d->rt <= MIPS64_BC_TL;
    }
    return d->rs == MIPS64_COP1_BC && d->rt <= MIPS64_BC_TL;
}

static int is_bc_likely(uint8_t op, const mips_dec_t *d)
{
    if (!is_bc(op, d)) {
        return 0;
    }
    return d->rt == MIPS64_BC_FL || d->rt == MIPS64_BC_TL;
}

int mips_is_branch(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS64_OP_BEQ:
    case MIPS64_OP_BNE:
    case MIPS64_OP_BLEZ:
    case MIPS64_OP_BGTZ:
    case MIPS64_OP_BEQL:
    case MIPS64_OP_BNEL:
    case MIPS64_OP_BLEZL:
    case MIPS64_OP_BGTZL:
        return 1;
    case MIPS64_OP_REGIMM:
        return is_regimm_branch(d->rt);
    case MIPS64_OP_COP0:
    case MIPS64_OP_COP1:
        return is_bc(d->op, d);
    default:
        return 0;
    }
}

int mips_is_branch_likely(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS64_OP_BEQL:
    case MIPS64_OP_BNEL:
    case MIPS64_OP_BLEZL:
    case MIPS64_OP_BGTZL:
        return 1;
    case MIPS64_OP_REGIMM:
        return is_regimm_likely(d->rt);
    case MIPS64_OP_COP0:
    case MIPS64_OP_COP1:
        return is_bc_likely(d->op, d);
    default:
        return 0;
    }
}

int mips_is_jump(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS64_OP_J || d->op == MIPS64_OP_JAL) {
        return 1;
    }
    /* JALX (op 0x1d) executes MIPS16 code: not a jump here, lane L1b
     * faults on it instead of transferring control into 16-bit code. */
    return d->op == MIPS64_OP_SPECIAL &&
        (d->funct == MIPS64_FUNCT_JR || d->funct == MIPS64_FUNCT_JALR);
}

int mips_is_link(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS64_OP_JAL) {
        return 1;
    }
    if (d->op == MIPS64_OP_SPECIAL && d->funct == MIPS64_FUNCT_JALR) {
        return 1;
    }
    return d->op == MIPS64_OP_REGIMM && is_regimm_link(d->rt);
}

int mips_has_delay_slot(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    return mips_is_branch(d) || mips_is_jump(d);
}

int mips_is_load(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS64_OP_LB:
    case MIPS64_OP_LH:
    case MIPS64_OP_LWL:
    case MIPS64_OP_LW:
    case MIPS64_OP_LBU:
    case MIPS64_OP_LHU:
    case MIPS64_OP_LWR:
    case MIPS64_OP_LWU:
    case MIPS64_OP_LL:
    case MIPS64_OP_LDL:
    case MIPS64_OP_LDR:
    case MIPS64_OP_LLD:
    case MIPS64_OP_LD:
    case MIPS64_OP_LWC1:
    case MIPS64_OP_LDC1:
        return 1;
    default:
        return 0;
    }
}

int mips_is_store(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS64_OP_SB:
    case MIPS64_OP_SH:
    case MIPS64_OP_SWL:
    case MIPS64_OP_SW:
    case MIPS64_OP_SDL:
    case MIPS64_OP_SDR:
    case MIPS64_OP_SWR:
    case MIPS64_OP_SC:
    case MIPS64_OP_SCD:
    case MIPS64_OP_SD:
    case MIPS64_OP_SWC1:
    case MIPS64_OP_SDC1:
        return 1;
    default:
        return 0;
    }
}

int mips_is_trap(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS64_OP_REGIMM) {
        return is_regimm_trap(d->rt);
    }
    if (d->op == MIPS64_OP_SPECIAL) {
        switch (d->funct) {
        case MIPS64_FUNCT_SYSCALL:
        case MIPS64_FUNCT_BREAK:
        case MIPS64_FUNCT_TGE:
        case MIPS64_FUNCT_TGEU:
        case MIPS64_FUNCT_TLT:
        case MIPS64_FUNCT_TLTU:
        case MIPS64_FUNCT_TEQ:
        case MIPS64_FUNCT_TNE:
            return 1;
        default:
            return 0;
        }
    }
    return d->op == MIPS64_OP_SPECIAL2 && d->funct == MIPS64_S2_SDBBP;
}
