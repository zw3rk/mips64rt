/*
 * src/interp/fpmove.c — FPR data-movement for the reference interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase-1 subset only: LWC1/SWC1/LDC1/SDC1 and MFC1/MTC1/CFC1/CTC1 move
 * bits between memory, GPRs, FCSR and the 32x64-bit FPR file WITHOUT
 * interpreting them (no arithmetic, no NaN rules), plus the COP0
 * ulr-alias moves (MFC0/DMFC0). Static binaries need these moves;
 * every FP arithmetic opcode faults for Phase 3 (fp.c).
 *
 * Transfer order is byte-wise through guest_ld/st8, so aligned and
 * (for the byte loop) unaligned addresses behave identically;
 * endianness follows mips_is_be.
 */

#include <stdint.h>

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"

/* Best-effort MIPS64R2 FIR for CFC1 $0 (read-only ID register); revisit
 * against qemu-mips64el/qemu-mips64 in Phase 3 (E03). Only CFC1 $0/$31
 * observability matters for Phase 1. */
#define MIPS64RT_FIR_MIPS64R2 0x007f0000u

/* Byte i (0 = lowest guest address) of a 32/64-bit FPR lane. */
static uint32_t lane_byte_u32(uint64_t v, unsigned i, int be)
{
    unsigned p = be ? (3u - i) : i;

    return (uint32_t)((v >> (8u * p)) & 0xFFu);
}

static uint32_t lane_byte_u64(uint64_t v, unsigned i, int be)
{
    unsigned p = be ? (7u - i) : i;

    return (uint32_t)((v >> (8u * p)) & 0xFFu);
}

static uint32_t build_u32(const uint8_t m[4], int be)
{
    uint32_t v = 0u;
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        unsigned p = be ? (3u - i) : i;

        v |= (uint32_t)m[i] << (8u * p);
    }
    return v;
}

static uint64_t build_u64(const uint8_t m[8], int be)
{
    uint64_t v = 0u;
    unsigned i;

    for (i = 0u; i < 8u; i++) {
        unsigned p = be ? (7u - i) : i;

        v |= (uint64_t)m[i] << (8u * p);
    }
    return v;
}

/* LWC1/SWC1/LDC1/SDC1: 0 ok, MIPS_FAULT for anything else (caller maps
 * the fault with the data address). Guest access failures are recorded
 * by the mem layer itself. Alignment is AdEL/AdES like real hardware. */
int fpmove_mem(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    uint64_t addr = ctx->gpr[d->rs] + (uint64_t)(int64_t)d->simm;
    unsigned fs = d->rt;
    int be = mips_is_be(ctx);
    unsigned i;

    if (fs >= 32u) {
        return MIPS_FAULT;
    }
    if (d->op == 0x31u || d->op == 0x39u) { /* LWC1 / SWC1: word aligned */
        if ((addr & 3u) != 0u) {
            mips_fault(ctx, addr);
            return MIPS_FAULT;
        }
    }
    if (d->op == 0x35u || d->op == 0x3Du) { /* LDC1 / SDC1: doubleword */
        if ((addr & 7u) != 0u) {
            mips_fault(ctx, addr);
            return MIPS_FAULT;
        }
    }
    switch (d->op) {
    case 0x31u: { /* LWC1: low 32 bits, upper lane preserved (FR=1) */
        uint8_t m[4] = { 0u, 0u, 0u, 0u };

        for (i = 0u; i < 4u; i++) {
            uint64_t v = 0u;

            if (guest_ld8(ctx, addr + i, &v) != 0) {
                return MIPS_FAULT;
            }
            m[i] = (uint8_t)v;
        }
        ctx->fpr[fs] =
            (ctx->fpr[fs] & UINT64_C(0xFFFFFFFF00000000)) | build_u32(m, be);
        return 0;
    }
    case 0x39u: { /* SWC1 */
        uint64_t v = ctx->fpr[fs];

        for (i = 0u; i < 4u; i++) {
            if (guest_st8(ctx, addr + i, lane_byte_u32(v, i, be)) != 0) {
                return MIPS_FAULT;
            }
        }
        return 0;
    }
    case 0x35u: { /* LDC1 */
        uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };

        for (i = 0u; i < 8u; i++) {
            uint64_t v = 0u;

            if (guest_ld8(ctx, addr + i, &v) != 0) {
                return MIPS_FAULT;
            }
            m[i] = (uint8_t)v;
        }
        ctx->fpr[fs] = build_u64(m, be);
        return 0;
    }
    case 0x3Du: { /* SDC1 */
        uint64_t v = ctx->fpr[fs];

        for (i = 0u; i < 8u; i++) {
            if (guest_st8(ctx, addr + i, lane_byte_u64(v, i, be)) != 0) {
                return MIPS_FAULT;
            }
        }
        return 0;
    }
    default:
        return MIPS_FAULT;
    }
}

/* MFC1/MTC1/CFC1/CTC1: 0 ok, MIPS_FAULT otherwise (caller maps it).
 * DMFC1/DMTC1 and every arithmetic/branch COP1 encoding fault here and
 * are recorded by the caller for Phase 3. */
int fpmove_cop1(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    unsigned rt = d->rt;
    unsigned fs = d->rd;

    if (rt >= 32u || fs >= 32u) {
        return MIPS_FAULT;
    }
    switch (d->rs) {
    case 0x00u: /* MFC1: low 32 bits, sign-extended */
        interp_set_reg(ctx, rt, interp_sext32((uint32_t)ctx->fpr[fs]));
        return 0;
    case 0x04u: /* MTC1: low 32 bits, upper lane preserved */
        ctx->fpr[fs] = (ctx->fpr[fs] & UINT64_C(0xFFFFFFFF00000000)) |
            (ctx->gpr[rt] & UINT64_C(0xFFFFFFFF));
        return 0;
    case 0x03u: /* MFHC1: upper 32 bits, sign-extended */
        interp_set_reg(ctx, rt,
            interp_sext32((uint32_t)(ctx->fpr[fs] >> 32u)));
        return 0;
    case 0x07u: /* MTHC1: upper 32 bits from GPR low word */
        ctx->fpr[fs] = (ctx->fpr[fs] & UINT64_C(0xFFFFFFFF)) |
            ((uint64_t)(uint32_t)ctx->gpr[rt] << 32u);
        return 0;
    case 0x02u: /* CFC1: $31 = FCSR, $0 = FIR (read-only ID). */
        if (fs == 31u) {
            interp_set_reg(ctx, rt, (uint64_t)ctx->fcsr);
            return 0;
        }
        if (fs == 0u) {
            interp_set_reg(ctx, rt, (uint64_t)MIPS64RT_FIR_MIPS64R2);
            return 0;
        }
        return MIPS_FAULT;
    case 0x06u: /* CTC1: $31 = FCSR, $0 = FIR (writes ignored). */
        if (fs == 31u) {
            ctx->fcsr = (uint32_t)ctx->gpr[rt];
            return 0;
        }
        if (fs == 0u) {
            return 0;
        }
        return MIPS_FAULT;
    case 0x01u: /* DMFC1: full 64-bit lane to GPR */
    case 0x05u: /* DMTC1: full 64-bit lane from GPR */
    case 0x08u: /* BC1F/BC1FL/BC1T/BC1TL (any cc) */
    case 0x16u: /* PS: paired-single lanes (fp_ps.c) */
    case 0x10u: /* S: arithmetic, converts, compares */
    case 0x11u: /* D: arithmetic, converts, compares */
    case 0x14u: /* W: CVT.S.W / CVT.D.W source */
    case 0x15u: /* L: CVT.S.L / CVT.D.L source */
        /* FP arithmetic/branches live in fp.c (Phase 3, lane L3a).
         * ctx->pc is the word's own address on every path that reaches
         * here: interp_step calls exec_simple with ctx->pc == pc, and
         * the delay-slot path sets ctx->pc to the slot first. */
        return fp_cop1(ctx, ctx->pc, d);
    default:
        return MIPS_FAULT;
    }
}

/* COP0 system-register moves: only MFC0/DMFC0 of the ulr alias (rd 4,
 * sel 2) are wired (E06); everything else faults for the caller to
 * record. 0 ok, MIPS_FAULT otherwise. */
int fpmove_cop0(mips64_ctx_t *ctx, const mips_dec_t *d)
{
    if ((d->rs == 0u || d->rs == 1u) && d->rd == 4u &&
        (d->funct & 7u) == 2u) {
        if (d->rs == 0u) { /* MFC0: low 32 bits, sign-extended */
            interp_set_reg(ctx, d->rt,
                           interp_sext32((uint32_t)ctx->ulr));
        } else { /* DMFC0: full 64-bit UserLocal */
            interp_set_reg(ctx, d->rt, ctx->ulr);
        }
        return 0;
    }
    return MIPS_FAULT;
}
