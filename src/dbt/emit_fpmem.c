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
        ei_probe_close(e);
        return 0;
    }
    ei_ldr(e, width == 8u ? 0 : 1, EI_C, EI_CTX, lane);
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
        ei_probe_close(e);
        return 0;
    }
    ei_ldr(e, width == 8u ? 0 : 1, EI_C, EI_CTX, lane);
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
