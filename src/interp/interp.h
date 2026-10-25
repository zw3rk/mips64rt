/*
 * src/interp/interp.h — lane-internal helpers for the integer reference
 * interpreter (Phase 1, lane L1b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Only the interpreter sources include this header. All cross-lane
 * interaction goes through the frozen contracts in src/core/cpu.h
 * (mips_decode/mips_fetch, guest_ld/st, mips_syscall, mips_fault,
 * mips_is_be). COP1 data movement (LWC1/SWC1/LDC1/SDC1, MFC1/MTC1/
 * CFC1/CTC1) lives in fpmove.c as uninterpreted 64-bit moves; every FP
 * arithmetic opcode faults for Phase 3.
 *
 * Interface assumptions (implemented by lanes L1a/L1c, recorded here so
 * the RC1 integration can verify them):
 * - mips_fetch returns 0 with *word set, or MIPS_FAULT on a bad pc.
 * - guest_ld/st return 0 on success and MIPS_FAULT on fault; the mem
 *   layer also faults on misaligned 16/32/64-bit accesses, so interp
 *   checks alignment first to report the data address.
 * - mips_syscall performs the N64/N32 call including its $v0/$a3
 *   writeback and leaves ctx->pc alone for a continuing call (interp
 *   advances it); the int64 return is opaque (guest errors are in
 *   $v0/$a3). ctx->exit_reason stops the run (guest exit/fatal fault).
 *
 * interp_step/interp_run return contract:
 * - 0 continues, MIPS_FAULT stops after mips_fault recorded EXIT_FAULT,
 *   1 stops with ctx->exit_reason already set (guest exit path).
 */

#ifndef MIPS64RT_INTERP_INTERP_H
#define MIPS64RT_INTERP_INTERP_H

#include <stdint.h>

#include "core/cpu.h"

/* $0 is hardwired zero: every write through this helper drops r == 0. */
static inline void interp_set_reg(mips64_ctx_t *ctx, unsigned r, uint64_t v)
{
    if (r != MIPS64_REG_ZERO) {
        ctx->gpr[r] = v;
    }
}

/* Canonical 32-bit sign-extension (SPEC 2.2, E02). */
static inline uint64_t interp_sext32(uint32_t v)
{
    return (uint64_t)(int64_t)(int32_t)v;
}

/* Count leading zeros (loop: defined for x == 0, unlike __builtin_clz). */
static inline uint32_t interp_clz32(uint32_t x)
{
    uint32_t n = 0u;
    uint32_t bit = 0x80000000u;

    while (bit != 0u && (x & bit) == 0u) {
        n++;
        bit >>= 1;
    }
    return n;
}

static inline uint64_t interp_clz64(uint64_t x)
{
    uint64_t n = 0u;
    uint64_t bit = UINT64_C(1) << 63;

    while (bit != 0u && (x & bit) == 0u) {
        n++;
        bit >>= 1;
    }
    return n;
}

/* Rotate-right (shift count masked, n == 0 is identity). */
static inline uint32_t interp_rotr32(uint32_t v, uint64_t n)
{
    unsigned s = (unsigned)(n & 31u);

    if (s == 0u) {
        return v;
    }
    return (v >> s) | (v << ((32u - s) & 31u));
}

static inline uint64_t interp_rotr64(uint64_t v, uint64_t n)
{
    unsigned s = (unsigned)(n & 63u);

    if (s == 0u) {
        return v;
    }
    return (v >> s) | (v << ((64u - s) & 63u));
}

/* Signed ADD/SUB overflow probes without signed UB (unsigned arithmetic). */
static inline int interp_add32_ov(uint32_t a, uint32_t b, uint32_t s)
{
    return (((a ^ s) & (b ^ s)) & 0x80000000u) != 0u;
}

static inline int interp_sub32_ov(uint32_t a, uint32_t b, uint32_t d)
{
    return (((a ^ b) & (a ^ d)) & 0x80000000u) != 0u;
}

static inline int interp_add64_ov(uint64_t a, uint64_t b, uint64_t s)
{
    return (((a ^ s) & (b ^ s)) & (UINT64_C(1) << 63)) != 0u;
}

static inline int interp_sub64_ov(uint64_t a, uint64_t b, uint64_t d)
{
    return (((a ^ b) & (a ^ d)) & (UINT64_C(1) << 63)) != 0u;
}

/* Unaligned merge helpers (src/interp/unaligned.c, E02 manual-correct). */
int do_lwl(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_lwr(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_swl(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval);
int do_swr(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval);
int do_ldl(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_ldr(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_sdl(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval);
int do_sdr(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval);

/* LL/SC/LLD/SCD reservation helpers (src/interp/unaligned.c, E05). */
int do_ll(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_sc(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_lld(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);
int do_scd(mips64_ctx_t *ctx, uint64_t addr, unsigned rt);

/* FPR data movement, no arithmetic (src/interp/fpmove.c). 0 ok,
 * MIPS_FAULT for anything else (caller maps it with fault_at). */
int fpmove_mem(mips64_ctx_t *ctx, const mips_dec_t *d);
int fpmove_cop1(mips64_ctx_t *ctx, const mips_dec_t *d);
/* COP0 ulr-alias moves (src/interp/fpmove.c). Same 0/MIPS_FAULT shape. */
int fpmove_cop0(mips64_ctx_t *ctx, const mips_dec_t *d);

/* Aligned load/store dispatcher (src/interp/unaligned.c). 0 ok,
 * MIPS_FAULT with the fault already recorded. */
int interp_exec_mem(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d);

/* True when the decoded instruction transfers control with a delay slot:
 * J/JAL, all (likely and non-likely) integer branches, JR/JALR. Traps,
 * SYSCALL/BREAK and SYNCI are not control transfers (no delay slot). */
static inline int interp_is_control(const mips_dec_t *d)
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
    case 0x00u: /* SPECIAL */
        return d->funct == 0x08u || d->funct == 0x09u; /* JR / JALR */
    default:
        return 0;
    }
}

#endif /* MIPS64RT_INTERP_INTERP_H */
