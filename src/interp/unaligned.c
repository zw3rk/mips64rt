/*
 * src/interp/unaligned.c — unaligned load/store merge + LL/SC helpers.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Byte-granular LWL/LWR/SWL/SWR merge rules (32-bit, result
 * sign-extended) and LDL/LDR/SDL/SDR merge rules (64-bit). Spans follow
 * the E02 tables: LDL/SDL take the right span mem[addr..pa+7], LDR/SDR
 * the left span mem[pa..addr]; placement into rt is endian-natural, so
 * the canonical (0,7) pair round-trips on every variant (manual-correct
 * on all four, per the RC-E adjudication in experiments/E02 — never the
 * qemu-mips64el/mipsn32el swapped-role behavior). LL/SC/LLD/SCD follow
 * E05 (exact-address reservation in llbit/lladdr/llval).
 *
 * This file also hosts interp_exec_mem, the aligned load/store
 * dispatcher that shares the helpers above (keeps interp.c under the
 * 900-line limit; no behavior difference vs a static executor).
 */

#include <stdint.h>
#include <stdio.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Byte position p (0 = LSB) of a 32/64-bit value. */
static uint32_t get_pos32(uint32_t v, unsigned p)
{
    return (v >> (8u * p)) & 0xFFu;
}

static uint32_t set_pos32(uint32_t v, unsigned p, uint64_t b)
{
    return (v & ~((uint32_t)0xFFu << (8u * p))) |
        (uint32_t)((b & 0xFFu) << (8u * p));
}

static uint64_t get_pos64(uint64_t v, unsigned p)
{
    return (v >> (8u * p)) & 0xFFu;
}

static uint64_t set_pos64(uint64_t v, unsigned p, uint64_t b)
{
    return (v & ~((uint64_t)0xFFu << (8u * p))) | ((b & 0xFFu) << (8u * p));
}

/* Load n bytes at PA..PA+n-1 into m (endianness-neutral). */
static int load_bytes(mips64_ctx_t *ctx, uint64_t pa, uint8_t m[8], unsigned n)
{
    unsigned i;

    for (i = 0u; i < n; i++) {
        uint64_t v = 0u;

        if (guest_ld8(ctx, pa + i, &v) != 0) {
            if (ctx->exit_reason == MIPS64_EXIT_NONE) {
                mips_fault(ctx, pa + i);
            }
            return MIPS_FAULT;
        }
        m[i] = (uint8_t)v;
    }
    return 0;
}

/* Store m[lo..hi] to PA+lo..PA+hi (endianness-neutral). */
static int store_bytes(mips64_ctx_t *ctx, uint64_t pa, const uint8_t m[8],
                       unsigned lo, unsigned hi)
{
    unsigned i;

    for (i = lo; i <= hi; i++) {
        if (guest_st8(ctx, pa + i, m[i]) != 0) {
            if (ctx->exit_reason == MIPS64_EXIT_NONE) {
                mips_fault(ctx, pa + i);
            }
            return MIPS_FAULT;
        }
    }
    return 0;
}

/* LWL/LWR merge rules: BE takes the right/left span into the
 * high/low half; LE mirrors the address role (32-bit E05 rules). */
int do_lwl(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t pa = addr & ~UINT64_C(3);
    unsigned k = (unsigned)(addr & UINT64_C(3));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint32_t v = (uint32_t)ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m, 4u) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = k; i < 4u; i++) {
            v = set_pos32(v, 3u - (i - k), m[i]);
        }
    } else {
        for (i = 0u; i <= k; i++) {
            v = set_pos32(v, 3u - k + i, m[i]);
        }
    }
    interp_set_reg(ctx, rt, interp_sext32(v));
    return 0;
}

int do_lwr(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t pa = addr & ~UINT64_C(3);
    unsigned k = (unsigned)(addr & UINT64_C(3));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint32_t v = (uint32_t)ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m, 4u) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            v = set_pos32(v, k - i, m[i]);
        }
    } else {
        for (i = k; i < 4u; i++) {
            v = set_pos32(v, i - k, m[i]);
        }
    }
    interp_set_reg(ctx, rt, interp_sext32(v));
    return 0;
}

/* SWL/SWR store rules mirror the loads (same rt positions). */
int do_swl(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval)
{
    uint64_t pa = addr & ~UINT64_C(3);
    unsigned k = (unsigned)(addr & UINT64_C(3));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = k; i < 4u; i++) {
            m[i] = (uint8_t)get_pos32((uint32_t)rtval, 3u - (i - k));
        }
        return store_bytes(ctx, pa, m, k, 3u);
    }
    for (i = 0u; i <= k; i++) {
        m[i] = (uint8_t)get_pos32((uint32_t)rtval, 3u - k + i);
    }
    return store_bytes(ctx, pa, m, 0u, k);
}

int do_swr(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval)
{
    uint64_t pa = addr & ~UINT64_C(3);
    unsigned k = (unsigned)(addr & UINT64_C(3));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            m[i] = (uint8_t)get_pos32((uint32_t)rtval, k - i);
        }
        return store_bytes(ctx, pa, m, 0u, k);
    }
    for (i = k; i < 4u; i++) {
        m[i] = (uint8_t)get_pos32((uint32_t)rtval, i - k);
    }
    return store_bytes(ctx, pa, m, k, 3u);
}

/* LDL/LDR merge rules (E02 tables, manual-correct on every variant):
 * LDL always takes the right span mem[addr..pa+7], LDR the left span
 * mem[pa..addr]; BE places the right span high / left span low, LE
 * mirrors the placement so the canonical (0,7) pair composes the
 * natural-endian doubleword either way. */
int do_ldl(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t pa = addr & ~UINT64_C(7);
    unsigned k = (unsigned)(addr & UINT64_C(7));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint64_t v = ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m, 8u) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = k; i < 8u; i++) {
            v = set_pos64(v, 7u - (i - k), m[i]);
        }
    } else {
        for (i = k; i < 8u; i++) {
            v = set_pos64(v, i - k, m[i]);
        }
    }
    interp_set_reg(ctx, rt, v);
    return 0;
}

int do_ldr(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t pa = addr & ~UINT64_C(7);
    unsigned k = (unsigned)(addr & UINT64_C(7));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint64_t v = ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m, 8u) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            v = set_pos64(v, k - i, m[i]);
        }
    } else {
        for (i = 0u; i <= k; i++) {
            v = set_pos64(v, 7u - (k - i), m[i]);
        }
    }
    interp_set_reg(ctx, rt, v);
    return 0;
}

/* SDL/SDR store rules mirror the loads (same rt positions). */
int do_sdl(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval)
{
    uint64_t pa = addr & ~UINT64_C(7);
    unsigned k = (unsigned)(addr & UINT64_C(7));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = k; i < 8u; i++) {
            m[i] = (uint8_t)get_pos64(rtval, 7u - (i - k));
        }
        return store_bytes(ctx, pa, m, k, 7u);
    }
    for (i = k; i < 8u; i++) {
        m[i] = (uint8_t)get_pos64(rtval, i - k);
    }
    return store_bytes(ctx, pa, m, k, 7u);
}

int do_sdr(mips64_ctx_t *ctx, uint64_t addr, uint64_t rtval)
{
    uint64_t pa = addr & ~UINT64_C(7);
    unsigned k = (unsigned)(addr & UINT64_C(7));
    uint8_t m[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            m[i] = (uint8_t)get_pos64(rtval, k - i);
        }
        return store_bytes(ctx, pa, m, 0u, k);
    }
    for (i = 0u; i <= k; i++) {
        m[i] = (uint8_t)get_pos64(rtval, 7u - (k - i));
    }
    return store_bytes(ctx, pa, m, 0u, k);
}

/* LL/SC (E05): aligned word load arms the reservation; SC commits only
 * on a live exact-address reservation. A dead reservation still faults
 * on a bad address (load side effect preserved). */
int do_ll(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t v = 0u;

    if ((addr & 3u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    if (guest_ld32(ctx, addr, &v) != 0) {
        return MIPS_FAULT;
    }
    ctx->llbit = 1;
    ctx->lladdr = addr;
    ctx->llval = (uint64_t)(uint32_t)v;
    interp_set_reg(ctx, rt, interp_sext32((uint32_t)v));
    return 0;
}

int do_sc(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t v = 0u;
    int sc_ok = 0;

    if ((addr & 3u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    if (ctx->llbit != 0u && ctx->lladdr == addr) {
        if (guest_st32(ctx, addr, ctx->gpr[rt] & 0xFFFFFFFFu) != 0) {
            return MIPS_FAULT;
        }
        sc_ok = 1;
    } else if (guest_ld32(ctx, addr, &v) != 0) {
        return MIPS_FAULT;
    }
    interp_set_reg(ctx, rt, (uint64_t)sc_ok);
    ctx->llbit = 0;
    return 0;
}

/* LLD/SCD (E05): doubleword twin of LL/SC. */
int do_lld(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t v = 0u;

    if ((addr & 7u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    if (guest_ld64(ctx, addr, &v) != 0) {
        return MIPS_FAULT;
    }
    ctx->llbit = 1;
    ctx->lladdr = addr;
    ctx->llval = v;
    interp_set_reg(ctx, rt, v);
    return 0;
}

int do_scd(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t v = 0u;
    int sc_ok = 0;

    if ((addr & 7u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    if (ctx->llbit != 0u && ctx->lladdr == addr) {
        if (guest_st64(ctx, addr, ctx->gpr[rt]) != 0) {
            return MIPS_FAULT;
        }
        sc_ok = 1;
    } else if (guest_ld64(ctx, addr, &v) != 0) {
        return MIPS_FAULT;
    }
    interp_set_reg(ctx, rt, (uint64_t)sc_ok);
    ctx->llbit = 0;
    return 0;
}

/* Local fault recorder for the dispatcher below (same trace shape as
 * interp.c so failure logs stay uniform). */
static int mem_fault_at(mips64_ctx_t *ctx, uint64_t addr)
{
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %llx at %llx\n",
                      (unsigned long long)ctx->pc,
                      (unsigned long long)addr);
    }
    mips_fault(ctx, addr);
    return MIPS_FAULT;
}

/* Aligned load/store dispatcher (LB..SD, LL/SC/LLD/SCD); unaligned
 * 16/32/64-bit accesses fault with the data address, like interp.c. */
int interp_exec_mem(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    uint64_t addr = ctx->gpr[d->rs] + (uint64_t)(int64_t)d->simm;
    uint64_t v = 0u;

    switch (d->op) {
    case 0x1Au: /* LDL */
        return do_ldl(ctx, addr, d->rt);
    case 0x1Bu: /* LDR */
        return do_ldr(ctx, addr, d->rt);
    case 0x20u: /* LB */
        /* guest_* records the fault itself; just propagate. */
        if (guest_ld8(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, (uint64_t)(int64_t)(int8_t)(v & 0xFFu));
        return 0;
    case 0x21u: /* LH */
        if ((addr & 1u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_ld16(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, (uint64_t)(int64_t)(int16_t)(v & 0xFFFFu));
        return 0;
    case 0x22u: /* LWL */
        return do_lwl(ctx, addr, d->rt);
    case 0x23u: /* LW */
        if ((addr & 3u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_ld32(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, interp_sext32((uint32_t)v));
        return 0;
    case 0x24u: /* LBU */
        if (guest_ld8(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, v & 0xFFu);
        return 0;
    case 0x25u: /* LHU */
        if ((addr & 1u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_ld16(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, v & 0xFFFFu);
        return 0;
    case 0x26u: /* LWR */
        return do_lwr(ctx, addr, d->rt);
    case 0x27u: /* LWU */
        if ((addr & 3u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_ld32(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, (uint64_t)(uint32_t)v);
        return 0;
    case 0x28u: /* SB */
        if (guest_st8(ctx, addr, ctx->gpr[d->rt] & 0xFFu) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    case 0x29u: /* SH */
        if ((addr & 1u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_st16(ctx, addr, ctx->gpr[d->rt] & 0xFFFFu) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    case 0x2Au: /* SWL */
        return do_swl(ctx, addr, ctx->gpr[d->rt]);
    case 0x2Bu: /* SW */
        if ((addr & 3u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_st32(ctx, addr, ctx->gpr[d->rt] & 0xFFFFFFFFu) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    case 0x2Cu: /* SDL */
        return do_sdl(ctx, addr, ctx->gpr[d->rt]);
    case 0x2Du: /* SDR */
        return do_sdr(ctx, addr, ctx->gpr[d->rt]);
    case 0x2Eu: /* SWR */
        return do_swr(ctx, addr, ctx->gpr[d->rt]);
    case 0x30u: /* LL */
        return do_ll(ctx, addr, d->rt);
    case 0x34u: /* LLD */
        return do_lld(ctx, addr, d->rt);
    case 0x37u: /* LD */
        if ((addr & 7u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_ld64(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, v);
        return 0;
    case 0x38u: /* SC */
        return do_sc(ctx, addr, d->rt);
    case 0x3Cu: /* SCD */
        return do_scd(ctx, addr, d->rt);
    case 0x3Fu: /* SD */
        if ((addr & 7u) != 0u) {
            return mem_fault_at(ctx, addr);
        }
        if (guest_st64(ctx, addr, ctx->gpr[d->rt]) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    default:
        return mem_fault_at(ctx, cur_pc);
    }
}
