/*
 * src/interp/interp.c — MIPS64r2 integer reference interpreter (Phase 1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Step-by-step SPEC 2 integer oracle: 32-bit ALU (E02 sign-extension),
 * 64-bit D-ops, shifts/rotates, DEXT/DINS/BSHFL, MULT/DIV via hi/lo,
 * delay-slot branches + likely-annul, SYSCALL (L1c), traps
 * (mips_fault), LWU/LD/SD, LL/SC/LLD/SCD, RDHWR/ulr, CACHE/PREF as NOP
 * (memory ops in unaligned.c, COP1 moves in fpmove.c); reg 0 stays 0.
 */

#include <stdint.h>
#include <stdio.h>

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"
#include "os/backend.h"

static int exec_branch(mips64_ctx_t *ctx, uint64_t pc, const mips_dec_t *d);
static int fault_at(mips64_ctx_t *ctx, uint64_t addr)
{
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %llx at %llx\n",
                      (unsigned long long)ctx->pc,
                      (unsigned long long)addr);
    }
    mips_fault(ctx, addr);
    return (ctx->exit_reason == MIPS64_EXIT_NONE) ? 2 : MIPS_FAULT;
}

extern void mips_insn_trap_code(mips64_ctx_t *ctx, int signo, int32_t code,
                                uint64_t addr);

static int trap_at_code(mips64_ctx_t *ctx, int signo, int32_t code,
                        uint64_t addr)
{
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %llx at %llx\n",
                      (unsigned long long)ctx->pc,
                      (unsigned long long)addr);
    }
    mips_insn_trap_code(ctx, signo, code, addr);
    return (ctx->exit_reason == MIPS64_EXIT_NONE) ? 2 : MIPS_FAULT;
}

static int trap_at(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    return trap_at_code(ctx, signo, 0, addr);
}

static int trap_code(mips64_ctx_t *ctx, uint64_t addr, const mips_dec_t *d)
{
    unsigned bcode = ((unsigned)d->uimm >> 6u) & 0x3FFu;
    int signo = (bcode == 6u || bcode == 7u) ? 8 : 5;
    int32_t scode = (bcode == 6u) ? 2 : 1;

    return trap_at_code(ctx, signo, scode, addr);
}

/* Shared COP1/COP1X result mapping: 1/2 = BC1 run-stop/pc-final. */
static int cop_rc(mips64_ctx_t *ctx, uint64_t cur_pc, int rc)
{
    if (rc == 1 || rc == 2) {
        return rc;
    }
    if (rc != 0 && ctx->exit_reason != MIPS64_EXIT_NONE) {
        return MIPS_FAULT;
    }
    return (rc != 0) ? trap_at(ctx, 4, cur_pc) : 0;
}

/* Fetch and decode the word at pc; fault when the fetcher did not. */
static int fetch_decode(mips64_ctx_t *ctx, uint64_t pc, mips_dec_t *d)
{
    uint32_t word = 0u;

    if (mips_fetch(ctx, pc, &word) != 0) {
        if (ctx->exit_reason == MIPS64_EXIT_NONE) {
            mips_fault(ctx, pc);
        }
        return MIPS_FAULT;
    }
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "I %llx %x\n", (unsigned long long)pc, word);
    }
    mips_decode(word, d);
    return 0;
}

/* SYSCALL: clears llbit; dispatcher owns $v0/$a3 writeback. Returns 0
 * (caller advances pc), 2 (dispatcher moved pc: keep it), 1 (stop). */
static int exec_syscall(mips64_ctx_t *ctx)
{
    uint64_t before = ctx->pc;
    uint64_t nr = ctx->gpr[MIPS64_REG_V0];

    ctx->llbit = 0;
    (void)mips_syscall(ctx);
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "S %llu a0=%llx a1=%llx a2=%llx -> v0=%llx a3=%llu\n",
                      (unsigned long long)nr,
                      (unsigned long long)ctx->gpr[MIPS64_REG_A0],
                      (unsigned long long)ctx->gpr[MIPS64_REG_A1],
                      (unsigned long long)ctx->gpr[MIPS64_REG_A2],
                      (unsigned long long)ctx->gpr[MIPS64_REG_V0],
                      (unsigned long long)ctx->gpr[MIPS64_REG_A3]);
    }
    if (ctx->exit_reason != MIPS64_EXIT_NONE) {
        return 1;
    }
    return (ctx->pc != before) ? 2 : 0;
}

/* Unsigned 64x64 -> 128-bit product (grade-school limbs; no __int128,
 * which -pedantic rejects). Result in *hi:*lo. */
static void mul_u64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t a0 = (uint64_t)(uint32_t)a;
    uint64_t a1 = a >> 32;
    uint64_t b0 = (uint64_t)(uint32_t)b;
    uint64_t b1 = b >> 32;
    uint64_t p0 = a0 * b0;
    uint64_t p1 = a0 * b1;
    uint64_t p2 = a1 * b0;
    uint64_t p3 = a1 * b1;
    uint64_t s = p1 + p2;
    uint64_t sc = (s < p1) ? 1u : 0u;
    uint64_t res = p0 + (s << 32);
    uint64_t c1 = (res < p0) ? 1u : 0u;

    *lo = res;
    *hi = p3 + (s >> 32) + c1 + (sc << 32);
}

/* Signed 64x64 -> 128-bit product via unsigned magnitudes. */
static void mul_s64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    int neg_a = (int64_t)a < 0;
    int neg_b = (int64_t)b < 0;
    uint64_t h;
    uint64_t l;
    mul_u64(neg_a ? (0u - a) : a, neg_b ? (0u - b) : b, &h, &l);
    if (neg_a != neg_b) {
        /* 128-bit two's-complement negate of h:l. */
        uint64_t nl = 0u - l;

        h = ~h + ((nl == 0u) ? 1u : 0u);
        l = nl;
    }
    *lo = l;
    *hi = h;
}

/* Execute one non-control instruction; callers advance ctx->pc except
 * for exec_syscall's dispatcher-moved-pc case (returns 2). */
static int exec_special(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    uint64_t rs = ctx->gpr[d->rs];
    uint64_t rt = ctx->gpr[d->rt];
    uint32_t rs32 = (uint32_t)rs;
    uint32_t rt32 = (uint32_t)rt;
    unsigned sh = d->sa & 31u;
    uint64_t out;

    switch (d->funct) {
    case 0x00u: /* SLL */
        interp_set_reg(ctx, d->rd, interp_sext32(rt32 << sh));
        return 0;
    case 0x01u: { /* MOVCI: MOVF/MOVT on FCSR cc=(rt field>>2)&7, tf=bit 0 */
        unsigned cc = ((unsigned)d->rt >> 2u) & 7u;
        unsigned tf = (unsigned)d->rt & 1u;
        uint32_t mask = (cc == 0u) ? 0x00800000u : (1u << (24u + cc));
        int cond = (((ctx->fcsr & mask) != 0u) == (tf != 0u));

        if (cond) {
            interp_set_reg(ctx, d->rd, rs);
        }
        return 0;
    }
    case 0x02u: /* SRL / ROTR (rs == 1 selects ROTR) */
        if (d->rs == 1u) {
            interp_set_reg(ctx, d->rd,
                           interp_sext32(interp_rotr32(rt32, d->sa)));
        } else {
            interp_set_reg(ctx, d->rd, interp_sext32(rt32 >> sh));
        }
        return 0;
    case 0x03u: /* SRA */
        interp_set_reg(ctx, d->rd, interp_sext32((uint32_t)((int32_t)rt32 >> sh)));
        return 0;
    case 0x04u: /* SLLV */
        interp_set_reg(ctx, d->rd, interp_sext32(rt32 << (rs & 31u)));
        return 0;
    case 0x06u: /* SRLV / RORV (sa == 1 selects RORV) */
        if (d->sa == 1u) {
            interp_set_reg(ctx, d->rd,
                           interp_sext32(interp_rotr32(rt32, rs)));
        } else {
            interp_set_reg(ctx, d->rd, interp_sext32(rt32 >> (rs & 31u)));
        }
        return 0;
    case 0x07u: /* SRAV */
        interp_set_reg(ctx, d->rd,
                       interp_sext32((uint32_t)((int32_t)rt32 >> (rs & 31u))));
        return 0;
    case 0x08u: /* JR */
    case 0x09u: /* JALR */
        return exec_branch(ctx, cur_pc, d);
    case 0x0Au: /* MOVZ */
        if (rt == 0u) { interp_set_reg(ctx, d->rd, rs); }
        return 0;
    case 0x0Bu: /* MOVN */
        if (rt != 0u) { interp_set_reg(ctx, d->rd, rs); }
        return 0;
    case 0x0Cu: /* SYSCALL */
        return exec_syscall(ctx);
    case 0x0Du: /* BREAK */ return trap_code(ctx, cur_pc, d);
    case 0x0Fu: /* SYNC */ return 0;
    case 0x10u: interp_set_reg(ctx, d->rd, ctx->hi); return 0; /* MFHI */
    case 0x11u: ctx->hi = rs; return 0; /* MTHI */
    case 0x12u: interp_set_reg(ctx, d->rd, ctx->lo); return 0; /* MFLO */
    case 0x13u: ctx->lo = rs; return 0; /* MTLO */
    case 0x14u: interp_set_reg(ctx, d->rd, rt << (rs & 63u)); return 0; /* DSLLV */
    case 0x16u: /* DSRLV / DROTRV (sa == 1 selects DROTRV) */
        interp_set_reg(ctx, d->rd, d->sa == 1u ? interp_rotr64(rt, rs) :
                       (rt >> (rs & 63u)));
        return 0;
    case 0x17u: /* DSRAV */
        interp_set_reg(ctx, d->rd, (uint64_t)((int64_t)rt >> (rs & 63u)));
        return 0;
    case 0x18u: { /* MULT: signed 32-bit product, halves sign-extended */
        uint64_t hi;
        uint64_t lo;

        mul_s64((uint64_t)(int64_t)(int32_t)rs32,
                (uint64_t)(int64_t)(int32_t)rt32, &hi, &lo);
        ctx->lo = interp_sext32((uint32_t)lo);
        ctx->hi = interp_sext32((uint32_t)(lo >> 32));
        (void)hi;
        return 0;
    }
    case 0x19u: { /* MULTU: unsigned 32-bit product, halves sign-extended */
        uint64_t hi;
        uint64_t lo;

        mul_u64((uint64_t)rs32, (uint64_t)rt32, &hi, &lo);
        ctx->lo = interp_sext32((uint32_t)lo);
        ctx->hi = interp_sext32((uint32_t)(lo >> 32));
        (void)hi;
        return 0;
    }
    case 0x1Au: /* DIV: divide-by-zero leaves hi/lo unchanged */
        if (rt32 != 0u) {
            int64_t q = (int64_t)(int32_t)rs32 / (int64_t)(int32_t)rt32;
            int64_t r = (int64_t)(int32_t)rs32 % (int64_t)(int32_t)rt32;

            ctx->lo = interp_sext32((uint32_t)q);
            ctx->hi = interp_sext32((uint32_t)r);
        }
        return 0;
    case 0x1Bu: /* DIVU: divide-by-zero leaves hi/lo unchanged */
        if (rt32 != 0u) {
            ctx->lo = interp_sext32(rs32 / rt32);
            ctx->hi = interp_sext32(rs32 % rt32);
        }
        return 0;
    case 0x1Cu: { /* DMULT: signed 128-bit product */
        uint64_t hi;
        uint64_t lo;

        mul_s64(rs, rt, &hi, &lo);
        ctx->lo = lo;
        ctx->hi = hi;
        return 0;
    }
    case 0x1Du: { /* DMULTU: unsigned 128-bit product */
        uint64_t hi;
        uint64_t lo;

        mul_u64(rs, rt, &hi, &lo);
        ctx->lo = lo;
        ctx->hi = hi;
        return 0;
    }
    case 0x1Eu: /* DDIV: zero divisor (or INT64_MIN/-1, which would be
        * UB in C) leaves hi/lo unchanged */
        if (rt != 0u && !(rs == (UINT64_C(1) << 63) && rt == UINT64_MAX)) {
            ctx->lo = (uint64_t)((int64_t)rs / (int64_t)rt);
            ctx->hi = (uint64_t)((int64_t)rs % (int64_t)rt);
        }
        return 0;
    case 0x1Fu: /* DDIVU: divide-by-zero leaves hi/lo unchanged */
        if (rt != 0u) {
            ctx->lo = rs / rt;
            ctx->hi = rs % rt;
        }
        return 0;
    case 0x20u: /* ADD (trapping) */
        out = (uint64_t)(rs32 + rt32);
        if (interp_add32_ov(rs32, rt32, (uint32_t)out)) {
            return trap_at_code(ctx, 8, 2, cur_pc);
        }
        interp_set_reg(ctx, d->rd, interp_sext32((uint32_t)out));
        return 0;
    case 0x21u: /* ADDU */
        interp_set_reg(ctx, d->rd, interp_sext32(rs32 + rt32));
        return 0;
    case 0x22u: /* SUB (trapping) */
        out = (uint64_t)(rs32 - rt32);
        if (interp_sub32_ov(rs32, rt32, (uint32_t)out)) {
            return trap_at_code(ctx, 8, 2, cur_pc);
        }
        interp_set_reg(ctx, d->rd, interp_sext32((uint32_t)out));
        return 0;
    case 0x23u: /* SUBU */
        interp_set_reg(ctx, d->rd, interp_sext32(rs32 - rt32));
        return 0;
    case 0x24u: /* AND (64-bit) */
        interp_set_reg(ctx, d->rd, rs & rt);
        return 0;
    case 0x25u: /* OR (64-bit) */
        interp_set_reg(ctx, d->rd, rs | rt);
        return 0;
    case 0x26u: /* XOR (64-bit) */
        interp_set_reg(ctx, d->rd, rs ^ rt);
        return 0;
    case 0x27u: /* NOR (64-bit) */
        interp_set_reg(ctx, d->rd, ~(rs | rt));
        return 0;
    case 0x2Au: /* SLT (signed 64-bit compare) */
        interp_set_reg(ctx, d->rd, (int64_t)rs < (int64_t)rt ? 1u : 0u);
        return 0;
    case 0x2Bu: /* SLTU (unsigned 64-bit compare) */
        interp_set_reg(ctx, d->rd, rs < rt ? 1u : 0u);
        return 0;
    case 0x2Cu: /* DADD (trapping) */
        out = rs + rt;
        if (interp_add64_ov(rs, rt, out)) {
            return trap_at_code(ctx, 8, 2, cur_pc);
        }
        interp_set_reg(ctx, d->rd, out);
        return 0;
    case 0x2Du: /* DADDU */
        interp_set_reg(ctx, d->rd, rs + rt);
        return 0;
    case 0x2Eu: /* DSUB (trapping) */
        out = rs - rt;
        if (interp_sub64_ov(rs, rt, out)) {
            return trap_at_code(ctx, 8, 2, cur_pc);
        }
        interp_set_reg(ctx, d->rd, out);
        return 0;
    case 0x2Fu: /* DSUBU */
        interp_set_reg(ctx, d->rd, rs - rt);
        return 0;
    case 0x30u: /* TGE */
        return (int64_t)rs >= (int64_t)rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x31u: /* TGEU */
        return rs >= rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x32u: /* TLT */
        return (int64_t)rs < (int64_t)rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x33u: /* TLTU */
        return rs < rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x34u: /* TEQ */
        return rs == rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x36u: /* TNE */
        return rs != rt ? trap_code(ctx, cur_pc, d) : 0;
    case 0x38u: /* DSLL */
        interp_set_reg(ctx, d->rd, rt << sh);
        return 0;
    case 0x3Au: /* DSRL / DROTR (rs == 1 selects DROTR) */
        if (d->rs == 1u) {
            interp_set_reg(ctx, d->rd, interp_rotr64(rt, d->sa));
        } else {
            interp_set_reg(ctx, d->rd, rt >> sh);
        }
        return 0;
    case 0x3Bu: /* DSRA */
        interp_set_reg(ctx, d->rd, (uint64_t)((int64_t)rt >> sh));
        return 0;
    case 0x3Cu: /* DSLL32 */
        interp_set_reg(ctx, d->rd, rt << (32u + sh));
        return 0;
    case 0x3Eu: /* DSRL32 / DROTR32 (rs == 1 selects DROTR32) */
        if (d->rs == 1u) {
            interp_set_reg(ctx, d->rd, interp_rotr64(rt, 32u + sh));
        } else {
            interp_set_reg(ctx, d->rd, rt >> (32u + sh));
        }
        return 0;
    case 0x3Fu: /* DSRA32 */
        interp_set_reg(ctx, d->rd, (uint64_t)((int64_t)rt >> (32u + sh)));
        return 0;
    default:
        return trap_at(ctx, 4, cur_pc);
    }
}

/* SPECIAL2 (major opcode 0x1C): MUL/MADD family, CLZ/CLO, DCLZ/DCLO, SDBBP. */
static int exec_special2(mips64_ctx_t *ctx, uint64_t cur_pc,
                         const mips_dec_t *d)
{
    uint64_t rs = ctx->gpr[d->rs];
    uint64_t rt = ctx->gpr[d->rt];
    uint32_t rs32 = (uint32_t)rs;
    uint32_t rt32 = (uint32_t)rt;
    uint64_t acc = ((uint64_t)(uint32_t)ctx->hi << 32) |
                   (uint64_t)(uint32_t)ctx->lo;

    switch (d->funct) {
    case 0x00u: /* MADD: signed 32-bit accumulate into hi:lo */
        acc += (uint64_t)((int64_t)(int32_t)rs32 * (int64_t)(int32_t)rt32);
        ctx->lo = interp_sext32((uint32_t)acc);
        ctx->hi = interp_sext32((uint32_t)(acc >> 32));
        return 0;
    case 0x01u: /* MADDU: unsigned 32-bit accumulate into hi:lo */
        acc += (uint64_t)rs32 * (uint64_t)rt32;
        ctx->lo = interp_sext32((uint32_t)acc);
        ctx->hi = interp_sext32((uint32_t)(acc >> 32));
        return 0;
    case 0x02u: /* MUL: low 32 bits of the product, sign-extended */
        interp_set_reg(ctx, d->rd, interp_sext32(rs32 * rt32));
        return 0;
    case 0x04u: /* MSUB: signed 32-bit subtract from hi:lo */
        acc -= (uint64_t)((int64_t)(int32_t)rs32 * (int64_t)(int32_t)rt32);
        ctx->lo = interp_sext32((uint32_t)acc);
        ctx->hi = interp_sext32((uint32_t)(acc >> 32));
        return 0;
    case 0x05u: /* MSUBU: unsigned 32-bit subtract from hi:lo */
        acc -= (uint64_t)rs32 * (uint64_t)rt32;
        ctx->lo = interp_sext32((uint32_t)acc);
        ctx->hi = interp_sext32((uint32_t)(acc >> 32));
        return 0;
    case 0x20u: /* CLZ (32-bit) */
        interp_set_reg(ctx, d->rd, interp_sext32(interp_clz32(rs32)));
        return 0;
    case 0x21u: /* CLO (32-bit) */
        interp_set_reg(ctx, d->rd, interp_sext32(interp_clz32(~rs32)));
        return 0;
    case 0x24u: /* DCLZ (64-bit) */
        interp_set_reg(ctx, d->rd, interp_clz64(rs));
        return 0;
    case 0x25u: /* DCLO (64-bit) */
        interp_set_reg(ctx, d->rd, interp_clz64(~rs));
        return 0;
    case 0x3Fu: /* SDBBP */
        return trap_at(ctx, 5, cur_pc);
    default:
        return trap_at(ctx, 4, cur_pc);
    }
}

/* EXT/DEXT/DINS/BSHFL/RDHWR (SPECIAL3, major opcode 0x1F). */
static int exec_special3(mips64_ctx_t *ctx, uint64_t cur_pc,
                         const mips_dec_t *d)
{
    uint64_t rs = ctx->gpr[d->rs];
    uint64_t rt = ctx->gpr[d->rt];

    switch (d->funct) {
    case 0x00u: { /* EXT rt, rs, pos, size (size = rd + 1) */
        unsigned pos = d->sa & 31u;
        unsigned size = (unsigned)d->rd + 1u;
        uint32_t mask = (size >= 32u) ? 0xFFFFFFFFu :
                                          (uint32_t)(((1u << size) - 1u));

        interp_set_reg(ctx, d->rt,
                       interp_sext32((uint32_t)((uint64_t)(rs >> pos) & mask)));
        return 0;
    }
    case 0x01u: { /* DEXTM: pos = sa (0..31), size = rd + 33 (33..64) */
        unsigned pos = d->sa & 31u;
        unsigned size = (unsigned)d->rd + 33u;
        uint64_t mask = (size >= 64u) ? UINT64_MAX :
                                          ((UINT64_C(1) << size) - 1u);

        interp_set_reg(ctx, d->rt, (rs >> pos) & mask);
        return 0;
    }
    case 0x02u: /* DEXTU: pos = sa + 32, size = rd + 1 */
    case 0x03u: { /* DEXT: pos = sa, size = rd + 1 */
        unsigned pos = (d->sa & 31u) + ((d->funct == 0x02u) ? 32u : 0u);
        unsigned size = (unsigned)d->rd + 1u;
        uint64_t mask = (size >= 32u) ? UINT64_C(0xFFFFFFFF) :
                                          ((UINT64_C(1) << size) - 1u);

        interp_set_reg(ctx, d->rt, (rs >> pos) & mask);
        return 0;
    }
    case 0x04u: { /* INS rt, rs, pos, msb (32-bit, result sign-extended) */
        unsigned pos = d->sa & 31u;
        unsigned msb = d->rd & 31u;

        if (msb < pos) {
            return trap_at(ctx, 4, cur_pc);
        } else {
            unsigned size = msb - pos + 1u;
            uint64_t mask = (size >= 32u) ? UINT64_C(0xFFFFFFFF) :
                                              ((UINT64_C(1) << size) - 1u);
            uint64_t field = (rs << pos) & (mask << pos);
            uint32_t out = (uint32_t)((rt & ~(mask << pos)) | field);

            interp_set_reg(ctx, d->rt, interp_sext32(out));
            return 0;
        }
    }
    case 0x05u: /* DINSM: pos = sa (0..31), msb = rd + 32 (32..63) */
    case 0x06u: /* DINSU: pos = sa + 32, msb = rd + 32 (32..63) */
    case 0x07u: { /* DINS: pos = sa, msb = rd (0..31) */
        unsigned pos = (d->sa & 31u) + ((d->funct == 0x06u) ? 32u : 0u);
        unsigned msb = (d->rd & 31u) + ((d->funct == 0x07u) ? 0u : 32u);

        if (msb < pos) {
            return trap_at(ctx, 4, cur_pc);
        } else {
            unsigned size = msb - pos + 1u;
            uint64_t mask = (size >= 64u) ? UINT64_MAX :
                                              ((UINT64_C(1) << size) - 1u);
            uint64_t field = (rs << pos) & (mask << pos);

            interp_set_reg(ctx, d->rt, (rt & ~(mask << pos)) | field);
            return 0;
        }
    }
    case 0x20u: /* BSHFL: source is rt (rs is unused, always $0). */
        switch (d->sa) {
        case 2u: /* WSBH: swap bytes within each halfword of low word */
            interp_set_reg(ctx, d->rd,
                           interp_sext32(((rt & 0x00FF00FFu) << 8) |
                                         ((rt & 0xFF00FF00u) >> 8)));
            return 0;
        case 16u: /* SEB */
            interp_set_reg(ctx, d->rd,
                           (uint64_t)(int64_t)(int8_t)(rt & 0xFFu));
            return 0;
        case 24u: /* SEH */
            interp_set_reg(ctx, d->rd,
                           (uint64_t)(int64_t)(int16_t)(rt & 0xFFFFu));
            return 0;
        default:
            return trap_at(ctx, 4, cur_pc);
        }
    case 0x24u: /* DSBH/DSHD: source is rt (rs is unused, always $0). */
        switch (d->sa) {
        case 2u: { /* DSBH: swap bytes within each halfword */
            uint64_t v = rt;
            uint64_t out = 0u;
            unsigned h;

            for (h = 0u; h < 4u; h++) {
                unsigned b = h * 16u;

                out |= ((v >> (b + 8u)) & 0xFFu) << b;
                out |= ((v >> b) & 0xFFu) << (b + 8u);
            }
            interp_set_reg(ctx, d->rd, out);
            return 0;
        }
        case 5u: /* DSHD: mirror halfword order across the doubleword */
            interp_set_reg(ctx, d->rd,
                           ((rt & UINT64_C(0xFFFF)) << 48) |
                               ((rt & UINT64_C(0xFFFF0000)) << 16) |
                               ((rt >> 16) & UINT64_C(0xFFFF0000)) |
                               ((rt >> 48) & UINT64_C(0xFFFF)));
            return 0;
        default:
            return trap_at(ctx, 4, cur_pc);
        }
    case 0x3Bu: /* RDHWR rt, rd: rd selects, rt receives (MIPS64R2). */
        if (d->rd != MIPS64_RDHWR_ULR) {
            return trap_at(ctx, 4, cur_pc);
        }
        interp_set_reg(ctx, d->rt, ctx->ulr);
        return 0;
    default:
        return trap_at(ctx, 4, cur_pc);
    }
}

static int exec_regimm_trap(mips64_ctx_t *ctx, uint64_t cur_pc,
                            const mips_dec_t *d)
{
    uint64_t rs = ctx->gpr[d->rs];
    int64_t imm = (int64_t)d->simm;
    int fire = 0;

    switch (d->rt) {
    case 0x08u: /* TGEI */
        fire = (int64_t)rs >= imm;
        break;
    case 0x09u: /* TGEIU */
        fire = rs >= (uint64_t)imm;
        break;
    case 0x0Au: /* TLTI */
        fire = (int64_t)rs < imm;
        break;
    case 0x0Bu: /* TLTIU */
        fire = rs < (uint64_t)imm;
        break;
    case 0x0Cu: /* TEQI */
        fire = (int64_t)rs == imm;
        break;
    case 0x0Eu: /* TNEI */
        fire = (int64_t)rs != imm;
        break;
    case 0x1Fu: /* SYNCI: no translated code exists in Phase 1 -> NOP */
        return 0;
    default:
        return trap_at(ctx, 4, cur_pc);
    }
    return fire ? trap_at(ctx, 5, cur_pc) : 0;
}

static int exec_simple(mips64_ctx_t *ctx, uint64_t cur_pc, const mips_dec_t *d)
{
    switch (d->op) {
    case 0x00u: /* SPECIAL */
        return exec_special(ctx, cur_pc, d);
    case 0x01u: /* REGIMM traps / SYNCI (branches never reach here) */
        return exec_regimm_trap(ctx, cur_pc, d);
    case 0x08u: /* ADDI (trapping) */
        {
            uint32_t rs = (uint32_t)ctx->gpr[d->rs];
            uint32_t out = rs + (uint32_t)d->simm;

            if (interp_add32_ov(rs, (uint32_t)d->simm, out)) {
                return trap_at_code(ctx, 8, 2, cur_pc);
            }
            interp_set_reg(ctx, d->rt, interp_sext32(out));
            return 0;
        }
    case 0x09u: /* ADDIU */
        interp_set_reg(ctx, d->rt,
                       interp_sext32((uint32_t)ctx->gpr[d->rs] +
                                     (uint32_t)d->simm));
        return 0;
    case 0x0Au: /* SLTI (signed 64-bit) */
        interp_set_reg(ctx, d->rt,
                       (int64_t)ctx->gpr[d->rs] < (int64_t)d->simm ? 1u : 0u);
        return 0;
    case 0x0Bu: /* SLTIU (unsigned 64-bit vs sign-extended imm) */
        interp_set_reg(ctx, d->rt,
                       ctx->gpr[d->rs] < (uint64_t)(int64_t)d->simm ? 1u : 0u);
        return 0;
    case 0x0Cu: /* ANDI: rs AND zero-extended imm (clears high bits) */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] & (uint64_t)d->uimm);
        return 0;
    case 0x0Du: /* ORI: rs OR zero-extended imm (preserves high bits) */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] | (uint64_t)d->uimm);
        return 0;
    case 0x0Eu: /* XORI: rs XOR zero-extended imm (preserves high bits) */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] ^ (uint64_t)d->uimm);
        return 0;
    case 0x0Fu: /* LUI */
        interp_set_reg(ctx, d->rt, interp_sext32(d->uimm << 16));
        return 0;
    case 0x10u: /* COP0: ulr-alias moves via fpmove.c, rest faults */
        if (fpmove_cop0(ctx, d) != 0) {
            return trap_at(ctx, 4, cur_pc);
        }
        return 0;
    case 0x18u: /* DADDI (trapping) */
        {
            uint64_t out = ctx->gpr[d->rs] + (uint64_t)(int64_t)d->simm;

            if (interp_add64_ov(ctx->gpr[d->rs], (uint64_t)(int64_t)d->simm,
                                out)) {
                return trap_at_code(ctx, 8, 2, cur_pc);
            }
            interp_set_reg(ctx, d->rt, out);
            return 0;
        }
    case 0x19u: /* DADDIU */
        interp_set_reg(ctx, d->rt,
                       ctx->gpr[d->rs] + (uint64_t)(int64_t)d->simm);
        return 0;
    case 0x1Cu: /* SPECIAL2 */
        return exec_special2(ctx, cur_pc, d);
    case 0x1Fu: /* SPECIAL3 */
        return exec_special3(ctx, cur_pc, d);
    case 0x1Au: /* LDL */
    case 0x1Bu: /* LDR */
    case 0x20u: /* LB */
    case 0x21u: /* LH */
    case 0x22u: /* LWL */
    case 0x23u: /* LW */
    case 0x24u: /* LBU */
    case 0x25u: /* LHU */
    case 0x26u: /* LWR */
    case 0x27u: /* LWU */
    case 0x28u: /* SB */
    case 0x29u: /* SH */
    case 0x2Au: /* SWL */
    case 0x2Bu: /* SW */
    case 0x2Cu: /* SDL */
    case 0x2Du: /* SDR */
    case 0x2Eu: /* SWR */
    case 0x30u: /* LL */
    case 0x34u: /* LLD */
    case 0x37u: /* LD */
    case 0x38u: /* SC */
    case 0x3Cu: /* SCD */
    case 0x3Fu: /* SD */
        return interp_exec_mem(ctx, cur_pc, d);
    case 0x31u: /* LWC1 */
    case 0x35u: /* LDC1 */
    case 0x39u: /* SWC1 */
    case 0x3Du: /* SDC1 */
        /* fpmove_mem records mapping faults itself; just propagate. */
        return fpmove_mem(ctx, d);
    case 0x11u: /* COP1 via fpmove.c+fp.c (1/2 = BC1 run-stop/pc-final) */
        return cop_rc(ctx, cur_pc, fpmove_cop1(ctx, d));
    case 0x13u: /* COP1X fused multiply-add (fp_ps.c) */
        return cop_rc(ctx, cur_pc, fp_cop1x(ctx, cur_pc, d));
    case 0x2Fu: /* CACHE */
    case 0x33u: /* PREF */
        return 0;
    default: /* COP2, MIPS64-only, reserved (COP1X handled above) */
        return trap_at(ctx, 4, cur_pc);
    }
}

/* Delay slot: link (ra = pc+8) first; likely-not-taken annuls the slot
 * with no fetch and no fault, else the slot runs with in_delay_slot = 1
 * and a fault there keeps pc at the slot (SPEC 2.2). A branch in the
 * slot is undefined; the inner one wins. The interp always steps one
 * instruction at a time (no block formation in Phase 1). */
static int exec_branch(mips64_ctx_t *ctx, uint64_t pc, const mips_dec_t *d)
{
    uint64_t rs = ctx->gpr[d->rs];
    uint64_t rt = ctx->gpr[d->rt];
    uint64_t off = (uint64_t)((int64_t)d->simm * 4);
    uint64_t target = pc + 8u;
    unsigned link_rd = MIPS64_REG_RA;
    int link = 0;
    int likely = 0;
    int taken = 0;

    switch (d->op) {
    case 0x02u: /* J */
    case 0x03u: /* JAL */
        taken = 1;
        link = (d->op == 0x03u);
        target = ((pc + 4u) & ~UINT64_C(0xFFFFFFF)) |
            ((uint64_t)d->target << 2);
        break;
    case 0x04u: /* BEQ */
    case 0x05u: /* BNE */
        taken = (d->op == 0x04u) ? (rs == rt) : (rs != rt);
        target = pc + 4u + off;
        break;
    case 0x06u: /* BLEZ */
    case 0x07u: /* BGTZ */
        taken = (d->op == 0x06u) ? ((int64_t)rs <= 0) : ((int64_t)rs > 0);
        target = pc + 4u + off;
        break;
    case 0x14u: /* BEQL */
    case 0x15u: /* BNEL */
        likely = 1;
        taken = (d->op == 0x14u) ? (rs == rt) : (rs != rt);
        target = pc + 4u + off;
        break;
    case 0x16u: /* BLEZL */
    case 0x17u: /* BGTZL */
        likely = 1;
        taken = (d->op == 0x16u) ? ((int64_t)rs <= 0) : ((int64_t)rs > 0);
        target = pc + 4u + off;
        break;
    case 0x01u: /* REGIMM */
        target = pc + 4u + off;
        switch (d->rt) {
        case 0x00u: taken = (int64_t)rs < 0; break;  /* BLTZ */
        case 0x01u: taken = (int64_t)rs >= 0; break; /* BGEZ */
        case 0x02u: likely = 1; taken = (int64_t)rs < 0; break;  /* BLTZL */
        case 0x03u: likely = 1; taken = (int64_t)rs >= 0; break; /* BGEZL */
        case 0x10u: link = 1; taken = (int64_t)rs < 0; break;    /* BLTZAL */
        case 0x11u: link = 1; taken = (int64_t)rs >= 0; break;   /* BGEZAL */
        case 0x12u: link = 1; likely = 1; taken = (int64_t)rs < 0; break;
        case 0x13u: link = 1; likely = 1; taken = (int64_t)rs >= 0; break;
        default:
            return trap_at(ctx, 4, pc);
        }
        break;
    case 0x00u: /* JR / JALR */
        taken = 1;
        target = rs;
        if ((target & 3u) != 0u) {
            return fault_at(ctx, target);
        }
        if (d->funct == 0x09u) {
            link = 1;
            link_rd = d->rd;
        } else if (d->funct != 0x08u) {
            return trap_at(ctx, 4, pc);
        }
        break;
    default:
        return trap_at(ctx, 4, pc);
    }

    if (link) {
        interp_set_reg(ctx, link_rd, pc + 8u);
    }
    if (likely && !taken) {
        ctx->in_delay_slot = 0;
        ctx->pc = pc + 8u;
        ctx->next_pc = pc + 12u;
        return 0;
    }
    ctx->in_delay_slot = 1;
    ctx->pc = pc + 4u;
    {
        mips_dec_t s;
        int rc;

        if (fetch_decode(ctx, pc + 4u, &s) != 0) {
            return MIPS_FAULT;
        }
        if (interp_is_control(&s)) {
            return exec_branch(ctx, pc + 4u, &s);
        }
        rc = exec_simple(ctx, pc + 4u, &s);
        if (rc == 0) {
            ctx->in_delay_slot = 0;
            ctx->pc = taken ? target : pc + 8u;
            ctx->next_pc = ctx->pc + 4u;
        } else if (rc == 2) {
            ctx->in_delay_slot = 0;
            rc = 0;
        } else if (rc == MIPS_FAULT && ctx->exit_reason == MIPS64_EXIT_NONE) {
            ctx->in_delay_slot = 0;
        }
        return rc;
    }
}

int interp_step(mips64_ctx_t *ctx)
{
    uint64_t pc = ctx->pc;
    mips_dec_t d;
    int rc = fetch_decode(ctx, pc, &d);

    if (rc == 0 && interp_is_control(&d)) {
        rc = exec_branch(ctx, pc, &d);
    } else if (rc == 0) {
        rc = exec_simple(ctx, pc, &d);
        if (rc == 0) {
            ctx->pc = pc + 4u;
            ctx->next_pc = pc + 8u;
        } else if (rc == 2) {
            ctx->next_pc = ctx->pc + 4u;
            rc = 0;
        }
    }
    if (rc == MIPS_FAULT && ctx->exit_reason == MIPS64_EXIT_NONE &&
        ctx->pc != pc) {
        ctx->next_pc = ctx->pc + 4u;
        rc = 0;
    }
    if (rc == 0 && ctx->exit_reason != MIPS64_EXIT_NONE) {
        rc = 1;
    }
    return rc;
}

extern void mips64_difftest_checkpoint(const mips64_ctx_t *ctx);

int interp_run(mips64_ctx_t *ctx)
{
    for (;;) {
        int rc = interp_step(ctx);

        if (rc != 0) {
            return rc;
        }
        mips64_difftest_checkpoint(ctx);
    }
}
