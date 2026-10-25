/*
 * src/os/mem.c — Guest memory window + endianness-aware accessors (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 reservation model (phase-1 lane card): guest_mem_init reserves
 * task_size bytes of host VA (PROT_NONE, MAP_NORESERVE) at any host
 * address and records guest_base; guest mappings are placed MAP_FIXED
 * inside it so guest_base + va is the host address. N64 task_size is
 * 1ULL<<40, N32 task_size is 0x7fff8000 (selected by ctx->is_n32).
 * Coverage is tracked in the process-global table in mem_table.c
 * (per-context copies go stale at clone, so they are not consulted).
 *
 * Endianness (mips_is_be): bytes are assembled explicitly so the code is
 * host-endian independent. guest_ld/st16/32/64 are aligned-only and
 * report MIPS_FAULT on a misaligned address; unaligned pairs compose via
 * guest_ld/st8 (lane L1b). Accesses outside recorded regions (or with
 * insufficient permission) report MIPS_FAULT via mips_fault, which
 * records EXIT_FAULT and stashes the fault address in exit_info.
 * 64-bit guest VAs are never truncated.
 *
 * W^X: host PROT_EXEC is never granted; the interpreter fetches via
 * mips64_guest_ptr and never executes host-side.
 */

#include "core/cpu.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Synchronous fault: records EXIT_FAULT, after an RC4 signal-delivery
 * attempt. Every execution fault traps SIGSEGV (11, identical on MIPS
 * and asm-generic) with the full 64-bit VA; mips_trap delivers
 * immediately to a live unblocked handler (frame built, pc at the
 * handler). Delivery is observed as the trap moving pc: the fatal
 * record is then skipped so both engines resume in the handler.
 * Faults with no handler (all Phase 1/2 gates) record exactly as
 * before. The trap owns delivery here (never raise a second time:
 * the first delivery blocks the signal, so a re-raise would nest a
 * bogus second frame and then overwrite the record with FAULT). */
void mips_fault(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t before;

    if (ctx == NULL) {
        return;
    }
    ctx->llbit = 0U; /* SPEC 2.2: any helper exit clears the LL bit */
    before = ctx->pc;
    mips_trap(ctx, 11, addr);
    if (ctx->pc != before) {
        ctx->exit_reason = MIPS64_EXIT_NONE;
        ctx->exit_info = 0U;
        return;
    }
    ctx->exit_reason = MIPS64_EXIT_FAULT;
    ctx->exit_info = (uint32_t)addr;
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %llx fault-addr %llx\n",
                      (unsigned long long)ctx->pc,
                      (unsigned long long)addr);
    }
}

int guest_ld8(mips64_ctx_t *ctx, uint64_t va, uint64_t *out)
{
    uint8_t b;

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 1U, MIPS_PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(&b, mips64_guest_ptr(ctx, va), 1U);
    *out = (uint64_t)b;
    return 0;
}

int guest_st8(mips64_ctx_t *ctx, uint64_t va, uint64_t val)
{
    uint8_t b;

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 1U, MIPS_PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    b = (uint8_t)(val & 0xFFU);
    memcpy(mips64_guest_ptr(ctx, va), &b, 1U);
    ctx->llbit = 0U; /* E05: any ordinary store clears the reservation */
    return 0;
}

int guest_ld16(mips64_ctx_t *ctx, uint64_t va, uint64_t *out)
{
    uint8_t b[2];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 1U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 2U, MIPS_PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(b, mips64_guest_ptr(ctx, va), 2U);
    if (mips_is_be(ctx)) {
        *out = ((uint64_t)b[0] << 8) | (uint64_t)b[1];
    } else {
        *out = (uint64_t)b[0] | ((uint64_t)b[1] << 8);
    }
    return 0;
}

int guest_st16(mips64_ctx_t *ctx, uint64_t va, uint64_t val)
{
    uint8_t b[2];

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 1U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 2U, MIPS_PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        b[0] = (uint8_t)((val >> 8) & 0xFFU);
        b[1] = (uint8_t)(val & 0xFFU);
    } else {
        b[0] = (uint8_t)(val & 0xFFU);
        b[1] = (uint8_t)((val >> 8) & 0xFFU);
    }
    memcpy(mips64_guest_ptr(ctx, va), b, 2U);
    ctx->llbit = 0U; /* E05: any ordinary store clears the reservation */
    return 0;
}

int guest_ld32(mips64_ctx_t *ctx, uint64_t va, uint64_t *out)
{
    uint8_t b[4];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 4U, MIPS_PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(b, mips64_guest_ptr(ctx, va), 4U);
    if (mips_is_be(ctx)) {
        *out = ((uint64_t)b[0] << 24) | ((uint64_t)b[1] << 16) |
               ((uint64_t)b[2] << 8) | (uint64_t)b[3];
    } else {
        *out = (uint64_t)b[0] | ((uint64_t)b[1] << 8) |
               ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24);
    }
    return 0;
}

int guest_st32(mips64_ctx_t *ctx, uint64_t va, uint64_t val)
{
    uint8_t b[4];

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 4U, MIPS_PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        b[0] = (uint8_t)((val >> 24) & 0xFFU);
        b[1] = (uint8_t)((val >> 16) & 0xFFU);
        b[2] = (uint8_t)((val >> 8) & 0xFFU);
        b[3] = (uint8_t)(val & 0xFFU);
    } else {
        b[0] = (uint8_t)(val & 0xFFU);
        b[1] = (uint8_t)((val >> 8) & 0xFFU);
        b[2] = (uint8_t)((val >> 16) & 0xFFU);
        b[3] = (uint8_t)((val >> 24) & 0xFFU);
    }
    memcpy(mips64_guest_ptr(ctx, va), b, 4U);
    ctx->llbit = 0U; /* E05: any ordinary store clears the reservation */
    return 0;
}

int guest_ld64(mips64_ctx_t *ctx, uint64_t va, uint64_t *out)
{
    uint8_t b[8];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 7U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 8U, MIPS_PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(b, mips64_guest_ptr(ctx, va), 8U);
    if (mips_is_be(ctx)) {
        *out = ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
               ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
               ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
               ((uint64_t)b[6] << 8) | (uint64_t)b[7];
    } else {
        *out = (uint64_t)b[0] | ((uint64_t)b[1] << 8) |
               ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
               ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
               ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
    }
    return 0;
}

int guest_st64(mips64_ctx_t *ctx, uint64_t va, uint64_t val)
{
    uint8_t b[8];

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 7U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!mips_mem_ok(ctx, va, 8U, MIPS_PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        b[0] = (uint8_t)((val >> 56) & 0xFFU);
        b[1] = (uint8_t)((val >> 48) & 0xFFU);
        b[2] = (uint8_t)((val >> 40) & 0xFFU);
        b[3] = (uint8_t)((val >> 32) & 0xFFU);
        b[4] = (uint8_t)((val >> 24) & 0xFFU);
        b[5] = (uint8_t)((val >> 16) & 0xFFU);
        b[6] = (uint8_t)((val >> 8) & 0xFFU);
        b[7] = (uint8_t)(val & 0xFFU);
    } else {
        b[0] = (uint8_t)(val & 0xFFU);
        b[1] = (uint8_t)((val >> 8) & 0xFFU);
        b[2] = (uint8_t)((val >> 16) & 0xFFU);
        b[3] = (uint8_t)((val >> 24) & 0xFFU);
        b[4] = (uint8_t)((val >> 32) & 0xFFU);
        b[5] = (uint8_t)((val >> 40) & 0xFFU);
        b[6] = (uint8_t)((val >> 48) & 0xFFU);
        b[7] = (uint8_t)((val >> 56) & 0xFFU);
    }
    memcpy(mips64_guest_ptr(ctx, va), b, 8U);
    ctx->llbit = 0U; /* E05: any ordinary store clears the reservation */
    return 0;
}
