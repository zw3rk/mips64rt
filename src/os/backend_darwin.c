/*
 * src/os/backend_darwin.c — Darwin host backend + U0 gate registry.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Implements src/os/backend.h on Darwin (Apple Silicon): the U0
 * gate state (fixade flag default 1, delay-slot target, 4096-entry
 * 32-byte soft-TLB) lives in a small process-wide registry keyed by
 * `mips64_ctx_t *` so the frozen cpu.h layout is never touched.
 * Pure C11 + pthread mutex; no Linux-only calls, so the same logic
 * compiles under the aarch64-musl cross compiler and natively.
 */

#include "os/backend.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define U0_MAX_SLOTS 16u

typedef struct {
    const mips64_ctx_t *key;
    int used;
    int fixade;
    int has_target;
    uint64_t target;
    mips_soft_tlb_entry_t tlb[MIPS64_SOFT_TLB_ENTRIES];
} u0_slot_t;

static u0_slot_t u0_slots[U0_MAX_SLOTS];
static pthread_mutex_t u0_mu = PTHREAD_MUTEX_INITIALIZER;

static void u0_invalidate(mips_soft_tlb_entry_t *tlb)
{
    size_t i;

    for (i = 0; i < MIPS64_SOFT_TLB_ENTRIES; i++) {
        tlb[i].read_tag = UINT64_MAX;
        tlb[i].addend = 0U;
        tlb[i].write_tag = UINT64_MAX;
        tlb[i].flags_reserved = 0U;
    }
}

/* Find or claim the slot for ctx; NULL ctx yields NULL. New slots
 * start with fixade enabled (MIPS_FIXADE_DEFAULT), no target, and
 * an invalidated TLB. */
static u0_slot_t *u0_slot_for(const mips64_ctx_t *ctx, int create)
{
    size_t i;
    u0_slot_t *free_slot = NULL;

    if (ctx == NULL) {
        return NULL;
    }
    (void)pthread_mutex_lock(&u0_mu);
    for (i = 0; i < U0_MAX_SLOTS; i++) {
        if (u0_slots[i].used && u0_slots[i].key == ctx) {
            (void)pthread_mutex_unlock(&u0_mu);
            return &u0_slots[i];
        }
        if (!u0_slots[i].used && free_slot == NULL) {
            free_slot = &u0_slots[i];
        }
    }
    if (create && free_slot != NULL) {
        free_slot->used = 1;
        free_slot->key = ctx;
        free_slot->fixade = MIPS_FIXADE_DEFAULT;
        free_slot->has_target = 0;
        free_slot->target = 0U;
        u0_invalidate(free_slot->tlb);
    }
    (void)pthread_mutex_unlock(&u0_mu);
    return (create != 0) ? free_slot : NULL;
}

const char *mips_backend_name(void)
{
    return "darwin";
}

int mips_fixade_enabled(const mips64_ctx_t *ctx)
{
    u0_slot_t *s = u0_slot_for(ctx, 0);

    return (s != NULL) ? s->fixade : MIPS_FIXADE_DEFAULT;
}

void mips_fixade_set(mips64_ctx_t *ctx, int on)
{
    u0_slot_t *s = u0_slot_for(ctx, 1);

    if (s != NULL) {
        (void)pthread_mutex_lock(&u0_mu);
        s->fixade = (on != 0) ? 1 : 0;
        (void)pthread_mutex_unlock(&u0_mu);
    }
}

int mips_fixade_ctl(mips64_ctx_t *ctx, unsigned long cmd, unsigned long arg)
{
    if (ctx == NULL || cmd != (unsigned long)MIPS_SYS_MIPS_FIXADE) {
        return MIPS_FAULT;
    }
    mips_fixade_set(ctx, (arg != 0UL) ? 1 : 0);
    return 0;
}

void mips_bus_fault(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t before;

    if (ctx == NULL) {
        return;
    }
    ctx->llbit = 0U; /* fault clears the reservation, like mips_fault */
    before = ctx->pc;
    /* Guest SIGBUS (10, MIPS UAPI); the frozen trap assigns si_code
     * 1, the BUS_ADRALN family value — never SIGSEGV. */
    mips_trap(ctx, (int)MIPS64_SIGBUS, addr);
    if (ctx->pc != before) {
        ctx->exit_reason = MIPS64_EXIT_NONE;
        ctx->exit_info = 0U;
        return;
    }
    ctx->exit_reason = MIPS64_EXIT_FAULT;
    ctx->exit_info = (uint32_t)addr;
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "B %llx bus-addr %llx\n",
                      (unsigned long long)ctx->pc,
                      (unsigned long long)addr);
    }
}

void mips_delay_target_set(mips64_ctx_t *ctx, uint64_t va)
{
    u0_slot_t *s = u0_slot_for(ctx, 1);

    if (s != NULL) {
        (void)pthread_mutex_lock(&u0_mu);
        s->has_target = 1;
        s->target = va;
        (void)pthread_mutex_unlock(&u0_mu);
    }
}

int mips_delay_target_get(const mips64_ctx_t *ctx, uint64_t *va)
{
    u0_slot_t *s = u0_slot_for(ctx, 0);

    if (s == NULL || va == NULL) {
        return 0;
    }
    (void)pthread_mutex_lock(&u0_mu);
    if (s->has_target == 0) {
        (void)pthread_mutex_unlock(&u0_mu);
        return 0;
    }
    *va = s->target;
    (void)pthread_mutex_unlock(&u0_mu);
    return 1;
}

void mips_delay_target_clear(mips64_ctx_t *ctx)
{
    u0_slot_t *s = u0_slot_for(ctx, 0);

    if (s != NULL) {
        (void)pthread_mutex_lock(&u0_mu);
        s->has_target = 0;
        s->target = 0U;
        (void)pthread_mutex_unlock(&u0_mu);
    }
}

int mips_npc_mode(const mips64_ctx_t *ctx)
{
    uint64_t va = 0U;

    if (ctx == NULL || mips_delay_target_get(ctx, &va) == 0) {
        return MIPS_NPC_STATIC;
    }
    return MIPS_NPC_DYNAMIC_CTX;
}

void *mips_soft_tlb_base(mips64_ctx_t *ctx)
{
    u0_slot_t *s = u0_slot_for(ctx, 1);

    return (s != NULL) ? (void *)&s->tlb[0] : NULL;
}

void mips_soft_tlb_fill(mips64_ctx_t *ctx, uint64_t va)
{
    u0_slot_t *s;
    uint64_t vpn;
    uint64_t page;
    mips_soft_tlb_entry_t *e;

    if (ctx == NULL) {
        return;
    }
    s = u0_slot_for(ctx, 1);
    if (s == NULL) {
        return;
    }
    vpn = va >> 12;
    page = vpn << 12;
    e = &s->tlb[vpn & MIPS64_SOFT_TLB_INDEX_MASK];
    (void)pthread_mutex_lock(&u0_mu);
    /* The write gate fires here: write_tag is populated only for
     * region-writable pages that also pass the page-state gate (no
     * COW-clean/file page, no translated code, no LL reservation).
     * The page-state restrictions land with the Provider A wiring;
     * until then the region prot decides. */
    if (mips_mem_ok(ctx, page, 4096U, (uint32_t)MIPS_PROT_READ)) {
        e->read_tag = page;
        e->addend = (uintptr_t)ctx->guest_base;
    } else {
        e->read_tag = UINT64_MAX;
        e->addend = 0U;
    }
    if (mips_mem_ok(ctx, page, 4096U, (uint32_t)MIPS_PROT_WRITE)) {
        e->write_tag = page;
    } else {
        e->write_tag = UINT64_MAX;
    }
    e->flags_reserved = 0U;
    (void)pthread_mutex_unlock(&u0_mu);
}

void mips_soft_tlb_invalidate(mips64_ctx_t *ctx)
{
    u0_slot_t *s = u0_slot_for(ctx, 0);

    if (s != NULL) {
        (void)pthread_mutex_lock(&u0_mu);
        u0_invalidate(s->tlb);
        (void)pthread_mutex_unlock(&u0_mu);
    }
}

void mips_soft_tlb_invalidate_all(void)
{
    size_t i;

    (void)pthread_mutex_lock(&u0_mu);
    for (i = 0; i < U0_MAX_SLOTS; i++) {
        if (u0_slots[i].used) {
            u0_invalidate(u0_slots[i].tlb);
        }
    }
    (void)pthread_mutex_unlock(&u0_mu);
}

void mips_backend_state_reset(mips64_ctx_t *ctx)
{
    u0_slot_t *s = u0_slot_for(ctx, 1);

    if (s != NULL) {
        (void)pthread_mutex_lock(&u0_mu);
        s->fixade = MIPS_FIXADE_DEFAULT;
        s->has_target = 0;
        s->target = 0U;
        u0_invalidate(s->tlb);
        (void)pthread_mutex_unlock(&u0_mu);
    }
}
