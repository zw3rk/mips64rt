/*
 * src/os/backend_state.c — Shared U0 slot registry, TIF_FIXADE state,
 * delay-slot NPC target, and 4096-entry Soft-TLB management.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "os/backend.h"
#include "os/quiesce.h"
#include "vm/vm_pages.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr);
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

#ifndef MIPS_PROT_READ
#define MIPS_PROT_READ 1U
#define MIPS_PROT_WRITE 2U
#endif

/* Covers the main thread plus L4B_THREAD_MAX (128) worker threads
 * and unit-test contexts. */
#define U0_MAX_SLOTS 160u

typedef struct {
    const mips64_ctx_t *ctx;
    int fixade;
    int has_delay;
    uint64_t delay_target;
    mips_soft_tlb_entry_t tlb[MIPS64_SOFT_TLB_ENTRIES]
        __attribute__((aligned(32)));
} u0_slot_t;

static u0_slot_t u0_slots[U0_MAX_SLOTS];
static mips_soft_tlb_entry_t u0_fallback_tlb[MIPS64_SOFT_TLB_ENTRIES]
    __attribute__((aligned(32)));
static int u0_inited = 0;
static pthread_mutex_t u0_mu = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int u0_preempt_depth;
static _Thread_local sigset_t u0_preempt_saved;

static void u0_lock(void)
{
    if (u0_preempt_depth == 0) {
        mips_qs_block_preempt(&u0_preempt_saved);
    }
    u0_preempt_depth++;
    (void)pthread_mutex_lock(&u0_mu);
}

static void u0_unlock(void)
{
    (void)pthread_mutex_unlock(&u0_mu);
    u0_preempt_depth--;
    if (u0_preempt_depth == 0) {
        mips_qs_unblock_preempt(&u0_preempt_saved);
    }
}

static void u0_invalidate_entries(mips_soft_tlb_entry_t *e)
{
    size_t i;

    for (i = 0; i < (size_t)MIPS64_SOFT_TLB_ENTRIES; i++) {
        e[i].read_tag = UINT64_MAX;
        e[i].addend = 0U;
        e[i].write_tag = UINT64_MAX;
        e[i].flags_reserved = 0U;
    }
}

static void u0_init_locked(void)
{
    size_t i;

    if (u0_inited != 0) {
        return;
    }
    for (i = 0; i < (size_t)U0_MAX_SLOTS; i++) {
        u0_slots[i].ctx = NULL;
        u0_slots[i].fixade = 1;
        u0_slots[i].has_delay = 0;
        u0_slots[i].delay_target = 0U;
        u0_invalidate_entries(u0_slots[i].tlb);
    }
    u0_invalidate_entries(u0_fallback_tlb);
    u0_inited = 1;
}

static u0_slot_t *u0_slot_locked(const mips64_ctx_t *ctx, int create)
{
    size_t i;

    if (ctx == NULL) {
        return NULL;
    }
    u0_init_locked();
    for (i = 0; i < (size_t)U0_MAX_SLOTS; i++) {
        if (u0_slots[i].ctx == ctx) {
            return &u0_slots[i];
        }
    }
    if (create == 0) {
        return NULL;
    }
    for (i = 0; i < (size_t)U0_MAX_SLOTS; i++) {
        if (u0_slots[i].ctx == NULL) {
            u0_slots[i].ctx = ctx;
            u0_slots[i].fixade = 1;
            u0_slots[i].has_delay = 0;
            u0_slots[i].delay_target = 0U;
            u0_invalidate_entries(u0_slots[i].tlb);
            return &u0_slots[i];
        }
    }
    return NULL;
}

void mips_backend_state_reset(mips64_ctx_t *ctx)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        s->fixade = 1;
        s->has_delay = 0;
        s->delay_target = 0U;
        u0_invalidate_entries(s->tlb);
    }
    u0_unlock();
}

void mips_backend_state_release(const mips64_ctx_t *ctx)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 0);
    if (s != NULL) {
        s->ctx = NULL;
        s->fixade = 1;
        s->has_delay = 0;
        s->delay_target = 0U;
        u0_invalidate_entries(s->tlb);
    }
    u0_unlock();
}

/* ---- §4 TIF_FIXADE + SIGBUS/BUS_ADRALN ---- */

int mips_fixade_enabled(const mips64_ctx_t *ctx)
{
    u0_slot_t *s;
    int en = 1;

    if (ctx == NULL) {
        return 1;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 0);
    if (s != NULL) {
        en = s->fixade;
    }
    u0_unlock();
    return en;
}

void mips_fixade_set(mips64_ctx_t *ctx, int enabled)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        s->fixade = (enabled != 0) ? 1 : 0;
    }
    u0_unlock();
}

int mips_fixade_ctl(mips64_ctx_t *ctx, unsigned long cmd,
                    unsigned long arg)
{
    u0_slot_t *s;

    if (ctx == NULL || cmd != (unsigned long)MIPS_SYS_MIPS_FIXADE) {
        return MIPS_FAULT;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        s->fixade = (arg != 0UL) ? 1 : 0;
    }
    u0_unlock();
    return (s != NULL) ? 0 : MIPS_FAULT;
}

void mips_bus_fault(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t before;

    if (ctx == NULL) {
        return;
    }
    ctx->llbit = 0U;
    before = ctx->pc;
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

/* ---- §5 delay-slot dynamic-NPC target ---- */

void mips_delay_target_set(mips64_ctx_t *ctx, uint64_t va)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        s->has_delay = 1;
        s->delay_target = va;
    }
    u0_unlock();
}

int mips_delay_target_get(const mips64_ctx_t *ctx, uint64_t *va)
{
    u0_slot_t *s;
    int has = 0;

    if (ctx == NULL || va == NULL) {
        return 0;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 0);
    if (s != NULL && s->has_delay != 0) {
        *va = s->delay_target;
        has = 1;
    }
    u0_unlock();
    return has;
}

void mips_delay_target_clear(mips64_ctx_t *ctx)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 0);
    if (s != NULL) {
        s->has_delay = 0;
        s->delay_target = 0U;
    }
    u0_unlock();
}

int mips_npc_mode(const mips64_ctx_t *ctx)
{
    u0_slot_t *s;
    int has = 0;

    if (ctx == NULL) {
        return (int)MIPS_NPC_STATIC;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 0);
    if (s != NULL) {
        has = s->has_delay;
    }
    u0_unlock();
    return (has != 0) ? (int)MIPS_NPC_DYNAMIC_CTX : (int)MIPS_NPC_STATIC;
}

/* ---- §6 4096-entry direct-mapped soft-TLB ---- */

void *mips_soft_tlb_base(mips64_ctx_t *ctx)
{
    u0_slot_t *s;
    void *base;

    if (ctx == NULL) {
        return NULL;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    base = (s != NULL) ? (void *)&s->tlb[0] : (void *)&u0_fallback_tlb[0];
    u0_unlock();
    return base;
}

void mips_soft_tlb_fill(mips64_ctx_t *ctx, uint64_t va)
{
    u0_slot_t *s;
    mips_soft_tlb_entry_t *e;
    uint64_t page;
    uint64_t vpn;
    size_t idx;
    int can_read;
    int prot_write;
    int can_write;

    if (ctx == NULL || ctx->guest_base == 0U) {
        return;
    }
    page = va & ~(uint64_t)0xFFFU;
    vpn = page >> 12;
    can_read = mips_mem_ok(ctx, page, 4096U, (uint32_t)MIPS_PROT_READ);
    prot_write = mips_mem_ok(ctx, page, 4096U, (uint32_t)MIPS_PROT_WRITE);

    u0_lock();
    can_write = prot_write &&
                mips_vm_page_writable(vpn) &&
                (ctx->llbit == 0U || (ctx->lladdr >> 12) != vpn);
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        idx = (size_t)(vpn & MIPS64_SOFT_TLB_INDEX_MASK);
        e = &s->tlb[idx];
        e->read_tag = (can_read != 0) ? page : UINT64_MAX;
        e->write_tag = (can_write != 0) ? page : UINT64_MAX;
        e->addend = (can_read != 0 || can_write != 0)
                        ? (uintptr_t)ctx->guest_base
                        : (uintptr_t)0U;
        e->flags_reserved = 0U;
    }
    u0_unlock();
}

void mips_soft_tlb_invalidate(mips64_ctx_t *ctx)
{
    u0_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    u0_lock();
    s = u0_slot_locked(ctx, 1);
    if (s != NULL) {
        u0_invalidate_entries(s->tlb);
    }
    u0_unlock();
}

void mips_soft_tlb_evict_write(mips64_ctx_t *ctx, uint64_t va,
                               uint64_t len)
{
    uint64_t start;
    uint64_t end;
    uint64_t page;
    size_t i;

    if (ctx == NULL || len == 0U) {
        return;
    }
    start = va & ~(uint64_t)0xFFFU;
    end = (va + len + 0xFFFU) & ~(uint64_t)0xFFFU;
    if (end <= start) {
        mips_soft_tlb_invalidate_all();
        return;
    }
    u0_lock();
    u0_init_locked();
    for (page = start; page < end; page += 0x1000U) {
        size_t idx =
            (size_t)((page >> 12) & MIPS64_SOFT_TLB_INDEX_MASK);

        for (i = 0u; i < (size_t)U0_MAX_SLOTS; i++) {
            if (u0_slots[i].ctx != NULL &&
                u0_slots[i].tlb[idx].write_tag == page) {
                u0_slots[i].tlb[idx].write_tag = UINT64_MAX;
            }
        }
        if (u0_fallback_tlb[idx].write_tag == page) {
            u0_fallback_tlb[idx].write_tag = UINT64_MAX;
        }
        if (page + 0x1000U < page) {
            break;
        }
    }
    u0_unlock();
}

void mips_soft_tlb_invalidate_all(void)
{
    size_t i;

    u0_lock();
    u0_init_locked();
    for (i = 0u; i < (size_t)U0_MAX_SLOTS; i++) {
        if (u0_slots[i].ctx != NULL) {
            u0_invalidate_entries(u0_slots[i].tlb);
        }
    }
    u0_invalidate_entries(u0_fallback_tlb);
    u0_unlock();
}

size_t mips_host_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);

    return (size_t)(ps < 4096L ? 4096L : ps);
}
