/*
 * src/interp/unaligned.c — unaligned load/store merge + LL/SC helpers.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Byte-granular LWL/LWR/SWL/SWR merge rules (32-bit, result
 * sign-extended) and LDL/LDR/SDL/SDR merge rules (64-bit). LDL/LDR
 * spans are endian-specific: on LE, LDL takes mem[pa..pa+k] into the
 * HIGH bytes of rt and LDR takes mem[pa+k..pa+7] into the LOW bytes;
 * on BE the spans swap (LDL takes mem[pa+k..pa+7] into HIGH, LDR
 * takes mem[pa..pa+k] into LOW). The LE canonical pair does not
 * compose a full doubleword (architectural, matches qemu-LE).
 * LL/SC/LLD/SCD follow E05 (exact-address reservation in
 * llbit/lladdr/llval).
 *
 * This file also hosts interp_exec_mem, the aligned load/store
 * dispatcher that shares the helpers above (keeps interp.c under the
 * 900-line limit; no behavior difference vs a static executor).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/interp.h"
#include "os/backend.h"
#include "os/quiesce.h"
#include "vm/vm_pages.h"

extern void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va,
                                     uint64_t len);

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

/* LDL/LDR merge rules (R4000/MIPS IV pseudocode, qemu-verified per endian):
 * endian swaps the span, placement is fixed: LDL takes mem[pa..pa+k]
 * on LE (mem[pa+k..pa+7] on BE) into HIGH rt, LDR takes mem[pa+k..pa+7]
 * on LE (mem[pa..pa+k] on BE) into LOW rt; the LE canonical pair does
 * not compose a full doubleword (architectural, matches qemu-LE). */
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
        for (i = 0u; i <= k; i++) {
            v = set_pos64(v, (7u - k) + i, m[i]);
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
        for (i = k; i < 8u; i++) {
            v = set_pos64(v, i - k, m[i]);
        }
    }
    interp_set_reg(ctx, rt, v);
    return 0;
}

/* SDL/SDR store rules mirror the loads (same spans, inverse direction). */
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
    for (i = 0u; i <= k; i++) {
        m[i] = (uint8_t)get_pos64(rtval, (7u - k) + i);
    }
    return store_bytes(ctx, pa, m, 0u, k);
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
    for (i = k; i < 8u; i++) {
        m[i] = (uint8_t)get_pos64(rtval, i - k);
    }
    return store_bytes(ctx, pa, m, k, 7u);
}

/* LL/SC (E05): aligned word load arms the reservation; SC commits only
 * on a live exact-address reservation whose per-word generation epoch
 * has not been bumped by an intervening store (defeating A->B->A ABA
 * and cross-thread DBT stores). A dead reservation still faults on a
 * bad address (load side effect preserved). */
#define LLSC_SLOTS 160u
#define LLSC_BUCKETS 4096u

typedef struct {
    const mips64_ctx_t *ctx;
    uint64_t addr;
    uint32_t width;
    int active;
    uint64_t epoch0;
    uint64_t epoch1;
} llsc_slot_t;

static unsigned char sc_lock;
static _Thread_local int g_sc_held;
static _Thread_local sigset_t g_sc_preempt_saved;
static llsc_slot_t g_llsc_slots[LLSC_SLOTS];
static uint64_t g_llsc_epoch[LLSC_BUCKETS];

static void sc_lock_acquire(void)
{
    if (g_sc_held > 0) {
        g_sc_held++;
        return;
    }
    mips_qs_block_preempt(&g_sc_preempt_saved);
    while (__atomic_test_and_set(&sc_lock, __ATOMIC_ACQUIRE) != 0) {
    }
    g_sc_held = 1;
}

static void sc_lock_release(void)
{
    if (g_sc_held > 1) {
        g_sc_held--;
        return;
    }
    g_sc_held = 0;
    __atomic_clear(&sc_lock, __ATOMIC_RELEASE);
    mips_qs_unblock_preempt(&g_sc_preempt_saved);
}

void mips_llsc_write_lock(void)
{
    sc_lock_acquire();
}

void mips_llsc_write_unlock(void)
{
    sc_lock_release();
}

void mips_llsc_atfork_child(const mips64_ctx_t *ctx)
{
    size_t i;

    sc_lock = 0;
    g_sc_held = 0;
    for (i = 0u; i < LLSC_SLOTS; i++) {
        if (g_llsc_slots[i].ctx != ctx) {
            g_llsc_slots[i].ctx = NULL;
        }
        g_llsc_slots[i].addr = 0u;
        g_llsc_slots[i].width = 0u;
        g_llsc_slots[i].active = 0;
        g_llsc_slots[i].epoch0 = 0u;
        g_llsc_slots[i].epoch1 = 0u;
    }
}

static llsc_slot_t *llsc_slot_locked(const mips64_ctx_t *ctx, int create)
{
    size_t i;

    if (ctx == NULL) {
        return NULL;
    }
    for (i = 0u; i < LLSC_SLOTS; i++) {
        if (g_llsc_slots[i].ctx == ctx) {
            return &g_llsc_slots[i];
        }
    }
    if (create == 0) {
        return NULL;
    }
    for (i = 0u; i < LLSC_SLOTS; i++) {
        if (g_llsc_slots[i].ctx == NULL) {
            g_llsc_slots[i].ctx = ctx;
            g_llsc_slots[i].addr = 0u;
            g_llsc_slots[i].width = 0u;
            g_llsc_slots[i].active = 0;
            g_llsc_slots[i].epoch0 = 0u;
            g_llsc_slots[i].epoch1 = 0u;
            return &g_llsc_slots[i];
        }
    }
    return NULL;
}

static void llsc_note_write_locked(uint64_t va, uint64_t len)
{
    uint64_t w;
    uint64_t end_w;
    size_t i;

    w = va & ~(uint64_t)3u;
    end_w = (va + len - 1u) & ~(uint64_t)3u;
    if (end_w < w || (end_w - w) > 64u) {
        for (i = 0u; i < LLSC_BUCKETS; i++) {
            g_llsc_epoch[i]++;
        }
    } else {
        for (; w <= end_w; w += 4u) {
            g_llsc_epoch[(w >> 2) & (LLSC_BUCKETS - 1u)]++;
            if (w + 4u < w) {
                break;
            }
        }
    }
    for (i = 0u; i < LLSC_SLOTS; i++) {
        llsc_slot_t *s = &g_llsc_slots[i];

        if (s->ctx != NULL && s->active != 0 &&
            va < s->addr + (uint64_t)s->width && s->addr < va + len) {
            s->active = 0;
        }
    }
}

void mips_llsc_note_write(uint64_t va, uint64_t len)
{
    if (len == 0u) {
        return;
    }
    sc_lock_acquire();
    llsc_note_write_locked(va, len);
    sc_lock_release();
}

void mips_llsc_release(const mips64_ctx_t *ctx)
{
    llsc_slot_t *s;

    if (ctx == NULL) {
        return;
    }
    sc_lock_acquire();
    s = llsc_slot_locked(ctx, 0);
    if (s != NULL) {
        s->ctx = NULL;
        s->addr = 0u;
        s->width = 0u;
        s->active = 0;
        s->epoch0 = 0u;
        s->epoch1 = 0u;
    }
    sc_lock_release();
}

static void llsc_gate_page_locked(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t page = addr & ~(uint64_t)4095U;

    if ((mips_vm_page_flags(page >> 12) &
         (unsigned)MIPS_VM_PAGE_LL_ACTIVE) == 0u) {
        mips_vm_pages_mark(page, 4096U, (unsigned)MIPS_VM_PAGE_LL_ACTIVE);
        mips_soft_tlb_evict_write(ctx, page, 4096U);
    }
}

int do_ll(mips64_ctx_t *ctx, uint64_t addr, unsigned rt)
{
    uint64_t v = 0u;
    llsc_slot_t *s;

    if ((addr & 3u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    sc_lock_acquire();
    llsc_gate_page_locked(ctx, addr);
    if (guest_ld32(ctx, addr, &v) != 0) {
        sc_lock_release();
        return MIPS_FAULT;
    }
    s = llsc_slot_locked(ctx, 1);
    if (s != NULL) {
        s->addr = addr;
        s->width = 4u;
        s->epoch0 = g_llsc_epoch[(addr >> 2) & (LLSC_BUCKETS - 1u)];
        s->epoch1 = s->epoch0;
        s->active = 1;
    }
    ctx->llbit = 1;
    ctx->lladdr = addr;
    ctx->llval = (uint64_t)(uint32_t)v;
    sc_lock_release();
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
        llsc_slot_t *s;
        int epoch_ok;

        sc_lock_acquire();
        s = llsc_slot_locked(ctx, 0);
        epoch_ok = (s != NULL && s->active != 0 &&
                    s->addr == addr && s->width == 4u &&
                    s->epoch0 ==
                        g_llsc_epoch[(addr >> 2) & (LLSC_BUCKETS - 1u)]);
        if (s != NULL) {
            s->active = 0;
        }
        if (epoch_ok == 0) {
            /* Dead reservation still faults on a bad address (load
             * side effect preserved). */
            uint64_t dummy = 0u;

            if (guest_ld32(ctx, addr, &dummy) != 0) {
                sc_lock_release();
                return MIPS_FAULT;
            }
            sc_lock_release();
        } else {
            uint32_t want;
            uint32_t expect;
            uint8_t eb[4];
            uint8_t db[4];
            uint32_t exp_h;
            uint32_t des_h;
            uint32_t *hp;
            uint32_t cur_h;

            if (!mips_mem_ok(ctx, addr, 4u,
                             (uint32_t)MIPS_PROT_WRITE)) {
                sc_lock_release();
                mips_fault(ctx, addr);
                return MIPS_FAULT;
            }
            want = (uint32_t)(ctx->gpr[rt] & 0xFFFFFFFFu);
            expect = (uint32_t)(ctx->llval & 0xFFFFFFFFu);
            if (mips_is_be(ctx) != 0) {
                eb[0] = (uint8_t)((expect >> 24) & 0xFFu);
                eb[1] = (uint8_t)((expect >> 16) & 0xFFu);
                eb[2] = (uint8_t)((expect >> 8) & 0xFFu);
                eb[3] = (uint8_t)(expect & 0xFFu);
                db[0] = (uint8_t)((want >> 24) & 0xFFu);
                db[1] = (uint8_t)((want >> 16) & 0xFFu);
                db[2] = (uint8_t)((want >> 8) & 0xFFu);
                db[3] = (uint8_t)(want & 0xFFu);
            } else {
                eb[0] = (uint8_t)(expect & 0xFFu);
                eb[1] = (uint8_t)((expect >> 8) & 0xFFu);
                eb[2] = (uint8_t)((expect >> 16) & 0xFFu);
                eb[3] = (uint8_t)((expect >> 24) & 0xFFu);
                db[0] = (uint8_t)(want & 0xFFu);
                db[1] = (uint8_t)((want >> 8) & 0xFFu);
                db[2] = (uint8_t)((want >> 16) & 0xFFu);
                db[3] = (uint8_t)((want >> 24) & 0xFFu);
            }
            (void)memcpy(&exp_h, eb, 4u);
            (void)memcpy(&des_h, db, 4u);
            hp = (uint32_t *)mips64_guest_ptr(ctx, addr);
            cur_h = exp_h;
            /* Host CAS under sc_lock: the value check and the store
             * are indivisible against DBT inline stores, which emit
             * plain host stores without taking sc_lock. Locked
             * writers are already serialized by sc_lock + epoch. */
            if (__atomic_compare_exchange_n(hp, &cur_h, des_h, 0,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE) != 0) {
                llsc_note_write_locked(addr, 4u);
                mips_vm_pages_clear(addr, 4u,
                    (unsigned)MIPS_VM_PAGE_COW_CLEAN);
                mips_vm_pages_retire_code(addr, 4u);
                mips_vm_file_shared_sync(ctx, addr, 4u);
                sc_ok = 1;
            }
            sc_lock_release();
        }
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
    llsc_slot_t *s;

    if ((addr & 7u) != 0u) {
        mips_fault(ctx, addr);
        return MIPS_FAULT;
    }
    sc_lock_acquire();
    llsc_gate_page_locked(ctx, addr);
    if (guest_ld64(ctx, addr, &v) != 0) {
        sc_lock_release();
        return MIPS_FAULT;
    }
    s = llsc_slot_locked(ctx, 1);
    if (s != NULL) {
        s->addr = addr;
        s->width = 8u;
        s->epoch0 = g_llsc_epoch[(addr >> 2) & (LLSC_BUCKETS - 1u)];
        s->epoch1 =
            g_llsc_epoch[((addr + 4u) >> 2) & (LLSC_BUCKETS - 1u)];
        s->active = 1;
    }
    ctx->llbit = 1;
    ctx->lladdr = addr;
    ctx->llval = v;
    sc_lock_release();
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
        llsc_slot_t *s;
        int epoch_ok;

        sc_lock_acquire();
        s = llsc_slot_locked(ctx, 0);
        epoch_ok =
            (s != NULL && s->active != 0 &&
             s->addr == addr && s->width == 8u &&
             s->epoch0 ==
                 g_llsc_epoch[(addr >> 2) & (LLSC_BUCKETS - 1u)] &&
             s->epoch1 ==
                 g_llsc_epoch[((addr + 4u) >> 2) & (LLSC_BUCKETS - 1u)]);
        if (s != NULL) {
            s->active = 0;
        }
        if (epoch_ok == 0) {
            uint64_t dummy = 0u;

            if (guest_ld64(ctx, addr, &dummy) != 0) {
                sc_lock_release();
                return MIPS_FAULT;
            }
            sc_lock_release();
        } else {
            uint64_t want = ctx->gpr[rt];
            uint64_t expect = ctx->llval;
            uint8_t eb[8];
            uint8_t db[8];
            uint64_t exp_h = 0u;
            uint64_t des_h = 0u;
            uint64_t *hp;
            uint64_t cur_h;
            unsigned i;

            if (!mips_mem_ok(ctx, addr, 8u,
                             (uint32_t)MIPS_PROT_WRITE)) {
                sc_lock_release();
                mips_fault(ctx, addr);
                return MIPS_FAULT;
            }
            if (mips_is_be(ctx) != 0) {
                for (i = 0u; i < 8u; i++) {
                    eb[i] = (uint8_t)((expect >> (8u * (7u - i))) &
                        0xFFu);
                    db[i] = (uint8_t)((want >> (8u * (7u - i))) &
                        0xFFu);
                }
            } else {
                for (i = 0u; i < 8u; i++) {
                    eb[i] = (uint8_t)((expect >> (8u * i)) & 0xFFu);
                    db[i] = (uint8_t)((want >> (8u * i)) & 0xFFu);
                }
            }
            (void)memcpy(&exp_h, eb, 8u);
            (void)memcpy(&des_h, db, 8u);
            hp = (uint64_t *)mips64_guest_ptr(ctx, addr);
            cur_h = exp_h;
            /* Host CAS under sc_lock: indivisible against DBT
             * inline doubleword stores (see do_sc). */
            if (__atomic_compare_exchange_n(hp, &cur_h, des_h, 0,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE) != 0) {
                llsc_note_write_locked(addr, 8u);
                mips_vm_pages_clear(addr, 8u,
                    (unsigned)MIPS_VM_PAGE_COW_CLEAN);
                mips_vm_pages_retire_code(addr, 8u);
                mips_vm_file_shared_sync(ctx, addr, 8u);
                sc_ok = 1;
            }
            sc_lock_release();
        }
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
    mips_insn_trap(ctx, 4, addr);
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
        if (guest_ld16(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, (uint64_t)(int64_t)(int16_t)(v & 0xFFFFu));
        return 0;
    case 0x22u: /* LWL */
        return do_lwl(ctx, addr, d->rt);
    case 0x23u: /* LW */
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
        if (guest_ld16(ctx, addr, &v) != 0) {
            return MIPS_FAULT;
        }
        interp_set_reg(ctx, d->rt, v & 0xFFFFu);
        return 0;
    case 0x26u: /* LWR */
        return do_lwr(ctx, addr, d->rt);
    case 0x27u: /* LWU */
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
        if (guest_st16(ctx, addr, ctx->gpr[d->rt] & 0xFFFFu) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    case 0x2Au: /* SWL */
        return do_swl(ctx, addr, ctx->gpr[d->rt]);
    case 0x2Bu: /* SW */
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
        if (guest_st64(ctx, addr, ctx->gpr[d->rt]) != 0) {
            return MIPS_FAULT;
        }
        return 0;
    default:
        return mem_fault_at(ctx, cur_pc);
    }
}
