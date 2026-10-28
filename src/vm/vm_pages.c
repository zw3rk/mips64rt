/*
 * src/vm/vm_pages.c — Lane U12 per-page write-gate flags.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements src/vm/vm_pages.h: a bounded open-addressed hash of
 * per-4 KiB-page flags (vpn -> flags) with a process-global lock.
 * The table only ever closes the write gate: overflow sets a global
 * overflow latch (every gate reads closed) until the next full
 * clear, so no state is ever lost open. Stale rows are safe in the
 * same direction (a leftover COW_CLEAN or HAS_CODE only slow-paths
 * a store that would have inlined), and unmap clears its range to
 * keep the table small.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "vm/vm_pages.h"

#include "os/quiesce.h"

#include <pthread.h>
#include <stddef.h>
#include <string.h>

#include "core/cpu.h"

#define VM_PAGES_SLOTS 65536u

typedef struct {
    int used;
    uint64_t vpn;
    unsigned flags;
} vm_page_slot_t;

static vm_page_slot_t vm_page_slots[VM_PAGES_SLOTS];
static pthread_mutex_t vm_page_mu = PTHREAD_MUTEX_INITIALIZER;
static int vm_page_overflow = 0;

static _Thread_local int vm_page_preempt_depth;
static _Thread_local sigset_t vm_page_preempt_saved;

/* Page-table lock with preemption blocked (see quiesce.h): the
 * mutator retires code marks through here. */
static void vm_page_lock(void)
{
    if (vm_page_preempt_depth == 0) {
        mips_qs_block_preempt(&vm_page_preempt_saved);
    }
    vm_page_preempt_depth++;
    (void)pthread_mutex_lock(&vm_page_mu);
}

static void vm_page_unlock(void)
{
    (void)pthread_mutex_unlock(&vm_page_mu);
    vm_page_preempt_depth--;
    if (vm_page_preempt_depth == 0) {
        mips_qs_unblock_preempt(&vm_page_preempt_saved);
    }
}

static size_t vm_page_hash(uint64_t vpn)
{
    uint64_t h = vpn ^ (vpn >> 17);

    h *= (uint64_t)0x9E3779B97F4A7C15u;
    h ^= h >> 29;
    return (size_t)(h & (uint64_t)(VM_PAGES_SLOTS - 1u));
}

static vm_page_slot_t *vm_page_find_locked(uint64_t vpn, int create)
{
    size_t i;
    size_t at = vm_page_hash(vpn);
    vm_page_slot_t *tomb = NULL;

    for (i = 0u; i < VM_PAGES_SLOTS; i++) {
        vm_page_slot_t *s = &vm_page_slots[(at + i) & (VM_PAGES_SLOTS - 1u)];

        if (s->used == 1 && s->vpn == vpn) {
            return s;
        }
        if (s->used == 2 && tomb == NULL) {
            tomb = s;
            continue;
        }
        if (s->used == 0) {
            if (create == 0) {
                return NULL;
            }
            if (tomb != NULL) {
                s = tomb;
            }
            s->used = 1;
            s->vpn = vpn;
            s->flags = 0u;
            return s;
        }
    }
    if (create != 0 && tomb != NULL) {
        tomb->used = 1;
        tomb->vpn = vpn;
        tomb->flags = 0u;
        return tomb;
    }
    return NULL;
}

static void vm_pages_apply(uint64_t va, uint64_t len, unsigned flags,
                           int set)
{
    uint64_t start;
    uint64_t end;
    uint64_t vpn;

    if (len == 0u) {
        return;
    }
    start = va & ~(uint64_t)4095U;
    end = (va + len + 4095U) & ~(uint64_t)4095U;
    if (end < start) {
        return;
    }
    (void)vm_page_lock();
    for (vpn = start >> 12; vpn < (end >> 12); vpn++) {
        vm_page_slot_t *s = vm_page_find_locked(vpn, set);

        if (s == NULL) {
            if (set != 0) {
                vm_page_overflow = 1;
            }
            continue;
        }
        if (set != 0) {
            s->flags |= flags;
        } else if ((s->flags & ~flags) == 0u) {
            s->used = 2;
            s->vpn = 0u;
            s->flags = 0u;
        } else {
            s->flags &= ~flags;
        }
        if (vpn + 1u < vpn) {
            break;
        }
    }
    (void)vm_page_unlock();
}

void mips_vm_pages_mark(uint64_t va, uint64_t len, unsigned flags)
{
    vm_pages_apply(va, len, flags, 1);
}

void mips_vm_pages_clear(uint64_t va, uint64_t len, unsigned flags)
{
    size_t i;

    /* Whole-address-space clear: walk the slots (not 2^52 pages),
     * clearing only the requested bits so unrelated marks (COW_CLEAN
     * across an SMC epoch bump) survive. The overflow latch stays
     * sticky: unknown pages may still carry flags. */
    if (len == ~(uint64_t)0u && flags != 0u) {
        int any_live = 0;

        (void)vm_page_lock();
        for (i = 0u; i < VM_PAGES_SLOTS; i++) {
            if (vm_page_slots[i].used != 1) {
                continue;
            }
            vm_page_slots[i].flags &= ~flags;
            if (vm_page_slots[i].flags == 0u) {
                vm_page_slots[i].used = 2;
                vm_page_slots[i].vpn = 0u;
            } else {
                any_live = 1;
            }
        }
        if (any_live == 0) {
            for (i = 0u; i < VM_PAGES_SLOTS; i++) {
                vm_page_slots[i].used = 0;
            }
        }
        (void)vm_page_unlock();
        return;
    }
    vm_pages_apply(va, len, flags, 0);
}

unsigned mips_vm_page_flags(uint64_t vpn)
{
    vm_page_slot_t *s;
    unsigned out = 0u;

    (void)vm_page_lock();
    s = vm_page_find_locked(vpn, 0);
    if (s != NULL) {
        out = s->flags;
    }
    if (vm_page_overflow != 0) {
        out |= (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                          MIPS_VM_PAGE_HAS_CODE);
    }
    (void)vm_page_unlock();
    return out;
}

int mips_vm_page_writable(uint64_t vpn)
{
    return mips_vm_page_flags(vpn) == 0u;
}

/* Weak DBT hook (mirrors the mem_table.c pattern): unit builds that
 * link the page table without the DBT core retire into the void. */
__attribute__((weak)) void dbt_invalidate_range(uint64_t va, uint64_t len)
{
    (void)va;
    (void)len;
}

int mips_vm_pages_any_set(uint64_t va, uint64_t len, unsigned flags)
{
    uint64_t start;
    uint64_t end;
    uint64_t vpn;
    int found = 0;

    if (len == 0u || flags == 0u) {
        return 0;
    }
    start = va & ~(uint64_t)4095U;
    end = (va + len + 4095U) & ~(uint64_t)4095U;
    if (end <= start) {
        /* Wrapped or degenerate span: retire conservatively. */
        return 1;
    }
    (void)vm_page_lock();
    if (vm_page_overflow != 0) {
        found = 1;
    } else {
        for (vpn = start >> 12; vpn < (end >> 12); vpn++) {
            vm_page_slot_t *s = vm_page_find_locked(vpn, 0);

            if (s != NULL && (s->flags & flags) != 0u) {
                found = 1;
                break;
            }
            if (vpn + 1u < vpn) {
                break;
            }
        }
    }
    (void)vm_page_unlock();
    return found;
}

void mips_vm_pages_retire_code(uint64_t va, uint64_t len)
{
    if (len == 0u) {
        return;
    }
    if (mips_vm_pages_any_set(va, len,
                              (unsigned)MIPS_VM_PAGE_HAS_CODE) != 0) {
        dbt_invalidate_range(va, len);
    }
}

static vm_page_slot_t vm_page_saved[VM_PAGES_SLOTS];
static int vm_page_overflow_saved;

void mips_vm_pages_snapshot(void)
{
    vm_page_lock();
    (void)memcpy(vm_page_saved, vm_page_slots, sizeof vm_page_slots);
    vm_page_overflow_saved = vm_page_overflow;
    vm_page_unlock();
}

void mips_vm_pages_restore(void)
{
    vm_page_lock();
    (void)memcpy(vm_page_slots, vm_page_saved, sizeof vm_page_slots);
    vm_page_overflow = vm_page_overflow_saved;
    vm_page_unlock();
}

void mips_vm_pages_remap(uint64_t old_va, uint64_t old_size,
                         uint64_t dst_va, uint64_t new_size)
{
    uint64_t kept = old_size < new_size ? old_size : new_size;
    uint64_t off;

    if (dst_va == old_va) {
        if (new_size < old_size) {
            mips_vm_pages_clear(old_va + new_size, old_size - new_size,
                                (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                                           MIPS_VM_PAGE_HAS_CODE));
        }
        return;
    }
    mips_vm_pages_clear(dst_va, new_size,
                        (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                                   MIPS_VM_PAGE_HAS_CODE));
    for (off = 0u; off < kept; off += 4096u) {
        unsigned fl = mips_vm_page_flags((old_va + off) >> 12) &
                      (unsigned)MIPS_VM_PAGE_COW_CLEAN;
        if (fl != 0u) {
            mips_vm_pages_mark(dst_va + off, 4096u, fl);
        }
    }
    mips_vm_pages_clear(old_va, old_size,
                        (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                                   MIPS_VM_PAGE_HAS_CODE));
}
