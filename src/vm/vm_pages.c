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

#include "vm/vm_pages.h"

#include <pthread.h>
#include <stddef.h>

#include "core/cpu.h"

#define VM_PAGES_SLOTS 2048u

typedef struct {
    int used;
    uint64_t vpn;
    unsigned flags;
} vm_page_slot_t;

static vm_page_slot_t vm_page_slots[VM_PAGES_SLOTS];
static pthread_mutex_t vm_page_mu = PTHREAD_MUTEX_INITIALIZER;
static int vm_page_overflow = 0;

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

    for (i = 0u; i < VM_PAGES_SLOTS; i++) {
        vm_page_slot_t *s = &vm_page_slots[(at + i) & (VM_PAGES_SLOTS - 1u)];

        if (s->used != 0 && s->vpn == vpn) {
            return s;
        }
        if (s->used == 0) {
            if (create == 0) {
                return NULL;
            }
            s->used = 1;
            s->vpn = vpn;
            s->flags = 0u;
            return s;
        }
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
    (void)pthread_mutex_lock(&vm_page_mu);
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
            s->used = 0;
            s->vpn = 0u;
            s->flags = 0u;
        } else {
            s->flags &= ~flags;
        }
        if (vpn + 1u < vpn) {
            break;
        }
    }
    (void)pthread_mutex_unlock(&vm_page_mu);
}

void mips_vm_pages_mark(uint64_t va, uint64_t len, unsigned flags)
{
    vm_pages_apply(va, len, flags, 1);
}

void mips_vm_pages_clear(uint64_t va, uint64_t len, unsigned flags)
{
    size_t i;

    /* Whole-address-space clear: walk the 2048 slots (not 2^52
     * pages), clearing only the requested bits so unrelated marks
     * (COW_CLEAN across an SMC epoch bump) survive. The overflow
     * latch stays sticky: unknown pages may still carry flags. */
    if (len == ~(uint64_t)0u && flags != 0u) {
        (void)pthread_mutex_lock(&vm_page_mu);
        for (i = 0u; i < VM_PAGES_SLOTS; i++) {
            if (vm_page_slots[i].used == 0) {
                continue;
            }
            vm_page_slots[i].flags &= ~flags;
            if (vm_page_slots[i].flags == 0u) {
                vm_page_slots[i].used = 0;
                vm_page_slots[i].vpn = 0u;
            }
        }
        (void)pthread_mutex_unlock(&vm_page_mu);
        return;
    }
    vm_pages_apply(va, len, flags, 0);
}

unsigned mips_vm_page_flags(uint64_t vpn)
{
    vm_page_slot_t *s;
    unsigned out = 0u;

    (void)pthread_mutex_lock(&vm_page_mu);
    s = vm_page_find_locked(vpn, 0);
    if (s != NULL) {
        out = s->flags;
    }
    if (vm_page_overflow != 0) {
        out |= (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                          MIPS_VM_PAGE_HAS_CODE);
    }
    (void)pthread_mutex_unlock(&vm_page_mu);
    return out;
}

int mips_vm_page_writable(uint64_t vpn)
{
    return mips_vm_page_flags(vpn) == 0u;
}
