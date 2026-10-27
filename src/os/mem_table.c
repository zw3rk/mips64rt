/*
 * src/os/mem_table.c — Process-global guest region table (lane H4 fix)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host mappings inside the reservation are process-global, so the region
 * table is process-global too, serialized on a recursive mutex with
 * quiescence preemption blocked across table critical sections.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/cpu.h"
#include "os/quiesce.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* macOS hides MAP_NORESERVE under strict feature macros; the reservation
 * is an overcommit hint only, so degrading to 0 there is correct. */
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

static pthread_once_t g_mem_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_mem_mu;
static mips64_region_t g_regions[MIPS64_MAX_REGIONS];
static size_t g_region_count = 0U;

/* atfork child: only the forking thread survives, so drop whatever the
 * copied mutex thought about holders and start unlocked. */
static void mem_atfork_child(void)
{
    pthread_mutexattr_t at;

    (void)pthread_mutexattr_init(&at);
    (void)pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
    (void)pthread_mutex_init(&g_mem_mu, &at);
    (void)pthread_mutexattr_destroy(&at);
}

static void mem_lock_init(void)
{
    pthread_mutexattr_t at;

    (void)pthread_mutexattr_init(&at);
    (void)pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
    (void)pthread_mutex_init(&g_mem_mu, &at);
    (void)pthread_mutexattr_destroy(&at);
    (void)pthread_atfork(NULL, NULL, mem_atfork_child);
}

static _Thread_local int mem_preempt_depth;
static _Thread_local sigset_t mem_preempt_saved;

static void mem_lock(void)
{
    /* Block preemption across the table critical section (see
     * quiesce.h): a peer parked holding this mutex would deadlock
     * the mutator waiting for it. Depth-counted for the recursive
     * mutex; the mask save/restore pairs nest. */
    if (mem_preempt_depth == 0) {
        mips_qs_block_preempt(&mem_preempt_saved);
    }
    mem_preempt_depth++;
    (void)pthread_once(&g_mem_once, mem_lock_init);
    (void)pthread_mutex_lock(&g_mem_mu);
}

static void mem_unlock(void)
{
    (void)pthread_mutex_unlock(&g_mem_mu);
    mem_preempt_depth--;
    if (mem_preempt_depth == 0) {
        mips_qs_unblock_preempt(&mem_preempt_saved);
    }
}

static uint64_t page_up(uint64_t v)
{
    return (v + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
}

/* Guest prot bits to host prot bits. PROT_EXEC is never granted: guest
 * code pages are data to the Phase 1 interpreter (W^X). */
static int host_prot(uint32_t prot)
{
    int hp = 0;

    if ((prot & MIPS_PROT_READ) != 0U) {
        hp |= PROT_READ;
    }
    if ((prot & MIPS_PROT_WRITE) != 0U) {
        hp |= PROT_WRITE;
    }
    return hp;
}

static void copy_tag(char *dst, const char *tag)
{
    size_t i = 0;

    if (tag == NULL) {
        dst[0] = '\0';
        return;
    }
    while (i + 1 < sizeof(((mips64_region_t *)0)->name) && tag[i] != '\0') {
        dst[i] = tag[i];
        i++;
    }
    dst[i] = '\0';
}

/* Phase 7 H1: DBT SMC hook. Weak default here so dbt-less unit links
 * (the test_decode host check, macOS ld has no ELF-style weak-undefined
 * reference) keep working; the strong definition in src/dbt/dbt.c
 * overrides it in the real translator, where the hook always fires.
 * Hooks fire only on map/protect/unmap — never on the common
 * store path. */
__attribute__((weak)) void dbt_invalidate_range(uint64_t va, uint64_t len)
{
    (void)va;
    (void)len;
}

__attribute__((weak)) void mips_qs_begin(mips64_ctx_t *ctx)
{
    (void)ctx;
}
__attribute__((weak)) void mips_qs_commit(mips64_ctx_t *ctx)
{
    (void)ctx;
}
__attribute__((weak)) void mips_qs_abort(mips64_ctx_t *ctx)
{
    (void)ctx;
}
__attribute__((weak)) void mips_vm_file_unmap_hook(uint64_t va, uint64_t len)
{
    (void)va;
    (void)len;
}

/* Split the region containing va so a region starts at va. Page
 * granularity: va must be page aligned (va == 0 and va == task_size are
 * boundaries that need no split). Returns 0, or -ENOMEM when the table
 * is full. Lock held on entry. */
static int split_at(uint64_t task_size, uint64_t va)
{
    size_t i;

    if (va == 0U || va >= task_size) {
        return 0;
    }
    if ((va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    for (i = 0; i < g_region_count; i++) {
        size_t free;

        if (va <= g_regions[i].start) {
            return 0; /* sorted: no later region can contain va */
        }
        if (va >= g_regions[i].end) {
            continue;
        }
        if (g_region_count >= MIPS64_MAX_REGIONS) {
            return -ENOMEM;
        }
        free = g_region_count;
        g_regions[free] = g_regions[i];
        g_regions[free].start = va;
        g_regions[i].end = va;
        g_region_count++;
        /* Insertion-sort the tail back down by start (at most one step
         * per split keeps this linear and allocation-free). */
        while (free > 0U &&
               g_regions[free].start < g_regions[free - 1U].start) {
            mips64_region_t tmp = g_regions[free];

            g_regions[free] = g_regions[free - 1U];
            g_regions[free - 1U] = tmp;
            free--;
        }
        return 0;
    }
    return 0;
}

/* Insert [va, va+len) sorted by start, merging contiguous neighbours
 * with identical prot. Caller guarantees no overlap and table space.
 * Lock held on entry. */
static void insert_region(uint64_t va, uint64_t len, uint32_t prot,
                          const char *tag)
{
    size_t at = g_region_count;
    size_t i;

    for (i = 0; i < g_region_count; i++) {
        if (va < g_regions[i].start) {
            at = i;
            break;
        }
    }
    for (i = g_region_count; i > at; i--) {
        g_regions[i] = g_regions[i - 1U];
    }
    g_regions[at].start = va;
    g_regions[at].end = va + len;
    g_regions[at].prot = prot;
    g_regions[at].flags = 0U;
    copy_tag(g_regions[at].name, tag);
    g_region_count++;
    /* Merge with the previous neighbour when contiguous and identical. */
    if (at > 0U && g_regions[at - 1U].end == va &&
        g_regions[at - 1U].prot == prot) {
        g_regions[at - 1U].end = va + len;
        for (i = at; i + 1U < g_region_count; i++) {
            g_regions[i] = g_regions[i + 1U];
        }
        g_region_count--;
        at--;
    }
    /* Merge with the next neighbour when contiguous and identical. */
    if (at + 1U < g_region_count &&
        g_regions[at].end == g_regions[at + 1U].start &&
        g_regions[at].prot == g_regions[at + 1U].prot) {
        g_regions[at].end = g_regions[at + 1U].end;
        for (i = at + 1U; i + 1U < g_region_count; i++) {
            g_regions[i] = g_regions[i + 1U];
        }
        g_region_count--;
    }
}

/*
 * True when every byte of [va, va+len) lies inside recorded regions
 * carrying the needed PROT bits. Regions are sorted by start; a sorted
 * gap or a permission mismatch fails the walk. Never truncates: the
 * end is computed in 64 bits and checked against task_size.
 */
int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                uint32_t need)
{
    uint64_t end;
    uint64_t cur;
    size_t i;
    int ok;

    if (ctx == NULL || len == 0U) {
        return ctx != NULL && len == 0U;
    }
    if (len > ctx->task_size || va > ctx->task_size - len) {
        return 0;
    }
    end = va + len;
    cur = va;
    ok = 0;
    mem_lock();
    for (i = 0; i < g_region_count; i++) {
        const mips64_region_t *r = &g_regions[i];

        if (r->start > cur) {
            break; /* sorted gap: nothing later can cover cur */
        }
        if (r->end <= cur) {
            continue;
        }
        if ((r->prot & need) != need) {
            break;
        }
        cur = r->end;
        if (cur >= end) {
            ok = 1;
            break;
        }
    }
    if (cur >= end) {
        ok = 1;
    }
    mem_unlock();
    return ok;
}

/* Map [va, va+len) inside the reservation with the given guest prot
 * (PROT_EXEC stripped on host). Returns 0, -EINVAL, -EEXIST, -ENOMEM. */
int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len, uint32_t prot,
                 const char *tag)
{
    void *got;
    size_t i;
    int rc = 0;

    if (ctx == NULL || ctx->guest_base == 0U) {
        return -EINVAL;
    }
    if (len == 0U || (va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    if ((prot & ~(MIPS_PROT_READ | MIPS_PROT_WRITE | MIPS_PROT_EXEC)) != 0U) {
        return -EINVAL;
    }
    len = page_up(len);
    if (len < MIPS64_PAGE_SIZE || len > ctx->task_size ||
        va > ctx->task_size - len) {
        return -EINVAL;
    }
    /* Quiescence step 1: park peers and drain leases before the
     * host mapping lands (steps 2-3 inside). */
    mips_qs_begin(ctx);
    mem_lock();
    for (i = 0; i < g_region_count; i++) {
        if (va < g_regions[i].end && g_regions[i].start < va + len) {
            rc = -EEXIST;
            break;
        }
    }
    if (rc == 0) {
        if (g_region_count >= MIPS64_MAX_REGIONS) {
            rc = -ENOMEM;
        } else {
            got = mmap((void *)(uintptr_t)(ctx->guest_base + va),
                       (size_t)len, host_prot(prot),
                       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            if (got == MAP_FAILED) {
                rc = -ENOMEM;
            } else {
                insert_region(va, len, prot, tag);
                dbt_invalidate_range(va, len);
            }
        }
    }
    mem_unlock();
    if (rc != 0) {
        mips_qs_abort(ctx);
    } else {
        mips_qs_commit(ctx);
    }
    return rc;
}

size_t mips_mem_snapshot(mips64_region_t *out, size_t cap);
void mips_mem_restore(const mips64_region_t *regs, size_t count);
static mips64_region_t g_saved_regions[MIPS64_MAX_REGIONS];

/* Release [va, va+len): drop covered region records and punch a
 * PROT_NONE hole so the reservation stays contiguous. */
int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len)
{
    uint64_t end;
    size_t i;
    size_t w;
    void *got;

    if (ctx == NULL || ctx->guest_base == 0U || len == 0U ||
        (va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    len = page_up(len);
    if (len > ctx->task_size || va > ctx->task_size - len) {
        return -EINVAL;
    }
    end = va + len;
    mips_qs_begin(ctx);
    mem_lock();
    if (split_at(ctx->task_size, va) != 0 ||
        (end < ctx->task_size && split_at(ctx->task_size, end) != 0)) {
        mem_unlock();
        mips_qs_abort(ctx);
        return -ENOMEM;
    }
    got = mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
               PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (got == MAP_FAILED) {
        int e = errno;

        mem_unlock();
        mips_qs_abort(ctx);
        return -e;
    }
    w = 0U;
    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].start >= va && g_regions[i].end <= end) {
            continue;
        }
        g_regions[w] = g_regions[i];
        w++;
    }
    g_region_count = w;
    dbt_invalidate_range(va, len);
    mips_vm_pages_clear(va, len,
                        (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                                   MIPS_VM_PAGE_HAS_CODE));
    mips_vm_file_unmap_hook(va, len);
    mem_unlock();
    mips_qs_commit(ctx);
    return 0;
}

/* Atomically replace [va, va+len) for MAP_FIXED / MREMAP_FIXED. */
int mips_mem_map_replace(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                         uint32_t prot, const char *tag)
{
    uint64_t end;
    size_t saved_count;
    size_t i;
    size_t w;
    void *got;

    if (ctx == NULL || ctx->guest_base == 0U || len == 0U ||
        (va & (MIPS64_PAGE_SIZE - 1U)) != 0U ||
        (prot & ~(MIPS_PROT_READ | MIPS_PROT_WRITE | MIPS_PROT_EXEC)) != 0U) {
        return -EINVAL;
    }
    len = page_up(len);
    if (len < MIPS64_PAGE_SIZE || len > ctx->task_size ||
        va > ctx->task_size - len) {
        return -EINVAL;
    }
    end = va + len;
    mips_qs_begin(ctx);
    mem_lock();
    saved_count = mips_mem_snapshot(g_saved_regions, MIPS64_MAX_REGIONS);
    if (split_at(ctx->task_size, va) != 0 ||
        (end < ctx->task_size && split_at(ctx->task_size, end) != 0)) {
        mips_mem_restore(g_saved_regions, saved_count);
        mem_unlock();
        mips_qs_abort(ctx);
        return -ENOMEM;
    }
    w = 0U;
    for (i = 0U; i < g_region_count; i++) {
        if (g_regions[i].start >= va && g_regions[i].end <= end) {
            continue;
        }
        g_regions[w] = g_regions[i];
        w++;
    }
    g_region_count = w;
    got = g_region_count >= MIPS64_MAX_REGIONS ? MAP_FAILED :
          mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
               host_prot(prot), MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
               -1, 0);
    if (got == MAP_FAILED) {
        mips_mem_restore(g_saved_regions, saved_count);
        mem_unlock();
        mips_qs_abort(ctx);
        return -ENOMEM;
    }
    insert_region(va, len, prot, tag);
    dbt_invalidate_range(va, len);
    mips_vm_pages_clear(va, len,
                        (unsigned)(MIPS_VM_PAGE_COW_CLEAN |
                                   MIPS_VM_PAGE_HAS_CODE));
    mips_vm_file_unmap_hook(va, len);
    mem_unlock();
    mips_qs_commit(ctx);
    return 0;
}

/* Change protection on a fully mapped range; -ENOMEM when any byte is
 * unmapped. Zero length is a no-op; positive length rounds up to 4 KiB. */
int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                     uint32_t prot)
{
    uint64_t end;
    size_t i;
    int rc = 0;

    if (ctx == NULL || ctx->guest_base == 0U ||
        (va & (MIPS64_PAGE_SIZE - 1U)) != 0U ||
        (prot & ~(MIPS_PROT_READ | MIPS_PROT_WRITE | MIPS_PROT_EXEC)) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    len = page_up(len);
    if (len < MIPS64_PAGE_SIZE || len > ctx->task_size ||
        va > ctx->task_size - len) {
        return -EINVAL;
    }
    end = va + len;
    mips_qs_begin(ctx);
    mem_lock();
    if (!mips_mem_ok(ctx, va, len, 0U)) {
        rc = -ENOMEM;
    } else if (split_at(ctx->task_size, va) != 0 ||
               (end < ctx->task_size &&
                split_at(ctx->task_size, end) != 0)) {
        rc = -ENOMEM;
    } else if (mprotect((void *)(uintptr_t)(ctx->guest_base + va),
                        (size_t)len, host_prot(prot)) != 0) {
        rc = -errno;
    } else {
        for (i = 0; i < g_region_count; i++) {
            if (g_regions[i].start >= va && g_regions[i].end <= end) {
                g_regions[i].prot = prot;
            }
        }
        dbt_invalidate_range(va, len);
    }
    mem_unlock();
    if (rc != 0) {
        mips_qs_abort(ctx);
    } else {
        mips_qs_commit(ctx);
    }
    return rc;
}

#define MIPS_MREMAP_MAYMOVE 1U
#define MIPS_MREMAP_FIXED 2U

static uint64_t remap_hole(uint64_t task_size, uint64_t cand, uint64_t size)
{
    size_t i;

    if (size == 0U || size > task_size || cand > task_size - size) {
        return 0U;
    }
    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].end <= cand) {
            continue;
        }
        if (g_regions[i].start >= cand + size) {
            return cand;
        }
        cand = g_regions[i].end;
        if (cand > task_size - size) {
            return 0U;
        }
    }
    return cand;
}

static uint32_t remap_prot(uint64_t va)
{
    size_t i;

    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].start <= va && va < g_regions[i].end) {
            return g_regions[i].prot;
        }
    }
    return 0U;
}

int64_t mips_mem_remap(mips64_ctx_t *ctx, uint64_t old_va, uint64_t old_len,
                       uint64_t new_len, uint64_t flags, uint64_t new_va)
{
    uint64_t old_size;
    uint64_t new_size;
    uint32_t prot;
    uint64_t dst;
    int rc;

    if (ctx == NULL || ctx->guest_base == 0U || old_len == 0U ||
        new_len == 0U || (old_va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -(int64_t)EINVAL;
    }
    if ((flags & ~(uint64_t)(MIPS_MREMAP_MAYMOVE |
                             MIPS_MREMAP_FIXED)) != 0U ||
        (((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) &&
         (((flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U) ||
          ((new_va & (MIPS64_PAGE_SIZE - 1U)) != 0U)))) {
        return -(int64_t)EINVAL;
    }
    old_size = page_up(old_len);
    new_size = page_up(new_len);
    if (old_size < MIPS64_PAGE_SIZE || old_size > ctx->task_size ||
        old_va > ctx->task_size - old_size ||
        new_size < MIPS64_PAGE_SIZE || new_size > ctx->task_size) {
        return -(int64_t)EINVAL;
    }
    if (!mips_mem_ok(ctx, old_va, old_size, 0U)) {
        return -(int64_t)ENOMEM;
    }
    prot = remap_prot(old_va);
    if (new_size <= old_size &&
        ((flags & (uint64_t)MIPS_MREMAP_FIXED) == 0U)) {
        if (new_size < old_size) {
            rc = mips_mem_unmap(ctx, old_va + new_size,
                                old_size - new_size);
            if (rc != 0) {
                return (int64_t)rc;
            }
        }
        return (int64_t)old_va;
    }
    if ((flags & (uint64_t)MIPS_MREMAP_FIXED) == 0U &&
        (flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U) {
        uint64_t ext = old_va + old_size;

        if (old_va > ctx->task_size - new_size) {
            return -(int64_t)ENOMEM;
        }
        if (mips_mem_ok(ctx, old_va, new_size, 0U)) {
            return (int64_t)old_va;
        }
        if (remap_hole(ctx->task_size, ext, new_size - old_size) != ext) {
            return -(int64_t)ENOMEM;
        }
        rc = mips_mem_map(ctx, ext, new_size - old_size, prot, "remap");
        return rc != 0 ? (int64_t)rc : (int64_t)old_va;
    }
    if ((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) {
        dst = new_va;
        if (dst > ctx->task_size - new_size ||
            !(dst + new_size <= old_va || old_va + old_size <= dst)) {
            return -(int64_t)EINVAL;
        }
    } else {
        uint64_t cand = ctx->mmap_base != 0U ? ctx->mmap_base : old_va;

        dst = remap_hole(ctx->task_size, cand, new_size);
        if (dst == 0U) {
            return -(int64_t)ENOMEM;
        }
    }
    mips_qs_begin(ctx);
    mem_lock();
    {
        static mips64_region_t remap_saved[MIPS64_MAX_REGIONS];
        size_t remap_saved_count =
            mips_mem_snapshot(remap_saved, MIPS64_MAX_REGIONS);
        uint64_t kept = old_size < new_size ? old_size : new_size;
        uint8_t *from = (uint8_t *)mips64_guest_ptr(ctx, old_va);
        uint8_t *to = (uint8_t *)mips64_guest_ptr(ctx, dst);
        uint8_t *rbuf = NULL;

        if (split_at(ctx->task_size, old_va) != 0 ||
            (old_va + old_size < ctx->task_size &&
             split_at(ctx->task_size, old_va + old_size) != 0) ||
            split_at(ctx->task_size, dst) != 0 ||
            (dst + new_size < ctx->task_size &&
             split_at(ctx->task_size, dst + new_size) != 0)) {
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return -(int64_t)ENOMEM;
        }
        rbuf = (uint8_t *)malloc((size_t)kept);
        if (rbuf == NULL) {
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return -(int64_t)ENOMEM;
        }
        if ((prot & MIPS_PROT_READ) == 0U &&
            mprotect(from, (size_t)kept, PROT_READ) != 0) {
            int e = errno;

            free(rbuf);
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return -(int64_t)e;
        }
        memcpy(rbuf, from, (size_t)kept);
        /* Unmap old_va before replacing dst so any failure on the
         * source unmap leaves dst completely untouched. */
        rc = mips_mem_unmap(ctx, old_va, old_size);
        if (rc != 0) {
            if ((prot & MIPS_PROT_READ) == 0U) {
                (void)mprotect(from, (size_t)kept, host_prot(prot));
            }
            free(rbuf);
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return (int64_t)rc;
        }
        rc = ((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) ?
             mips_mem_map_replace(ctx, dst, new_size,
                                  prot | MIPS_PROT_WRITE, "remap") :
             mips_mem_map(ctx, dst, new_size,
                          prot | MIPS_PROT_WRITE, "remap");
        if (rc != 0) {
            free(rbuf);
            mem_unlock();
            mips_qs_abort(ctx);
            return (int64_t)rc;
        }
        memcpy(to, rbuf, (size_t)kept);
        free(rbuf);
        if ((prot & MIPS_PROT_WRITE) == 0U &&
            mips_mem_protect(ctx, dst, new_size, prot) != 0) {
            mem_unlock();
            mips_qs_abort(ctx);
            return -(int64_t)ENOMEM;
        }
    }
    mem_unlock();
    mips_qs_commit(ctx);
    return (int64_t)dst;
}

/* Reserve task_size host VA (PROT_NONE, MAP_NORESERVE) and record guest_base. */
int guest_mem_init(mips64_ctx_t *ctx)
{
    uint64_t size;
    void *base;

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    size = mips_task_size(ctx);
    mem_lock();
    if (ctx->guest_base != 0U && ctx->task_size != 0U) {
        (void)munmap((void *)(uintptr_t)ctx->guest_base,
                     (size_t)ctx->task_size);
        ctx->guest_base = 0U;
    }
    base = mmap(NULL, (size_t)size, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) {
        ctx->guest_base = 0U;
        ctx->task_size = 0U;
        g_region_count = 0U;
        mem_unlock();
        return MIPS_FAULT;
    }
    ctx->guest_base = (uint64_t)(uintptr_t)base;
    ctx->task_size = size;
    g_region_count = 0U;
    ctx->brk_base = 0U;
    ctx->brk_curr = 0U;
    mem_unlock();
    return 0;
}

/* Fetch cover for [pc, pc+4): an empty table (unit-test scratch
 * window) allows everything; otherwise exactly one recorded region
 * must span the word and carry EXEC. Lock held across the walk. */
int mips_mem_exec_ok(const mips64_ctx_t *ctx, uint64_t pc)
{
    size_t i;
    int ok = 0;

    if (ctx == NULL) {
        return 0;
    }
    mem_lock();
    if (g_region_count == 0U) {
        ok = 1;
    } else {
        for (i = 0; i < g_region_count; i++) {
            if (g_regions[i].start <= pc &&
                pc + 4U <= g_regions[i].end) {
                ok = (g_regions[i].prot & MIPS_PROT_EXEC) != 0U;
                break;
            }
        }
    }
    mem_unlock();
    return ok;
}

/* First gap of at least size bytes at or after cand (page granular),
 * 0 when none. Under the lock so the result is atomic with respect
 * to other table writers; the caller still maps via mips_mem_map,
 * which re-checks overlap (a lost race surfaces as -EEXIST). */
uint64_t mips_mem_hole_after(const mips64_ctx_t *ctx, uint64_t cand,
                             uint64_t size)
{
    uint64_t out = 0U;
    size_t i;

    if (ctx == NULL) {
        return 0U;
    }
    if (cand + size < cand || cand + size > ctx->task_size) {
        return 0U;
    }
    mem_lock();
    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].end <= cand) {
            continue;
        }
        if (g_regions[i].start >= cand + size) {
            out = cand;
            break;
        }
        cand = g_regions[i].end;
        if (cand + size < cand) {
            cand = 0U;
            break;
        }
    }
    if (out == 0U && cand != 0U) {
        if (cand + size < cand || cand + size > ctx->task_size) {
            cand = 0U;
        }
        out = cand;
    }
    mem_unlock();
    return out;
}

/* Live region count for /proc/self/maps style walks. */
size_t mips_mem_region_count(void)
{
    size_t n;

    mem_lock();
    n = g_region_count;
    mem_unlock();
    return n;
}

/* Copy out one region descriptor; 0 on success, -1 past the end. */
int mips_mem_region_at(size_t idx, uint64_t *start, uint64_t *end,
                       uint32_t *prot)
{
    int rc = -1;

    mem_lock();
    if (idx < g_region_count) {
        if (start != NULL) {
            *start = g_regions[idx].start;
        }
        if (end != NULL) {
            *end = g_regions[idx].end;
        }
        if (prot != NULL) {
            *prot = g_regions[idx].prot;
        }
        rc = 0;
    }
    mem_unlock();
    return rc;
}

/* Drop every region record (fresh image load; host mappings are owned
 * by the reservation lifecycle, not the table). */
void mips_mem_reset(void)
{
    mem_lock();
    g_region_count = 0U;
    mips_vm_file_unmap_hook(0U, ~(uint64_t)0U);
    mem_unlock();
}

/* Copy up to cap records out; returns the live count. The caller
 * sizes the buffer at MIPS64_MAX_REGIONS for a lossless snapshot
 * (exec failure rollback). */
size_t mips_mem_snapshot(mips64_region_t *out, size_t cap)
{
    size_t n;
    size_t i;

    if (out == NULL || cap == 0U) {
        return 0U;
    }
    mem_lock();
    n = g_region_count;
    for (i = 0U; i < n && i < cap; i++) {
        out[i] = g_regions[i];
    }
    mem_unlock();
    return n;
}

/* Replace the table with a snapshot (exec failure rollback). */
void mips_mem_restore(const mips64_region_t *regs, size_t count)
{
    size_t i;

    if (regs == NULL) {
        return;
    }
    if (count > MIPS64_MAX_REGIONS) {
        count = MIPS64_MAX_REGIONS;
    }
    mem_lock();
    for (i = 0U; i < count; i++) {
        g_regions[i] = regs[i];
    }
    g_region_count = count;
    mem_unlock();
}
