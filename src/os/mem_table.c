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
    mem_atfork_child();
    (void)pthread_atfork(NULL, NULL, mem_atfork_child);
}

static _Thread_local int mem_preempt_depth;
static _Thread_local sigset_t mem_preempt_saved;

static void mem_lock(void)
{
    if (mem_preempt_depth++ == 0)
        mips_qs_block_preempt(&mem_preempt_saved);
    (void)pthread_once(&g_mem_once, mem_lock_init);
    (void)pthread_mutex_lock(&g_mem_mu);
}

static void mem_unlock(void)
{
    (void)pthread_mutex_unlock(&g_mem_mu);
    if (--mem_preempt_depth == 0)
        mips_qs_unblock_preempt(&mem_preempt_saved);
}

static uint64_t page_up(uint64_t v)
{
    return (v + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
}
static int host_prot(uint32_t prot)
{
    return ((prot & MIPS_PROT_READ) ? PROT_READ : 0) |
           ((prot & MIPS_PROT_WRITE) ? PROT_WRITE : 0);
}
static void copy_tag(char *dst, const char *tag)
{
    size_t i = 0;
    if (tag != NULL) {
        while (i + 1 < sizeof(((mips64_region_t *)0)->name) && tag[i] != '\0') {
            dst[i] = tag[i];
            i++;
        }
    }
    dst[i] = '\0';
}
__attribute__((weak)) void dbt_invalidate_range(uint64_t va, uint64_t len) { (void)va; (void)len; }
__attribute__((weak)) void mips_qs_begin(mips64_ctx_t *ctx) { (void)ctx; }
__attribute__((weak)) void mips_qs_commit(mips64_ctx_t *ctx) { (void)ctx; }
__attribute__((weak)) void mips_qs_abort(mips64_ctx_t *ctx) { (void)ctx; }
__attribute__((weak)) int mips_qs_has_peers(void) { return 0; }
__attribute__((weak)) void mips_vm_file_unmap_hook(uint64_t va, uint64_t len) { (void)va; (void)len; }
__attribute__((weak)) void mips_vm_file_protect_hook(uint64_t va, uint64_t len, uint32_t prot) { (void)va; (void)len; (void)prot; }
__attribute__((weak)) int mips_vm_file_read_page(mips64_ctx_t *ctx,
                                                 uint64_t page_va,
                                                 uint8_t *out_page)
{
    (void)ctx; (void)page_va; (void)out_page; return 0;
}
__attribute__((weak)) void mips_vm_file_restore(mips64_ctx_t *ctx,
                                                uint64_t va1, uint64_t len1,
                                                uint64_t va2, uint64_t len2)
{
    (void)ctx; (void)va1; (void)len1; (void)va2; (void)len2;
}
__attribute__((weak)) void mips_vm_file_remap_hook(mips64_ctx_t *ctx,
                                                   uint64_t old_va,
                                                   uint64_t old_size,
                                                   uint64_t dst_va,
                                                   uint64_t new_size)
{
    (void)ctx; (void)old_va; (void)old_size; (void)dst_va; (void)new_size;
}

static int split_at(uint64_t task_size, uint64_t va)
{
    size_t i;

    if (va == 0U || va >= task_size)
        return 0;
    if ((va & (MIPS64_PAGE_SIZE - 1U)) != 0U)
        return -EINVAL;
    for (i = 0; i < g_region_count; i++) {
        size_t free;

        if (va <= g_regions[i].start)
            return 0;
        if (va >= g_regions[i].end)
            continue;
        if (g_region_count >= MIPS64_MAX_REGIONS)
            return -ENOMEM;
        free = g_region_count;
        g_regions[free] = g_regions[i];
        g_regions[free].start = va;
        g_regions[i].end = va;
        g_region_count++;
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

static void insert_region(uint64_t va, uint64_t len, uint32_t prot,
                          const char *tag)
{
    size_t at = g_region_count, i;

    for (i = 0; i < g_region_count; i++) {
        if (va < g_regions[i].start) {
            at = i;
            break;
        }
    }
    for (i = g_region_count; i > at; i--)
        g_regions[i] = g_regions[i - 1U];
    g_regions[at].start = va;
    g_regions[at].end = va + len;
    g_regions[at].prot = prot;
    g_regions[at].flags = 0U;
    copy_tag(g_regions[at].name, tag);
    g_region_count++;
    if (at > 0U && g_regions[at - 1U].end == va &&
        g_regions[at - 1U].prot == prot &&
        strcmp(g_regions[at - 1U].name, g_regions[at].name) == 0) {
        g_regions[at - 1U].end = va + len;
        for (i = at; i + 1U < g_region_count; i++)
            g_regions[i] = g_regions[i + 1U];
        g_region_count--;
        at--;
    }
    if (at + 1U < g_region_count &&
        g_regions[at].end == g_regions[at + 1U].start &&
        g_regions[at].prot == g_regions[at + 1U].prot &&
        strcmp(g_regions[at].name, g_regions[at + 1U].name) == 0) {
        g_regions[at].end = g_regions[at + 1U].end;
        for (i = at + 1U; i + 1U < g_region_count; i++)
            g_regions[i] = g_regions[i + 1U];
        g_region_count--;
    }
}

int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                uint32_t need)
{
    uint64_t end, cur;
    size_t i;
    int ok = 0;

    if (ctx == NULL || len == 0U)
        return ctx != NULL && len == 0U;
    if (len > ctx->task_size || va > ctx->task_size - len)
        return 0;
    end = va + len;
    cur = va;
    mem_lock();
    for (i = 0; i < g_region_count; i++) {
        const mips64_region_t *r = &g_regions[i];

        if (r->start > cur)
            break;
        if (r->end <= cur)
            continue;
        if ((r->prot & need) != need)
            break;
        cur = r->end;
        if (cur >= end) {
            ok = 1;
            break;
        }
    }
    if (cur >= end)
        ok = 1;
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
            uint64_t hps = (uint64_t)sysconf(_SC_PAGESIZE);
            uint64_t hlo = va & ~(hps - 1u), hhi = (va + len + hps - 1u) & ~(hps - 1u);
            got = mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
                       host_prot(prot), MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            if (got == MAP_FAILED && hps > MIPS64_PAGE_SIZE &&
                mprotect((void *)(uintptr_t)(ctx->guest_base + hlo),
                         (size_t)(hhi - hlo), PROT_READ | PROT_WRITE) == 0) {
                memset((void *)(uintptr_t)(ctx->guest_base + va), 0, (size_t)len);
                got = (void *)(uintptr_t)(ctx->guest_base + va);
            }
            if (got == MAP_FAILED) {
                rc = -ENOMEM;
            } else {
                insert_region(va, len, prot, tag);
                dbt_invalidate_range(va, len);
            }
        }
    }
    mem_unlock();
    if (rc != 0)
        mips_qs_abort(ctx);
    else
        mips_qs_commit(ctx);
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
                        (size_t)len, host_prot(prot)) != 0 &&
               sysconf(_SC_PAGESIZE) <= (long)MIPS64_PAGE_SIZE) {
        rc = -errno;
    } else {
        for (i = 0; i < g_region_count; i++) {
            if (g_regions[i].start >= va && g_regions[i].end <= end)
                g_regions[i].prot = prot;
        }
        mips_vm_file_protect_hook(va, len, prot);
        dbt_invalidate_range(va, len);
    }
    mem_unlock();
    if (rc != 0)
        mips_qs_abort(ctx);
    else
        mips_qs_commit(ctx);
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

static uint32_t remap_prot(uint64_t va, char *tag_out)
{
    size_t i;

    copy_tag(tag_out, "remap");
    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].start <= va && va < g_regions[i].end) {
            copy_tag(tag_out, g_regions[i].name);
            return g_regions[i].prot;
        }
    }
    return 0U;
}

static int remap_host_prot_at(const mips64_region_t *regs, size_t nregs,
                              uint64_t hlo_va, uint64_t hhi_va)
{
    size_t i;
    int hp = 0;

    for (i = 0u; i < nregs; i++)
        if (regs[i].end > hlo_va && regs[i].start < hhi_va)
            hp |= host_prot(regs[i].prot);
    return hp;
}

static int remap_copy_span(mips64_ctx_t *ctx, uint8_t *buf,
                           const mips64_region_t *regs, size_t nregs,
                           uint64_t span_va, uint64_t span_len)
{
    long ps = sysconf(_SC_PAGESIZE);
    uint64_t hpsz = (uint64_t)(ps > 4096L ? ps : 4096L), hmask = hpsz - 1u;
    size_t ri;

    for (ri = 0u; ri < nregs; ri++) {
        uint64_t lo = regs[ri].start > span_va ? regs[ri].start : span_va;
        uint64_t hi = regs[ri].end < span_va + span_len ?
                      regs[ri].end : span_va + span_len;
        uint64_t pva;

        for (pva = lo; pva < hi; pva += MIPS64_PAGE_SIZE) {
            uint8_t *out = buf + (pva - span_va);
            uint8_t *hp = (uint8_t *)mips64_guest_ptr(ctx, pva);
            uintptr_t haddr = (uintptr_t)hp & ~(uintptr_t)hmask;
            uint64_t hlo = (haddr > (uintptr_t)ctx->guest_base) ?
                           (uint64_t)(haddr - (uintptr_t)ctx->guest_base) : 0u;
            int oprot = remap_host_prot_at(regs, nregs, hlo, hlo + hpsz);

            if (mips_vm_file_read_page(ctx, pva, out) != 0)
                continue;
            if ((regs[ri].prot & MIPS_PROT_READ) == 0U &&
                mprotect((void *)haddr, (size_t)hpsz, oprot | PROT_READ) != 0)
                return -errno;
            memcpy(out, hp, MIPS64_PAGE_SIZE);
            if ((regs[ri].prot & MIPS_PROT_READ) == 0U)
                (void)mprotect((void *)haddr, (size_t)hpsz, oprot);
        }
    }
    return 0;
}

int64_t mips_mem_remap(mips64_ctx_t *ctx, uint64_t old_va, uint64_t old_len,
                       uint64_t new_len, uint64_t flags, uint64_t new_va)
{
    char tail_tag[sizeof(((mips64_region_t *)0)->name)];
    uint64_t old_size, new_size, dst;
    uint32_t prot;
    int rc;

    if (ctx == NULL || ctx->guest_base == 0U || old_len == 0U ||
        new_len == 0U || (old_va & (MIPS64_PAGE_SIZE - 1U)) != 0U)
        return -(int64_t)EINVAL;
    if ((flags & ~(uint64_t)(MIPS_MREMAP_MAYMOVE | MIPS_MREMAP_FIXED)) != 0U ||
        (((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) &&
         (((flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U) ||
          ((new_va & (MIPS64_PAGE_SIZE - 1U)) != 0U))))
        return -(int64_t)EINVAL;
    old_size = page_up(old_len);
    new_size = page_up(new_len);
    if (old_size < MIPS64_PAGE_SIZE || old_size > ctx->task_size ||
        old_va > ctx->task_size - old_size ||
        new_size < MIPS64_PAGE_SIZE || new_size > ctx->task_size)
        return -(int64_t)EINVAL;
    if (!mips_mem_ok(ctx, old_va, old_size, 0U))
        return -(int64_t)ENOMEM;
    prot = remap_prot(old_va + old_size - MIPS64_PAGE_SIZE, tail_tag);
    if (new_size <= old_size && ((flags & (uint64_t)MIPS_MREMAP_FIXED) == 0U)) {
        if (new_size < old_size) {
            rc = mips_mem_unmap(ctx, old_va + new_size, old_size - new_size);
            if (rc != 0)
                return (int64_t)rc;
        }
        return (int64_t)old_va;
    }
    if ((flags & (uint64_t)MIPS_MREMAP_FIXED) == 0U &&
        (flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U) {
        uint64_t ext = old_va + old_size;

        if (old_va > ctx->task_size - new_size)
            return -(int64_t)ENOMEM;
        if (mips_mem_ok(ctx, old_va, new_size, 0U))
            return (int64_t)old_va;
        if (remap_hole(ctx->task_size, ext, new_size - old_size) != ext)
            return -(int64_t)ENOMEM;
        rc = mips_mem_map(ctx, ext, new_size - old_size, prot, tail_tag);
        if (rc == 0)
            mips_vm_file_remap_hook(ctx, old_va, old_size, old_va, new_size);
        return rc != 0 ? (int64_t)rc : (int64_t)old_va;
    }
    if ((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) {
        dst = new_va;
        if (dst > ctx->task_size - new_size ||
            !(dst + new_size <= old_va || old_va + old_size <= dst))
            return -(int64_t)EINVAL;
    } else {
        uint64_t cand = ctx->mmap_base != 0U ? ctx->mmap_base : old_va;

        dst = remap_hole(ctx->task_size, cand, new_size);
        if (dst == 0U)
            return -(int64_t)ENOMEM;
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
        uint8_t *rbuf = (uint8_t *)calloc(1u, (size_t)old_size);
        uint8_t *dbuf = (uint8_t *)calloc(1u, (size_t)new_size);
        size_t ri, w;

        mips_vm_pages_snapshot();
        if (rbuf == NULL || dbuf == NULL ||
            split_at(ctx->task_size, old_va) != 0 ||
            (old_va + old_size < ctx->task_size &&
             split_at(ctx->task_size, old_va + old_size) != 0) ||
            split_at(ctx->task_size, dst) != 0 ||
            (dst + new_size < ctx->task_size &&
             split_at(ctx->task_size, dst + new_size) != 0) ||
            g_region_count + 1U >= MIPS64_MAX_REGIONS) {
            free(rbuf);
            free(dbuf);
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return -(int64_t)ENOMEM;
        }
        rc = remap_copy_span(ctx, rbuf, remap_saved, remap_saved_count,
                             old_va, old_size);
        if (rc == 0)
            rc = remap_copy_span(ctx, dbuf, remap_saved, remap_saved_count,
                                 dst, new_size);
        if (rc != 0) {
            free(rbuf);
            free(dbuf);
            mips_mem_restore(remap_saved, remap_saved_count);
            mem_unlock();
            mips_qs_abort(ctx);
            return (int64_t)rc;
        }
        if (mmap(to, (size_t)new_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) ==
            MAP_FAILED) {
            rc = -ENOMEM;
        } else {
            memcpy(to, rbuf, (size_t)kept);
            for (ri = 0u; ri < remap_saved_count && rc == 0; ri++) {
                uint64_t olo = remap_saved[ri].start > old_va ?
                               remap_saved[ri].start : old_va;
                uint64_t ohi = remap_saved[ri].end < old_va + kept ?
                               remap_saved[ri].end : old_va + kept;
                if (olo < ohi &&
                    mprotect(to + (olo - old_va), (size_t)(ohi - olo),
                             host_prot(remap_saved[ri].prot)) != 0) {
                    rc = -ENOMEM;
                }
            }
            if (rc == 0 && new_size > kept &&
                mprotect(to + kept, (size_t)(new_size - kept),
                         host_prot(prot)) != 0) {
                rc = -ENOMEM;
            }
            if (rc == 0 &&
                mmap(from, (size_t)old_size, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
                     -1, 0) == MAP_FAILED) {
                rc = -ENOMEM;
            }
        }
        if (rc != 0) {
            (void)mmap(from, (size_t)old_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
                       -1, 0);
            (void)mmap(to, (size_t)new_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
                       -1, 0);
            for (ri = 0u; ri < remap_saved_count; ri++) {
                uint64_t rlo = remap_saved[ri].start, rhi = remap_saved[ri].end;
                uint64_t olo = rlo > old_va ? rlo : old_va;
                uint64_t ohi = rhi < old_va + old_size ? rhi : old_va + old_size;
                uint64_t dlo = rlo > dst ? rlo : dst;
                uint64_t dhi = rhi < dst + new_size ? rhi : dst + new_size;
                if (dlo < dhi) {
                    uint8_t *hp = (uint8_t *)mips64_guest_ptr(ctx, dlo);
                    (void)mmap(hp, (size_t)(dhi - dlo), PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    memcpy(hp, dbuf + (dlo - dst), (size_t)(dhi - dlo));
                    (void)mprotect(hp, (size_t)(dhi - dlo),
                                   host_prot(remap_saved[ri].prot));
                }
                if (olo < ohi) {
                    uint8_t *hp = (uint8_t *)mips64_guest_ptr(ctx, olo);
                    (void)mmap(hp, (size_t)(ohi - olo), PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    memcpy(hp, rbuf + (olo - old_va), (size_t)(ohi - olo));
                    (void)mprotect(hp, (size_t)(ohi - olo),
                                   host_prot(remap_saved[ri].prot));
                }
            }
            mips_mem_restore(remap_saved, remap_saved_count);
            mips_vm_pages_restore();
            mips_vm_file_restore(ctx, old_va, old_size, dst, new_size);
            free(rbuf);
            free(dbuf);
            mem_unlock();
            mips_qs_abort(ctx);
            return (int64_t)rc;
        }
        w = 0u;
        for (ri = 0u; ri < g_region_count; ri++) {
            uint64_t rs = g_regions[ri].start, re = g_regions[ri].end;
            if ((rs >= old_va && re <= old_va + old_size) ||
                (rs >= dst && re <= dst + new_size))
                continue;
            g_regions[w++] = g_regions[ri];
        }
        g_region_count = w;
        for (ri = 0u; ri < remap_saved_count; ri++) {
            uint64_t olo = remap_saved[ri].start > old_va ?
                           remap_saved[ri].start : old_va;
            uint64_t ohi = remap_saved[ri].end < old_va + kept ?
                           remap_saved[ri].end : old_va + kept;
            if (olo < ohi) {
                insert_region(dst + (olo - old_va), ohi - olo,
                              remap_saved[ri].prot, remap_saved[ri].name);
            }
        }
        if (new_size > kept)
            insert_region(dst + kept, new_size - kept, prot, tail_tag);
        mips_vm_pages_remap(old_va, old_size, dst, new_size);
        mips_vm_file_remap_hook(ctx, old_va, old_size, dst, new_size);
        dbt_invalidate_range(old_va, old_size);
        dbt_invalidate_range(dst, new_size);
        free(rbuf);
        free(dbuf);
    }
    mem_unlock();
    mips_qs_commit(ctx);
    return (int64_t)dst;
}

int guest_mem_init(mips64_ctx_t *ctx)
{
    uint64_t size;
    void *base;

    if (ctx == NULL)
        return MIPS_FAULT;
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

int mips_mem_exec_ok(const mips64_ctx_t *ctx, uint64_t pc)
{
    size_t i;
    int ok = 0;

    if (ctx == NULL)
        return 0;
    mem_lock();
    if (g_region_count == 0U) {
        ok = 1;
    } else {
        for (i = 0; i < g_region_count; i++) {
            if (g_regions[i].start <= pc && pc + 4U <= g_regions[i].end) {
                ok = (g_regions[i].prot & MIPS_PROT_EXEC) != 0U;
                break;
            }
        }
    }
    mem_unlock();
    return ok;
}

uint64_t mips_mem_hole_after(const mips64_ctx_t *ctx, uint64_t cand,
                             uint64_t size)
{
    uint64_t out = 0U;
    size_t i;

    if (ctx == NULL || cand + size < cand || cand + size > ctx->task_size)
        return 0U;
    mem_lock();
    for (i = 0; i < g_region_count; i++) {
        if (g_regions[i].end <= cand)
            continue;
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
        if (cand + size < cand || cand + size > ctx->task_size)
            cand = 0U;
        out = cand;
    }
    mem_unlock();
    return out;
}

size_t mips_mem_region_count(void)
{
    size_t n;
    mem_lock();
    n = g_region_count;
    mem_unlock();
    return n;
}

int mips_mem_region_at(size_t idx, uint64_t *start, uint64_t *end,
                       uint32_t *prot)
{
    int rc = -1;
    mem_lock();
    if (idx < g_region_count) {
        if (start != NULL) *start = g_regions[idx].start;
        if (end != NULL) *end = g_regions[idx].end;
        if (prot != NULL) *prot = g_regions[idx].prot;
        rc = 0;
    }
    mem_unlock();
    return rc;
}

void mips_mem_reset(void)
{
    mem_lock();
    g_region_count = 0U;
    mips_vm_file_unmap_hook(0U, ~(uint64_t)0U);
    mem_unlock();
}

size_t mips_mem_snapshot(mips64_region_t *out, size_t cap)
{
    size_t n, i;
    if (out == NULL || cap == 0U)
        return 0U;
    mem_lock();
    n = g_region_count;
    for (i = 0U; i < n && i < cap; i++)
        out[i] = g_regions[i];
    mem_unlock();
    return n;
}

void mips_mem_restore(const mips64_region_t *regs, size_t count)
{
    size_t i;
    if (regs == NULL)
        return;
    if (count > MIPS64_MAX_REGIONS)
        count = MIPS64_MAX_REGIONS;
    mem_lock();
    for (i = 0U; i < count; i++)
        g_regions[i] = regs[i];
    g_region_count = count;
    mem_unlock();
}
