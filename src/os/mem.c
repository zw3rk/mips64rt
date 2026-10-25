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
 * Tracked in ctx->regions for maps-gap queries.
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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

/* macOS hides MAP_NORESERVE under strict feature macros; the reservation
 * is an overcommit hint only, so degrading to 0 there is correct. */
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

/* Guest prot bits live frozen in core/cpu.h (POSIX numbering); the
 * loader translates ELF p_flags (opposite corners) at map time. */

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

    if (ctx == NULL || len == 0U) {
        return ctx != NULL && len == 0U;
    }
    if (len > ctx->task_size || va > ctx->task_size - len) {
        return 0;
    }
    end = va + len;
    cur = va;
    for (i = 0; i < ctx->region_count; i++) {
        const mips64_region_t *r = &ctx->regions[i];

        if (r->start > cur) {
            return 0; /* sorted gap: nothing later can cover cur */
        }
        if (r->end <= cur) {
            continue;
        }
        if ((r->prot & need) != need) {
            return 0;
        }
        cur = r->end;
        if (cur >= end) {
            return 1;
        }
    }
    return cur >= end;
}

/* Split the region containing va so a region starts at va. Page
 * granularity: va must be page aligned (va == 0 and va == task_size are
 * boundaries that need no split). Returns 0, or -ENOMEM when the table
 * is full. */
static int split_at(mips64_ctx_t *ctx, uint64_t va)
{
    size_t i;

    if (va == 0U || va >= ctx->task_size) {
        return 0;
    }
    if ((va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    for (i = 0; i < ctx->region_count; i++) {
        size_t free;

        if (va <= ctx->regions[i].start) {
            return 0; /* sorted: no later region can contain va */
        }
        if (va >= ctx->regions[i].end) {
            continue;
        }
        if (ctx->region_count >= MIPS64_MAX_REGIONS) {
            return -ENOMEM;
        }
        free = ctx->region_count;
        ctx->regions[free] = ctx->regions[i];
        ctx->regions[free].start = va;
        ctx->regions[i].end = va;
        ctx->region_count++;
        /* Insertion-sort the tail back down by start (at most one step
         * per split keeps this linear and allocation-free). */
        while (free > 0U &&
               ctx->regions[free].start < ctx->regions[free - 1U].start) {
            mips64_region_t tmp = ctx->regions[free];

            ctx->regions[free] = ctx->regions[free - 1U];
            ctx->regions[free - 1U] = tmp;
            free--;
        }
        return 0;
    }
    return 0;
}

/* Insert [va, va+len) sorted by start, merging contiguous neighbours
 * with identical prot. Caller guarantees no overlap and table space. */
static void insert_region(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                          uint32_t prot, const char *tag)
{
    size_t at = ctx->region_count;
    size_t i;

    for (i = 0; i < ctx->region_count; i++) {
        if (va < ctx->regions[i].start) {
            at = i;
            break;
        }
    }
    for (i = ctx->region_count; i > at; i--) {
        ctx->regions[i] = ctx->regions[i - 1U];
    }
    ctx->regions[at].start = va;
    ctx->regions[at].end = va + len;
    ctx->regions[at].prot = prot;
    ctx->regions[at].flags = 0U;
    copy_tag(ctx->regions[at].name, tag);
    ctx->region_count++;
    /* Merge with the previous neighbour when contiguous and identical. */
    if (at > 0U && ctx->regions[at - 1U].end == va &&
        ctx->regions[at - 1U].prot == prot) {
        ctx->regions[at - 1U].end = va + len;
        for (i = at; i + 1U < ctx->region_count; i++) {
            ctx->regions[i] = ctx->regions[i + 1U];
        }
        ctx->region_count--;
        at--;
    }
    /* Merge with the next neighbour when contiguous and identical. */
    if (at + 1U < ctx->region_count &&
        ctx->regions[at].end == ctx->regions[at + 1U].start &&
        ctx->regions[at].prot == ctx->regions[at + 1U].prot) {
        ctx->regions[at].end = ctx->regions[at + 1U].end;
        for (i = at + 1U; i + 1U < ctx->region_count; i++) {
            ctx->regions[i] = ctx->regions[i + 1U];
        }
        ctx->region_count--;
    }
}

/*
 * Map [va, va+len) inside the reservation with the given guest prot.
 * The address must be page aligned; a positive length rounds up to a
 * 4 KiB multiple for the mapped extent (contract section 2.1), so
 * callers may pass byte-exact sizes. The host mapping is MAP_FIXED
 * anonymous with PROT_EXEC stripped (W^X). Returns 0, -EINVAL,
 * -EEXIST, -ENOMEM.
 */
int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len, uint32_t prot,
                 const char *tag)
{
    void *got;

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
    {
        size_t i;

        for (i = 0; i < ctx->region_count; i++) {
            if (va < ctx->regions[i].end &&
                ctx->regions[i].start < va + len) {
                return -EEXIST;
            }
        }
    }
    if (ctx->region_count >= MIPS64_MAX_REGIONS) {
        return -ENOMEM;
    }
    got = mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
               host_prot(prot), MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
               -1, 0);
    if (got == MAP_FAILED) {
        return -ENOMEM;
    }
    insert_region(ctx, va, len, prot, tag);
    dbt_invalidate_range(va, len);
    return 0;
}

/* Release [va, va+len): drop covered region records and punch a
 * PROT_NONE hole so the reservation stays contiguous. Valid aligned
 * args always succeed (Linux munmap semantics on unmapped pages). */
int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len)
{
    uint64_t end;
    size_t i;
    size_t w;

    if (ctx == NULL || ctx->guest_base == 0U) {
        return -EINVAL;
    }
    if (len == 0U || (va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    len = page_up(len);
    if (len > ctx->task_size || va > ctx->task_size - len) {
        return -EINVAL;
    }
    end = va + len;
    if (split_at(ctx, va) != 0) {
        return -ENOMEM;
    }
    if (end < ctx->task_size && split_at(ctx, end) != 0) {
        return -ENOMEM;
    }
    w = 0U;
    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].start >= va && ctx->regions[i].end <= end) {
            continue;
        }
        ctx->regions[w] = ctx->regions[i];
        w++;
    }
    ctx->region_count = w;
    (void)mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
               PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    dbt_invalidate_range(va, len);
    return 0;
}

/* Change protection on a fully mapped range; -ENOMEM when any byte is
 * unmapped. The host mapping keeps PROT_EXEC stripped (W^X). A zero
 * length succeeds as a no-op and a positive length rounds up to a 4
 * KiB multiple (contract section 2.1: `mprotect` alignment, `munmap`
 * `len == 0` differs). */
int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                     uint32_t prot)
{
    uint64_t end;
    size_t i;

    if (ctx == NULL || ctx->guest_base == 0U) {
        return -EINVAL;
    }
    if ((va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    if ((prot & ~(MIPS_PROT_READ | MIPS_PROT_WRITE | MIPS_PROT_EXEC)) != 0U) {
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
    if (!mips_mem_ok(ctx, va, len, 0U)) {
        return -ENOMEM;
    }
    if (split_at(ctx, va) != 0) {
        return -ENOMEM;
    }
    if (end < ctx->task_size && split_at(ctx, end) != 0) {
        return -ENOMEM;
    }
    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].start >= va && ctx->regions[i].end <= end) {
            ctx->regions[i].prot = prot;
        }
    }
    if (mprotect((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
                 host_prot(prot)) != 0) {
        return -ENOMEM;
    }
    dbt_invalidate_range(va, len);
    return 0;
}

/* mremap flags (Linux uapi, arch-independent values). */
#define MIPS_MREMAP_MAYMOVE 1U
#define MIPS_MREMAP_FIXED 2U

/* First hole of at least size bytes at or after cand; 0 when none. */
static uint64_t remap_hole(const mips64_ctx_t *ctx, uint64_t cand,
                           uint64_t size)
{
    size_t i;

    if (size == 0U || size > ctx->task_size ||
        cand > ctx->task_size - size) {
        return 0U;
    }
    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].end <= cand) {
            continue;
        }
        if (ctx->regions[i].start >= cand + size) {
            return cand;
        }
        cand = ctx->regions[i].end;
        if (cand > ctx->task_size - size) {
            return 0U;
        }
    }
    return cand;
}

/* Protection of the region covering va (caller guarantees mapped). */
static uint32_t remap_prot(const mips64_ctx_t *ctx, uint64_t va)
{
    size_t i;

    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].start <= va && va < ctx->regions[i].end) {
            return ctx->regions[i].prot;
        }
    }
    return 0U;
}

/*
 * Resize/move a mapping (contract section 2.1): old address alignment
 * and zero sizes are -EINVAL, unknown flags are -EINVAL, FIXED needs
 * MAYMOVE. Lengths round up to 4 KiB; the old range must be fully
 * mapped (-ENOMEM otherwise). Shrink and in-place growth keep the old
 * address; MAYMOVE relocates through a fresh hole (contents copied);
 * FIXED unmaps the destination first and refuses overlap. Returns the
 * new address, or a negative errno.
 */
int64_t mips_mem_remap(mips64_ctx_t *ctx, uint64_t old_va, uint64_t old_len,
                       uint64_t new_len, uint64_t flags, uint64_t new_va)
{
    uint64_t old_size;
    uint64_t new_size;
    uint32_t prot;
    uint64_t dst;
    int rc;

    if (ctx == NULL || ctx->guest_base == 0U) {
        return -(int64_t)EINVAL;
    }
    if ((flags & ~(uint64_t)(MIPS_MREMAP_MAYMOVE |
                             MIPS_MREMAP_FIXED)) != 0U) {
        return -(int64_t)EINVAL;
    }
    if (((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) &&
        ((flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U)) {
        return -(int64_t)EINVAL;
    }
    if (old_len == 0U || new_len == 0U) {
        return -(int64_t)EINVAL;
    }
    if ((old_va & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return -(int64_t)EINVAL;
    }
    if (((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) &&
        ((new_va & (MIPS64_PAGE_SIZE - 1U)) != 0U)) {
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
    prot = remap_prot(ctx, old_va);
    if (new_size <= old_size &&
        ((flags & (uint64_t)MIPS_MREMAP_FIXED) == 0U)) {
        /* Shrink in place; the tail is dropped, contents kept. A
         * FIXED request always relocates (even when shrinking). */
        if (new_size < old_size) {
            rc = mips_mem_unmap(ctx, old_va + new_size,
                                old_size - new_size);
            if (rc != 0) {
                return (int64_t)rc;
            }
        }
        return (int64_t)old_va;
    }
    if ((flags & (uint64_t)MIPS_MREMAP_FIXED) != 0U) {
        dst = new_va;
        if (dst > ctx->task_size - new_size) {
            return -(int64_t)EINVAL;
        }
        /* Fixed moves must not overlap the source (the destination
         * is unmapped first, which would destroy overlapped data). */
        if (!(dst + new_size <= old_va || old_va + old_size <= dst)) {
            return -(int64_t)EINVAL;
        }
        rc = mips_mem_unmap(ctx, dst, new_size);
        if (rc != 0) {
            return (int64_t)rc;
        }
    } else if ((flags & (uint64_t)MIPS_MREMAP_MAYMOVE) == 0U) {
        uint64_t ext = old_va + old_size;

        /* Grow in place or fail. */
        if (old_va > ctx->task_size - new_size) {
            return -(int64_t)ENOMEM;
        }
        if (mips_mem_ok(ctx, old_va, new_size, 0U)) {
            return (int64_t)old_va; /* extension already mapped */
        }
        if (remap_hole(ctx, ext, new_size - old_size) != ext) {
            return -(int64_t)ENOMEM;
        }
        rc = mips_mem_map(ctx, ext, new_size - old_size, prot, "remap");
        if (rc != 0) {
            return (int64_t)rc;
        }
        return (int64_t)old_va;
    } else {
        uint64_t cand = ctx->mmap_base != 0U ? ctx->mmap_base : old_va;

        /* Relocate through a fresh hole; the old image stays intact
         * until the copy lands. */
        dst = remap_hole(ctx, cand, new_size);
        if (dst == 0U) {
            return -(int64_t)ENOMEM;
        }
    }
    rc = mips_mem_map(ctx, dst, new_size, prot, "remap");
    if (rc != 0) {
        return (int64_t)rc;
    }
    {
        /* A FIXED shrink relocates fewer bytes than the source holds. */
        uint64_t kept = old_size < new_size ? old_size : new_size;
        uint8_t *to = (uint8_t *)mips64_guest_ptr(ctx, dst);
        const uint8_t *from = (const uint8_t *)mips64_guest_ptr(ctx,
                                                                old_va);

        memcpy(to, from, (size_t)kept);
    }
    rc = mips_mem_unmap(ctx, old_va, old_size);
    if (rc != 0) {
        return (int64_t)rc;
    }
    return (int64_t)dst;
}

/*
 * Reserve task_size host VA (PROT_NONE, MAP_NORESERVE) and record
 * guest_base. The size follows ctx->is_n32 (N64 1ULL<<40, N32
 * 0x7fff8000); ctx->task_size records the choice. Re-init drops the
 * previous reservation and its region records.
 */
int guest_mem_init(mips64_ctx_t *ctx)
{
    uint64_t size;
    void *base;

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    size = mips_task_size(ctx);
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
        return MIPS_FAULT;
    }
    ctx->guest_base = (uint64_t)(uintptr_t)base;
    ctx->task_size = size;
    ctx->region_count = 0U;
    ctx->brk_base = 0U;
    ctx->brk_curr = 0U;
    return 0;
}

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
