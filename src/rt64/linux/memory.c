/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/memory.h"

#include <stdlib.h>
#include <string.h>

#define VMA_LIMIT ((size_t)65536)
/* Unhinted-mmap search base from the frozen per-ABI placements
 * (SPEC 2.1, `core/cpu.h`): N64 searches from `MIPS64_N64_MMAP_BASE`,
 * N32 from `MIPS64_N32_MMAP_BASE`. The space limit selects the window. */
static uint64_t mmap_search_base(const mips64_space_t *space)
{
    if (space->limit > MIPS64_N64_MMAP_BASE)
        return MIPS64_N64_MMAP_BASE;
    return MIPS64_N32_MMAP_BASE;
}
#define G_MAP_SHARED UINT64_C(1)
#define G_MAP_PRIVATE UINT64_C(2)
#define G_MAP_FIXED UINT64_C(0x10)
#define G_MAP_ANONYMOUS UINT64_C(0x20)
#define G_MAP_NOREPLACE UINT64_C(0x100000)

static uint64_t error(unsigned int number)
{
    return UINT64_C(0) - number;
}

static unsigned int page_permissions(unsigned int requested)
{
    /* Linux MIPS's protection_map gives writable PTEs read permission too.
     * Retain requested protection in VMAs; execute-only stays execute-only. */
    return requested | ((requested & MIPS64_MEM_WRITE) != 0 ? MIPS64_MEM_READ : 0u);
}

static bool round_length(uint64_t length, uint64_t *rounded)
{
    if (length == 0 || length > UINT64_MAX - (MIPS64_PAGE_SIZE - 1))
        return false;
    *rounded = (length + MIPS64_PAGE_SIZE - 1) & MIPS64_PAGE_MASK;
    return true;
}

static bool valid_range(const mips64_linux_memory_t *memory, uint64_t address, uint64_t size)
{
    return address >= MIPS64_PAGE_SIZE && address < memory->space->limit &&
           size <= memory->space->limit - address;
}

static size_t lookup(const mips64_linux_memory_t *memory, uint64_t address)
{
    size_t left = 0, right = memory->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (memory->vmas[middle].end <= address)
            left = middle + 1;
        else
            right = middle;
    }
    return left;
}

static bool hole(const mips64_linux_memory_t *memory, uint64_t address, uint64_t size)
{
    size_t at = lookup(memory, address);
    return valid_range(memory, address, size) &&
           (at == memory->count || memory->vmas[at].start >= address + size);
}

static int compare_vmas(const void *left, const void *right)
{
    const mips64_vma_t *a = left, *b = right;
    return a->start < b->start ? -1 : a->start != b->start;
}

static bool compatible(const mips64_vma_t *a, const mips64_vma_t *b)
{
    return a->end == b->start && a->backing_id == b->backing_id &&
           a->offset + (a->end - a->start) == b->offset &&
           a->kind == b->kind && a->permissions == b->permissions &&
           a->may_permissions == b->may_permissions;
}

/* All allocations precede sparse-page mutation. Replace/remove the interval,
 * or protect its existing records while retaining backing/offset ownership.
 * This routine never changes live records. The caller publishes only after
 * the corresponding space operation succeeds. */
static mips64_vma_t *edit(const mips64_linux_memory_t *memory, uint64_t start, uint64_t end,
                      const mips64_vma_t *insert, bool protect, unsigned int permissions,
                      size_t *count)
{
    if (memory->count > VMA_LIMIT)
        return NULL;
    size_t capacity = memory->count + 3;
    mips64_vma_t *vmas = malloc(capacity * sizeof(*vmas));
    if (vmas == NULL)
        return NULL;
    size_t used = 0;
    for (size_t i = 0; i < memory->count; ++i) {
        mips64_vma_t original = memory->vmas[i];
        if (original.end <= start || original.start >= end) {
            vmas[used++] = original;
            continue;
        }
        if (original.start < start) {
            mips64_vma_t prefix = original;
            prefix.end = start;
            vmas[used++] = prefix;
        }
        if (protect) {
            mips64_vma_t changed = original;
            if (changed.start < start) {
                changed.offset += start - changed.start;
                changed.start = start;
            }
            if (changed.end > end)
                changed.end = end;
            changed.permissions = permissions;
            vmas[used++] = changed;
        }
        if (original.end > end) {
            mips64_vma_t suffix = original;
            suffix.offset += end - suffix.start;
            suffix.start = end;
            vmas[used++] = suffix;
        }
    }
    if (insert != NULL)
        vmas[used++] = *insert;
    qsort(vmas, used, sizeof(*vmas), compare_vmas);
    size_t merged = 0;
    for (size_t i = 0; i < used; ++i) {
        if (merged != 0 && compatible(&vmas[merged - 1], &vmas[i]))
            vmas[merged - 1].end = vmas[i].end;
        else
            vmas[merged++] = vmas[i];
    }
    if (merged > VMA_LIMIT) {
        free(vmas);
        return NULL;
    }
    *count = merged;
    return vmas;
}

static void publish(mips64_linux_memory_t *memory, mips64_vma_t *vmas, size_t count)
{
    free(memory->vmas);
    memory->vmas = vmas;
    memory->count = count;
}

bool mips64_linux_memory_init(mips64_linux_memory_t *memory, mips64_space_t *space,
                          uint64_t program_break)
{
    if (memory == NULL || space == NULL)
        return false;
    memset(memory, 0, sizeof(*memory));
    memory->space = space;
    memory->next_id = 1;
    memory->minimum_break = memory->current_break = program_break;
    memory->vmas = calloc(space->count == 0 ? 1 : space->count, sizeof(*memory->vmas));
    if (memory->vmas == NULL)
        return false;
    for (size_t i = 0; i < space->count; ++i) {
        const mips64_page_t *page = &space->pages[i];
        if (memory->count != 0 && memory->vmas[memory->count - 1].end == page->address &&
            memory->vmas[memory->count - 1].permissions == page->permissions) {
            memory->vmas[memory->count - 1].end += MIPS64_PAGE_SIZE;
        } else {
            memory->vmas[memory->count++] = (mips64_vma_t){
                page->address, page->address + MIPS64_PAGE_SIZE, memory->next_id++, 0,
                page->permissions, 7, MIPS64_VMA_INITIAL};
        }
    }
    memory->brk_id = memory->next_id++;
    return true;
}

void mips64_linux_memory_destroy(mips64_linux_memory_t *memory)
{
    if (memory == NULL)
        return;
    free(memory->vmas);
    memset(memory, 0, sizeof(*memory));
}

static uint64_t mmap_pages(mips64_linux_memory_t *memory, uint64_t address,
                           uint64_t length, uint64_t protection, uint64_t flags,
                           mips64_file_source_t *source, uint64_t offset)
{
    uint64_t size;
    if (length == 0 || offset % MIPS64_PAGE_SIZE != 0 || (protection & ~UINT64_C(7)) != 0)
        return error(22);
    if (!round_length(length, &size) || size > memory->space->limit)
        return error(12);
    if ((flags & 3) == 0)
        return error(22);
    bool shared = (flags & 3) == G_MAP_SHARED;
    bool file_mapping = (flags & G_MAP_ANONYMOUS) == 0;
    if ((flags & 3) != G_MAP_PRIVATE && !shared)
        return error(95); /* MAP_SHARED_VALIDATE has a separate flag contract. */
    if (shared && file_mapping)
        return error(95); /* File views need retained shared inode ownership. */
    /* Kernel-ignored legacy hints and eager population hints are safe with
     * eager private backing. Grow-down, locked/huge pages and unknown features
     * are deliberately unsupported instead of silently changing semantics. */
    const uint64_t allowed = G_MAP_SHARED | G_MAP_PRIVATE | G_MAP_FIXED | G_MAP_ANONYMOUS |
        G_MAP_NOREPLACE | UINT64_C(0x800) | UINT64_C(0x1000) | UINT64_C(0x4000) |
        UINT64_C(0x8000) | UINT64_C(0x10000) | UINT64_C(0x20000);
    if ((flags & ~allowed) != 0)
        return error(95);
    if (file_mapping && source == NULL)
        return error(38);
    if (file_mapping && (source->space != memory->space || size > UINT64_MAX - offset))
        return error(75);
    bool fixed = (flags & (G_MAP_FIXED | G_MAP_NOREPLACE)) != 0;
    if (fixed) {
        if (address % MIPS64_PAGE_SIZE != 0)
            return error(22);
        if (!valid_range(memory, address, size))
            return error(address < MIPS64_PAGE_SIZE ? 1 : 12);
        if ((flags & G_MAP_NOREPLACE) != 0 && !hole(memory, address, size))
            return error(17);
    } else {
        address &= MIPS64_PAGE_MASK;
        if (!hole(memory, address, size)) {
            uint64_t base = mmap_search_base(memory->space);
            uint64_t start = base < memory->space->limit ? base : MIPS64_PAGE_SIZE;
            if (!mips64_space_find_hole(memory->space, start, size, &address) &&
                !mips64_space_find_hole(memory->space, MIPS64_PAGE_SIZE, size, &address))
                return error(12);
        }
    }
    if (memory->next_id == UINT64_MAX)
        return error(12);
    mips64_vma_t added = {address, address + size, memory->next_id,
                      file_mapping ? offset : 0, (unsigned int)protection, 7,
                      file_mapping ? MIPS64_VMA_FILE_PRIVATE :
                      shared ? MIPS64_VMA_ANONYMOUS_SHARED : MIPS64_VMA_ANONYMOUS};
    size_t count;
    mips64_vma_t *vmas = edit(memory, address, address + size, &added, false, 0, &count);
    if (vmas == NULL)
        return error(12);
    unsigned int effective = page_permissions(added.permissions);
    bool success = file_mapping ?
        mips64_space_map_file(memory->space, address, size, effective, fixed, source, offset) :
        fixed ? mips64_space_replace(memory->space, address, size, effective) :
                mips64_space_map(memory->space, address, size, effective, false);
    if (!success) {
        free(vmas);
        return error(12);
    }
    publish(memory, vmas, count);
    ++memory->next_id;
    return address;
}

uint64_t mips64_linux_mmap(mips64_linux_memory_t *memory, uint64_t address,
                       uint64_t length, uint64_t protection, uint64_t flags,
                       uint64_t fd, uint64_t offset)
{
    (void)fd;
    return mmap_pages(memory, address, length, protection, flags, NULL, offset);
}

uint64_t mips64_linux_mmap_source(mips64_linux_memory_t *memory, uint64_t address,
                              uint64_t length, uint64_t protection, uint64_t flags,
                              mips64_file_source_t *source, uint64_t offset)
{
    return mmap_pages(memory, address, length, protection, flags, source, offset);
}

uint64_t mips64_linux_munmap(mips64_linux_memory_t *memory, uint64_t address, uint64_t length)
{
    uint64_t size;
    if (address % MIPS64_PAGE_SIZE != 0 || !round_length(length, &size) ||
        address >= memory->space->limit || size > memory->space->limit - address)
        return error(22);
    /* Page zero cannot be mapped, but unmapping that hole is legal. */
    if (address == 0) {
        if (size == MIPS64_PAGE_SIZE)
            return 0;
        address = MIPS64_PAGE_SIZE;
        size -= MIPS64_PAGE_SIZE;
    }
    /* Linux succeeds immediately when the whole interval is a hole. Do not
     * allocate VMA storage or consume sparse-map generations for that no-op. */
    size_t at = lookup(memory, address);
    if (at == memory->count || memory->vmas[at].start >= address + size)
        return 0;
    size_t count;
    mips64_vma_t *vmas = edit(memory, address, address + size, NULL, false, 0, &count);
    if (vmas == NULL)
        return error(12);
    if (!mips64_space_unmap(memory->space, address, size)) {
        free(vmas);
        return error(12);
    }
    publish(memory, vmas, count);
    return 0;
}

uint64_t mips64_linux_mprotect(mips64_linux_memory_t *memory, uint64_t address,
                           uint64_t length, uint64_t protection)
{
    if (address % MIPS64_PAGE_SIZE != 0 || (protection & ~UINT64_C(7)) != 0)
        return error(22);
    if (length == 0)
        return 0;
    uint64_t size;
    /* Arithmetic wrap is rejected before any change. A non-wrapping suffix
     * beyond the guest VA limit is a later hole, so protect the mapped prefix
     * before returning ENOMEM, just as for a hole inside the supported range. */
    if (!round_length(length, &size) || address < MIPS64_PAGE_SIZE ||
        address >= memory->space->limit || size > UINT64_MAX - address)
        return error(12);
    uint64_t end = address + size, prefix = address;
    unsigned int failure = 0;
    for (size_t i = lookup(memory, address); prefix < end; ++i) {
        if (i == memory->count || memory->vmas[i].start > prefix) {
            failure = 12;
            break;
        }
        if ((protection & ~memory->vmas[i].may_permissions) != 0) {
            failure = 13;
            break;
        }
        prefix = memory->vmas[i].end < end ? memory->vmas[i].end : end;
    }
    if (prefix != address) {
        size_t count;
        mips64_vma_t *vmas = edit(memory, address, prefix, NULL, true,
                              (unsigned int)protection, &count);
        if (vmas == NULL)
            return error(12);
        if (!mips64_space_protect(memory->space, address, prefix - address,
                              page_permissions((unsigned int)protection))) {
            free(vmas);
            return error(12);
        }
        publish(memory, vmas, count);
    }
    return failure == 0 ? 0 : error(failure);
}

uint64_t mips64_linux_brk(mips64_linux_memory_t *memory, uint64_t address)
{
    uint64_t previous = memory->current_break, old_end, new_end;
    if (address < memory->minimum_break || address >= memory->space->limit ||
        !round_length(previous, &old_end) || !round_length(address, &new_end))
        return previous;
    if (new_end == old_end) {
        memory->current_break = address;
        return address;
    }
    if (new_end < old_end) {
        size_t at = lookup(memory, new_end);
        if (at == memory->count || memory->vmas[at].start >= old_end)
            return previous;
        if (mips64_linux_munmap(memory, new_end, old_end - new_end) != 0)
            return previous;
    } else {
        if (new_end > memory->space->limit - MIPS64_PAGE_SIZE ||
            !hole(memory, old_end, new_end - old_end + MIPS64_PAGE_SIZE))
            return previous;
        mips64_vma_t added = {old_end, new_end, memory->brk_id,
                          old_end - memory->minimum_break, 3, 7, MIPS64_VMA_BRK};
        size_t count;
        mips64_vma_t *vmas = edit(memory, old_end, new_end, &added, false, 0, &count);
        if (vmas == NULL)
            return previous;
        if (!mips64_space_map(memory->space, old_end, new_end - old_end, 3, false)) {
            free(vmas);
            return previous;
        }
        publish(memory, vmas, count);
    }
    memory->current_break = address;
    return address;
}

uint64_t mips64_linux_mremap(mips64_linux_memory_t *memory, uint64_t address,
                         uint64_t old_length, uint64_t new_length,
                         uint64_t flags, uint64_t new_address)
{
    uint64_t old_size, new_size;
    if ((flags & ~UINT64_C(7)) != 0 || address % MIPS64_PAGE_SIZE != 0 ||
        ((flags & 2) != 0 && (flags & 1) == 0) ||
        !round_length(old_length, &old_size) || !round_length(new_length, &new_size))
        return error(22);
    if ((flags & 4) != 0)
        return error(95); /* DONTUNMAP requires its own backing/fault contract. */
    if (!valid_range(memory, address, old_size))
        return error(14);
    bool fixed = (flags & 2) != 0;
    if (fixed && (new_address % MIPS64_PAGE_SIZE != 0 ||
                  !valid_range(memory, new_address, new_size) ||
                  (new_address < address + old_size && address < new_address + new_size)))
        return error(22);
    size_t at = lookup(memory, address);
    if (at == memory->count || memory->vmas[at].start > address)
        return error(14);
    mips64_vma_t source = memory->vmas[at];
    if (!fixed && new_size <= old_size) {
        if (new_size != old_size) {
            uint64_t result = mips64_linux_munmap(memory, address + new_size, old_size - new_size);
            if (result != 0)
                return result;
        }
        return address;
    }
    if (old_size > source.end - address)
        return error(fixed && old_size == new_size ? 95 : 14);
    if (!fixed) {
        if (address + old_size == source.end &&
            hole(memory, source.end, new_size - old_size))
            new_address = address;
        else if ((flags & 1) == 0)
            return error(12);
        else if (!mips64_space_find_hole(memory->space, mmap_search_base(memory->space),
                                            new_size, &new_address) &&
                 !mips64_space_find_hole(memory->space, MIPS64_PAGE_SIZE, new_size, &new_address))
            return error(12);
    }
    /* Build both registry edits before page ownership changes. Backing identity
     * is retained; sparse mapping bindings change even on in-place growth. */
    size_t intermediate_count;
    mips64_vma_t *intermediate = edit(memory, address, address + old_size, NULL, false,
                                  0, &intermediate_count);
    if (intermediate == NULL)
        return error(12);
    mips64_linux_memory_t staged = *memory;
    staged.vmas = intermediate;
    staged.count = intermediate_count;
    mips64_vma_t moved = source;
    moved.offset += address - source.start;
    if (new_size > UINT64_MAX - moved.offset) {
        free(intermediate);
        return error(22);
    }
    moved.start = new_address;
    moved.end = new_address + new_size;
    size_t count;
    mips64_vma_t *vmas = edit(&staged, moved.start, moved.end, &moved, false, 0, &count);
    free(intermediate);
    if (vmas == NULL)
        return error(12);
    if (!mips64_space_remap(memory->space, address, old_size, new_address, new_size,
                        page_permissions(source.permissions))) {
        free(vmas);
        return error(12);
    }
    publish(memory, vmas, count);
    return new_address;
}
