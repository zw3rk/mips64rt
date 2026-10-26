/*
 * src/vm/vm_file.c — File-backed provider for the 6-step contract.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Implements Provider F: step 1 (reserve) takes
 * an anonymous PROT_NONE reservation like Provider A and records
 * the fd in priv; the file step maps shared file pages MAP_FIXED
 * into it (W^X: EXEC rejected); protect/query/unmap/release mirror
 * the anonymous provider. Unmapped file spans return to PROT_NONE
 * anonymous pages.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "vm/vm_file.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

static int u0f_host_prot(uint32_t prot)
{
    int h = 0;

    if ((prot & 1u) != 0u) {
        h |= PROT_READ;
    }
    if ((prot & 2u) != 0u) {
        h |= PROT_WRITE;
    }
    return h;
}

static long u0f_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);

    return (ps < 4096L) ? 4096L : ps;
}

static uint64_t u0f_down(uint64_t x, uint64_t ps)
{
    return x & ~(ps - 1u);
}

static uint64_t u0f_up(uint64_t x, uint64_t ps)
{
    return (x + (ps - 1u)) & ~(ps - 1u);
}

static int u0f_record(mips_vm64_t *vm, uint64_t start, uint64_t end,
                      uint32_t prot, uint32_t tag)
{
    size_t i = 0;

    while (i < vm->region_count && vm->regions[i].start < start) {
        i++;
    }
    if (i > 0 && vm->regions[i - 1].end == start &&
        vm->regions[i - 1].prot == prot && vm->regions[i - 1].tag == tag) {
        vm->regions[i - 1].end = end;
        return 0;
    }
    if (vm->region_count >= MIPS64_VM64_MAX_REGIONS) {
        return MIPS_FAULT;
    }
    memmove(&vm->regions[i + 1], &vm->regions[i],
            (vm->region_count - i) * sizeof vm->regions[0]);
    vm->regions[i].start = start;
    vm->regions[i].end = end;
    vm->regions[i].prot = prot;
    vm->regions[i].tag = tag;
    vm->region_count++;
    return 0;
}

static void u0f_forget(mips_vm64_t *vm, uint64_t start, uint64_t end)
{
    size_t i = 0;

    while (i < vm->region_count) {
        uint64_t rs = vm->regions[i].start;
        uint64_t re = vm->regions[i].end;

        if (re <= start || rs >= end) {
            i++;
            continue;
        }
        if (rs < start && re > end) {
            if (vm->region_count >= MIPS64_VM64_MAX_REGIONS) {
                return;
            }
            memmove(&vm->regions[i + 2], &vm->regions[i + 1],
                    (vm->region_count - i - 1) * sizeof vm->regions[0]);
            vm->regions[i].end = start;
            vm->regions[i + 1].start = end;
            vm->regions[i + 1].end = re;
            vm->regions[i + 1].prot = vm->regions[i].prot;
            vm->regions[i + 1].tag = vm->regions[i].tag;
            vm->region_count++;
            return;
        }
        if (rs < start) {
            vm->regions[i].end = start;
            i++;
        } else if (re > end) {
            vm->regions[i].start = end;
            i++;
        } else {
            memmove(&vm->regions[i], &vm->regions[i + 1],
                    (vm->region_count - i - 1) * sizeof vm->regions[0]);
            vm->region_count--;
        }
    }
}

static int u0f_reserve(mips_vm64_t *vm, uint64_t size)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    void *base;

    if (vm == NULL || size == 0U || (size & (ps - 1u)) != 0U) {
        return MIPS_FAULT;
    }
    base = mmap(NULL, (size_t)size, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) {
        return MIPS_FAULT;
    }
    vm->base = (uint64_t)(uintptr_t)base;
    vm->size = size;
    vm->priv = NULL;
    vm->region_count = 0U;
    return 0;
}

static int u0f_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                   uint32_t prot, uint32_t tag)
{
    (void)vm;
    (void)va;
    (void)len;
    (void)prot;
    (void)tag;
    /* File placement always goes through mips_vmfile_map (needs the
     * fd + offset); the plain map step is not meaningful here. */
    return MIPS_FAULT;
}

static int u0f_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                       uint32_t prot)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    uint64_t start = u0f_down(va, ps);
    uint64_t end = u0f_up(va + len, ps);

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size || (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    if (mips_vm64_query(vm, start, NULL) != 0) {
        return MIPS_FAULT;
    }
    if (mprotect((void *)(uintptr_t)(vm->base + start),
                 (size_t)(end - start), u0f_host_prot(prot)) != 0) {
        return MIPS_FAULT;
    }
    u0f_forget(vm, start, end);
    return u0f_record(vm, start, end, prot, MIPS_VM_TAG_FILE);
}

static int u0f_query(const mips_vm64_t *vm, uint64_t va,
                     mips_vm_region_t *out)
{
    size_t i;

    if (vm == NULL || vm->base == 0U || va >= vm->size) {
        return MIPS_FAULT;
    }
    for (i = 0; i < vm->region_count; i++) {
        if (vm->regions[i].start <= va && va < vm->regions[i].end) {
            if (out != NULL) {
                *out = vm->regions[i];
            }
            return 0;
        }
    }
    return MIPS_FAULT;
}

static int u0f_unmap(mips_vm64_t *vm, uint64_t va, uint64_t len)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    uint64_t start = u0f_down(va, ps);
    uint64_t end = u0f_up(va + len, ps);
    void *at;

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size) {
        return MIPS_FAULT;
    }
    at = mmap((void *)(uintptr_t)(vm->base + start), (size_t)(end - start),
              PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (at == MAP_FAILED) {
        return MIPS_FAULT;
    }
    u0f_forget(vm, start, end);
    return 0;
}

static int u0f_release(mips_vm64_t *vm)
{
    if (vm == NULL || vm->base == 0U) {
        return MIPS_FAULT;
    }
    if (munmap((void *)(uintptr_t)vm->base, (size_t)vm->size) != 0) {
        return MIPS_FAULT;
    }
    vm->base = 0U;
    vm->size = 0U;
    vm->priv = NULL;
    vm->region_count = 0U;
    return 0;
}

const mips_provider_ops_t mips_provider_f = {
    "provider-f-file",
    u0f_reserve,
    u0f_map,
    u0f_protect,
    u0f_query,
    u0f_unmap,
    u0f_release
};

int mips_vmfile_map(mips_vm64_t *vm, int fd, uint64_t off, uint64_t va,
                    uint64_t len, uint32_t prot)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    void *at;

    if (vm == NULL || vm->base == 0U || fd < 0 || len == 0U ||
        (va & (ps - 1u)) != 0U || (len & (ps - 1u)) != 0U ||
        (off & (ps - 1u)) != 0U || va + len < va || va + len > vm->size ||
        (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    at = mmap((void *)(uintptr_t)(vm->base + va), (size_t)len,
              u0f_host_prot(prot), MAP_SHARED | MAP_FIXED, fd,
              (off_t)off);
    if (at == MAP_FAILED) {
        return MIPS_FAULT;
    }
    return u0f_record(vm, va, va + len, prot, MIPS_VM_TAG_FILE);
}
