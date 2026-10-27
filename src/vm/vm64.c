/*
 * src/vm/vm64.c — 64-bit address-space handle + Provider A.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Implements the 6-step contract from vm64.h over
 * Provider A (anonymous mmap storage). Steps 1/2/3/5/6 drive
 * mmap/mprotect/munmap; step 4 (query) consults the handle-local
 * region list. Page granularity is the host page (sysconf); spans
 * are rounded out. PROT_EXEC is rejected for maps (W^X: guest data
 * pages are never host-executable).
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "vm/vm64.h"
#include "vm/vm_file.h"
#include "core/cpu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* macOS hides MAP_NORESERVE under strict feature macros. */
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

/* MIPS_PROT_* (1/2/4) to host PROT_* translation. */
static int u0_host_prot(uint32_t prot)
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

static long u0_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);

    return (ps < 4096L) ? 4096L : ps;
}

static uint64_t u0_down(uint64_t x, uint64_t ps)
{
    return x & ~(ps - 1u);
}

static uint64_t u0_up(uint64_t x, uint64_t ps)
{
    return (x + (ps - 1u)) & ~(ps - 1u);
}

/* Sorted-insert one region; coalesce with a same-prot/same-tag
 * neighbor. MIPS_FAULT when full. */
static int u0_record(mips_vm64_t *vm, uint64_t start, uint64_t end,
                     uint32_t prot, uint32_t tag)
{
    size_t i = 0;

    while (i < vm->region_count && vm->regions[i].start < start) {
        i++;
    }
    if (i > 0 && vm->regions[i - 1].end == start &&
        vm->regions[i - 1].prot == prot && vm->regions[i - 1].tag == tag) {
        vm->regions[i - 1].end = end;
        start = vm->regions[i - 1].start;
        i--;
    }
    if (i < vm->region_count && vm->regions[i].start == end &&
        vm->regions[i].prot == prot && vm->regions[i].tag == tag) {
        vm->regions[i].start = start;
        vm->regions[i].end = (vm->regions[i].end > end) ?
            vm->regions[i].end : end;
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

/* Drop [start, end) from the records, splitting straddlers. */
static void u0_forget(mips_vm64_t *vm, uint64_t start, uint64_t end)
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

static int u0_a_reserve(mips_vm64_t *vm, uint64_t size)
{
    uint64_t ps = (uint64_t)u0_page_size();
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

static int u0_a_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                    uint32_t prot, uint32_t tag)
{
    uint64_t ps = (uint64_t)u0_page_size();
    uint64_t start = u0_down(va, ps);
    uint64_t end = u0_up(va + len, ps);
    void *at;

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size || (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    at = mmap((void *)(uintptr_t)(vm->base + start), (size_t)(end - start),
              u0_host_prot(prot), MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
              -1, 0);
    if (at == MAP_FAILED) {
        return MIPS_FAULT;
    }
    return u0_record(vm, start, end, prot, tag);
}

static int u0_a_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                        uint32_t prot)
{
    uint64_t ps = (uint64_t)u0_page_size();
    uint64_t start = u0_down(va, ps);
    uint64_t end = u0_up(va + len, ps);

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size || (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    if (mips_vm64_query(vm, start, NULL) != 0) {
        return MIPS_FAULT;
    }
    if (mprotect((void *)(uintptr_t)(vm->base + start),
                 (size_t)(end - start), u0_host_prot(prot)) != 0) {
        return MIPS_FAULT;
    }
    u0_forget(vm, start, end);
    return u0_record(vm, start, end, prot, MIPS_VM_TAG_ANON);
}

static int u0_a_query(const mips_vm64_t *vm, uint64_t va,
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

static int u0_a_unmap(mips_vm64_t *vm, uint64_t va, uint64_t len)
{
    uint64_t ps = (uint64_t)u0_page_size();
    uint64_t start = u0_down(va, ps);
    uint64_t end = u0_up(va + len, ps);
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
    u0_forget(vm, start, end);
    return 0;
}

static int u0_a_release(mips_vm64_t *vm)
{
    if (vm == NULL || vm->base == 0U) {
        return MIPS_FAULT;
    }
    if (munmap((void *)(uintptr_t)vm->base, (size_t)vm->size) != 0) {
        return MIPS_FAULT;
    }
    vm->base = 0U;
    vm->size = 0U;
    vm->region_count = 0U;
    return 0;
}

const mips_provider_ops_t mips_provider_a = {
    "provider-a-anon",
    u0_a_reserve,
    u0_a_map,
    u0_a_protect,
    u0_a_query,
    u0_a_unmap,
    u0_a_release
};

static int u0_f_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                    uint32_t prot, uint32_t tag)
{
    (void)vm; (void)va; (void)len; (void)prot; (void)tag;
    return MIPS_FAULT;
}

static int u0_f_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                        uint32_t prot)
{
    uint64_t ps = (uint64_t)u0_page_size();
    uint64_t start = u0_down(va, ps), end = u0_up(va + len, ps);

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size || (prot & 4u) != 0u ||
        mips_vm64_query(vm, start, NULL) != 0 ||
        mprotect((void *)(uintptr_t)(vm->base + start),
                 (size_t)(end - start), u0_host_prot(prot)) != 0)
        return MIPS_FAULT;
    u0_forget(vm, start, end);
    return u0_record(vm, start, end, prot, MIPS_VM_TAG_FILE);
}

const mips_provider_ops_t mips_provider_f = {
    "provider-f-file",
    u0_a_reserve,
    u0_f_map,
    u0_f_protect,
    u0_a_query,
    u0_a_unmap,
    u0_a_release
};

int mips_vmfile_map(mips_vm64_t *vm, int fd, uint64_t off, uint64_t va,
                    uint64_t len, uint32_t prot)
{
    uint64_t ps = (uint64_t)u0_page_size();
    void *at;

    if (vm == NULL || vm->base == 0U || fd < 0 || len == 0U ||
        (va & (ps - 1u)) != 0U || (len & (ps - 1u)) != 0U ||
        (off & (ps - 1u)) != 0U || va + len < va || va + len > vm->size ||
        (prot & 4u) != 0u)
        return MIPS_FAULT;
    at = mmap((void *)(uintptr_t)(vm->base + va), (size_t)len,
              u0_host_prot(prot), MAP_SHARED | MAP_FIXED, fd, (off_t)off);
    if (at == MAP_FAILED)
        return MIPS_FAULT;
    return u0_record(vm, va, va + len, prot, MIPS_VM_TAG_FILE);
}

int mips_vm_inode_page_host_prot(uint64_t page_va)
{
    size_t n = mips_mem_region_count(), i;

    for (i = 0u; i < n; i++) {
        uint64_t s = 0u, e = 0u;
        uint32_t prot = 0u;

        if (mips_mem_region_at(i, &s, &e, &prot) != 0)
            break;
        if (s <= page_va && page_va < e) {
            return (((prot & (uint32_t)MIPS_PROT_READ) != 0u) ? PROT_READ : 0) |
                   (((prot & (uint32_t)MIPS_PROT_WRITE) != 0u) ? PROT_WRITE : 0);
        }
    }
    return -1;
}

void mips_vm_inode_zero_span(mips64_ctx_t *ctx, uint64_t page_va,
                             uint64_t from, uint64_t to)
{
    uint8_t *p;
    int hp;

    if (ctx == NULL || from >= to || to > 4096u)
        return;
    p = (uint8_t *)mips64_guest_ptr(ctx, page_va);
    hp = (p != NULL) ? mips_vm_inode_page_host_prot(page_va) : -1;
    if (hp < 0)
        return;
    if ((hp & PROT_WRITE) == 0) {
        if (mprotect(p, 4096u, PROT_READ | PROT_WRITE) != 0)
            return;
        (void)memset(p + from, 0, (size_t)(to - from));
        (void)mprotect(p, 4096u, hp);
        return;
    }
    (void)memset(p + from, 0, (size_t)(to - from));
}

void mips_vm_inode_refresh_span(mips64_ctx_t *ctx, int fd, uint64_t page_va,
                                uint64_t glo, uint64_t ghi, uint64_t fpos)
{
    uint8_t *p;
    uint64_t from, to;
    int hp;
    ssize_t got;

    if (ctx == NULL || fd < 0 || glo >= ghi)
        return;
    from = glo - (page_va & ~(uint64_t)4095U);
    to = ghi - (page_va & ~(uint64_t)4095U);
    if (to > 4096u)
        return;
    p = (uint8_t *)mips64_guest_ptr(ctx, page_va & ~(uint64_t)4095U);
    hp = (p != NULL) ?
         mips_vm_inode_page_host_prot(page_va & ~(uint64_t)4095U) : -1;
    if (hp < 0)
        return;
    if ((hp & PROT_WRITE) == 0 &&
        mprotect(p, 4096u, PROT_READ | PROT_WRITE) != 0)
        return;
    got = pread(fd, p + from, (size_t)(to - from), (off_t)fpos);
    if (got < 0)
        got = 0;
    if ((uint64_t)got < to - from) {
        (void)memset(p + from + (uint64_t)got, 0,
                     (size_t)(to - from - (uint64_t)got));
    }
    if ((hp & PROT_WRITE) == 0)
        (void)mprotect(p, 4096u, hp);
}

int mips_vm64_reserve(mips_vm64_t *vm, const mips_provider_ops_t *ops,
                      uint64_t size)
{
    if (vm == NULL || ops == NULL || ops->reserve == NULL) {
        return MIPS_FAULT;
    }
    vm->ops = ops;
    return ops->reserve(vm, size);
}

int mips_vm64_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                  uint32_t prot, uint32_t tag)
{
    if (vm == NULL || vm->ops == NULL || vm->ops->map == NULL) {
        return MIPS_FAULT;
    }
    return vm->ops->map(vm, va, len, prot, tag);
}

int mips_vm64_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                      uint32_t prot)
{
    if (vm == NULL || vm->ops == NULL || vm->ops->protect == NULL) {
        return MIPS_FAULT;
    }
    return vm->ops->protect(vm, va, len, prot);
}

int mips_vm64_query(const mips_vm64_t *vm, uint64_t va,
                    mips_vm_region_t *out)
{
    if (vm == NULL || vm->ops == NULL || vm->ops->query == NULL) {
        return MIPS_FAULT;
    }
    return vm->ops->query(vm, va, out);
}

int mips_vm64_unmap(mips_vm64_t *vm, uint64_t va, uint64_t len)
{
    if (vm == NULL || vm->ops == NULL || vm->ops->unmap == NULL) {
        return MIPS_FAULT;
    }
    return vm->ops->unmap(vm, va, len);
}

int mips_vm64_release(mips_vm64_t *vm)
{
    const mips_provider_ops_t *ops;

    if (vm == NULL || vm->ops == NULL || vm->ops->release == NULL) {
        return MIPS_FAULT;
    }
    ops = vm->ops;
    if (ops->release(vm) != 0) {
        return MIPS_FAULT;
    }
    vm->ops = NULL;
    return 0;
}

void *mips_vm64_host(const mips_vm64_t *vm, uint64_t va)
{
    if (vm == NULL || vm->base == 0U || va >= vm->size) {
        return NULL;
    }
    return (void *)(uintptr_t)(vm->base + va);
}
