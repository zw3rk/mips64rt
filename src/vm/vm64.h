/*
 * src/vm/vm64.h — 64-bit guest address-space handle + Provider A.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Prototype for the Class-B full address-space
 * manager shared with lane L-U0-B: a `mips_vm64_t` handle over one
 * provider, driven through the same 6-step contract in both lanes:
 *
 *   1. reserve  (provider reserves host VA, PROT_NONE)
 *   2. map      (provider places MAP_FIXED pages with a prot + tag)
 *   3. protect  (provider changes prot on a mapped span)
 *   4. query    (lookup the recorded region covering a VA)
 *   5. unmap    (provider returns a span to PROT_NONE, record dropped)
 *   6. release  (provider tears the reservation down)
 *
 * Provider A is the anonymous-memory provider (backed by mmap). The
 * file-backed provider lives in src/vm/vm_file.h and implements the
 * same 6 steps. Guest VAs are uint64_t offsets from the handle base
 * and are never truncated; the manager never maps PROT_EXEC on the
 * host for guest data (W^X discipline).
 */

#ifndef MIPS64RT_VM_VM64_H
#define MIPS64RT_VM_VM64_H

#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h" /* MIPS_FAULT step-failure sentinel */

/* Region record cap per handle (fixed array, no allocator). */
#define MIPS64_VM64_MAX_REGIONS 64u

/* Region tag: ownership class for diagnostics (not a prot). */
#define MIPS_VM_TAG_ANON 0u
#define MIPS_VM_TAG_FILE 1u

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t prot;
    uint32_t tag;
} mips_vm_region_t;

typedef struct mips_vm64 mips_vm64_t;

/* Provider A: six operations every backing store implements. All
 * VAs are offsets from the reservation base; len is in bytes. prot
 * uses the MIPS_PROT_* numbering (1 read, 2 write, 4 exec). */
typedef struct {
    const char *name;
    int (*reserve)(mips_vm64_t *vm, uint64_t size);
    int (*map)(mips_vm64_t *vm, uint64_t va, uint64_t len, uint32_t prot,
               uint32_t tag);
    int (*protect)(mips_vm64_t *vm, uint64_t va, uint64_t len,
                   uint32_t prot);
    int (*query)(const mips_vm64_t *vm, uint64_t va, mips_vm_region_t *out);
    int (*unmap)(mips_vm64_t *vm, uint64_t va, uint64_t len);
    int (*release)(mips_vm64_t *vm);
} mips_provider_ops_t;

struct mips_vm64 {
    const mips_provider_ops_t *ops;
    uint64_t base;   /* host address of the reservation (0 unset) */
    uint64_t size;   /* reservation size in bytes */
    void *priv;      /* provider-private state (fd for files) */
    mips_vm_region_t regions[MIPS64_VM64_MAX_REGIONS];
    size_t region_count;
};

/* Provider A (anonymous mmap storage). */
extern const mips_provider_ops_t mips_provider_a;

/* 6-step contract entry points (dispatch to vm->ops). Every step
 * returns 0 on success, MIPS_FAULT (-1) on failure; NULL vm fails
 * every step. Reserve binds the provider and records base/size. */
int mips_vm64_reserve(mips_vm64_t *vm, const mips_provider_ops_t *ops,
                      uint64_t size);
int mips_vm64_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                  uint32_t prot, uint32_t tag);
int mips_vm64_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                      uint32_t prot);
int mips_vm64_query(const mips_vm64_t *vm, uint64_t va,
                    mips_vm_region_t *out);
int mips_vm64_unmap(mips_vm64_t *vm, uint64_t va, uint64_t len);
int mips_vm64_release(mips_vm64_t *vm);

/* Host pointer for a reserved VA (base + va); NULL unless va is
 * inside the reservation. */
void *mips_vm64_host(const mips_vm64_t *vm, uint64_t va);

#endif /* MIPS64RT_VM_VM64_H */
