/*
 * src/dbt/emit_mem.h — Lane U12: serialized DBT memory miss-site table.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each emitted memory word that can miss (aligned, unaligned RMW,
 * LL/SC) owns one 24-byte `dbt_mem_site_t` record: the faulting guest
 * VA, the access class, the word index of its 2-insn miss stub, and a
 * reserved displacement. The table is bump-allocated per block
 * (`dbt_mem_site_bump`) and serializes to flat little-endian bytes
 * (`dbt_mem_sites_serialize`: 24 bytes per record) for the AOT cache.
 *
 * The miss stub itself is exactly two A64 words (`movz w0, #site`
 * then `brk #DBT_MEM_SITE_BRK_IMM`); the host trap handler reads the
 * site index from `w0`. Only `w0` is touched, so `x18` never appears.
 */

#ifndef MIPS64RT_DBT_EMIT_MEM_H
#define MIPS64RT_DBT_EMIT_MEM_H

#include <stddef.h>
#include <stdint.h>

#include "dbt/emit_int.h"

/* Access class recorded in `miss_kind`. */
enum {
    DBT_MEM_SITE_LOAD = 0,
    DBT_MEM_SITE_STORE = 1,
    DBT_MEM_SITE_ATOMIC = 2,
    DBT_MEM_SITE_UNALIGNED = 3
};

/* `brk` immediate identifying a miss-stub trap. */
#define DBT_MEM_SITE_BRK_IMM 0x00DBu

/* One miss site: exactly 24 bytes (8 + 4 + 4 + 8). */
typedef struct {
    uint64_t guest_pc;  /* Faulting guest virtual address. */
    uint32_t miss_kind; /* One of `DBT_MEM_SITE_*`. */
    uint32_t host_off;  /* Word index of the 2-insn stub in the block. */
    uint64_t disp;      /* Reserved (patch displacement, zero for now). */
} dbt_mem_site_t;

_Static_assert(sizeof(dbt_mem_site_t) == 24u,
               "dbt_mem_site_t must serialize as 24 bytes");
_Static_assert(offsetof(dbt_mem_site_t, miss_kind) == 8u,
               "miss_kind offset");
_Static_assert(offsetof(dbt_mem_site_t, host_off) == 12u,
               "host_off offset");
_Static_assert(offsetof(dbt_mem_site_t, disp) == 16u, "disp offset");

/* Per-block bump table (64 insns max per block, so 256 is ample). */
#define DBT_MEM_SITES_MAX 256u

typedef struct {
    dbt_mem_site_t sites[DBT_MEM_SITES_MAX];
    size_t count;
} dbt_mem_sites_t;

void dbt_mem_sites_init(dbt_mem_sites_t *t);

/* Record one site; returns the site index, or -1 when `t` is NULL or
 * the table is full (the emitter then falls back to the shared fault
 * epilogue). */
int dbt_mem_site_bump(dbt_mem_sites_t *t, uint64_t guest_pc,
                      uint32_t miss_kind, uint32_t host_off);

/* Serialize the table as flat little-endian 24-byte records. Returns
 * `count * 24` on success, 0 when `t` is NULL, when `out` is NULL with
 * a non-empty table, or when `cap` is too small (all-or-nothing). */
size_t dbt_mem_sites_serialize(const dbt_mem_sites_t *t, uint8_t *out,
                               size_t cap);

/* Emit the 2-insn miss stub for `site` (`site` must fit 16 bits).
 * Returns the word index of the stub, or `(size_t)-1` on error. */
size_t ei_mem_miss_stub(a64_emit_t *e, unsigned site);

#endif /* MIPS64RT_DBT_EMIT_MEM_H */
