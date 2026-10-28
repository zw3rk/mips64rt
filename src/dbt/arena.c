/*
 * src/dbt/arena.c — Bump-allocated W^X code arena (Wave P, lane P4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Replaces the old per-block `mmap` in `dbt_code_publish`: translated
 * blocks bump-allocate out of 8 MiB thread-local chunks and seal RX
 * through the backend JIT hooks before they execute (Linux flips the
 * block's page range RW->RX; Darwin toggles the MAP_JIT write window
 * or mprotects, and never mprotects MAP_JIT pages), then flush the
 * I-cache. Because every cache (block cache, IBTC) is thread-local, a
 * thread never executes code from another thread's chunk while that
 * chunk's tail page is briefly RW for the next copy — strict W^X
 * holds even for multi-threaded guests. Exhausted chunks (and the
 * whole arena) are retained until process end: the RC2 1024-entry
 * bound keeps the working set small and no live IBTC slot can ever
 * dangle.
 *
 * The chunk bookkeeping (base/used/cap) lives in thread-local
 * scalars, NEVER inside the JIT mapping: per-publish page-range
 * sealing flips mapping pages RX, so any header stored there would
 * fault on the next bump. Likewise every publish re-opens its range
 * through `mips_jit_begin_write` (the tail page flip-flops RW/RX as
 * consecutive blocks land on it).
 *
 * `x18` is never touched here (plain C, no inline asm).
 */

#include "dbt/dbt.h"

#include "os/backend.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* One 8 MiB payload chunk (the backend rounds the raw mapping to the
 * host page size itself). */
#define DBT_ARENA_CHUNK (8u * 1024u * 1024u)

/* Retained mappings (never unmapped: published code stays valid until
 * process end, so no live IBTC slot can dangle). */
#define DBT_ARENA_RETAIN_MAX 64u

static _Thread_local uint8_t *arena_base;
static _Thread_local size_t arena_used;
static _Thread_local size_t arena_cap;
static _Thread_local void *arena_maps[DBT_ARENA_RETAIN_MAX];
static _Thread_local unsigned arena_nmaps;

static void arena_retain(void *p)
{
    if (p != NULL && arena_nmaps < DBT_ARENA_RETAIN_MAX) {
        arena_maps[arena_nmaps++] = p;
    }
}

void *dbt_arena_alloc(size_t len)
{
    void *out;

    len = (len + 15u) & ~(size_t)15u;
    if (len == 0u) {
        return NULL;
    }
    if (arena_base == NULL || arena_used + len > arena_cap) {
        size_t cap = len > DBT_ARENA_CHUNK ? len : DBT_ARENA_CHUNK;
        uint8_t *mem = (uint8_t *)mips_jit_alloc(cap);

        if (mem == NULL) {
            return NULL;
        }
        arena_retain(mem);
        arena_base = mem;
        arena_used = 0u;
        arena_cap = cap;
    }
    out = (void *)(arena_base + arena_used);
    arena_used += len;
    return out;
}

void *dbt_code_publish(const uint8_t *buf, size_t len)
{
    void *p;

    if (buf == NULL || len == 0u) {
        return NULL;
    }
    p = dbt_arena_alloc(len);
    if (p == NULL) {
        return NULL;
    }
    /* Re-open the range (the tail page may already be sealed RX from
     * a previous block), copy, and seal RX before anyone executes. */
    mips_jit_begin_write(p, len);
    memcpy(p, buf, len);
    if (mips_jit_seal_rx(p, len) != 0) {
        /* The bytes stay arena-retained but unsealed: decline the
         * block so nothing ever executes them. */
        return NULL;
    }
    return p;
}
