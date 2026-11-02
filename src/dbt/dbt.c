/*
 * src/dbt/dbt.c — AArch64 DBT dispatcher, block cache, IBTC, and RAS.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Execution model: guest basic blocks (up to 64 instructions, ending
 * at control transfers, traps/syscalls, or page boundaries) translate
 * to AArch64 code via lane L2c's `dbt_emit_int` (frozen contract in
 * `src/core/cpu.h`). Words the emitter declines end the block with a
 * fallback exit: the dispatcher single-steps the declining word in
 * `interp_step` and resumes, bit-identical to `interp` by
 * construction. Wave P compiles the L3b FP subset too (COP1
 * arithmetic/CVT/compare, COP1X FMA, LWC1/SWC1/LDC1/SDC1); indexed
 * COP1X words and COP2 still decline to `interp_step`.
 *
 * Host register discipline (see `src/dbt/dbt.h`; U0 lane rebinds
 * `x20`): `x19` pins the `mips64_ctx_t *`, `x20` pins the U0
 * soft-TLB base, guest `$0`
 * reads as `wzr`, everything else is memory-backed in `ctx`, and
 * `x18` is never touched anywhere in `src/dbt/`.
 */

#define _POSIX_C_SOURCE 200809L
/* macOS hides `MAP_ANONYMOUS`/`MAP_JIT` under strict POSIX. */
#define _DARWIN_C_SOURCE 1

#include "dbt/dbt.h"

#include "core/cpu.h"
#include "dbt/aot/sites.h"
#include "dbt/emit_mem.h"
#include "interp/decode.h"
#include "os/backend.h"
#include "vm/vm_pages.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Availability and the non-AArch64 enter fallback.                   */
/* ------------------------------------------------------------------ */

int mips64_dbt_available(void)
{
#if defined(__aarch64__) || defined(__arm64__)
    return 1;
#else
    return 0;
#endif
}

/* C fallback for non-AArch64 hosts so unit builds link; the real
 * dispatcher only enters code when `mips64_dbt_available()` is true. */
#if !defined(__aarch64__) && !defined(__arm64__)
long mips64_dbt_enter(mips64_ctx_t *ctx, uint64_t base, void *code,
                      uint64_t budget, const _Atomic uint64_t *epoch)
{
    (void)ctx;
    (void)base;
    (void)code;
    (void)budget;
    (void)epoch;
    return (long)MIPS64_DBT_EXIT_UNDEF;
}
#endif

/* ------------------------------------------------------------------ */
/* SMC invalidation epoch.                                            */
/* ------------------------------------------------------------------ */

static _Atomic uint64_t dbt_smc_epoch = 1;

void dbt_invalidate_all(void)
{
    uint64_t next = atomic_fetch_add_explicit(&dbt_smc_epoch, 1u,
                                              memory_order_acq_rel) + 1u;
    if (next == 0u) {
        atomic_store_explicit(&dbt_smc_epoch, 1u, memory_order_release);
    }
    /* Drop every code mark with the translations: the next fill
     * re-marks whatever recompiles (the write gate reopens). */
    mips_vm_pages_clear(0u, ~(uint64_t)0u,
                        (unsigned)MIPS_VM_PAGE_HAS_CODE);
}

void dbt_invalidate_range(uint64_t va, uint64_t len)
{
    /* Retire the code marks first so a racing fill cannot repopulate
     * a write tag over a page whose translation just died; the epoch
     * bump below keeps stale translations unreachable, and the
     * per-entry guest-word snapshot retires translations clobbered
     * by plain stores without any hook. */
    if (len != 0u) {
        mips_vm_pages_clear(va, len, (unsigned)MIPS_VM_PAGE_HAS_CODE);
    }
    dbt_invalidate_all();
}

uint64_t dbt_epoch(void)
{
    return atomic_load_explicit(&dbt_smc_epoch, memory_order_acquire);
}

/* ------------------------------------------------------------------ */
/* U0 delay-slot NPC + soft-TLB prefill (lane L-U0-C).                */
/* ------------------------------------------------------------------ */

int dbt_npc_resume(mips64_ctx_t *ctx)
{
    uint64_t applied = 0U;

    return mips_npc_resume_step(ctx, &applied);
}

/* NOTE: dbt_u0_prefill, dbt_u0_fill_retry and dbt_fault_ea live in
 * src/dbt/mem_recover.c (lane U12): the site-based miss path shares
 * their span decode, so they moved next to it. The dbt.h
 * declarations are unchanged. */

/* ------------------------------------------------------------------ */
/* W^X code arena + Block cache + IBTC + RAS.                         */
/* ------------------------------------------------------------------ */
/* Block publication lives in src/dbt/arena.c. Published chunks are
 * retained up to DBT_ARENA_RETAIN_MAX per thread, then reclaimed only
 * after dbt_flush_thread_caches clears the thread's block cache and
 * IBTC so no live slot can dangle. */
typedef struct {
    int used;
    uint64_t pc;
    dbt_block_t blk;   /* frozen shape: pc/end/code/len/smc_version */
    uint64_t epoch;    /* `dbt_smc_epoch` at compile time */
    uint8_t *snap;     /* malloc'd copy of the covered guest bytes */
    int fallback;      /* set: run `interp_step`, never native code */
    dbt_mem_site_t *sites; /* retained relative miss-site rows */
    size_t site_count;
} dbt_entry_t;

/* Release an entry snapshot and site table (code mappings live in the
 * thread-local arena and are reclaimed together by dbt_arena_reset). */
static void dbt_snap_drop(dbt_entry_t *e)
{
    if (e != NULL && e->snap != NULL) {
        free(e->snap);
        e->snap = NULL;
    }
    if (e != NULL && e->sites != NULL) {
        free(e->sites);
        e->sites = NULL;
        e->site_count = 0u;
    }
}

static _Thread_local dbt_entry_t block_cache[MIPS64_DBT_CACHE_ENTRIES];
static _Thread_local uint64_t ras[MIPS64_DBT_RAS_ENTRIES];
static _Thread_local unsigned ras_top;
static _Thread_local uint64_t ibtc_epoch;

/* Preloaded AOT site cache from `--cache-dir` (`mips_aot_sites_load`):
 * avoids duplicate `.aot` leaf appends across runs and reuses validated
 * persisted site rows on block compile. */
#define DBT_AOT_PRELOAD_MAX 256u
typedef struct {
    int used;
    uint64_t pc;
    dbt_mem_site_t *sites;
    size_t count;
} dbt_aot_preload_t;

static _Thread_local dbt_aot_preload_t aot_preload[DBT_AOT_PRELOAD_MAX];
static _Thread_local char aot_preload_path[512];

static int dbt_aot_visit(uint64_t guest_pc, const struct dbt_mem_site *sites,
                         size_t count, void *arg)
{
    unsigned idx = (unsigned)((guest_pc >> 2) ^ (guest_pc >> 12)) &
                   (DBT_AOT_PRELOAD_MAX - 1u);
    dbt_aot_preload_t *p = &aot_preload[idx];
    dbt_mem_site_t *copy;

    (void)arg;
    if (sites == NULL || count == 0u || count > DBT_MEM_SITES_MAX)
        return 0;
    copy = (dbt_mem_site_t *)malloc(count * sizeof(dbt_mem_site_t));
    if (copy == NULL)
        return 0;
    memcpy(copy, sites, count * sizeof(dbt_mem_site_t));
    if (p->sites != NULL)
        free(p->sites);
    p->used = 1;
    p->pc = guest_pc;
    p->sites = copy;
    p->count = count;
    return 0;
}

static void dbt_aot_ensure_loaded(void)
{
    const char *leaf = mips_aot_leaf_path();
    size_t i;

    if (leaf == NULL || leaf[0] == '\0') {
        aot_preload_path[0] = '\0';
        return;
    }
    if (strcmp(aot_preload_path, leaf) == 0)
        return;
    for (i = 0u; i < DBT_AOT_PRELOAD_MAX; i++) {
        if (aot_preload[i].sites != NULL) {
            free(aot_preload[i].sites);
            aot_preload[i].sites = NULL;
        }
        aot_preload[i].used = 0;
        aot_preload[i].count = 0u;
    }
    strncpy(aot_preload_path, leaf, sizeof aot_preload_path - 1u);
    aot_preload_path[sizeof aot_preload_path - 1u] = '\0';
    (void)mips_aot_sites_load(leaf, dbt_aot_visit, NULL);
}

static const dbt_mem_site_t *dbt_aot_take_match(uint64_t pc,
                                                const dbt_mem_site_t *rows,
                                                size_t nrows,
                                                size_t code_len)
{
    unsigned idx = (unsigned)((pc >> 2) ^ (pc >> 12)) &
                   (DBT_AOT_PRELOAD_MAX - 1u);
    const dbt_aot_preload_t *p = &aot_preload[idx];
    size_t i;

    if (!p->used || p->pc != pc || p->sites == NULL || p->count != nrows)
        return NULL;
    for (i = 0u; i < nrows; i++) {
        if (memcmp(&p->sites[i], &rows[i], sizeof(dbt_mem_site_t)) != 0 ||
            p->sites[i].seq_start_offset > p->sites[i].host_insn_offset ||
            p->sites[i].host_insn_offset >= p->sites[i].cont_insn_offset ||
            (size_t)p->sites[i].cont_insn_offset > code_len) {
            return NULL;
        }
    }
    return p->sites;
}

static unsigned cache_index(uint64_t pc)
{
    return (unsigned)((pc >> 2) ^ (pc >> 12)) & (MIPS64_DBT_CACHE_ENTRIES - 1u);
}

static unsigned ibtc_index(uint64_t pc)
{
    return (unsigned)((pc >> 2) & (MIPS64_IBTC_SIZE - 1u));
}

/* Lazily allocate the 4096-entry IBTC behind `ctx->ibtc_ptr`. */
static int ensure_ibtc(mips64_ctx_t *ctx)
{
    mips64_ibtc_slot_t *slots;

    if (ctx->ibtc_ptr != 0u)
        return 0;
    slots = calloc(MIPS64_IBTC_SIZE, sizeof *slots);
    if (slots == NULL)
        return -1;
    ctx->ibtc_ptr = (uint64_t)(uintptr_t)slots;
    return 0;
}

static void ibtc_insert(mips64_ctx_t *ctx, uint64_t guest, void *host)
{
    mips64_ibtc_slot_t *slots = (void *)(uintptr_t)ctx->ibtc_ptr;

    slots[ibtc_index(guest)].guest = guest;
    slots[ibtc_index(guest)].host = host;
}

static void ibtc_evict(mips64_ctx_t *ctx, uint64_t guest)
{
    mips64_ibtc_slot_t *slots;

    if (ctx == NULL || ctx->ibtc_ptr == 0u)
        return;
    slots = (void *)(uintptr_t)ctx->ibtc_ptr;
    if (slots[ibtc_index(guest)].guest == guest) {
        slots[ibtc_index(guest)].guest = 0u;
        slots[ibtc_index(guest)].host = NULL;
    }
}

/* Snapshot match for one cache entry: cover check (READ + EXEC) plus a
 * host-side memcmp of the covered guest bytes on SMC epoch advances. */
static int dbt_snap_match(mips64_ctx_t *ctx, const dbt_entry_t *e)
{
    uint64_t len;
    const void *cur;

    if (e->snap == NULL || e->blk.guest_end <= e->blk.guest_pc)
        return 0;
    len = e->blk.guest_end - e->blk.guest_pc;
    if (!mips_mem_ok(ctx, e->blk.guest_pc, len,
                     MIPS_PROT_READ | MIPS_PROT_EXEC))
        return 0;
    cur = mips64_guest_ptr(ctx, e->blk.guest_pc);
    return memcmp(cur, e->snap, (size_t)len) == 0;
}

/* Arm every page a translated block spans as code-bearing BEFORE
 * publishing, and revoke writable Soft-TLB tags for those pages. */
static void dbt_arm_code_pages(mips64_ctx_t *ctx, uint64_t start,
                               uint64_t end)
{
    uint64_t len;

    if (ctx == NULL || end <= start) {
        return;
    }
    len = end - start;
    mips_vm_pages_mark(start, len, (unsigned)MIPS_VM_PAGE_HAS_CODE);
    mips_soft_tlb_evict_write(ctx, start, len);
}

/* Validate one cache entry (Wave P epoch-gated): matching SMC epoch hits
 * with no snapshot scan; epoch advances flush the IBTC and revalidate. */
static dbt_entry_t *lookup_entry(mips64_ctx_t *ctx, uint64_t pc)
{
    dbt_entry_t *e = &block_cache[cache_index(pc)];
    uint64_t epoch = atomic_load_explicit(&dbt_smc_epoch, memory_order_acquire);

    if (ibtc_epoch != epoch) {
        if (ctx != NULL && ctx->ibtc_ptr != 0u)
            memset((void *)(uintptr_t)ctx->ibtc_ptr, 0,
                   MIPS64_IBTC_SIZE * sizeof(mips64_ibtc_slot_t));
        ibtc_epoch = epoch;
    }
    if (!e->used || e->pc != pc)
        return NULL;
    if (e->epoch == epoch)
        return e;
    if (e->fallback || e->blk.code == NULL) {
        e->epoch = epoch;
        return e;
    }
    if (!dbt_snap_match(ctx, e))
        return NULL;
    dbt_arm_code_pages(ctx, e->blk.guest_pc, e->blk.guest_end);
    if (atomic_load_explicit(&dbt_smc_epoch, memory_order_acquire) !=
        epoch)
        return NULL;
    e->epoch = epoch;
    if (ctx != NULL && ctx->ibtc_ptr != 0u)
        ibtc_insert(ctx, pc, e->blk.code);
    return e;
}

void *dbt_lookup(mips64_ctx_t *ctx, uint64_t pc)
{
    dbt_entry_t *e;
    mips64_ibtc_slot_t *slots;

    if (ctx == NULL)
        return NULL;
    if (ensure_ibtc(ctx) != 0)
        return NULL;
    /* Single probe: the epoch gate above makes the snapshot scan free
     * on the hot path, so one lookup serves the IBTC refresh too. */
    e = lookup_entry(ctx, pc);
    if (e == NULL || e->fallback || e->blk.code == NULL)
        return NULL;
    slots = (void *)(uintptr_t)ctx->ibtc_ptr;
    slots[ibtc_index(pc)].guest = pc;
    slots[ibtc_index(pc)].host = e->blk.code;
    return e->blk.code;
}

/* Privileged words end the block without a delay slot (the emitter
 * exits to the dispatcher and `interp` evaluates them). MIPS16
 * entry (`JALX`) likewise: `interp` faults, never jumps. FP words
 * flow into the L2c/L3b emitters (Wave P); only COP2/FP moves the
 * emitters decline abort the block via the emitter itself. */
static int is_bare_ender(const mips_dec_t *d)
{
    return d->op == MIPS64_OP_COP0 || d->op == MIPS64_OP_JALX;
}

/* Record a negative entry (run `interp_step` for this pc) and report
 * the compile as declined. Negative entries are always correct: the
 * fallback reads current guest bytes. */
static int compile_decline(mips64_ctx_t *ctx, uint64_t pc)
{
    dbt_entry_t *e = &block_cache[cache_index(pc)];

    if (e->used)
        ibtc_evict(ctx, e->pc);
    e->used = 1;
    e->pc = pc;
    e->blk.guest_pc = pc;
    e->blk.guest_end = pc + 4u;
    e->blk.code = NULL;
    e->blk.code_len = 0;
    e->blk.smc_version = (uint32_t)dbt_smc_epoch;
    e->epoch = dbt_smc_epoch;
    dbt_snap_drop(e);
    e->fallback = 1;
    return 1;
}

static int dbt_probe_insn(mips64_ctx_t *ctx, uint64_t pc, uint32_t *out)
{
    uint8_t b[4];
    if (ctx == NULL || out == NULL || (pc & 3ULL) != 0ULL ||
        !mips_mem_ok(ctx, pc, 4U, MIPS_PROT_READ | MIPS_PROT_EXEC))
        return MIPS_FAULT;
    memcpy(b, mips64_guest_ptr(ctx, pc), 4U);
    *out = mips_is_be(ctx)
        ? (((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3])
        : ((uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
    return 0;
}

int dbt_compile(mips64_ctx_t *ctx, uint64_t pc)
{
    static _Thread_local uint32_t staging[MIPS64_DBT_STAGING_WORDS];
    mips_dec_t insns[MIPS64_DBT_MAX_INSNS];
    dbt_entry_t *slot;
    uint64_t start_page, cur, out_end = 0u;
    size_t out_len = 0u;
    unsigned n = 0u;
    int rc;

    if (ctx == NULL || (pc & 3ULL) != 0ULL || ensure_ibtc(ctx) != 0)
        return 1;
    dbt_aot_ensure_loaded();
    slot = &block_cache[cache_index(pc)];
    if (slot->used && slot->pc == pc && slot->epoch == dbt_smc_epoch) {
        if (slot->fallback || slot->blk.code == NULL)
            return 1;
        if (lookup_entry(ctx, pc) != NULL)
            return 0;
    }
    start_page = pc & MIPS64_PAGE_MASK;
    cur = pc;
    while (n < (ctx->difftest_enabled ? 1u : MIPS64_DBT_MAX_INSNS)) {
        uint32_t word = 0u;
        mips_dec_t *d;

        if (n > 0u && (cur & MIPS64_PAGE_MASK) != start_page)
            break; /* SPEC 2.2: blocks end at page boundaries. */
        if (dbt_probe_insn(ctx, cur, &word) != 0)
            break;
        d = &insns[n];
        mips_decode(word, d);
        n++;
        cur += 4u;
        if (is_bare_ender(d) || mips_is_trap(d))
            break;
        if (mips_has_delay_slot(d)) {
            mips_dec_t *s;

            if (n >= MIPS64_DBT_MAX_INSNS ||
                dbt_probe_insn(ctx, cur, &word) != 0) {
                n--;
                cur -= 4u;
                break;
            }
            s = &insns[n];
            mips_decode(word, s);
            n++;
            cur += 4u;
            break;
        }
    }
    if (n == 0u)
        return compile_decline(ctx, pc);
    rc = dbt_emit_int(ctx, pc, insns, n, (uint8_t *)staging, sizeof staging,
                      &out_len, &out_end);
    if (rc != 0 || out_len == 0 || out_len > sizeof staging ||
        out_end <= pc || out_end > cur || (out_len & 3u) != 0u)
        return compile_decline(ctx, pc);
    {
        void *host = dbt_code_publish((const uint8_t *)staging, out_len);
        size_t len = (size_t)(out_end - pc);
        uint8_t *snap = NULL;

        if (host == NULL)
            return 1;
        if (len == 0u || len > (size_t)MIPS64_DBT_MAX_INSNS * 4u)
            return compile_decline(ctx, pc);
        snap = (uint8_t *)malloc(len);
        if (snap == NULL)
            return 1;
        memcpy(snap, mips64_guest_ptr(ctx, pc), len);
        if (slot->used)
            ibtc_evict(ctx, slot->pc);
        dbt_snap_drop(slot);
        slot->used = 1;
        slot->pc = pc;
        slot->blk.guest_pc = pc;
        slot->blk.guest_end = out_end;
        slot->blk.code = host;
        slot->blk.code_len = out_len;
        slot->blk.smc_version = (uint32_t)dbt_smc_epoch;
        slot->epoch = dbt_smc_epoch;
        slot->snap = snap;
        slot->fallback = 0;
        slot->sites = NULL;
        slot->site_count = 0u;
        {
            const dbt_mem_site_t *rows = NULL;
            size_t nrows = 0u;

            ei_mem_take_sites(&rows, &nrows);
            if (rows != NULL && nrows != 0u &&
                nrows <= DBT_MEM_SITES_MAX) {
                const dbt_mem_site_t *aot_rows =
                    dbt_aot_take_match(pc, rows, nrows, out_len);
                dbt_mem_site_t *copy =
                    (dbt_mem_site_t *)malloc(nrows *
                                             sizeof(dbt_mem_site_t));

                if (copy != NULL) {
                    memcpy(copy, aot_rows != NULL ? aot_rows : rows,
                           nrows * sizeof(dbt_mem_site_t));
                    slot->sites = copy;
                    slot->site_count = nrows;
                    if (aot_rows == NULL) {
                        mips_aot_note_block(pc, copy, nrows);
                        (void)dbt_aot_visit(pc, copy, nrows, NULL);
                    }
                }
            }
        }
        /* Wave P: arm the write gate for every published block (not
         * just memory-bearing ones), BEFORE the entry becomes
         * visible, and prefill once here instead of per execution. */
        dbt_arm_code_pages(ctx, pc, out_end);
        dbt_u0_prefill(ctx, pc, out_end);
        ibtc_insert(ctx, pc, host);
        ctx->blocks_compiled++;
        ctx->wx_transitions++;
        ctx->icache_flushes++;
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Trace + run loop.                                                  */
/* ------------------------------------------------------------------ */

extern void mips64_difftest_checkpoint(const mips64_ctx_t *ctx);

static void dbt_difftest_step(mips64_ctx_t *ctx)
{
    if (ctx != NULL && ctx->difftest_enabled) {
        dbt_npc_resume(ctx);
        mips64_difftest_checkpoint(ctx);
    }
}

void mips64_dbt_trace(mips64_ctx_t *ctx, uint64_t pc, uint32_t word)
{
    if (ctx == NULL || !ctx->trace_enabled)
        return;
    (void)fprintf(stderr, "I %llx %x\n", (unsigned long long)pc, word);
}

struct dbt_guarded_enter {
    uint64_t base;
    void *code;
    uint64_t budget;
    const _Atomic uint64_t *epoch;
    long ex;
};

static _Thread_local struct dbt_guarded_enter dbt_ge;

static void dbt_guarded_tramp(mips64_ctx_t *ctx)
{
    dbt_ge.ex =
        mips64_dbt_enter(ctx, dbt_ge.base, dbt_ge.code, dbt_ge.budget,
                         dbt_ge.epoch);
}

static void *dbt_tramp_ptr(void (*fn)(mips64_ctx_t *))
{
    void *p = NULL;

    memcpy(&p, &fn, sizeof p);
    return p;
}

static int block_branch_likely(mips64_ctx_t *ctx, uint64_t end)
{
    uint32_t w = 0u;
    mips_dec_t d;

    if (end < 8u || dbt_probe_insn(ctx, end - 8u, &w) != 0)
        return 0;
    mips_decode(w, &d);
    if (d.op >= 0x14u && d.op <= 0x17u)
        return 1;
    if (d.op == 0x01u &&
        (d.rt == 0x02u || d.rt == 0x03u || d.rt == 0x12u || d.rt == 0x13u))
        return 1;
    return 0;
}

static void trace_block_exit(mips64_ctx_t *ctx, uint64_t start, uint64_t end,
                             int full)
{
    uint64_t hi;
    uint64_t va;

    if (!ctx->trace_enabled)
        return;
    if (full || ctx->pc < start || ctx->pc > end)
        hi = end;
    else
        hi = ctx->pc;
    if (full && hi == end && ctx->pc == end && end >= start + 8u &&
        block_branch_likely(ctx, end) != 0)
        hi = end - 4u;
    for (va = start; va < hi; va += 4u) {
        uint32_t word = 0u;

        if (dbt_probe_insn(ctx, va, &word) != 0)
            break;
        mips64_dbt_trace(ctx, va, word);
    }
}

static void ras_update(mips64_ctx_t *ctx, unsigned info)
{
    if ((info & MIPS64_DBT_INFO_LINK) != 0u) {
        if (ras_top < MIPS64_DBT_RAS_ENTRIES)
            ras[ras_top++] = ctx->next_pc;
    } else if ((info & MIPS64_DBT_INFO_RETURN) != 0u) {
        if (ras_top > 0)
            ras_top--;
    }
}

void dbt_trace_fault_prefix(mips64_ctx_t *ctx, uint64_t start,
                            uint64_t fault)
{
    if (ctx == NULL) {
        return;
    }
    ctx->pc = fault;
    trace_block_exit(ctx, start, fault, 0);
}

void dbt_visit_blocks(dbt_block_visit_t visit, void *arg)
{
    size_t i;

    if (visit == NULL) {
        return;
    }
    for (i = 0u; i < MIPS64_DBT_CACHE_ENTRIES; i++) {
        dbt_entry_t *e = &block_cache[i];

        if (e->used == 0 || e->fallback != 0 || e->blk.code == NULL ||
            e->sites == NULL || e->site_count == 0u) {
            continue;
        }
        if (visit(e->sites, e->site_count,
                  (uint64_t)(uintptr_t)e->blk.code,
                  (size_t)e->blk.code_len, e->blk.guest_pc, arg) != 0) {
            return;
        }
    }
}

static void dbt_flush_thread_caches(mips64_ctx_t *ctx)
{
    size_t i;

    for (i = 0u; i < MIPS64_DBT_CACHE_ENTRIES; i++) {
        dbt_snap_drop(&block_cache[i]);
        memset(&block_cache[i], 0, sizeof block_cache[i]);
    }
    ras_top = 0u;
    ibtc_epoch = 0u;
    if (ctx != NULL && ctx->ibtc_ptr != 0u) {
        memset((void *)(uintptr_t)ctx->ibtc_ptr, 0,
               MIPS64_IBTC_SIZE * sizeof(mips64_ibtc_slot_t));
    }
    dbt_arena_reset();
}

void dbt_thread_exit(mips64_ctx_t *ctx)
{
    size_t i;

    dbt_flush_thread_caches(ctx);
    for (i = 0u; i < DBT_AOT_PRELOAD_MAX; i++) {
        if (aot_preload[i].sites != NULL) {
            free(aot_preload[i].sites);
            aot_preload[i].sites = NULL;
        }
        aot_preload[i].used = 0;
        aot_preload[i].count = 0u;
    }
    aot_preload_path[0] = '\0';
    if (ctx != NULL && ctx->ibtc_ptr != 0u) {
        free((void *)(uintptr_t)ctx->ibtc_ptr);
        ctx->ibtc_ptr = 0u;
    }
}

static const dbt_mem_site_t *dbt_find_site(const dbt_entry_t *e,
                                           uint64_t delta)
{
    size_t i;

    if (e == NULL || e->sites == NULL || delta > (uint64_t)0xFFFFu) {
        return NULL;
    }
    for (i = 0u; i < e->site_count; i++) {
        if ((uint64_t)e->sites[i].guest_pc_delta == delta) {
            return &e->sites[i];
        }
    }
    return NULL;
}

int dbt_run(mips64_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;
    if (ensure_ibtc(ctx) != 0) {
        for (;;) {
            int rc = interp_step(ctx);

            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
        }
    }
    mips_hostfault_install((const void *)(uintptr_t)ctx->guest_base,
                           ctx->task_size);
    for (;;) {
        uint64_t pc = ctx->pc;
        dbt_entry_t *e;
        uint64_t start;
        uint64_t end;
        void *code;
        long ex;
        int rc;

        if (ctx->exit_reason != MIPS64_EXIT_NONE)
            return 1;
        if (dbt_arena_needs_reclaim() != 0)
            dbt_flush_thread_caches(ctx);
        dbt_npc_resume(ctx);
        pc = ctx->pc;
        /* Single probe: the epoch gate retires stale entries without
         * a snapshot scan, so no second lookup is needed. */
        e = lookup_entry(ctx, pc);
        if (e == NULL) {
            if (dbt_compile(ctx, pc) != 0) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                dbt_difftest_step(ctx);
                continue;
            }
            e = lookup_entry(ctx, pc);
            if (e == NULL) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                dbt_difftest_step(ctx);
                continue;
            }
        }
        if (e->fallback || e->blk.code == NULL) {
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
            continue;
        }
        start = e->blk.guest_pc;
        end = e->blk.guest_end;
        code = e->blk.code;
        ctx->blocks_executed++;
        if (!mips64_dbt_available()) {
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
            continue;
        }
        dbt_ge.base = (uint64_t)(uintptr_t)mips_soft_tlb_base(ctx);
        dbt_ge.code = code;
        /* In-trampoline chaining is exact-lockstep-hostile: one block
         * per enter under --difftest, single-step, or tracing. The
         * budget also bounds signal/quiescence latency (preempt
         * signals are never blocked inside JIT code, so they still
         * preempt a chaining loop). */
        dbt_ge.budget = (ctx->difftest_enabled || ctx->trace_enabled) !=
                0 ? 1u : 4096u;
        dbt_ge.epoch = &dbt_smc_epoch;
        dbt_ge.ex = MIPS64_DBT_EXIT_FAULT;
        {
            uint32_t reason = (uint32_t)MIPS64_EXIT_NONE;
            int frc = mips_hostfault_run(ctx,
                                         dbt_tramp_ptr(dbt_guarded_tramp),
                                         &reason);

            if (frc == MIPS_FAULT) {
                ex = MIPS64_DBT_EXIT_FAULT;
            } else {
                ex = dbt_ge.ex;
            }
        }
        switch (ex) {
        case MIPS64_DBT_EXIT_DIRECT:
            trace_block_exit(ctx, start, end, 1);
            ras_update(ctx, ctx->exit_info);
            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            dbt_difftest_step(ctx);
            continue;
        case MIPS64_DBT_EXIT_UNDEF:
        case MIPS64_DBT_EXIT_SINGLE_STEP:
        case MIPS64_DBT_EXIT_SYSCALL:
            trace_block_exit(ctx, start, end, 0);
            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
            continue;
        case MIPS64_DBT_EXIT_FAULT:
        case MIPS64_DBT_EXIT_TRAP: {
            uint32_t idx = ctx->exit_info;
            uint64_t fpc = ctx->pc;
            dbt_entry_t *te = (ex == MIPS64_DBT_EXIT_TRAP) ?
                ((fpc == start) ? e : lookup_entry(ctx, fpc)) :
                ((fpc >= start && fpc < end) ? e : lookup_entry(ctx, fpc));
            uint64_t bstart = te != NULL ? te->blk.guest_pc : fpc;
            const dbt_mem_site_t *site = NULL;
            int mrc;

            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            ctx->pad150 = 0u;
            if (ex == MIPS64_DBT_EXIT_TRAP) {
                if (te != NULL && te->sites != NULL && idx < te->site_count) {
                    site = &te->sites[idx];
                    fpc = bstart + (uint64_t)site->guest_pc_delta;
                }
            } else if (te != NULL && te->sites != NULL && fpc >= bstart) {
                site = dbt_find_site(te, fpc - bstart);
            }
            mrc = dbt_mem_recover(ctx, site, bstart, fpc);
            if (mrc == 0) {
                ctx->exit_reason = MIPS64_EXIT_NONE;
                ctx->exit_info = 0u;
                dbt_difftest_step(ctx);
                continue;
            }
            if (mrc == 2 && ctx->trace_enabled) {
                uint32_t word = 0u;

                if (mips_fetch(ctx, ctx->pc, &word) == 0)
                    mips64_dbt_trace(ctx, ctx->pc, word);
            }
            if (ctx->exit_reason == MIPS64_EXIT_NONE) {
                ctx->exit_info = 0u;
                dbt_difftest_step(ctx);
                continue;
            }
            return (int)MIPS_FAULT;
        }
        default:
            trace_block_exit(ctx, start, end, 0);
            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
            continue;
        }
    }
}
