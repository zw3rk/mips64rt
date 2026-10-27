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
 * construction. FP/COP1 blocks never reach the emitter: the compile
 * scan hands them to `interp_step` until Phase 3.
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
long mips64_dbt_enter(mips64_ctx_t *ctx, uint64_t base, void *code)
{
    (void)ctx;
    (void)base;
    (void)code;
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
/* W^X code pages.                                                    */
/* ------------------------------------------------------------------ */

/* Publish one block through the backend JIT hooks (W^X done right
 * per host: Linux flips RW->RX, Darwin toggles MAP_JIT writability
 * and never mprotects). Guest data pages are never `PROT_EXEC` on
 * the host. Evicted cache entries keep their RX mapping until
 * process end (RC2 bound: the cache holds 1024 entries), so no live
 * IBTC slot can ever dangle. */
static void *dbt_code_publish(const uint8_t *buf, size_t len)
{
    void *p;

    if (buf == NULL || len == 0)
        return NULL;
    p = mips_jit_alloc(len);
    if (p == NULL)
        return NULL;
    mips_jit_begin_write(p, len);
    memcpy(p, buf, len);
    if (mips_jit_seal_rx(p, len) != 0) {
        mips_jit_free(p, len);
        return NULL;
    }
    return p;
}

/* ------------------------------------------------------------------ */
/* Block cache + IBTC + RAS.                                          */
/* ------------------------------------------------------------------ */

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

/* Release an entry snapshot (evict/decline overwrite, code mappings
 * are intentionally retained per the RC2 1024-entry bound). */
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
        if (p->sites[i].guest_pc_delta != rows[i].guest_pc_delta ||
            p->sites[i].insn_word != rows[i].insn_word ||
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

/* Snapshot match for one cache entry: a single cover check plus a
 * host-side memcmp of the covered guest bytes. Same detection power
 * as the old per-word fetch+hash (any clobbering plain store
 * retires the translation), at one lock acquisition and no fetch
 * calls: the per-entry O(block) scan with per-word overhead is what
 * kept `dbt` below `interp` on branch-heavy code (lane H3). The
 * snapshot holds raw host bytes (not decoded words), so the compare
 * is endianness-neutral: a word compare would pass on LE and fail on
 * BE forever, recompiling every block until the RX mappings exhaust
 * the container (lane H4 n32be-dbt SIGKILL). Returns 0 when the
 * range is not fully readable (lookup miss: the dispatcher
 * retranslates, and `interp` raises the guest fault). */
static int dbt_snap_match(mips64_ctx_t *ctx, const dbt_entry_t *e)
{
    uint64_t len;
    const void *cur;

    if (e->snap == NULL || e->blk.guest_end <= e->blk.guest_pc)
        return 0;
    len = e->blk.guest_end - e->blk.guest_pc;
    if (!mips_mem_ok(ctx, e->blk.guest_pc, len, MIPS_PROT_READ))
        return 0;
    cur = mips64_guest_ptr(ctx, e->blk.guest_pc);
    return memcmp(cur, e->snap, (size_t)len) == 0;
}

/* Validate one cache entry: epoch match plus, for native entries, a
 * guest-word snapshot match (retires translations clobbered by plain
 * stores with no remap epoch bump). Negative entries need no check:
 * the `interp_step` fallback always reads current bytes. */
static dbt_entry_t *lookup_entry(mips64_ctx_t *ctx, uint64_t pc)
{
    dbt_entry_t *e = &block_cache[cache_index(pc)];

    if (!e->used || e->pc != pc || e->epoch != dbt_smc_epoch)
        return NULL;
    if (e->fallback || e->blk.code == NULL)
        return e;
    if (!dbt_snap_match(ctx, e))
        return NULL;
    return e;
}

void *dbt_lookup(mips64_ctx_t *ctx, uint64_t pc)
{
    dbt_entry_t *e;
    mips64_ibtc_slot_t *slots;
    mips64_ibtc_slot_t *s;

    if (ctx == NULL)
        return NULL;
    if (ensure_ibtc(ctx) != 0)
        return NULL;
    /* IBTC fast path, revalidated like the cache probe (an evicted
     * entry never matches: its code pointer is gone from the cache). */
    slots = (void *)(uintptr_t)ctx->ibtc_ptr;
    s = &slots[ibtc_index(pc)];
    if (s->host != NULL && s->guest == pc) {
        e = lookup_entry(ctx, pc);
        if (e != NULL && !e->fallback && e->blk.code == s->host)
            return s->host;
    }
    e = lookup_entry(ctx, pc);
    if (e == NULL || e->fallback || e->blk.code == NULL)
        return NULL;
    ibtc_insert(ctx, pc, e->blk.code);
    return e->blk.code;
}

/* True for instructions lowered by Phase 3: any COP1/COP1X/COP2 word
 * or FPR load/store. Such words abort the whole block compile; the
 * dispatcher runs them in `interp_step` instead. */
static int is_fp_coproc(const mips_dec_t *d)
{
    switch (d->op) {
    case MIPS64_OP_COP1:
    case MIPS64_OP_COP1X:
    case MIPS64_OP_COP2:
    case MIPS64_OP_LWC1:
    case MIPS64_OP_LDC1:
    case MIPS64_OP_SWC1:
    case MIPS64_OP_SDC1:
    case MIPS64_OP_LWC2:
    case MIPS64_OP_LDC2:
    case MIPS64_OP_SWC2:
    case MIPS64_OP_SDC2:
        return 1;
    default:
        return 0;
    }
}

/* Privileged words end the block without a delay slot (the emitter
 * exits to the dispatcher and `interp` evaluates them). MIPS16
 * entry (`JALX`) likewise: `interp` faults, never jumps. */
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

    (void)ctx;

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

int dbt_compile(mips64_ctx_t *ctx, uint64_t pc)
{
    static _Thread_local uint32_t staging[MIPS64_DBT_STAGING_WORDS];
    mips_dec_t insns[MIPS64_DBT_MAX_INSNS];
    dbt_entry_t *slot;
    uint64_t start_page;
    uint64_t cur;
    uint64_t out_end = 0u;
    size_t out_len = 0u;
    unsigned n = 0u;
    int rc;

    if (ctx == NULL || (pc & 3ULL) != 0ULL)
        return 1;
    if (ensure_ibtc(ctx) != 0)
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
        if (mips_fetch(ctx, cur, &word) != 0)
            break;
        d = &insns[n];
        mips_decode(word, d);
        if (is_fp_coproc(d))
            return compile_decline(ctx, pc);
        n++;
        cur += 4u;
        if (is_bare_ender(d) || mips_is_trap(d))
            break;
        if (mips_has_delay_slot(d)) {
            mips_dec_t *s;

            if (mips_fetch(ctx, cur, &word) != 0) {
                n--;
                cur -= 4u;
                break;
            }
            s = &insns[n];
            mips_decode(word, s);
            if (is_fp_coproc(s))
                return compile_decline(ctx, pc);
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
                    if (out_end > pc) {
                        mips_vm_pages_mark(pc, out_end - pc,
                                           (unsigned)MIPS_VM_PAGE_HAS_CODE);
                    }
                }
            }
        }
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
    long ex;
};

static _Thread_local struct dbt_guarded_enter dbt_ge;

static void dbt_guarded_tramp(mips64_ctx_t *ctx)
{
    dbt_ge.ex = mips64_dbt_enter(ctx, dbt_ge.base, dbt_ge.code);
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

    if (end < 8u || mips_fetch(ctx, end - 8u, &w) != 0)
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

        if (mips_fetch(ctx, va, &word) != 0)
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
        dbt_npc_resume(ctx);
        pc = ctx->pc;
        code = dbt_lookup(ctx, pc);
        if (code == NULL) {
            if (dbt_compile(ctx, pc) != 0) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                dbt_difftest_step(ctx);
                continue;
            }
            code = dbt_lookup(ctx, pc);
            if (code == NULL) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                dbt_difftest_step(ctx);
                continue;
            }
        }
        e = lookup_entry(ctx, pc);
        if (e == NULL || e->fallback || e->blk.code != code) {
            continue;
        }
        start = e->blk.guest_pc;
        end = e->blk.guest_end;
        ctx->blocks_executed++;
        if (!mips64_dbt_available()) {
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            dbt_difftest_step(ctx);
            continue;
        }
        dbt_u0_prefill(ctx, start, end);
        dbt_ge.base = (uint64_t)(uintptr_t)mips_soft_tlb_base(ctx);
        dbt_ge.code = code;
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
        case MIPS64_DBT_EXIT_FAULT: {
            dbt_entry_t *te = e;
            const dbt_mem_site_t *site = NULL;
            uint64_t fpc = ctx->pc;
            int mrc;

            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            ctx->pad150 = 0u;
            if (te != NULL && te->sites != NULL && fpc >= start) {
                site = dbt_find_site(te, fpc - start);
            }
            mrc = dbt_mem_recover(ctx, site, start, fpc);
            if (mrc == 0) {
                ctx->exit_reason = MIPS64_EXIT_NONE;
                ctx->exit_info = 0u;
                dbt_difftest_step(ctx);
                continue;
            }
            if (mrc == 2 && ctx->trace_enabled) {
                uint32_t word = 0u;

                if (mips_fetch(ctx, ctx->pc, &word) == 0) {
                    mips64_dbt_trace(ctx, ctx->pc, word);
                }
            }
            if (ctx->exit_reason == MIPS64_EXIT_NONE) {
                ctx->exit_info = 0u;
                dbt_difftest_step(ctx);
                continue;
            }
            return (int)MIPS_FAULT;
        }
        case MIPS64_DBT_EXIT_TRAP: {
            uint32_t idx = ctx->exit_info;
            dbt_entry_t *te = e;
            const dbt_mem_site_t *site = NULL;
            uint64_t fpc = ctx->pc;
            int mrc;

            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            ctx->pad150 = 0u;
            if (te != NULL && te->sites != NULL && idx < te->site_count) {
                site = &te->sites[idx];
                fpc = start + (uint64_t)site->guest_pc_delta;
            }
            mrc = dbt_mem_recover(ctx, site, start, fpc);
            if (mrc == 0) {
                ctx->exit_reason = MIPS64_EXIT_NONE;
                ctx->exit_info = 0u;
                dbt_difftest_step(ctx);
                continue;
            }
            if (mrc == 2 && ctx->trace_enabled) {
                uint32_t word = 0u;

                if (mips_fetch(ctx, ctx->pc, &word) == 0) {
                    mips64_dbt_trace(ctx, ctx->pc, word);
                }
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
