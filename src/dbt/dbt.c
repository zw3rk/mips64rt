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
#include "interp/decode.h"
#include "os/backend.h"

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

static uint64_t dbt_smc_epoch = 1;

void dbt_invalidate_all(void)
{
    dbt_smc_epoch++;
    if (dbt_smc_epoch == 0)
        dbt_smc_epoch = 1;
}

void dbt_invalidate_range(uint64_t va, uint64_t len)
{
    (void)va;
    (void)len;
    /* Range-granular SMC tracking lands with the L2a syscall hooks; a
     * full epoch bump keeps every stale translation unreachable, and
     * the per-entry guest-word snapshot below retires translations
     * clobbered by plain stores without any hook. */
    dbt_invalidate_all();
}

uint64_t dbt_epoch(void)
{
    return dbt_smc_epoch;
}

/* ------------------------------------------------------------------ */
/* U0 delay-slot NPC + soft-TLB prefill (lane L-U0-C).                */
/* ------------------------------------------------------------------ */

int dbt_npc_resume(mips64_ctx_t *ctx)
{
    uint64_t applied = 0U;

    return mips_npc_resume_step(ctx, &applied);
}

void dbt_u0_prefill(mips64_ctx_t *ctx, uint64_t start, uint64_t end)
{
    uint64_t va;

    if (ctx == NULL || end <= start) {
        return;
    }
    /* One fill per 4 KiB page in the block span; misses fault to
     * the interp_step fallback by construction, so a short span
     * stays correct even without this loop. Fill empty slots only:
     * the invalidation sentinel is UINT64_MAX (see u0_invalidate)
     * and a matching tag is already correct. Overwriting a live
     * entry here evicts just-filled data pages every iteration when
     * a code vpn aliases a data vpn in the 64-entry table,
     * livelocking fill-and-retry (demand fills still overwrite on
     * miss). */
    {
        mips_soft_tlb_entry_t *tlb =
            (mips_soft_tlb_entry_t *)mips_soft_tlb_base(ctx);

        if (tlb == NULL) {
            return;
        }
        va = start & ~(uint64_t)4095U;
        while (va < end) {
            uint64_t vpn = va >> 12;
            mips_soft_tlb_entry_t *e =
                &tlb[vpn & MIPS64_SOFT_TLB_INDEX_MASK];

            if (e->tag == UINT64_MAX || e->tag == vpn) {
                mips_soft_tlb_fill(ctx, va);
            }
            if (va + 4096U < va) {
                break;
            }
            va += 4096U;
        }
    }
}

/* ------------------------------------------------------------------ */
/* W^X code pages.                                                    */
/* ------------------------------------------------------------------ */

static long dbt_host_page_size(void)
{
    static long cached = 0;

    if (cached <= 0) {
        cached = sysconf(_SC_PAGESIZE);
        if (cached < 4096)
            cached = 4096;
    }
    return cached;
}

/* Publish one block: copy to a fresh RW mapping, flip to R+X, flush
 * the I-cache (W^X). Guest data pages are never `PROT_EXEC` on the
 * host. Evicted cache entries keep their RX mapping until process
 * end (RC2 bound: the cache holds 1024 entries), so no live IBTC
 * slot can ever dangle. */
static void *dbt_code_publish(const uint8_t *buf, size_t len)
{
    size_t ps = (size_t)dbt_host_page_size();
    size_t n = (len + ps - 1u) & ~(ps - 1u);
    void *p;

    if (buf == NULL || len == 0 || n < len)
        return NULL;
    p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    memcpy(p, buf, len);
    if (mprotect(p, n, PROT_READ | PROT_EXEC) != 0) {
        (void)munmap(p, n);
        return NULL;
    }
    __builtin___clear_cache((char *)p, (char *)p + len);
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
} dbt_entry_t;

/* Release an entry snapshot (evict/decline overwrite, code mappings
 * are intentionally retained per the RC2 1024-entry bound). */
static void dbt_snap_drop(dbt_entry_t *e)
{
    if (e != NULL && e->snap != NULL) {
        free(e->snap);
        e->snap = NULL;
    }
}

static dbt_entry_t block_cache[MIPS64_DBT_CACHE_ENTRIES];
static uint64_t ras[MIPS64_DBT_RAS_ENTRIES];
static unsigned ras_top;

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
    static uint32_t staging[MIPS64_DBT_STAGING_WORDS];
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
    slot = &block_cache[cache_index(pc)];
    if (slot->used && slot->pc == pc && slot->epoch == dbt_smc_epoch) {
        /* A valid entry means a retry with no guest change: native
         * entries re-enter, negative entries stay in `interp`. */
        if (slot->fallback || slot->blk.code == NULL)
            return 1;
        if (lookup_entry(ctx, pc) != NULL)
            return 0;
    }
    start_page = pc & MIPS64_PAGE_MASK;
    cur = pc;
    while (n < MIPS64_DBT_MAX_INSNS) {
        uint32_t word = 0u;
        mips_dec_t *d;

        if (n > 0u && (cur & MIPS64_PAGE_MASK) != start_page)
            break; /* SPEC 2.2: blocks end at page boundaries. */
        if (mips_fetch(ctx, cur, &word) != 0)
            break; /* Unreadable tail: the block falls through to pc
                    * `cur`, where `interp` raises the guest fault. */
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
                /* Delay slot unreadable (the RC1 `page_end - 4`
                 * probe): drop the branch and let `interp` run the
                 * pair across the page edge. */
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
            return 1; /* Resource exhaustion: retry later, cache nothing. */
        if (len == 0u || len > (size_t)MIPS64_DBT_MAX_INSNS * 4u)
            return compile_decline(ctx, pc);
        snap = (uint8_t *)malloc(len);
        if (snap == NULL)
            return 1; /* Retry later, cache nothing. */
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

void mips64_dbt_trace(mips64_ctx_t *ctx, uint64_t pc, uint32_t word)
{
    if (ctx == NULL || !ctx->trace_enabled)
        return;
    (void)fprintf(stderr, "I %llx %x\n", (unsigned long long)pc, word);
}

/* RC4: run one compiled block under the L4b host-fault guard, so a
 * compiled load/store to a PROT_NONE (or unmapped) guest page becomes
 * a guest SIGSEGV — deliverable via the EXIT_FAULT case — instead of
 * killing the translator with a host fault. mips_hostfault_run takes
 * a void (*)(ctx); the trampoline below carries the (base, code) pair
 * in a thread-local slot. The guard is installed once per dbt_run
 * over the whole guest reservation (idempotent). */
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

/* A not-taken MIPS branch-likely annuls its delay slot: the word
 * at `end - 4` never executes, so the trace must skip it. Mirrors
 * the `likely` set in `ei_branch` (emit_int.c); COP1-likely declines
 * to interp and never reaches a compiled block. */
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

/* Print the natively executed prefix of a block exit: full blocks
 * print `[start, end)`; fallback exits print `[start, ctx->pc)` (the
 * dispatcher completes the insn at `ctx->pc` via `interp_step`,
 * which prints its own line). A not-taken likely exit lands exactly
 * on `end` with its delay slot annulled, so it prints `[start,
 * end - 4)`. Same `I <pc> <word>` shape as `interp`'s fetch trace,
 * so the L2d difftest compares equal. */
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

/* RC4: effective address of the faulting word at pc (load/store with
 * base+offset form; anything else reports pc itself). exit_info only
 * carries the low 32 bits, so si_addr for a handled SIGSEGV is
 * recomputed here from the decoded word and current regs. */
static uint64_t dbt_fault_ea(mips64_ctx_t *ctx, uint64_t pc)
{
    uint32_t word = 0u;
    mips_dec_t d;

    if (mips_fetch(ctx, pc, &word) != 0) {
        return pc;
    }
    mips_decode(word, &d);
    if (d.op >= 0x20u && d.op <= 0x3Fu) {
        return ctx->gpr[d.rs] + (uint64_t)(int64_t)d.simm;
    }
    return pc;
}

/* U0 cold-data-page fill-and-retry (see dbt.h): distinguish a TLB
 * miss on a mapped page (fill + retry) from a genuine fault. Span
 * ops (LWL/LWR/SWL/SWR touch a 4-byte word span, LDL/LDR/SDL/SDR an
 * 8-byte doubleword span) probe the aligned span; every other op
 * probes [ea, ea+width). Coprocessor transfers share the integer
 * widths; CACHE probes one byte read; PREF never faults in the
 * emitter but a mapped span still fills harmlessly. */
int dbt_u0_fill_retry(mips64_ctx_t *ctx, uint64_t pc)
{
    uint32_t word = 0u;
    mips_dec_t d;
    uint64_t ea;
    uint64_t base;
    uint64_t len = 0u;
    uint64_t p0;
    uint64_t p1;
    uint32_t need = MIPS_PROT_READ;
    int is_span = 0;
    mips_soft_tlb_entry_t *tlb;

    if (ctx == NULL || mips_fetch(ctx, pc, &word) != 0) {
        return 0;
    }
    mips_decode(word, &d);
    switch (d.op) {
    case 0x20u: /* LB */
    case 0x24u: /* LBU */
        len = 1u;
        break;
    case 0x21u: /* LH */
    case 0x25u: /* LHU */
        len = 2u;
        break;
    case 0x23u: /* LW */
    case 0x27u: /* LWU */
    case 0x30u: /* LL */
    case 0x31u: /* LWC1 */
        len = 4u;
        break;
    case 0x37u: /* LD */
    case 0x34u: /* LLD */
    case 0x35u: /* LDC1 */
        len = 8u;
        break;
    case 0x28u: /* SB */
        need = MIPS_PROT_WRITE;
        len = 1u;
        break;
    case 0x29u: /* SH */
        need = MIPS_PROT_WRITE;
        len = 2u;
        break;
    case 0x2bu: /* SW */
    case 0x38u: /* SC */
    case 0x39u: /* SWC1 */
        need = MIPS_PROT_WRITE;
        len = 4u;
        break;
    case 0x3fu: /* SD */
    case 0x3cu: /* SCD */
    case 0x3du: /* SDC1 */
        need = MIPS_PROT_WRITE;
        len = 8u;
        break;
    case 0x22u: /* LWL */
    case 0x26u: /* LWR */
        len = 4u;
        is_span = 1;
        break;
    case 0x2au: /* SWL */
    case 0x2eu: /* SWR */
        need = MIPS_PROT_WRITE;
        len = 4u;
        is_span = 1;
        break;
    case 0x1au: /* LDL */
    case 0x1bu: /* LDR */
        len = 8u;
        is_span = 1;
        break;
    case 0x2cu: /* SDL */
    case 0x2du: /* SDR */
        need = MIPS_PROT_WRITE;
        len = 8u;
        is_span = 1;
        break;
    case 0x2fu: /* CACHE */
        len = 1u;
        break;
    case 0x33u: /* PREF */
        len = 1u;
        break;
    default:
        return 0;
    }
    ea = ctx->gpr[d.rs] + (uint64_t)(int64_t)d.simm;
    if (is_span != 0) {
        base = ea & ~(len - 1u);
    } else {
        base = ea;
    }
    if (mips_mem_ok(ctx, base, len, need) == 0) {
        return 0;
    }
    tlb = (mips_soft_tlb_entry_t *)mips_soft_tlb_base(ctx);
    if (tlb == NULL) {
        return 0;
    }
    p0 = base >> 12;
    p1 = (base + len - 1u) >> 12;
    if (tlb[p0 & MIPS64_SOFT_TLB_INDEX_MASK].tag == p0 &&
        (p1 == p0 ||
         tlb[p1 & MIPS64_SOFT_TLB_INDEX_MASK].tag == p1)) {
        return 0;
    }
    mips_soft_tlb_fill(ctx, base);
    if (p1 != p0) {
        mips_soft_tlb_fill(ctx, base + len - 1u);
    }
    return 1;
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
        }
    }
    /* Guard installed once per run (idempotent): the reservation base
     * is fixed for the run, so per-block install only paid a mutex
     * round-trip per translated block (lane H3). */
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
        /* U0 dynamic NPC: a pending delay target (x25 in emitted
         * code) selects the resume pc before the cache probe. */
        dbt_npc_resume(ctx);
        pc = ctx->pc;
        code = dbt_lookup(ctx, pc);
        if (code == NULL) {
            if (dbt_compile(ctx, pc) != 0) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                continue;
            }
            code = dbt_lookup(ctx, pc);
            if (code == NULL) {
                rc = interp_step(ctx);
                if (rc != 0)
                    return rc;
                continue;
            }
        }
        e = lookup_entry(ctx, pc);
        start = (e != NULL) ? e->blk.guest_pc : pc;
        end = (e != NULL) ? e->blk.guest_end : pc + 4u;
        ctx->blocks_executed++;
        if (!mips64_dbt_available()) {
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            continue;
        }
        /* U0: x20 binds the soft-TLB base; prefill the block span
         * so the inlined probe hits. */
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
        /* All chaining flavors share the cpu.h BRANCH code (dbt.h):
         * one label covers FALLTHROUGH, DIRECT and INDIRECT. */
        case MIPS64_DBT_EXIT_DIRECT:
            trace_block_exit(ctx, start, end, 1);
            ras_update(ctx, ctx->exit_info);
            /* Consumed: a stale BRANCH reason must not abort the next
             * iteration at the loop-top check (RC2: every taken branch
             * ended the run with (exit 1)). */
            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
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
            continue;
        case MIPS64_DBT_EXIT_FAULT:
            /* RC4: every compiled load/store records its guest pc in
             * the scratch slot before touching host memory, so a
             * host-guard capture lands on the precise faulting word
             * even though blocks never advance ctx->pc per insn. */
            if (ctx->pad150 != 0u) {
                ctx->pc = ctx->pad150;
            }
            /* U0 cold-data-page fill-and-retry runs before any
             * tracing: the re-executed block traces its own prefix
             * on its real exit, so tracing here would print the
             * prefix twice and break --trace/difftest parity. */
            if (dbt_u0_fill_retry(ctx, ctx->pc) != 0) {
                /* Retry at the faulting word: earlier words already
                 * committed (re-executing them would replay register
                 * clobbers with clobbered inputs, e.g. startup
                 * gp-ra chains), so only the faulting access runs
                 * again against the freshly filled entry. When the
                 * faulting word is a delay slot, resume at its branch
                 * instead: the slot alone cannot re-apply the
                 * taken/fallthrough decision. The scratch slot is
                 * cleared so a later guard capture without a fresh
                 * record cannot reuse a stale pc. */
                {
                    uint32_t prev = 0u;
                    mips_dec_t pd;

                    if (ctx->pc >= 4u &&
                        mips_fetch(ctx, ctx->pc - 4u, &prev) == 0) {
                        mips_decode(prev, &pd);
                        if (mips_has_delay_slot(&pd) != 0) {
                            ctx->pc -= 4u;
                        }
                    }
                }
                ctx->pad150 = 0u;
                ctx->exit_reason = MIPS64_EXIT_NONE;
                ctx->exit_info = 0u;
                continue;
            }
            trace_block_exit(ctx, start, end, 0);
            /* The faulting insn is terminal: no `interp_step`
             * re-run prints it, so print its line here to match
             * `interp` (which traces the faulting fetch). */
            if (ctx->trace_enabled) {
                uint32_t word = 0u;

                if (mips_fetch(ctx, ctx->pc, &word) == 0)
                    mips64_dbt_trace(ctx, ctx->pc, word);
            }
            /* RC4: exactly one mips_fault trap per fault (inline
             * epilogue faults and host-guard captures alike), so a
             * handled SIGSEGV delivers exactly like interp (frame +
             * handler pc) with no stale duplicate queued. */
            if (ctx->exit_reason == MIPS64_EXIT_FAULT) {
                mips_fault(ctx, dbt_fault_ea(ctx, ctx->pc));
            }
            if (ctx->exit_reason == MIPS64_EXIT_NONE) {
                ctx->exit_info = 0u;
                continue;
            }
            return (int)MIPS_FAULT;
        default:
            trace_block_exit(ctx, start, end, 0);
            ctx->exit_reason = MIPS64_EXIT_NONE;
            ctx->exit_info = 0u;
            rc = interp_step(ctx);
            if (rc != 0)
                return rc;
            continue;
        }
    }
}
