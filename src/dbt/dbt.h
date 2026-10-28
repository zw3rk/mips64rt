/*
 * src/dbt/dbt.h — AArch64 DBT core interface (lane L2b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The dispatcher owns the block cache (keyed by guest PC, versioned by
 * the SMC epoch plus a guest-word hash), direct chaining, the
 * 4096-entry per-thread IBTC, the return address stack (RAS), W^X code
 * pages, and the `interp_step` fallback for `EXIT_UNDEF`,
 * `EXIT_SINGLE_STEP`, and FP/COP1 blocks.
 *
 * Host register map (frozen for lane L2c — `src/dbt/emit_int.c` codes
 * against exactly this):
 *   `x19` pins the `mips64_ctx_t *` across compiled code;
 *   `x20` pins the U0 soft-TLB base (`mips_soft_tlb_base(ctx)` from
 *     `src/os/backend.h`); guest addresses resolve through the
 *     7-instruction probe in `src/dbt/emit_mem.c` (host address into
 *     `x4`, `x0` preserved) instead of the legacy `[x20, #addr]` map;
 *   guest `$0` reads as `wzr` and writes to it are dropped;
 *   all other guest state stays spilled to `[x19, #off]` using the
 *     frozen `MIPS64_CTX_*_OFFSET` values from `src/core/cpu.h`;
 *   `x21..x24` are scratch; `x0..x17`/`x25..x28` are available for
 *     helper calls and wider temporaries;
 *   **never read or write `x18`** (platform register).
 */

#ifndef MIPS64RT_DBT_DBT_H
#define MIPS64RT_DBT_DBT_H

#include "core/cpu.h"

#include <stddef.h>
#include <stdint.h>

/* Frozen shape (SPEC 2.1): the IBTC has exactly 4096 entries. The
 * table itself lives behind `ctx->ibtc_ptr` (ABI offset `0x150`). */
_Static_assert(MIPS64_IBTC_SIZE == 4096U, "IBTC must have 4096 entries");

/* Direct-mapped block-cache entries (lane-internal sizing). */
#define MIPS64_DBT_CACHE_ENTRIES 4096u
/* Return address stack depth (call/return pairing is advisory: it
 * only skips a cache probe, never changes the resume PC). */
#define MIPS64_DBT_RAS_ENTRIES 16u
/* Staging cap for one block's worth of A64 words (64 guest insns;
 * the emitter reports overflow and the block falls back). */
#define MIPS64_DBT_STAGING_WORDS 4096u

/* Pinned host registers (frozen for L2c). */
enum {
    MIPS64_DBT_REG_CTX = 19,   /* x19: `mips64_ctx_t *` */
    MIPS64_DBT_REG_BASE = 20,  /* x20: `ctx->guest_base` */
    MIPS64_DBT_REG_TMP0 = 21,  /* x21..x24: scratch */
    MIPS64_DBT_REG_TMP1 = 22,
    MIPS64_DBT_REG_TMP2 = 23,
    MIPS64_DBT_REG_TMP3 = 24
};

/* DBT exit codes reported by compiled blocks in `w0`. Blocks store
 * the resume guest VA into `ctx->pc` (via `x19`) before returning.
 * The dispatcher executes at most the `[entry, ctx->pc)` prefix of
 * the block has run natively; the `interp_step` fallback completes
 * the insn at `ctx->pc` (or faults there).
 *
 * Values are identical to the frozen `MIPS64_EXIT_*` contract in
 * `core/cpu.h` because the emitter (L2c) reports those codes: the
 * dispatcher must switch on the same values (RC2: mismatched codes
 * made `SYSCALL`(2) match `INDIRECT` and re-enter the syscall block
 * forever). All chaining flavors share `BRANCH`; the RAS heuristic
 * still distinguishes calls/returns via `exit_info`. */
enum {
    MIPS64_DBT_EXIT_FALLTHROUGH = MIPS64_EXIT_BRANCH, /* resume at pc */
    MIPS64_DBT_EXIT_DIRECT = MIPS64_EXIT_BRANCH,      /* direct branch */
    MIPS64_DBT_EXIT_INDIRECT = MIPS64_EXIT_BRANCH,   /* indirect branch */
    MIPS64_DBT_EXIT_UNDEF = MIPS64_EXIT_UNDEF,        /* interp one step */
    MIPS64_DBT_EXIT_SINGLE_STEP = MIPS64_EXIT_SINGLE_STEP, /* step+resume */
    MIPS64_DBT_EXIT_SYSCALL = MIPS64_EXIT_SYSCALL,   /* syscall at pc */
    MIPS64_DBT_EXIT_FAULT = MIPS64_EXIT_FAULT,       /* reason recorded */
    MIPS64_DBT_EXIT_TRAP = MIPS64_EXIT_TRAP          /* site idx in info */
};

/* `exit_info` convention for `EXIT_DIRECT` (set by the emitter,
 * consumed by the RAS heuristic only):
 * bit 0 (`LINK`) marks a call: the emitter also stores the return
 *   address in `ctx->next_pc` and the dispatcher pushes it;
 * bit 1 (`RETURN`) marks a return (`jr ra` / `jalr ra`): the
 *   dispatcher compares the RAS top against `ctx->pc`. */
#define MIPS64_DBT_INFO_LINK 1u
#define MIPS64_DBT_INFO_RETURN 2u

/* One 4096-entry IBTC slot: guest VA to host RX entry. The table is
 * allocated on first use and owned via `ctx->ibtc_ptr`. */
typedef struct {
    uint64_t guest;
    void *host;
} mips64_ibtc_slot_t;

/* True when this build can execute translated code (AArch64 host);
 * otherwise `--dbt` must report unavailable. */
int mips64_dbt_available(void);

/* U0 delay-slot NPC resume (lane L-U0-C): when a delay-target is
 * pending (npc_mode RT_NPC_DYNAMIC_CTX, parked in x25 by emitted
 * code), move it into pc/next_pc, clear it, and report 1; else 0.
 * Called at the top of the dispatch loop; shares the backend
 * mips_npc_resume_step helper so tests cover the same path. */
int dbt_npc_resume(mips64_ctx_t *ctx);

/* U0 soft-TLB prefill for one block span: fill every page in
 * [start, end) so the probe hits inline (misses fault to the
 * interp_step fallback by construction). */
void dbt_u0_prefill(mips64_ctx_t *ctx, uint64_t start, uint64_t end);

/* U0 cold-data-page fill-and-retry: the inlined probe exits with
 * EXIT_FAULT on every first-touch data page, so a miss on a MAPPED
 * page must fill the entry and retry the block instead of delivering
 * a spurious guest SIGSEGV (the first N64 startup stack load faulted
 * the whole --dbt run before this). Decodes the word at pc, probes
 * the access span with mips_mem_ok (READ for loads, WRITE for
 * stores), and fills the uncovered pages. Returns 1 when the caller
 * should clear the exit state and retry, 0 for a genuine fault
 * (unmapped span, non-memory word, undecodable pc, or an entry that
 * is already present, which rules out a cold miss and stops a
 * fill/retry loop on a host-level fault). */
int dbt_u0_fill_retry(mips64_ctx_t *ctx, uint64_t pc);

/* Fault effective address of the memory word at `pc` (0 when the
 * word is not a memory access). Lane U12: the dispatcher no longer
 * calls this directly (the site-based `dbt_mem_recover` below maps
 * si_addr from the retained row); it stays for the unit gate. */
uint64_t dbt_fault_ea(mips64_ctx_t *ctx, uint64_t pc);

/* Shared site-based miss path (see src/dbt/mem_recover.c): 0 means
 * the word ran again (caller clears the exit and continues), 1
 * means a fault or exit was delivered with its trace lines already
 * printed (caller returns), 2 means a fault was delivered but the
 * faulting word line is still owed (caller prints it from
 * `ctx->pc`). */
struct dbt_mem_site;
int dbt_mem_recover(mips64_ctx_t *ctx, const struct dbt_mem_site *site,
                    uint64_t block_pc, uint64_t fault_pc);

/* Block visitor for host-pc resolution: rows, count, RX base/len,
 * guest base; nonzero stops the walk. */
typedef int (*dbt_block_visit_t)(const struct dbt_mem_site *sites,
                                 size_t count, uint64_t rx_base,
                                 size_t rx_len, uint64_t guest_pc,
                                 void *arg);
void dbt_visit_blocks(dbt_block_visit_t visit, void *arg);

/* Print the natively executed prefix [start, fault); leaves
 * `ctx->pc` at fault. */
void dbt_trace_fault_prefix(mips64_ctx_t *ctx, uint64_t start,
                            uint64_t fault);

/* Resolve a host pc captured inside RX to the faulting guest pc (1)
 * or report no match (0). Rewind a host pc interrupted inside a
 * sequence prefix to the sequence start (1) or report no match (0). */
int dbt_host_pc_to_guest(uint64_t host_pc, uint64_t *guest_pc);
int dbt_rewind_pc(uint64_t host_pc, uint64_t *seq_out);

/* Enter compiled code: saves host callee-saved registers, pins
 * `x19 = ctx` and `x20 = base`, calls `code`, restores, and returns
 * the `w0` exit code. Implemented in `trampoline_a64.S` on AArch64;
 * a C fallback in `dbt.c` reports `MIPS64_DBT_EXIT_UNDEF` elsewhere
 * so unit builds still link.
 *
 * Wave P in-trampoline chaining: after a DIRECT exit the trampoline
 * consults the IBTC for `ctx->pc` and enters the next block without
 * returning to C, up to `budget` chained blocks (1 disables chaining
 * for --difftest/single-step/tracing). Each chained step re-reads
 * `*epoch` (the live SMC epoch) and bails to C on a mismatch, so
 * cross-thread SMC never runs stale code. The epoch arrives by
 * pointer so the pure-GAS trampoline needs no platform symbol
 * spelling. */
long mips64_dbt_enter(mips64_ctx_t *ctx, uint64_t base, void *code,
                      uint64_t budget, const _Atomic uint64_t *epoch);

/* Bump-allocated W^X code arena (src/dbt/arena.c): carve `len`
 * 16-byte-aligned bytes out of the thread-local chunk (NULL on
 * exhaustion); publish one block through the backend JIT hooks. */
void *dbt_arena_alloc(size_t len);
void *dbt_code_publish(const uint8_t *buf, size_t len);

/* Run guest code until a syscall `exit`/`exit_group` ends the
 * process (via `_Exit` inside the syscall layer) or a fault stops
 * the run. Returns 0 on the unreachable fall-through, nonzero (like
 * `interp_run`) when a fault or a stopped engine ends the loop.
 * Returns immediately for a null `ctx`. */
int dbt_run(mips64_ctx_t *ctx);

/* SMC invalidation. `dbt_invalidate_all` bumps the epoch (called on
 * `mprotect`/`munmap`/region remaps and on any guest write to a
 * translated page); `dbt_invalidate_range` covers a guest span and
 * currently bumps the same epoch. Until the L2a syscall layer calls
 * these, a per-block guest-word hash still retires translations
 * clobbered by plain stores. */
void dbt_invalidate_all(void);
void dbt_invalidate_range(uint64_t va, uint64_t len);

/* Current invalidation epoch (for tests and the future L2a hooks). */
uint64_t dbt_epoch(void);

/* Trace hook contract (implemented in `dbt.c`, used by the
 * dispatcher, not emitted code): print one interp-compatible
 * `I <pc> <word>` line per executed guest insn to `stderr` when
 * `ctx->trace_enabled` is set, so the L2d difftest can compare
 * trace streams across engines. */
void mips64_dbt_trace(mips64_ctx_t *ctx, uint64_t pc, uint32_t word);

#endif /* MIPS64RT_DBT_DBT_H */
