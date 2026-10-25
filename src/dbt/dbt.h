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
 *   `x20` pins the guest window base (`ctx->guest_base`), so guest
 *     effective addresses lower to `[x20, #addr]`-style sequences;
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
#define MIPS64_DBT_CACHE_ENTRIES 1024u
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
 * the insn at `ctx->pc` (or faults there). */
enum {
    MIPS64_DBT_EXIT_FALLTHROUGH = 0, /* resume at `ctx->pc` */
    MIPS64_DBT_EXIT_DIRECT = 1,      /* direct branch: resume at `ctx->pc` */
    MIPS64_DBT_EXIT_INDIRECT = 2,    /* indirect: IBTC probe, then cache */
    MIPS64_DBT_EXIT_UNDEF = 3,       /* single-step `ctx->pc` in interp */
    MIPS64_DBT_EXIT_SINGLE_STEP = 4, /* debug/edge page: interp and resume */
    MIPS64_DBT_EXIT_SYSCALL = 5,     /* syscall/trap insn at `ctx->pc` */
    MIPS64_DBT_EXIT_FAULT = 6        /* `exit_reason` already recorded */
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

/* Enter compiled code: saves host callee-saved registers, pins
 * `x19 = ctx` and `x20 = base`, calls `code`, restores, and returns
 * the `w0` exit code. Implemented in `trampoline_a64.S` on AArch64;
 * a C fallback in `dbt.c` reports `MIPS64_DBT_EXIT_UNDEF` elsewhere
 * so unit builds still link. */
long mips64_dbt_enter(mips64_ctx_t *ctx, uint64_t base, void *code);

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
