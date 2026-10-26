/*
 * src/os/backend.h — Host OS backend seam + U0 prototype gate (Rev4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Codes against the frozen headers only
 * (`src/core/cpu.h` is included, never modified): all U0 gate state
 * (fixade flag, delay-slot target, soft-TLB array) lives in the
 * backend registry keyed by `mips64_ctx_t *`, so the ABI-locked
 * prefix of `mips64_ctx_t` is untouched.
 *
 * Layout: §1 revision/identity, §2 guest signal constants (MIPS
 * Linux UAPI, identical on both hosts), §3 sysmips(2) commands
 * (uapi/asm/sysmips.h), §4 TIF_FIXADE emulation control, §5
 * delay-slot dynamic-NPC target, §6 soft-TLB + backend identity
 * (the exact Rev4 §6 U0 gate surface: fixade hook, SIGBUS/ADRALN
 * fault, delay_target, npc_mode, x20 TLB binding).
 */

#ifndef MIPS64RT_OS_BACKEND_H
#define MIPS64RT_OS_BACKEND_H

#include "core/cpu.h"

#include <stddef.h>
#include <stdint.h>

/* ---- §1 revision/identity ---- */

/* Backend interface revision. Rev4 is the U0 prototype gate level:
 * fixade control, bus-fault, delay target, npc_mode, soft-TLB. */
#define MIPS64RT_BACKEND_REV 4u

/* Host backend name ("linux" / "darwin"); never NULL. */
const char *mips_backend_name(void);

/* ---- §2 guest signal constants (MIPS Linux UAPI) ---- */

/* Guest signal numbers: identical on both hosts because they name
 * MIPS UAPI signals, not host signals. SIGBUS is 10 on MIPS Linux
 * (arch/mips/include/uapi/asm/signal.h: SIGBUS 10, matching
 * src/os/sigframe.c); the host mapping (Linux 7, Darwin 10) is the
 * backend's private concern. */
#define MIPS64_SIGBUS 10u
#define MIPS64_SIGSEGV 11u

/* si_code for an alignment fault (Linux BUS_ADRALN == 1, same on the
 * BSD/Darwin si_code family). The frozen `mips_trap` assigns code 1
 * to SIGBUS, which is this ADRALN value — never SEGV_MAPERR. */
#define MIPS64_BUS_ADRALN 1u

/* ---- §3 sysmips(2) commands (uapi/asm/sysmips.h) ---- */

#define MIPS_SYS_SETNAME 1u
#define MIPS_SYS_FLUSH_CACHE 3u
#define MIPS_SYS_MIPS_FIXADE 7u

/* ---- §4 TIF_FIXADE unaligned-access emulation ---- */

/* Default when no ctx state was ever set: emulate (kernel TIF_FIXADE
 * set). 1 emulates, 0 reports. */
#define MIPS_FIXADE_DEFAULT 1

/* 1 when unaligned integer loads/stores are emulated byte-wise,
 * 0 when they must fault. Unknown contexts read the default. */
int mips_fixade_enabled(const mips64_ctx_t *ctx);

/* Set the emulation flag for ctx (nonzero enables). NULL is a no-op. */
void mips_fixade_set(mips64_ctx_t *ctx, int on);

/* sysmips(2) hook for the syscall layer (owned by the L2a syscall
 * lane; declared here so mem.c and the backends share one shape):
 * cmd == MIPS_SYS_MIPS_FIXADE sets the flag from arg (nonzero
 * enables, zero disables) and returns 0; any other cmd returns
 * MIPS_FAULT. NULL ctx returns MIPS_FAULT. */
int mips_fixade_ctl(mips64_ctx_t *ctx, unsigned long cmd, unsigned long arg);

/* Synchronous alignment fault: traps guest SIGBUS with ADRALN code
 * and records EXIT_FAULT with the fault address. Never SIGSEGV:
 * callers route here (not to mips_fault) when fixade is disabled. */
void mips_bus_fault(mips64_ctx_t *ctx, uint64_t addr);

/* ---- §5 delay-slot dynamic-NPC target ---- */

/* NPC select mode for resuming after a delay-slot fault. STATIC is
 * the frozen direct behavior (resume at ctx->pc/next_pc); DYNAMIC_CTX
 * means a pending side-table target (parked in x25 in emitted code)
 * selects the resume pc. */
enum mips_npc_mode {
    MIPS_NPC_STATIC = 0,
    MIPS_NPC_DYNAMIC_CTX = 1
};

/* Record the dynamic resume target for ctx (the delay-slot branch
 * target parked in x25 by emitted code). NULL is a no-op. */
void mips_delay_target_set(mips64_ctx_t *ctx, uint64_t va);

/* Fetch the pending target: 1 with *va set when one is pending,
 * 0 otherwise. NULL ctx (or NULL va) reports 0. */
int mips_delay_target_get(const mips64_ctx_t *ctx, uint64_t *va);

/* Drop any pending target. NULL is a no-op. */
void mips_delay_target_clear(mips64_ctx_t *ctx);

/* Current NPC mode: DYNAMIC_CTX while a target is pending, else
 * STATIC. NULL ctx reads STATIC. */
int mips_npc_mode(const mips64_ctx_t *ctx);

/* Dispatcher step shared with dbt.c: when a target is pending, move
 * it into pc/next_pc (in_delay_slot cleared) and drop it; returns 1
 * when it resumed, 0 when there was nothing pending. NULL is 0. */
static inline int mips_npc_resume_step(mips64_ctx_t *ctx, uint64_t *applied)
{
    uint64_t va = 0U;

    if (ctx == NULL || mips_delay_target_get(ctx, &va) == 0) {
        return 0;
    }
    ctx->in_delay_slot = 0U;
    ctx->pc = va;
    ctx->next_pc = va + 4U;
    mips_delay_target_clear(ctx);
    if (applied != NULL) {
        *applied = va;
    }
    return 1;
}

/* ---- §6 soft-TLB + gate state (exact Rev4 §6 surface) ---- */

/* Direct-mapped soft-TLB: 64 entries of 16 bytes, indexed by
 * (va >> 12) & 63. Emitted code binds x20 to &tlb[0] (never x18);
 * the 7-instruction probe in src/dbt/emit_mem.c resolves the host
 * page and materializes the host address into x4, preserving x0. */
#define MIPS64_SOFT_TLB_BITS 6u
#define MIPS64_SOFT_TLB_ENTRIES (1u << MIPS64_SOFT_TLB_BITS)
#define MIPS64_SOFT_TLB_INDEX_MASK (MIPS64_SOFT_TLB_ENTRIES - 1u)

typedef struct {
    uint64_t tag;       /* va >> 12, or UINT64_MAX when invalid */
    uint64_t host_base; /* host address of the page base */
} mips_soft_tlb_entry_t;

/* Stable base of ctx's TLB (&tlb[0]); this is the pointer the DBT
 * dispatcher passes as the x20 binding. Never NULL for non-NULL
 * ctx (NULL ctx yields NULL). */
void *mips_soft_tlb_base(mips64_ctx_t *ctx);

/* Fill the entry covering va from the reservation direct map
 * (host_base = guest_base + (va >> 12) * 4096). NULL is a no-op. */
void mips_soft_tlb_fill(mips64_ctx_t *ctx, uint64_t va);

/* Invalidate every entry for ctx (all tags UINT64_MAX). NULL is
 * a no-op. */
void mips_soft_tlb_invalidate(mips64_ctx_t *ctx);

/* Reset all U0 gate state for ctx: fixade back to default (1),
 * delay target dropped, TLB invalidated. NULL is a no-op. */
void mips_backend_state_reset(mips64_ctx_t *ctx);

#endif /* MIPS64RT_OS_BACKEND_H */
