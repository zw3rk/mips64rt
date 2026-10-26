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

/* Backend interface revision. Rev5 is the U12 remediation level:
 * 32-byte split-tag soft-TLB entries (read_tag/addend/write_tag),
 * relative miss-site records, and the TRAP miss path. */
#define MIPS64RT_BACKEND_REV 5u

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

/* ---- §6 soft-TLB + gate state (Rev4 §4.3 surface) ---- */

/* Direct-mapped soft-TLB: 4096 entries of 32 bytes, indexed by
 * (va >> 12) & 0xFFF (128 KiB per thread). Emitted code binds x20
 * to &tlb[0] (never x18); the 7-instruction probe in
 * src/dbt/emit_mem.c checks read_tag/write_tag plus alignment in one
 * subtract and addresses the host page as [guest_va, addend].
 *
 * The write gate: write_tag carries the page base if and only if
 * the page is region-writable AND the page-state gate passes (not
 * COW-clean, no live translated code, no active LL reservation);
 * otherwise it is ~0ULL and every store traps to the miss path. The
 * addend is uniform across the arena (Provider A in-place design:
 * host_page_base = arena_base + page_base). */
#define MIPS64_SOFT_TLB_BITS 12u
#define MIPS64_SOFT_TLB_ENTRIES (1u << MIPS64_SOFT_TLB_BITS)
#define MIPS64_SOFT_TLB_INDEX_MASK (MIPS64_SOFT_TLB_ENTRIES - 1u)

typedef struct {
    uint64_t read_tag;        /* +0: page base when readable, else ~0 */
    uintptr_t addend;         /* +8: host_page_base - page_base */
    uint64_t write_tag;       /* +16: page base when writable-per-gate */
    uint64_t flags_reserved;  /* +24: zero (32-byte cache alignment) */
} mips_soft_tlb_entry_t;

_Static_assert(sizeof(mips_soft_tlb_entry_t) == 32u,
               "soft-TLB entry must be 32 bytes");
_Static_assert(offsetof(mips_soft_tlb_entry_t, addend) == 8u,
               "addend at +8");
_Static_assert(offsetof(mips_soft_tlb_entry_t, write_tag) == 16u,
               "write_tag at +16");

/* Stable base of ctx's TLB (&tlb[0]); this is the pointer the DBT
 * dispatcher passes as the x20 binding. Never NULL for non-NULL
 * ctx (NULL ctx yields NULL). */
void *mips_soft_tlb_base(mips64_ctx_t *ctx);

/* Fill the entry covering va: read_tag when the page is readable,
 * write_tag when the page is region-writable and the page-state
 * gate passes, addend from the reservation direct map
 * (host_page_base = guest_base + page). NULL is a no-op. */
void mips_soft_tlb_fill(mips64_ctx_t *ctx, uint64_t va);

/* Invalidate every entry for ctx (all tags UINT64_MAX). NULL is
 * a no-op. */
void mips_soft_tlb_invalidate(mips64_ctx_t *ctx);

/* Invalidate every entry of every live slot (quiescence step 5). */
void mips_soft_tlb_invalidate_all(void);

/* ---- §7 JIT code publication (W^X done right per host) ----
 *
 * The DBT publishes AArch64 code through these hooks (see
 * dbt_code_publish); guest data pages are never PROT_EXEC on any
 * host. Linux: RW staging, flip to R|X, clear the I-cache. Darwin:
 * MAP_JIT pages toggled with pthread_jit_write_protect_np, sealed
 * WITHOUT mprotect (which would break JIT pages), I-cache retired
 * with sys_icache_invalidate. */
size_t mips_host_page_size(void);
void *mips_jit_alloc(size_t size);
void mips_jit_begin_write(void *p, size_t size);
int mips_jit_seal_rx(void *p, size_t size);
void mips_jit_free(void *p, size_t size);

/* Reset all U0 gate state for ctx: fixade back to default (1),
 * delay target dropped, TLB invalidated. NULL is a no-op. */
void mips_backend_state_reset(mips64_ctx_t *ctx);

#endif /* MIPS64RT_OS_BACKEND_H */
