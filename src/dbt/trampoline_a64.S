/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b + U0 lane L-U0-C + Wave P chaining: AArch64
 * enter/exit trampoline. Saves the host callee-saved registers, pins
 * `x19` to the `mips64_ctx_t *` and `x20` to the U0 soft-TLB base
 * (`&tlb[0]` from `mips_soft_tlb_base(ctx)`, passed in `x1`) across
 * compiled code, dispatches to cached code, and returns the block's
 * `w0` exit code to the C dispatcher.
 *
 * Wave P in-trampoline IBTC chaining: after a DIRECT (`w0 == 1`)
 * exit the trampoline looks up `ctx->pc` in the IBTC and enters the
 * next block without returning to C, up to `budget` blocks per enter
 * (`x3`; 1 disables chaining for --difftest/single-step/tracing).
 * Each chained step re-reads the live SMC epoch through `x4` and
 * bails to C on a mismatch, so cross-thread SMC never runs stale
 * code. The budget also bounds signal/quiescence latency: preempt
 * signals are never blocked inside JIT code, so they still preempt
 * a chaining loop. Only `x19`/`x20` (pinned by contract) and the
 * trampoline's own stack slots survive across `blr`; every other
 * register is reloaded per step.
 *
 * Pure GAS assembly (no C preprocessor): the lane acceptance
 * assembles this file with raw `aarch64-unknown-linux-musl-as`, so
 * there are no `#` lines or macros here. Both the ELF
 * (`mips64_dbt_enter`) and Mach-O (`_mips64_dbt_enter`) spellings are
 * exported via `.set`; the C declaration in `src/dbt/dbt.h` links
 * against whichever the host object format needs. Non-AArch64 hosts
 * exclude this file (see `Makefile`/RC2 wiring) and use the C
 * fallback in `src/dbt/dbt.c`.
 *
 * `x18` is deliberately never touched here (it is the platform
 * register and may hold the host's thread state). The ctx layout is
 * consulted only for the ABI-locked `pc` (`0x100`) and `ibtc_ptr`
 * (`0x150`) offsets from `src/core/cpu.h`.
 */

    .text
    .align 2
    .global mips64_dbt_enter
    .global _mips64_dbt_enter
    .set _mips64_dbt_enter, mips64_dbt_enter
mips64_dbt_enter:
    /* Enter: ctx in x0, guest base in x1, code in x2, chain budget in
     * x3, SMC epoch pointer in x4. Save fp/lr plus x19-x28 (x19/x20
     * are repinned, so their old values must survive the round trip;
     * x21-x28 are scratch but saved for hygiene). */
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    /* Chaining scratch below the saved regs (blocks never touch sp,
     * the same invariant the saved regs above rely on): budget at
     * [sp, #0], enter-epoch at [sp, #8], epoch pointer at [sp, #16].
     * x5/x6 are the per-step scratch. */
    sub sp, sp, #32
    /* Pin the guest context and U0 soft-TLB base, stash the chaining
     * state, enter the first block. */
    mov x19, x0
    mov x20, x1
    str x3, [sp, #0]
    ldr x5, [x4]
    str x5, [sp, #8]
    str x4, [sp, #16]
.Lchain_enter:
    blr x2
    /* w0 carries the DBT exit code: chain only DIRECT exits. */
    cmp w0, #1
    b.ne .Lchain_done
    /* One chained block per budget unit (1 disables chaining). */
    ldr x5, [sp, #0]
    subs x5, x5, #1
    str x5, [sp, #0]
    b.ls .Lchain_done
    /* Bail on an SMC epoch advance (cross-thread store to a code
     * page retired the translations while chained). */
    ldr x5, [sp, #16]
    ldr x5, [x5]
    ldr x6, [sp, #8]
    cmp x5, x6
    b.ne .Lchain_done
    /* IBTC probe for ctx->pc (4096-entry table of {guest, host}
     * pairs behind ctx->ibtc_ptr). */
    ldr x5, [x19, #0x150]
    cbz x5, .Lchain_done
    ldr x6, [x19, #0x100]
    lsr x3, x6, #2
    and x3, x3, #0xFFF
    lsl x3, x3, #4
    add x3, x5, x3
    ldr x5, [x3]
    cmp x5, x6
    b.ne .Lchain_done
    ldr x2, [x3, #8]
    cbz x2, .Lchain_done
    b .Lchain_enter
.Lchain_done:
    /* w0 still carries the final exit code; restore and return it. */
    add sp, sp, #32
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
