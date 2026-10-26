/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b + U0 lane L-U0-C: AArch64 enter/exit trampoline.
 * Saves the host callee-saved registers, pins `x19` to the
 * `mips64_ctx_t *` and `x20` to the U0 soft-TLB base (`&tlb[0]` from
 * `mips_soft_tlb_base(ctx)`, passed in `x1`) across compiled code,
 * dispatches to cached code, and returns the block's `w0` exit code
 * to the C dispatcher.
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
 * not consulted: the TLB base arrives as a plain argument, so no asm
 * offset can drift from `src/core/cpu.h`.
 */

    .text
    .align 2
    .global mips64_dbt_enter
    .global _mips64_dbt_enter
    .set _mips64_dbt_enter, mips64_dbt_enter
mips64_dbt_enter:
    /* Enter: ctx in x0, guest base in x1, code in x2. Save fp/lr plus
     * x19-x28 (x19/x20 are repinned, so their old values must survive
     * the round trip; x21-x24 are scratch but saved for hygiene). */
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    /* Pin the guest context and U0 soft-TLB base, enter code. */
    mov x19, x0
    mov x20, x1
    blr x2
    /* w0 carries the DBT exit code; restore and return it. */
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
