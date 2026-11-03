/*
 * tests/test_r7_defects.c — Round-7 ISA interpreter regression gate.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-portable, no Docker, no guest toolchain: drives the real
 * interpreter, unaligned/LLSC, loader, and file-backing TUs directly.
 * FP arithmetic findings (R7-6/7/8/12/13/14/15/16/17/18) live in the
 * sibling tests/test_r7_fp.c so every file stays <= 900 lines.
 *
 * - R7-1: R6 ELF (arch 0x9) rejected at admission; R2/legacy admitted;
 *   isa_rev set; NAN2008 flag initializes ctx->nan2008.
 * - R7-2: LL/SC through a second MAP_SHARED alias that writes and
 *   restores the word fails SC (cross-alias ABA breaks the backing
 *   generation); same-VA ABA still fails; quiet SC still succeeds.
 * - R7-3: a BC1T delay slot that redirects pc (dispatcher syscall
 *   move, inner taken branch) is preserved, not overwritten.
 * - R7-4: a merge access into the unmapped page delivers exactly one
 *   fault (no second mips_fault after a handled delivery).
 * - R7-5: BC1 $fcc1/$fcc2 decode as branches; BC1FL/BC1T constants
 *   and COP1 likely derivation (rt & 2) are correct.
 * - R7-6: NAN2008 polarity honored (quiet/signalling swapped vs
 *   legacy, 2008 default NaN produced).
 * - R7-7: aliased fd==fs SQRT/ADD still raise Invalid for sNaN.
 * - R7-8: MADD.S/MADD.D round product then sum in guest RM (the
 *   finding's -2^-46 case yields +0; directed zero signs differ).
 * - R7-9: misaligned JALR commits link + slot, then faults with pc
 *   at the target (not the jump pc).
 * - R7-10: GNU break 6/7 deliver SIGFPE; other BREAKs SIGTRAP.
 * - R7-11: misaligned LL/SC/LLD/SCD deliver SIGBUS (10), not SEGV.
 * - R7-12: FCSR Cause is replaced per op (DIV.S Z then ADD.S exact
 *   leaves Cause clear, Flags.Z sticky).
 * - R7-13: a trapped op leaves sticky Flags untouched.
 * - R7-14: DIV.S 1/+inf is exact +0; inf/0 has no DivideByZero.
 * - R7-15: FS flushes tiny results to signed zero with U and I.
 * - R7-16: PS cancellation under round-down yields -0 per lane.
 * - R7-17: FCCR/FEXR/FENR alias packing, masks, and trap checks.
 * - R7-18: MOVF/MOVT/MOVZ/MOVN move lanes with no FCSR effects.
 *
 * Protocol: "R7-PASS <name>", "R7-FAIL <name> ...", final
 * "R7-RESULT: PASS|FAIL" plus summary. Exit 0 iff zero failures.
 */

#include "core/cpu.h"
#include "interp/decode.h"
#include "interp/fp.h"
#include "interp/interp.h"
#include "loader.h"
#include "os/backend.h"
#include "vm/vm_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

#define R7_CHECK64(name, got, want) do { \
        uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
        if (_g == _w) { \
            g_pass++; \
            (void)printf("R7-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R7-FAIL %s got=0x%llx want=0x%llx\n", \
                name, (unsigned long long)_g, \
                (unsigned long long)_w); \
        } \
    } while (0)

#define R7_CHECK(name, cond) do { \
        if (cond) { \
            g_pass++; \
            (void)printf("R7-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R7-FAIL %s\n", name); \
        } \
    } while (0)

/* ---- recording seams (replace tests/stubs_signal.c here) ---- */

static int g_trap_count;
static int g_trap_signo;
static uint64_t g_trap_addr;
static int g_trap_move;
static uint64_t g_trap_pc;
static int g_sys_move;
static uint64_t g_sys_pc;

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    g_trap_count++;
    g_trap_signo = signo;
    g_trap_addr = addr;
    if (g_trap_move != 0 && ctx != NULL && ctx->pc != g_trap_pc) {
        ctx->pc = g_trap_pc;
    }
}

int mips_signal_has_handler(int signo)
{
    (void)signo;
    return 0;
}

int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr)
{
    (void)ctx;
    (void)signo;
    (void)fault_addr;
    return 1;
}

void mips_hostfault_install(const void *pool, size_t len)
{
    (void)pool;
    (void)len;
}

int mips_hostfault_run(mips64_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    (void)ctx;
    (void)code;
    if (reasonp != NULL) {
        *reasonp = (uint32_t)MIPS64_EXIT_UNDEF;
    }
    return 0;
}

void mips_hostfault_disarm(void)
{
}

/* Syscall stub: default NOP; R7-3 arms a dispatcher-owned pc move. */
int64_t mips_syscall(mips64_ctx_t *ctx)
{
    ctx->llbit = 0;
    if (g_sys_move != 0) {
        ctx->pc = g_sys_pc;
    }
    return 0;
}

/* ---- shared fixture ---- */

#define R7_PAGE   UINT64_C(0x10000)
#define R7_CODE   UINT64_C(0x11000)
#define R7_DATA   UINT64_C(0x12000)
#define R7_SPAN   UINT64_C(0x13000)
#define R7_A1     UINT64_C(0x50000)
#define R7_A2     UINT64_C(0x60000)
#define R7_HANDLER UINT64_C(0x77000)

static mips64_ctx_t g_ctx;

static void r7_setup(void)
{
    (void)memset(&g_ctx, 0, sizeof g_ctx);
    g_ctx.is_n32 = 0U;
    g_ctx.is_be = 0U;
    mips_backend_state_reset(&g_ctx);
    if (guest_mem_init(&g_ctx) != 0) {
        (void)printf("R7-FAIL setup: guest_mem_init\n");
        g_fail++;
        return;
    }
    if (mips_mem_map(&g_ctx, R7_PAGE, UINT64_C(0x1000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r7-page") != 0) {
        (void)printf("R7-FAIL setup: data map errno=%d\n", errno);
        g_fail++;
    }
    if (mips_mem_map(&g_ctx, R7_CODE, UINT64_C(0x1000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_EXEC),
                     "r7-code") != 0) {
        (void)printf("R7-FAIL setup: code map errno=%d\n", errno);
        g_fail++;
    }
    if (mips_mem_map(&g_ctx, R7_DATA, UINT64_C(0x1000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r7-data") != 0) {
        (void)printf("R7-FAIL setup: r7-data map errno=%d\n", errno);
        g_fail++;
    }
    /* Span page: 0x14000 stays unmapped so LE LWR/SWR at 0x13FFE
     * fault on their first out-of-range byte. */
    if (mips_mem_map(&g_ctx, R7_SPAN, UINT64_C(0x1000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r7-span") != 0) {
        (void)printf("R7-FAIL setup: r7-span map errno=%d\n", errno);
        g_fail++;
    }
}

static void r7_reset_traps(void)
{
    g_trap_count = 0;
    g_trap_signo = 0;
    g_trap_addr = 0u;
    g_trap_move = 0;
    g_trap_pc = 0u;
    g_sys_move = 0;
    g_sys_pc = 0u;
}

/* Little-endian 32-bit store into guest memory (guest is LE here). */
static void r7_put32(uint64_t va, uint32_t w)
{
    uint8_t *p = (uint8_t *)mips64_guest_ptr(&g_ctx, va);

    p[0] = (uint8_t)(w & 0xFFu);
    p[1] = (uint8_t)((w >> 8) & 0xFFu);
    p[2] = (uint8_t)((w >> 16) & 0xFFu);
    p[3] = (uint8_t)((w >> 24) & 0xFFu);
}

/* R7-5: FCC1-7 branches decode; BC1T/BC1FL constants unswapped. */
static void t_bc_decode(void)
{
    mips_dec_t d;

    R7_CHECK("bc-const-fl", MIPS64_COP1_BC1FL == 0x02u);
    R7_CHECK("bc-const-t", MIPS64_COP1_BC1T == 0x01u);
    R7_CHECK("bc-shared-t", MIPS64_BC_T == MIPS64_COP1_BC1T);
    R7_CHECK("bc-shared-fl", MIPS64_BC_FL == MIPS64_COP1_BC1FL);
    /* BC1T $fcc1: op 0x11, rs 8, rt (1<<2)|1 = 5. */
    mips_decode((uint32_t)((0x11u << 26) | (8u << 21) | (5u << 16)), &d);
    R7_CHECK("bc-fcc1-branch", mips_is_branch(&d) != 0);
    R7_CHECK("bc-fcc1-not-likely", mips_is_branch_likely(&d) == 0);
    R7_CHECK("bc-fcc1-delay", mips_has_delay_slot(&d) != 0);
    /* BC1FL $fcc2: rt (2<<2)|2 = 10. */
    mips_decode((uint32_t)((0x11u << 26) | (8u << 21) | (10u << 16)), &d);
    R7_CHECK("bc-fcc2-branch", mips_is_branch(&d) != 0);
    R7_CHECK("bc-fcc2-likely", mips_is_branch_likely(&d) != 0);
    /* BC1F cc0 stays non-likely; COP0 BC0T unchanged. */
    mips_decode((uint32_t)((0x11u << 26) | (8u << 21)), &d);
    R7_CHECK("bc-fcc0-branch", mips_is_branch(&d) != 0);
    R7_CHECK("bc-fcc0-not-likely", mips_is_branch_likely(&d) == 0);
    mips_decode((uint32_t)((0x10u << 26) | (8u << 21) | (1u << 16)), &d);
    R7_CHECK("bc0t-branch", mips_is_branch(&d) != 0);
    R7_CHECK("bc0t-not-likely", mips_is_branch_likely(&d) == 0);
    mips_decode((uint32_t)((0x10u << 26) | (8u << 21) | (2u << 16)), &d);
    R7_CHECK("bc0fl-branch", mips_is_branch(&d) != 0);
    R7_CHECK("bc0fl-likely", mips_is_branch_likely(&d) != 0);
}

/* R7-10: BREAK code extraction (GNU history in bits 25:16). */
static void t_break_codes(void)
{
    struct {
        uint32_t word;
        int signo;
    } cases[] = {
        { 0x0007000Du, 8 }, /* break 7: SIGFPE */
        { 0x0006000Du, 8 }, /* break 6: SIGFPE */
        { 0x0000000Du, 5 }, /* break 0: SIGTRAP */
        { 0x00000034u, 5 }, /* teq $0,$0: SIGTRAP */
    };
    size_t i;

    for (i = 0U; i < sizeof cases / sizeof cases[0]; i++) {
        int rc;

        r7_reset_traps();
        r7_put32(R7_CODE, cases[i].word);
        g_ctx.pc = R7_CODE;
        g_ctx.next_pc = R7_CODE + 4u;
        g_ctx.exit_reason = MIPS64_EXIT_NONE;
        rc = interp_step(&g_ctx);
        R7_CHECK("break-rc", rc == MIPS_FAULT);
        R7_CHECK64("break-signo", (uint64_t)g_trap_signo,
            (uint64_t)cases[i].signo);
    }
}

/* R7-9: misaligned JALR commits link + slot, faults at the target. */
static void t_jr_align(void)
{
    int rc;

    r7_reset_traps();
    /* jalr $t1($9),$t0($8); slot: addiu $t4($12),$zero,1. */
    r7_put32(R7_CODE, (uint32_t)((8u << 21) | (9u << 11) | 9u));
    r7_put32(R7_CODE + 4u,
        (uint32_t)((9u << 26) | (12u << 16) | 1u));
    g_ctx.pc = R7_CODE;
    g_ctx.next_pc = R7_CODE + 4u;
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    g_ctx.gpr[8] = UINT64_C(0x1003);
    g_ctx.gpr[9] = 0u;
    g_ctx.gpr[12] = 0u;
    rc = interp_step(&g_ctx);
    R7_CHECK("jr-rc", rc == MIPS_FAULT);
    R7_CHECK64("jr-link", g_ctx.gpr[9], R7_CODE + 8u);
    R7_CHECK64("jr-slot", g_ctx.gpr[12], 1u);
    R7_CHECK64("jr-pc-target", g_ctx.pc, UINT64_C(0x1003));
    R7_CHECK64("jr-exit-info", (uint64_t)g_ctx.exit_info,
        UINT64_C(0x1003));
    R7_CHECK64("jr-signo", (uint64_t)g_trap_signo, 11u);
}

/* R7-3: FP delay-slot redirection survives fp_branch. Uses g_ctx
 * (the slot executes via interp_step over mapped code). */
static void t_fp_branch_slot(void)
{
    mips_dec_t d;
    int rc;

    /* Dispatcher-owned pc move (syscall in the slot installs pc). */
    r7_reset_traps();
    g_ctx.fcsr = 1u << 23; /* FCC0 set: BC1T taken */
    g_ctx.pc = R7_CODE;
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    r7_put32(R7_CODE, (uint32_t)((0x11u << 26) | (8u << 21) |
        (1u << 16) | 1u));
    r7_put32(R7_CODE + 4u, 0x0000000Cu); /* SYSCALL */
    g_sys_move = 1;
    g_sys_pc = R7_HANDLER;
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x08u;
    d.rt = 1u;
    d.simm = 1;
    rc = fp_cop1(&g_ctx, R7_CODE, &d);
    R7_CHECK("fp-slot-syscall-rc", rc == FP_RC_BRANCH);
    R7_CHECK64("fp-slot-syscall-pc", g_ctx.pc, R7_HANDLER);
    /* Inner taken branch wins over the outer target. */
    r7_reset_traps();
    (void)memset(&g_ctx.fpr, 0, sizeof g_ctx.fpr);
    g_ctx.fcsr = 1u << 23;
    g_ctx.pc = R7_CODE;
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    g_ctx.gpr[8] = 5u;
    r7_put32(R7_CODE + 4u, (uint32_t)((4u << 26) | (8u << 21) |
        (8u << 16) | 1u)); /* beq $t0,$t0,+1 -> CODE+12 */
    r7_put32(R7_CODE + 8u, 0u); /* inner slot: nop */
    (void)memset(&d, 0, sizeof d);
    d.rs = 0x08u;
    d.rt = 1u;
    d.simm = 3; /* outer target CODE+16 */
    rc = fp_cop1(&g_ctx, R7_CODE, &d);
    R7_CHECK("fp-slot-inner-rc", rc == FP_RC_BRANCH);
    R7_CHECK64("fp-slot-inner-pc", g_ctx.pc, R7_CODE + 12u);
}

/* R7-4: a merge access into the unmapped page faults exactly once.
 * A merge always touches one aligned word, which never spans pages,
 * so the first unmapped byte (SPAN+0x1000) faults inside the
 * accessor; the handled delivery moves pc and no second mips_fault
 * may follow. */
static void t_unaligned_once(void)
{
    int rc;

    /* LWR at the first unmapped byte; the trap moves pc once
     * (handled delivery), so a second mips_fault would show. */
    r7_reset_traps();
    g_trap_move = 1;
    g_trap_pc = R7_HANDLER;
    g_ctx.pc = R7_CODE;
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    g_ctx.gpr[8] = 0x11223344u;
    rc = do_lwr(&g_ctx, R7_SPAN + UINT64_C(0x1000), 8u);
    R7_CHECK("lwr-rc", rc == MIPS_FAULT);
    R7_CHECK64("lwr-traps", (uint64_t)g_trap_count, 1u);
    R7_CHECK64("lwr-pc", g_ctx.pc, R7_HANDLER);
    R7_CHECK("lwr-exit-none",
        g_ctx.exit_reason == MIPS64_EXIT_NONE);
    /* SWR store variant. */
    r7_reset_traps();
    g_trap_move = 1;
    g_trap_pc = R7_HANDLER;
    g_ctx.pc = R7_CODE;
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    rc = do_swr(&g_ctx, R7_SPAN + UINT64_C(0x1000), 0xA5A5A5A5u);
    R7_CHECK("swr-rc", rc == MIPS_FAULT);
    R7_CHECK64("swr-traps", (uint64_t)g_trap_count, 1u);
    R7_CHECK64("swr-pc", g_ctx.pc, R7_HANDLER);
    g_trap_move = 0;
}

/* R7-11: misaligned LL/SC/LLD/SCD trap SIGBUS, never SIGSEGV. */
static void t_llsc_bus(void)
{
    r7_reset_traps();
    g_ctx.exit_reason = MIPS64_EXIT_NONE;
    R7_CHECK("ll-bus-rc", do_ll(&g_ctx, 1u, 8u) == MIPS_FAULT);
    R7_CHECK64("ll-bus-signo", (uint64_t)g_trap_signo, 10u);
    r7_reset_traps();
    R7_CHECK("sc-bus-rc", do_sc(&g_ctx, 2u, 8u) == MIPS_FAULT);
    R7_CHECK64("sc-bus-signo", (uint64_t)g_trap_signo, 10u);
    r7_reset_traps();
    R7_CHECK("lld-bus-rc", do_lld(&g_ctx, 4u, 8u) == MIPS_FAULT);
    R7_CHECK64("lld-bus-signo", (uint64_t)g_trap_signo, 10u);
    r7_reset_traps();
    R7_CHECK("scd-bus-rc", do_scd(&g_ctx, 8u + 4u, 8u) == MIPS_FAULT);
    R7_CHECK64("scd-bus-signo", (uint64_t)g_trap_signo, 10u);
}

/* R7-2: same-value ABA through a second MAP_SHARED alias fails SC. */
static void t_llsc_alias(void)
{
    mips64_ctx_t ctx;
    char path[64];
    int fd;
    uint64_t v;
    static uint8_t zeros[8192];

    (void)memset(&ctx, 0, sizeof ctx);
    ctx.is_n32 = 0U;
    ctx.is_be = 0U;
    mips_backend_state_reset(&ctx);
    if (guest_mem_init(&ctx) != 0) {
        R7_CHECK("alias-mem", 0);
        return;
    }
    if (mips_mem_map(&ctx, R7_A1, UINT64_C(0x2000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r7-a1") != 0 ||
        mips_mem_map(&ctx, R7_A2, UINT64_C(0x2000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r7-a2") != 0) {
        R7_CHECK("alias-map", 0);
        return;
    }
    (void)snprintf(path, sizeof path, "/tmp/mips64rt-r7-%d",
        (int)getpid());
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        R7_CHECK("alias-open", 0);
        return;
    }
    if (ftruncate(fd, (off_t)sizeof zeros) != 0 ||
        (ssize_t)sizeof zeros != write(fd, zeros, sizeof zeros)) {
        (void)close(fd);
        R7_CHECK("alias-fill", 0);
        return;
    }
    mips_vm_file_map_hook(&ctx, fd, R7_A1, UINT64_C(0x2000), 0u,
                          (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                          1);
    mips_vm_file_map_hook(&ctx, fd, R7_A2, UINT64_C(0x2000), 0u,
                          (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                          1);
    if (mips_vm_file_has_shared(R7_A1, UINT64_C(0x2000)) == 0 ||
        mips_vm_file_has_shared(R7_A2, UINT64_C(0x2000)) == 0) {
        (void)close(fd);
        R7_CHECK("alias-hook", 0);
        return;
    }
    (void)close(fd);
    (void)unlink(path);
    /* Quiet SC still succeeds on a shared backing. */
    if (guest_st32(&ctx, R7_A1, 0x11111111u) != 0) {
        R7_CHECK("alias-st", 0);
        return;
    }
    ctx.gpr[5] = 0x22222222u;
    R7_CHECK("alias-ll-rc", do_ll(&ctx, R7_A1, 8u) == 0);
    R7_CHECK64("alias-ll-val", ctx.gpr[8], UINT64_C(0x11111111));
    R7_CHECK("alias-sc-quiet", do_sc(&ctx, R7_A1, 5u) == 0);
    R7_CHECK64("alias-sc-rt", ctx.gpr[5], 1u);
    if (guest_ld32(&ctx, R7_A1, &v) != 0 || v != 0x22222222u) {
        R7_CHECK("alias-quiet-mem", 0);
        return;
    }
    /* Same-value ABA through the second alias must fail. */
    R7_CHECK("alias-reload", do_ll(&ctx, R7_A1, 8u) == 0);
    if (guest_st32(&ctx, R7_A2, 0x33333333u) != 0 ||
        guest_st32(&ctx, R7_A2, 0x22222222u) != 0) {
        R7_CHECK("alias-aba-st", 0);
        return;
    }
    if (guest_ld32(&ctx, R7_A1, &v) != 0 || v != 0x22222222u) {
        R7_CHECK("alias-aba-visible", 0);
        return;
    }
    ctx.gpr[6] = 0x44444444u;
    R7_CHECK("alias-sc-aba", do_sc(&ctx, R7_A1, 6u) == 0);
    R7_CHECK64("alias-sc-rt-fail", ctx.gpr[6], 0u);
    if (guest_ld32(&ctx, R7_A1, &v) != 0 || v != 0x22222222u) {
        R7_CHECK("alias-aba-nostore", 0);
        return;
    }
    /* Same-VA ABA still fails (VA epochs). */
    R7_CHECK("alias-reload2", do_ll(&ctx, R7_A1, 10u) == 0);
    if (guest_st32(&ctx, R7_A1, 0x55555555u) != 0 ||
        guest_st32(&ctx, R7_A1, 0x22222222u) != 0) {
        R7_CHECK("alias-aba-st2", 0);
        return;
    }
    ctx.gpr[7] = 0x66666666u;
    R7_CHECK("alias-sc-aba2", do_sc(&ctx, R7_A1, 7u) == 0);
    R7_CHECK64("alias-sc-rt-fail2", ctx.gpr[7], 0u);
}

/* Write a minimal static ELF64 (one PT_LOAD) with given e_flags. */
static int r7_write_elf(const char *path, uint32_t flags)
{
    static uint8_t img[0x110];
    int fd;
    size_t i;

    (void)memset(img, 0, sizeof img);
    img[0] = 0x7Fu;
    img[1] = (uint8_t)'E';
    img[2] = (uint8_t)'L';
    img[3] = (uint8_t)'F';
    img[4] = 2u; /* 64-bit */
    img[5] = 1u; /* LE */
    img[6] = 1u; /* version */
    img[16] = 2u; /* ET_EXEC */
    img[18] = 8u; /* EM_MIPS */
    img[20] = 1u; /* version */
    for (i = 0u; i < 8u; i++) { /* entry = vaddr */
        img[24 + i] = (uint8_t)((UINT64_C(0x400000) >> (8u * i)) & 0xFFu);
    }
    for (i = 0u; i < 8u; i++) { /* phoff = 64 */
        img[32 + i] = (uint8_t)((UINT64_C(64) >> (8u * i)) & 0xFFu);
    }
    for (i = 0u; i < 4u; i++) { /* e_flags */
        img[48 + i] = (uint8_t)((flags >> (8u * i)) & 0xFFu);
    }
    img[52] = 64u; /* ehsize */
    img[54] = 56u; /* phentsize */
    img[56] = 1u; /* phnum */
    /* phdr at 64: PT_LOAD, flags R+W, off 0, vaddr 0x400000. The
     * segment starts at file offset 0 so the program header table
     * (phoff 64) lies inside it, as the loader requires. */
    img[64] = 1u;
    img[68] = 6u;
    for (i = 0u; i < 8u; i++) {
        img[72 + i] = 0u;
        img[80 + i] = (uint8_t)((UINT64_C(0x400000) >> (8u * i)) & 0xFFu);
        img[88 + i] = img[80 + i];
    }
    for (i = 0u; i < 8u; i++) { /* filesz = memsz = whole image */
        img[96 + i] =
            (uint8_t)(((uint64_t)sizeof img >> (8u * i)) & 0xFFu);
        img[104 + i] = img[96 + i];
    }
    img[112] = 0u;
    img[113] = 16u; /* align 0x1000 LE */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    if ((ssize_t)sizeof img != write(fd, img, sizeof img)) {
        (void)close(fd);
        return -1;
    }
    return close(fd);
}

/* R7-1/R7-6: loader admits R2/legacy, rejects R6, reads NAN2008. */
static void t_loader(void)
{
    char path[64];
    mips64_ctx_t ctx;
    char *argv[2];
    char *envp[2];
    int rc;

    (void)snprintf(path, sizeof path, "/tmp/mips64rt-r7elf-%d",
        (int)getpid());
    argv[0] = (char *)"/x";
    argv[1] = NULL;
    envp[0] = (char *)"A=B";
    envp[1] = NULL;
    if (r7_write_elf(path, 0x80000007u) != 0) { /* N64 R2 */
        R7_CHECK("elf-write", 0);
        return;
    }
    (void)memset(&ctx, 0, sizeof ctx);
    if (guest_mem_init(&ctx) != 0) {
        R7_CHECK("elf-r2-mem", 0);
        return;
    }
    rc = mips_load_elf(&ctx, path, path, argv, envp);
    R7_CHECK("elf-r2-ok", rc == 0);
    R7_CHECK64("elf-r2-isa", (uint64_t)ctx.isa_rev, 1u);
    R7_CHECK64("elf-r2-nan", (uint64_t)ctx.nan2008, 0u);
    R7_CHECK("elf-r2-be", ctx.is_be == 0u);
    if (r7_write_elf(path, 0x90000007u) != 0) { /* N64 R6 */
        R7_CHECK("elf-write-r6", 0);
        return;
    }
    (void)memset(&ctx, 0, sizeof ctx);
    errno = 0;
    rc = mips_load_elf(&ctx, path, path, argv, envp);
    R7_CHECK("elf-r6-reject", rc == -1 && errno == ENOEXEC);
    if (r7_write_elf(path, 0x00000007u) != 0) { /* legacy, no arch */
        R7_CHECK("elf-write-legacy", 0);
        return;
    }
    (void)memset(&ctx, 0, sizeof ctx);
    if (guest_mem_init(&ctx) != 0) {
        R7_CHECK("elf-legacy-mem", 0);
        return;
    }
    rc = mips_load_elf(&ctx, path, path, argv, envp);
    R7_CHECK("elf-legacy-ok", rc == 0);
    R7_CHECK64("elf-legacy-isa", (uint64_t)ctx.isa_rev, 1u);
    if (r7_write_elf(path, 0x30000007u) != 0) { /* MIPS III, pre-R2 */
        R7_CHECK("elf-write-pre-r2", 0);
        return;
    }
    (void)memset(&ctx, 0, sizeof ctx);
    if (guest_mem_init(&ctx) != 0) {
        R7_CHECK("elf-pre-r2-mem", 0);
        return;
    }
    rc = mips_load_elf(&ctx, path, path, argv, envp);
    R7_CHECK("elf-pre-r2-ok", rc == 0);
    if (r7_write_elf(path, 0x80000807u) != 0) { /* R2 + NAN2008 */
        R7_CHECK("elf-write-nan", 0);
        return;
    }
    (void)memset(&ctx, 0, sizeof ctx);
    if (guest_mem_init(&ctx) != 0) {
        R7_CHECK("elf-nan-mem", 0);
        return;
    }
    rc = mips_load_elf(&ctx, path, path, argv, envp);
    R7_CHECK("elf-nan-ok", rc == 0);
    R7_CHECK64("elf-nan-flag", (uint64_t)ctx.nan2008, 1u);
    (void)unlink(path);
}

int main(void)
{
    r7_setup();
    t_bc_decode();
    t_break_codes();
    t_jr_align();
    t_fp_branch_slot();
    t_unaligned_once();
    t_llsc_bus();
    t_llsc_alias();
    t_loader(); /* last: the loader resets global memory state */
    (void)printf("R7-RESULT: %s (%d pass, %d fail)\n",
        (g_fail == 0) ? "PASS" : "FAIL", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
