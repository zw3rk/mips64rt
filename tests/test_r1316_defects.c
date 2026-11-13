/*
 * tests/test_r1316_defects.c — Round-13/14/16 remediation regression gate.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-portable, no Docker, no guest toolchain: drives the real
 * interpreter, DBT miss path, and syscall dispatch TUs directly.
 *
 * - R13-8: legacy unlink (N64 5085 / N32 6085) dispatches to
 *   mips_sc_unlink via the file-extra tail and removes the file.
 * - R13-9: symlinkat (N64 5256 / N32 6260) dispatches to
 *   mips_sc_symlinkat and creates a link with a verbatim target.
 * - R13-5: the canonical delay-slot classifier in interp.h covers
 *   COP1 BC1 (JR/JALR/branches unchanged, traps still excluded).
 * - R14-1: integer traps recover through the interpreter instead of
 *   SIGSEGV: BREAK 7 (0x0007000D) to SIGFPE (8, R7-10), BREAK 0 to
 *   SIGTRAP (5), trapping ADD/DADD overflow to SIGFPE (8) — in the
 *   delay slot and out of it.
 * - R14-2: a BLTZAL $ra block declines to compile (interp fallback),
 *   so the delay-slot miss path never re-tests the clobbered $ra.
 *
 * Protocol: "RDEF-PASS <name>", "RDEF-FAIL <name> ...", final
 * "RDEF-RESULT: PASS|FAIL". Exit 0 iff zero failures.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/emit_mem.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "os/backend.h"
#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

#define RDEF_CHECK(name, cond) do { \
        if (cond) { \
            g_pass++; \
            (void)printf("RDEF-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("RDEF-FAIL %s\n", name); \
        } \
    } while (0)

/* ---- seams: hostfault/syscall stubs, capturing mips_trap ---- */

static int g_signo = -1;
static uint64_t g_sigaddr = 0;

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    g_signo = signo;
    g_sigaddr = addr;
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

int64_t mips_syscall(mips64_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

/* ---- syscall dispatch seam owned by src/os/syscalls_sync.c ---- */

extern int64_t mips_sc_file_extra(mips64_ctx_t *ctx, int n32, uint64_t nr,
                                  uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, int *claimed);

#define T_PAGE UINT64_C(0x10000)
#define T_CODE (T_PAGE + UINT64_C(0x000))
#define T_DATA (T_PAGE + UINT64_C(0x800))

static void setup_ctx(mips64_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof *ctx);
    ctx->is_n32 = 0U;
    ctx->is_be = 0U;
    mips_backend_state_reset(ctx);
    if (guest_mem_init(ctx) != 0) {
        (void)printf("RDEF-FAIL guest_mem_init\n");
        g_fail++;
        return;
    }
    if (mips_mem_map(ctx, T_PAGE, UINT64_C(0x1000),
                     (uint32_t)(1u | 2u | 4u), "rdef-page") != 0) {
        (void)printf("RDEF-FAIL mips_mem_map errno=%d\n", errno);
        g_fail++;
    }
}

static void plant32(mips64_ctx_t *ctx, uint64_t va, uint32_t w)
{
    uint8_t b[4];

    b[0] = (uint8_t)(w & 0xFFu);
    b[1] = (uint8_t)((w >> 8) & 0xFFu);
    b[2] = (uint8_t)((w >> 16) & 0xFFu);
    b[3] = (uint8_t)((w >> 24) & 0xFFu);
    memcpy(mips64_guest_ptr(ctx, va), b, sizeof b);
}

static void plant_str(mips64_ctx_t *ctx, uint64_t va, const char *s)
{
    memcpy(mips64_guest_ptr(ctx, va), s, strlen(s) + 1U);
}

static dbt_mem_site_t trap_site(uint64_t pc, uint64_t block, uint32_t word,
                                uint8_t flags, int32_t npc_delta,
                                uint8_t npc_mode)
{
    dbt_mem_site_t s;

    (void)memset(&s, 0, sizeof s);
    s.guest_pc_delta = (uint16_t)(pc - block);
    s.insn_word = word;
    s.npc_delta = npc_delta;
    s.npc_mode = npc_mode;
    s.flags = flags;
    return s;
}

static void reset_trap(mips64_ctx_t *ctx, uint64_t pc)
{
    ctx->pc = pc;
    ctx->next_pc = pc + 4u;
    ctx->in_delay_slot = 0U;
    ctx->exit_reason = MIPS64_EXIT_NONE;
    ctx->exit_info = 0U;
    g_signo = -1;
    g_sigaddr = 0U;
}

int main(void)
{
    static mips64_ctx_t ctx;
    dbt_mem_site_t site;
    int claimed = 0;
    int64_t rc = 0;
    int mrc = 0;
    char path[64];
    char link[64];
    char tgt[64];
    char buf[128];
    ssize_t n = 0;
    int fd = -1;
    mips_dec_t d;
    uint64_t pend = 0U;

    setup_ctx(&ctx);

    /* R13-8: legacy unlink dispatches through the file-extra tail. */
    (void)snprintf(path, sizeof path, "/tmp/mips64rt-rdef-u-%d", (int)getpid());
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    RDEF_CHECK("unlink-setup", fd >= 0);
    if (fd < 0) {
        goto done;
    }
    (void)close(fd);
    plant_str(&ctx, T_DATA, path);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 0, (uint64_t)MIPS64_NR_unlink,
                            T_DATA, 0U, 0U, 0U, &claimed);
    RDEF_CHECK("unlink-n64", claimed == 1 && rc == 0 &&
               ctx.gpr[MIPS64_REG_V0] == 0U &&
               ctx.gpr[MIPS64_REG_A3] == 0U &&
               access(path, F_OK) != 0);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)close(fd);
    }
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 1, (uint64_t)MIPS64_NR32_unlink,
                            T_DATA, 0U, 0U, 0U, &claimed);
    RDEF_CHECK("unlink-n32", claimed == 1 && rc == 0 &&
               access(path, F_OK) != 0);

    /* R13-9: symlinkat dispatches; the target passes through verbatim. */
    (void)snprintf(tgt, sizeof tgt, "rdef-verbatim-%d", (int)getpid());
    (void)snprintf(link, sizeof link, "/tmp/mips64rt-rdef-l-%d", (int)getpid());
    plant_str(&ctx, T_DATA, tgt);
    plant_str(&ctx, T_DATA + UINT64_C(0x40), link);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 0, (uint64_t)MIPS64_NR_symlinkat,
                            T_DATA, (uint64_t)(int64_t)-100,
                            T_DATA + UINT64_C(0x40), 0U, &claimed);
    n = readlink(link, buf, sizeof buf - 1U);
    RDEF_CHECK("symlinkat-n64", claimed == 1 && rc == 0 && n == (ssize_t)strlen(tgt) &&
               memcmp(buf, tgt, (size_t)n) == 0);
    (void)unlink(link);
    (void)snprintf(link, sizeof link, "/tmp/mips64rt-rdef-l32-%d", (int)getpid());
    plant_str(&ctx, T_DATA + UINT64_C(0x40), link);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 1, (uint64_t)MIPS64_NR32_symlinkat,
                            T_DATA, (uint64_t)(int64_t)-100,
                            T_DATA + UINT64_C(0x40), 0U, &claimed);
    n = readlink(link, buf, sizeof buf - 1U);
    RDEF_CHECK("symlinkat-n32", claimed == 1 && rc == 0 && n == (ssize_t)strlen(tgt) &&
               memcmp(buf, tgt, (size_t)n) == 0);
    (void)unlink(link);

    /* R13-5: canonical classifier covers COP1 BC1; traps excluded. */
    mips_decode(UINT32_C(0x45000000), &d); /* BC1F (op 0x11, rs 0x08) */
    RDEF_CHECK("is-control-bc1f", interp_is_control(&d) == 1);
    mips_decode(UINT32_C(0x45010001), &d); /* BC1T (rt odd) */
    RDEF_CHECK("is-control-bc1t", interp_is_control(&d) == 1);
    mips_decode(UINT32_C(0x00800008), &d); /* JR $a0 */
    RDEF_CHECK("is-control-jr", interp_is_control(&d) == 1);
    mips_decode(UINT32_C(0x10220003), &d); /* BEQ */
    RDEF_CHECK("is-control-beq", interp_is_control(&d) == 1);
    mips_decode(UINT32_C(0x0007000D), &d); /* BREAK 7 */
    RDEF_CHECK("is-control-break", interp_is_control(&d) == 0);

    /* R14-1: BREAK 7 recovers to SIGFPE (R7-10), never SIGSEGV. */
    plant32(&ctx, T_CODE, UINT32_C(0x0007000D));
    site = trap_site(T_CODE, T_CODE, UINT32_C(0x0007000D), 0u, 0, 0u);
    reset_trap(&ctx, T_CODE);
    mrc = dbt_mem_recover(&ctx, &site, T_CODE, T_CODE);
    RDEF_CHECK("break7-sigfpe", mrc == 1 && g_signo == 8 &&
               ctx.exit_reason == (uint32_t)MIPS64_EXIT_FAULT);

    /* R14-1: BREAK 0 recovers to SIGTRAP, never SIGSEGV. */
    plant32(&ctx, T_CODE, UINT32_C(0x0000000D));
    site = trap_site(T_CODE, T_CODE, UINT32_C(0x0000000D), 0u, 0, 0u);
    reset_trap(&ctx, T_CODE);
    mrc = dbt_mem_recover(&ctx, &site, T_CODE, T_CODE);
    RDEF_CHECK("break0-sigtrap", mrc == 1 && g_signo == 5 &&
               ctx.exit_reason == (uint32_t)MIPS64_EXIT_FAULT);

    /* R14-1: trapping ADD overflow recovers to SIGFPE. */
    plant32(&ctx, T_CODE, UINT32_C(0x012A4020)); /* add $t0,$t1,$t2 */
    site = trap_site(T_CODE, T_CODE, UINT32_C(0x012A4020), 0u, 0, 0u);
    reset_trap(&ctx, T_CODE);
    ctx.gpr[9] = UINT64_C(0x40000000);
    ctx.gpr[10] = UINT64_C(0x40000000);
    mrc = dbt_mem_recover(&ctx, &site, T_CODE, T_CODE);
    RDEF_CHECK("add-overflow-sigfpe", mrc == 1 && g_signo == 8 &&
               ctx.exit_reason == (uint32_t)MIPS64_EXIT_FAULT);

    /* R14-1: trapping DADD overflow recovers to SIGFPE. */
    plant32(&ctx, T_CODE, UINT32_C(0x012A402C)); /* dadd $t0,$t1,$t2 */
    site = trap_site(T_CODE, T_CODE, UINT32_C(0x012A402C), 0u, 0, 0u);
    reset_trap(&ctx, T_CODE);
    ctx.gpr[9] = UINT64_C(0x4000000000000000);
    ctx.gpr[10] = UINT64_C(0x4000000000000000);
    mrc = dbt_mem_recover(&ctx, &site, T_CODE, T_CODE);
    RDEF_CHECK("dadd-overflow-sigfpe", mrc == 1 && g_signo == 8 &&
               ctx.exit_reason == (uint32_t)MIPS64_EXIT_FAULT);

    /* R14-1: trap in a delay slot keeps SIGTRAP and drops the target. */
    {
        uint64_t b = T_CODE + UINT64_C(0x40);
        uint64_t s = b + 4u;

        plant32(&ctx, b, UINT32_C(0x10210001)); /* beq $at,$v0,1 (taken) */
        plant32(&ctx, s, UINT32_C(0x0000000D)); /* break 0 in the slot */
        ctx.gpr[1] = UINT64_C(7);
        ctx.gpr[2] = UINT64_C(7);
        site = trap_site(s, b, UINT32_C(0x0000000D),
                         (uint8_t)DBT_MEM_F_IN_DELAY_SLOT, 12,
                         (uint8_t)RT_NPC_STATIC_TARGET);
        reset_trap(&ctx, s);
        mrc = dbt_mem_recover(&ctx, &site, b, s);
        RDEF_CHECK("delay-break-sigtrap", mrc == 1 && g_signo == 5 &&
                   ctx.exit_reason == (uint32_t)MIPS64_EXIT_FAULT &&
                   mips_delay_target_get(&ctx, &pend) == 0);
    }

    /* R14-2: BLTZAL $ra declines to compile (interp fallback). */
    {
        uint64_t b = T_CODE + UINT64_C(0x80);

        plant32(&ctx, b, UINT32_C(0x07F00002)); /* bltzal $ra, b+12 */
        plant32(&ctx, b + 4u, UINT32_C(0x8C620000)); /* lw $v0,0($v1) */
        ctx.gpr[MIPS64_REG_RA] = (uint64_t)(int64_t)-1;
        RDEF_CHECK("bltzal-ra-decline", dbt_compile(&ctx, b) != 0);
    }

done:
    if (g_fail == 0) {
        (void)printf("RDEF-RESULT: PASS (%d checks)\n", g_pass);
        return 0;
    }
    (void)printf("RDEF-RESULT: FAIL (%d pass, %d fail)\n", g_pass, g_fail);
    return 1;
}
