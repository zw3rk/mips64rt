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
 * - T14-S1: close_range with a live vfork channel skips the channel
 *   fd (two host calls at most, no per-fd loop); unknown flags are
 *   EINVAL.
 * - T14-S3: SIG_DFL SIGCONT (25) is ignored by the EINTR verdict, and
 *   a recorded SIGCHLD under a blocked guest mask forwards to an
 *   eligible peer instead of queueing into the blocked context.
 * - T14-F1: the vfork pre-exec flush keeps the channel live (a failed
 *   execve still reports through it); the exit-path flush closes it.
 * - T14-F3: the host SIGCHLD install mirrors the guest SA_NOCLDSTOP
 *   bit, re-installing whenever it changes, and never carries
 *   SA_RESTART (EINTR must always surface).
 * - T14-F4: guest SA_RESTART syscall restart: a restartable syscall
 *   interrupted with -EINTR restores $v0/$a3 and keeps pc on the
 *   syscall when the delivered handler carries SA_RESTART.
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
#include "os/errno_map.h"
#include "os/host_args.h"
#include "os/signal_core.h"
#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
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

/* Controllable delivery seams for the T14-F4 restart checks:
 * g_has_handler names the one signal reporting a live handler;
 * the raise stub records the regs/pc at entry and answers g_raise_ret. */
static int g_has_handler = 0;

int mips_signal_has_handler(int signo)
{
    return signo == g_has_handler;
}

static int g_raise_ret = 1;
static int g_raise_signo = -1;
static uint64_t g_raise_v0 = 0U;
static uint64_t g_raise_a3 = 0U;
static uint64_t g_raise_pc = 0U;

int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr)
{
    (void)fault_addr;
    g_raise_signo = signo;
    if (ctx != NULL) {
        g_raise_v0 = ctx->gpr[MIPS64_REG_V0];
        g_raise_a3 = ctx->gpr[MIPS64_REG_A3];
        g_raise_pc = ctx->pc;
    }
    return g_raise_ret;
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

/* ---- lane L4b thread-registry seam (src/os/threads.c, not linked
 * into this gate): the SIGCHLD peer-wake hook. The stub counts
 * forwardings so the blocked-mask poll path is observable. */
static int g_wake_peer_calls = 0;

void mips_threads_wake_sigchld_peer(const mips64_ctx_t *ctx)
{
    (void)ctx;
    g_wake_peer_calls++;
}

/* ---- T14-S seams: close_range split + vfork channel ---- */
extern int64_t mips_sc_close_range(mips64_ctx_t *ctx, uint64_t first,
                                   uint64_t last, uint64_t flags);
extern int64_t mips64_vfork_pre(mips64_ctx_t *ctx, uint64_t flags, int *rfd,
                                int *wfd, uint64_t *va, size_t *len,
                                uint8_t **snap);
extern void mips64_vfork_child(uint64_t va, size_t len, uint8_t *snap,
                               int rfd, int wfd);
extern int mips64_vfork_pipe_fd(void);
extern void mips64_vfork_drop(void);
extern void mips64_vfork_flush(mips64_ctx_t *ctx);
extern void mips64_vfork_flush_pre_exec(mips64_ctx_t *ctx);

/* ---- syscall dispatch seam owned by src/os/syscalls_sync.c ---- */

extern int64_t mips_sc_file_extra(mips64_ctx_t *ctx, int n32, uint64_t nr,
                                  uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, uint64_t a4, int *claimed);
extern int64_t mips_sc_fcntl_lock(mips64_ctx_t *ctx, int n32, uint64_t fd,
                                  uint64_t cmd, uint64_t arg);

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
                            T_DATA, 0U, 0U, 0U, 0U, &claimed);
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
                            T_DATA, 0U, 0U, 0U, 0U, &claimed);
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
                            T_DATA + UINT64_C(0x40), 0U, 0U, &claimed);
    n = readlink(link, buf, sizeof buf - 1U);
    RDEF_CHECK("symlinkat-n64", claimed == 1 && rc == 0 && n == (ssize_t)strlen(tgt) &&
               memcmp(buf, tgt, (size_t)n) == 0);
    (void)unlink(link);
    (void)snprintf(link, sizeof link, "/tmp/mips64rt-rdef-l32-%d", (int)getpid());
    plant_str(&ctx, T_DATA + UINT64_C(0x40), link);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 1, (uint64_t)MIPS64_NR32_symlinkat,
                            T_DATA, (uint64_t)(int64_t)-100,
                            T_DATA + UINT64_C(0x40), 0U, 0U, &claimed);
    n = readlink(link, buf, sizeof buf - 1U);
    RDEF_CHECK("symlinkat-n32", claimed == 1 && rc == 0 && n == (ssize_t)strlen(tgt) &&
               memcmp(buf, tgt, (size_t)n) == 0);
    (void)unlink(link);

    /* T14 fable A1: N32 fchdir is 6079 (N32 mkdir is 6081). A bad-fd
     * fchdir claims 6079 with EBADF; 6081 creates the directory. */
    RDEF_CHECK("n32-fchdir-nr", MIPS64_NR32_fchdir == 6079);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 1, (uint64_t)MIPS64_NR32_fchdir,
                            (uint64_t)(int64_t)-1, 0U, 0U, 0U, 0U,
                            &claimed);
    RDEF_CHECK("n32-fchdir-dispatch", claimed == 1 &&
               rc == -(int64_t)EBADF &&
               ctx.gpr[MIPS64_REG_V0] == (uint64_t)EBADF &&
               ctx.gpr[MIPS64_REG_A3] == 1U);
    (void)snprintf(path, sizeof path, "/tmp/mips64rt-rdef-d-%d",
                   (int)getpid());
    plant_str(&ctx, T_DATA, path);
    claimed = 0;
    rc = mips_sc_file_extra(&ctx, 1, 6081U, T_DATA, 0700U, 0U, 0U, 0U,
                            &claimed);
    RDEF_CHECK("n32-mkdir-dispatch", claimed == 1 && rc == 0 &&
               access(path, F_OK) == 0);
    (void)rmdir(path);

    /* T14 fable A1: errno mapping spot checks (host-specific). */
#ifdef __APPLE__
    RDEF_CHECK("errno-darwin-edestaddrreq",
               l2a_errno_from_host(EDESTADDRREQ) == 96);
    RDEF_CHECK("errno-darwin-econnrefused",
               l2a_errno_from_host(ECONNREFUSED) == 146);
    RDEF_CHECK("errno-darwin-etimedout",
               l2a_errno_from_host(ETIMEDOUT) == 145);
    RDEF_CHECK("errno-darwin-enotempty",
               l2a_errno_from_host(ENOTEMPTY) == 93);
#else
    RDEF_CHECK("errno-eloop", l2a_errno_from_host(40) == 90);
    RDEF_CHECK("errno-enotempty", l2a_errno_from_host(39) == 93);
    RDEF_CHECK("errno-econnreset", l2a_errno_from_host(104) == 131);
    RDEF_CHECK("errno-edquot", l2a_errno_from_host(122) == 1133);
    RDEF_CHECK("errno-eopnotsupp", l2a_errno_from_host(95) == 122);
#endif

    /* T14 fable B: relative guest paths never gain the sysroot. */
    {
        char out[64];

        RDEF_CHECK("sysroot-rel",
                   mips64_sysroot_join("/sr", "a/b", out, sizeof out) == 0 &&
                   strcmp(out, "a/b") == 0);
        RDEF_CHECK("sysroot-abs",
                   mips64_sysroot_join("/sr", "/x", out, sizeof out) == 0 &&
                   strcmp(out, "/sr/x") == 0);
    }

    /* T14 fable C: N32 fcntl 64-bit commands dispatch; bogus ones are
     * EINVAL without touching guest memory. */
    RDEF_CHECK("fcntl-bogus",
               mips_sc_fcntl_lock(&ctx, 0, 0U, 99U, 0U) ==
               -(int64_t)EINVAL);
    fd = open("/dev/null", O_RDONLY);
    RDEF_CHECK("fcntl-null-setup", fd >= 0);
    if (fd >= 0) {
        memset(mips64_guest_ptr(&ctx, T_DATA), 0, 36);
        rc = mips_sc_fcntl_lock(&ctx, 1, (uint64_t)fd, 33U, T_DATA);
        RDEF_CHECK("fcntl-n32-flock64-getlk",
                   rc == 0 && ctx.gpr[MIPS64_REG_A3] == 0U);
        (void)close(fd);
    }

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

    /* T14-S1: close_range with a live vfork channel skips the channel
     * fd through at most two host calls (no per-fd loop): a range
     * covering it closes the neighbours and keeps the channel open. */
    {
        int rfd = -1;
        int wfd = -1;
        uint64_t vva = 0U;
        size_t vlen = 0U;
        uint8_t *vsnap = NULL;
        int64_t pre;

        ctx.gpr[MIPS64_REG_SP] = T_PAGE + UINT64_C(0x900);
        pre = mips64_vfork_pre(&ctx, UINT64_C(0x4000), &rfd, &wfd,
                               &vva, &vlen, &vsnap);
        RDEF_CHECK("close-range-vf-pre", pre == 1 && rfd >= 0 &&
                   wfd >= 0);
        if (pre == 1) {
            int vfd;
            int lo = -1;
            int hi = -1;

            mips64_vfork_child(vva, vlen, vsnap, rfd, wfd);
            vsnap = NULL;
            vfd = mips64_vfork_pipe_fd();
            RDEF_CHECK("close-range-vf-fd", vfd == wfd && vfd >= 512);
            lo = open("/dev/null", O_RDONLY);
            hi = open("/dev/null", O_RDONLY);
            RDEF_CHECK("close-range-vf-setup", lo >= 0 && hi >= 0 &&
                       lo != vfd && hi != vfd);
            if (lo >= 0 && hi >= 0 && vfd >= 0) {
                uint64_t first = (uint64_t)(lo < hi ? lo : hi);

                rc = mips_sc_close_range(&ctx, first, (uint64_t)vfd,
                                         0U);
                RDEF_CHECK("close-range-vf-split",
                           rc == 0 && ctx.gpr[MIPS64_REG_A3] == 0U &&
                           fcntl(lo, F_GETFD) != 0 &&
                           errno == EBADF &&
                           fcntl(hi, F_GETFD) != 0 &&
                           errno == EBADF &&
                           fcntl(vfd, F_GETFD) >= 0);
                rc = mips_sc_close_range(&ctx, (uint64_t)vfd,
                                         (uint64_t)vfd, 0U);
                RDEF_CHECK("close-range-vf-only",
                           rc == 0 && fcntl(vfd, F_GETFD) >= 0);
                RDEF_CHECK("close-range-flags",
                           mips_sc_close_range(&ctx, 3U, 4U, 8U) ==
                           -(int64_t)EINVAL);
            }
            if (lo >= 0) {
                (void)close(lo);
            }
            if (hi >= 0) {
                (void)close(hi);
            }
            mips64_vfork_drop();
            RDEF_CHECK("close-range-vf-drop",
                       mips64_vfork_pipe_fd() == -1);
        } else {
            free(vsnap);
        }
    }

    /* T14-S3: SIG_DFL SIGCONT (25) is ignored, never a fatal/stop
     * EINTR verdict. */
    ctx.sigactions[25].handler = 0U;
    ctx.sig_blocked[0] = 0U;
    ctx.sig_blocked[1] = 0U;
    ctx.pend_head = 0U;
    ctx.pend_count = 1U;
    ctx.pend_queue[0].signo = 25U;
    ctx.pend_queue[0].code = 0;
    ctx.pend_queue[0].errnum = 0;
    ctx.pend_queue[0].addr = 0U;
    RDEF_CHECK("sigcont-dfl-retry", mips64_host_eintr_retry(&ctx) == 1);
    ctx.pend_count = 0U;

    /* T14-S3: a recorded SIGCHLD seen under a blocked guest mask is
     * forwarded to an eligible peer (wake hook runs) and left queued
     * for it — nothing is consumed into the blocked context. */
    ctx.sigactions[MIPS64_SIGCHLD].handler = 2U;
    ctx.sig_blocked[0] = UINT64_C(1) << 17U;
    ctx.sig_blocked[1] = 0U;
    ctx.pend_head = 0U;
    ctx.pend_count = 0U;
    g_wake_peer_calls = 0;
    mips64_host_sigchld_arm(0U);
    (void)raise(SIGCHLD);
    mips64_host_sigchld_poll(&ctx);
    RDEF_CHECK("sigchld-blocked-forward", g_wake_peer_calls == 1 &&
               ctx.pend_count == 0U);
    mips64_host_sigchld_disarm();
    ctx.sig_blocked[0] = 0U;
    ctx.sigactions[MIPS64_SIGCHLD].handler = 0U;
    ctx.sigactions[25].handler = 0U;

    /* T14-F1: the pre-exec flush replays diffs but keeps the channel
     * live (a failed execve still reports through it); the exit-path
     * flush closes it. */
    {
        int rfd = -1;
        int wfd = -1;
        uint64_t vva = 0U;
        size_t vlen = 0U;
        uint8_t *vsnap = NULL;
        int64_t pre;

        ctx.gpr[MIPS64_REG_SP] = T_PAGE + UINT64_C(0x900);
        pre = mips64_vfork_pre(&ctx, UINT64_C(0x4000), &rfd, &wfd,
                               &vva, &vlen, &vsnap);
        RDEF_CHECK("vf-pre-exec-setup", pre == 1 && rfd >= 0 &&
                   wfd >= 0);
        if (pre == 1) {
            mips64_vfork_child(vva, vlen, vsnap, rfd, wfd);
            vsnap = NULL;
            if (vlen > 0U) {
                uint8_t *cell =
                    (uint8_t *)mips64_guest_ptr(&ctx, vva);

                cell[0] ^= 0xA5U;
            }
            /* No parent holds the read end here (vfork_child
             * closed it), so ignore SIGPIPE: the writes fail with
             * EPIPE and the flush paths still run their course. */
            (void)signal(SIGPIPE, SIG_IGN);
            mips64_vfork_flush_pre_exec(&ctx);
            RDEF_CHECK("vf-pre-exec-live",
                       mips64_vfork_pipe_fd() == wfd &&
                       fcntl(wfd, F_GETFD) >= 0);
            mips64_vfork_flush(&ctx);
            (void)signal(SIGPIPE, SIG_DFL);
            RDEF_CHECK("vf-flush-drop",
                       mips64_vfork_pipe_fd() == -1);
        } else {
            free(vsnap);
        }
    }

    /* T14-F3: the host SIGCHLD install mirrors the guest
     * SA_NOCLDSTOP bit (stop/continue reports only when the guest
     * left it clear), re-installing whenever the bit changes — and
     * never carries SA_RESTART, even when the guest action has it. */
    {
        struct sigaction cur;

        mips64_host_sigchld_arm(0U);
        (void)sigaction(SIGCHLD, NULL, &cur);
        RDEF_CHECK("sigchld-nocldstop-clear",
                   (cur.sa_flags & SA_NOCLDSTOP) == 0 &&
                   (cur.sa_flags & SA_RESTART) == 0);
        mips64_host_sigchld_arm(MIPS64_SA_NOCLDSTOP);
        (void)sigaction(SIGCHLD, NULL, &cur);
        RDEF_CHECK("sigchld-nocldstop-set",
                   (cur.sa_flags & SA_NOCLDSTOP) != 0 &&
                   (cur.sa_flags & SA_RESTART) == 0);
        mips64_host_sigchld_arm((uint64_t)(MIPS64_SA_NOCLDSTOP |
                                           MIPS64_SA_RESTART));
        (void)sigaction(SIGCHLD, NULL, &cur);
        RDEF_CHECK("sigchld-no-host-restart",
                   (cur.sa_flags & SA_NOCLDSTOP) != 0 &&
                   (cur.sa_flags & SA_RESTART) == 0);
        mips64_host_sigchld_arm((uint64_t)MIPS64_SA_RESTART);
        (void)sigaction(SIGCHLD, NULL, &cur);
        RDEF_CHECK("sigchld-restart-never-installed",
                   (cur.sa_flags & SA_NOCLDSTOP) == 0 &&
                   (cur.sa_flags & SA_RESTART) == 0);
        mips64_host_sigchld_disarm();
        RDEF_CHECK("sigchld-disarmed",
                   mips64_host_sigchld_armed() == 0);
        /* The SA_SIGINFO handler captures the exact triggering child
         * (si_pid/si_uid/si_status/si_code), so the poller never needs
         * a waitid(WNOWAIT) that could report an older un-reaped
         * stopped child instead. A real exiting child drives this
         * (raise() self-delivery carries si_pid 0 on some hosts). */
        mips64_host_sigchld_arm(0U);
        {
            pid_t cap_child = fork();
            uint32_t cap_pid = 0U;
            uint32_t cap_uid = 0U;
            int32_t cap_status = -1;
            int32_t cap_code = -1;
            int cap_got = 0;
            int cap_tries = 0;

            if (cap_child == 0) {
                _exit(7);
            }
            if (cap_child > 0) {
                struct timespec cap_step;

                cap_step.tv_sec = 0;
                cap_step.tv_nsec = 1000000L;
                while (cap_tries < 5000) {
                    if (mips64_sigchld_info(&cap_pid, &cap_uid,
                                            &cap_status,
                                            &cap_code) == 1) {
                        if (cap_pid == (uint32_t)cap_child) {
                            cap_got = 1;
                            break;
                        }
                    }
                    cap_tries++;
                    (void)nanosleep(&cap_step, NULL);
                }
                (void)waitpid(cap_child, NULL, 0);
                RDEF_CHECK("sigchld-handler-capture",
                           cap_got == 1 &&
                           cap_uid == (uint32_t)getuid() &&
                           cap_code == 1 && cap_status == 7);
            } else {
                RDEF_CHECK("sigchld-handler-capture", 0);
            }
        }
        mips64_host_sigchld_disarm();
    }

    /* T14-F4: guest SA_RESTART syscall restart. The interrupted
     * syscall already wrote -EINTR into $v0/$a3; a restartable
     * syscall (read) keeps pc on the syscall and restores the entry
     * $v0/$a3 when the delivered handler carries SA_RESTART. Any
     * other combination (no SA_RESTART, non-restartable ppoll, or
     * no -EINTR) reports -EINTR after the syscall. */
    {
        mips64_ctx_t rctx;

        (void)memset(&rctx, 0, sizeof rctx);
        rctx.is_n32 = 0U;
        rctx.sigactions[MIPS64_SIGCHLD].handler = UINT64_C(0x30000);
        rctx.sig_blocked[0] = 0U;
        rctx.sig_blocked[1] = 0U;
        rctx.pend_head = 0U;
        rctx.pend_count = 1U;
        rctx.pend_queue[0].signo = (uint32_t)MIPS64_SIGCHLD;
        rctx.pend_queue[0].code = 0;
        rctx.pend_queue[0].errnum = 0;
        rctx.pend_queue[0].addr = 0U;
        g_has_handler = MIPS64_SIGCHLD;
        g_raise_ret = 0;
        /* Restartable + SA_RESTART: regs restored, pc held. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        rctx.sigactions[MIPS64_SIGCHLD].flags = MIPS64_SA_RESTART;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_read, 0U,
                                  -(int64_t)EINTR);
        RDEF_CHECK("restart-syscall",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   g_raise_v0 == (uint64_t)MIPS64_NR_read &&
                   g_raise_a3 == 0U &&
                   g_raise_pc == UINT64_C(0x120000) &&
                   rctx.pc == UINT64_C(0x120000));
        /* Same -EINTR without SA_RESTART: pc advances, EINTR stands. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        rctx.sigactions[MIPS64_SIGCHLD].flags = 0U;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_read, 0U,
                                  -(int64_t)EINTR);
        RDEF_CHECK("no-restart-without-sa-restart",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   rctx.gpr[MIPS64_REG_V0] == 4U &&
                   rctx.gpr[MIPS64_REG_A3] == 1U &&
                   rctx.pc == UINT64_C(0x120004));
        /* Non-restartable wait with SA_RESTART: EINTR still stands. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        rctx.sigactions[MIPS64_SIGCHLD].flags = MIPS64_SA_RESTART;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_ppoll, 0U,
                                  -(int64_t)EINTR);
        RDEF_CHECK("no-restart-nonrestartable",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   rctx.gpr[MIPS64_REG_V0] == 4U &&
                   rctx.gpr[MIPS64_REG_A3] == 1U &&
                   rctx.pc == UINT64_C(0x120004));
        /* Untimed FUTEX_WAIT (op 0, timeout NULL) with SA_RESTART:
         * restarted like read, even though the no-arg futex query
         * stays non-restartable. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A1] = 0U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        rctx.sigactions[MIPS64_SIGCHLD].flags = MIPS64_SA_RESTART;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_futex, 0U,
                                  -(int64_t)EINTR);
        RDEF_CHECK("restart-futex-wait-untimed",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   g_raise_v0 == (uint64_t)MIPS64_NR_futex &&
                   g_raise_a3 == 0U &&
                   g_raise_pc == UINT64_C(0x120000) &&
                   rctx.pc == UINT64_C(0x120000));
        /* Timed FUTEX_WAIT (timeout != NULL): EINTR still stands. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A1] = 0U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_futex,
                                  UINT64_C(0x1000), -(int64_t)EINTR);
        RDEF_CHECK("no-restart-futex-wait-timed",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   rctx.gpr[MIPS64_REG_V0] == 4U &&
                   rctx.gpr[MIPS64_REG_A3] == 1U &&
                   rctx.pc == UINT64_C(0x120004));
        /* Untimed FUTEX_WAIT_BITSET (op 9): EINTR still stands. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A1] = 9U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_futex, 0U,
                                  -(int64_t)EINTR);
        RDEF_CHECK("no-restart-futex-wait-bitset",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   rctx.gpr[MIPS64_REG_V0] == 4U &&
                   rctx.gpr[MIPS64_REG_A3] == 1U &&
                   rctx.pc == UINT64_C(0x120004));
        /* N32 untimed FUTEX_WAIT restarts too (32-bit NULL timeout). */
        rctx.is_n32 = 1U;
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 4U;
        rctx.gpr[MIPS64_REG_A1] = 0U;
        rctx.gpr[MIPS64_REG_A3] = 1U;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR32_futex,
                                  0U, -(int64_t)EINTR);
        RDEF_CHECK("restart-futex-wait-untimed-n32",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   g_raise_v0 == (uint64_t)MIPS64_NR32_futex &&
                   g_raise_a3 == 0U &&
                   rctx.pc == UINT64_C(0x120000));
        rctx.is_n32 = 0U;
        rctx.gpr[MIPS64_REG_A1] = 0U;
        /* Successful syscall with a pending handler: no restart. */
        rctx.pc = UINT64_C(0x120000);
        rctx.next_pc = rctx.pc + 4U;
        rctx.gpr[MIPS64_REG_V0] = 0U;
        rctx.gpr[MIPS64_REG_A3] = 0U;
        g_raise_signo = -1;
        mips64_sc_deliver_pending(&rctx, (uint64_t)MIPS64_NR_read, 0U, 0);
        RDEF_CHECK("no-restart-on-success",
                   g_raise_signo == (int)MIPS64_SIGCHLD &&
                   rctx.gpr[MIPS64_REG_V0] == 0U &&
                   rctx.pc == UINT64_C(0x120004));
        /* Restartable set shape (both ABIs + time64 companions). */
        RDEF_CHECK("restartable-set",
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_read, 0) == 1 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_write, 0) == 1 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_wait4, 0) == 1 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_waitid, 0) == 1 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_ioctl, 0) == 1 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_read, 1) == 1);
        RDEF_CHECK("non-restartable-set",
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_ppoll, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_pselect6, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_nanosleep, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_clock_nanosleep, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_futex, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_rt_sigtimedwait, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_ppoll, 1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_clock_nanosleep_time64,
                       1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_futex_time64, 1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR_LINUX_BASE + 33), 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR32_LINUX_BASE + 33),
                       1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR_LINUX_BASE + 127), 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR32_LINUX_BASE + 127),
                       1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR_LINUX_BASE + 128), 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR32_LINUX_BASE + 128),
                       1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_epoll_wait, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_epoll_wait, 1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR_epoll_pwait, 0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)MIPS64_NR32_epoll_pwait, 1) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR_LINUX_BASE + 441),
                       0) == 0 &&
                   mips64_syscall_restartable(
                       (uint64_t)(MIPS64_NR32_LINUX_BASE + 441),
                       1) == 0);
        g_has_handler = 0;
        g_raise_ret = 1;
        g_raise_signo = -1;
    }

done:
    if (g_fail == 0) {
        (void)printf("RDEF-RESULT: PASS (%d checks)\n", g_pass);
        return 0;
    }
    (void)printf("RDEF-RESULT: FAIL (%d pass, %d fail)\n", g_pass, g_fail);
    return 1;
}
