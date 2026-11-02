/*
 * tests/test_r3_defects.c — Round-3 defect regression gate (host-native).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-portable, no Docker, no guest toolchain: drives the real
 * interpreter and syscall TUs directly.
 *
 * - R3-1: a same-value mips_sc_copyout clears the LL reservation, so
 *   a following SC fails (copyout + invalidation commit together).
 * - R3-2: ADD.S/SUB.S with an absorbed small operand (1.0f +/- 2^-126)
 *   round exactly under all four FCSR modes and always set Inexact;
 *   single-infinite operands stay +-Inf with no flags in all modes.
 * - R3-3: a 65-entry writev issues one host call (one datagram on a
 *   SOCK_DGRAM socketpair, not two).
 * - R3-4: l2a_vec_copyout reports bytes already committed when a
 *   later destination faults (-EFAULT only when nothing committed).
 *
 * Protocol: "R3-PASS <name>", "R3-FAIL <name> ...", final
 * "R3-RESULT: PASS|FAIL" plus summary. Exit 0 iff zero failures.
 */

#include "core/cpu.h"
#include "interp/fp.h"
#include "interp/interp.h"
#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

#define R3_CHECK64(name, got, want) do { \
        uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
        if (_g == _w) { \
            g_pass++; \
            (void)printf("R3-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R3-FAIL %s got=0x%llx want=0x%llx\n", \
                name, (unsigned long long)_g, \
                (unsigned long long)_w); \
        } \
    } while (0)

#define R3_CHECK(name, cond) do { \
        if (cond) { \
            g_pass++; \
            (void)printf("R3-PASS %s\n", name); \
        } else { \
            g_fail++; \
            (void)printf("R3-FAIL %s\n", name); \
        } \
    } while (0)

/* ---- interp seams (same pattern as tests/test_u0_gate.c) ---- */

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

/* ---- syscall seams owned by src/os/syscalls.c / syscalls_sync.c --- */

extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern int64_t mips_sc_vec(mips64_ctx_t *ctx, uint64_t fd, uint64_t iov_va,
                           uint64_t iovcnt, uint64_t off, int is_p,
                           int is_write);
extern int64_t l2a_vec_copyout(mips64_ctx_t *ctx, const uint64_t *gva,
                               const uint64_t *glen, uint8_t **kbuf,
                               uint64_t iovcnt, uint64_t nbytes);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);

#define R3_PAGE   UINT64_C(0x10000)
#define R3_WORD   (R3_PAGE + UINT64_C(0x100))
#define R3_DATA   (R3_PAGE + UINT64_C(0x200))
#define R3_IOV    (R3_PAGE + UINT64_C(0x300))
#define R3_DST    (R3_PAGE + UINT64_C(0x800))
#define R3_NOMAP  UINT64_C(0x20000)

static mips64_ctx_t g_ctx;

static void r3_setup(void)
{
    (void)memset(&g_ctx, 0, sizeof g_ctx);
    g_ctx.is_n32 = 0U;
    g_ctx.is_be = 0U;
    mips_backend_state_reset(&g_ctx);
    if (guest_mem_init(&g_ctx) != 0) {
        (void)printf("R3-FAIL setup: guest_mem_init\n");
        g_fail++;
        return;
    }
    if (mips_mem_map(&g_ctx, R3_PAGE, UINT64_C(0x1000),
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE),
                     "r3-page") != 0) {
        (void)printf("R3-FAIL setup: mips_mem_map errno=%d\n", errno);
        g_fail++;
    }
}

/* R3-2: absorbed-operand ADD.S/SUB.S under RM 0..3, plus
 * single-infinite operands (no flags, result stays +-Inf). */
static void t_fp_swallow(void)
{
    static const struct {
        uint32_t a;
        uint32_t b;
        unsigned funct;
        unsigned rm;
        uint32_t want;
        uint32_t fcsr;
    } cases[] = {
        { 0x3F800000u, 0x00800000u, 0x00u, 0u, 0x3F800000u, 0x1004u },
        { 0x3F800000u, 0x00800000u, 0x00u, 1u, 0x3F800000u, 0x1005u },
        { 0x3F800000u, 0x00800000u, 0x00u, 2u, 0x3F800001u, 0x1006u },
        { 0x3F800000u, 0x00800000u, 0x00u, 3u, 0x3F800000u, 0x1007u },
        { 0x3F800000u, 0x00800000u, 0x01u, 0u, 0x3F800000u, 0x1004u },
        { 0x3F800000u, 0x00800000u, 0x01u, 1u, 0x3F7FFFFFu, 0x1005u },
        { 0x3F800000u, 0x00800000u, 0x01u, 2u, 0x3F800000u, 0x1006u },
        { 0x3F800000u, 0x00800000u, 0x01u, 3u, 0x3F7FFFFFu, 0x1007u },
        { 0xBF800000u, 0x80800000u, 0x00u, 0u, 0xBF800000u, 0x1004u },
        { 0xBF800000u, 0x80800000u, 0x00u, 1u, 0xBF800000u, 0x1005u },
        { 0xBF800000u, 0x80800000u, 0x00u, 2u, 0xBF800000u, 0x1006u },
        { 0xBF800000u, 0x80800000u, 0x00u, 3u, 0xBF800001u, 0x1007u },
        { 0x7F800000u, 0xBF800000u, 0x00u, 0u, 0x7F800000u, 0x0000u },
        { 0x7F800000u, 0xBF800000u, 0x00u, 1u, 0x7F800000u, 0x0001u },
        { 0x7F800000u, 0xBF800000u, 0x00u, 2u, 0x7F800000u, 0x0002u },
        { 0x7F800000u, 0xBF800000u, 0x00u, 3u, 0x7F800000u, 0x0003u },
        { 0xFF800000u, 0x3F800000u, 0x00u, 0u, 0xFF800000u, 0x0000u },
        { 0xFF800000u, 0x3F800000u, 0x00u, 1u, 0xFF800000u, 0x0001u },
        { 0xFF800000u, 0x3F800000u, 0x00u, 2u, 0xFF800000u, 0x0002u },
        { 0xFF800000u, 0x3F800000u, 0x00u, 3u, 0xFF800000u, 0x0003u },
        { 0x7F800000u, 0xBF800000u, 0x01u, 0u, 0x7F800000u, 0x0000u },
        { 0x7F800000u, 0xBF800000u, 0x01u, 1u, 0x7F800000u, 0x0001u },
        { 0x7F800000u, 0xBF800000u, 0x01u, 2u, 0x7F800000u, 0x0002u },
        { 0x7F800000u, 0xBF800000u, 0x01u, 3u, 0x7F800000u, 0x0003u },
        { 0xFF800000u, 0x3F800000u, 0x01u, 0u, 0xFF800000u, 0x0000u },
        { 0xFF800000u, 0x3F800000u, 0x01u, 1u, 0xFF800000u, 0x0001u },
        { 0xFF800000u, 0x3F800000u, 0x01u, 2u, 0xFF800000u, 0x0002u },
        { 0xFF800000u, 0x3F800000u, 0x01u, 3u, 0xFF800000u, 0x0003u },
    };
    size_t i;
    char name[64];

    for (i = 0U; i < sizeof cases / sizeof cases[0]; i++) {
        mips64_ctx_t ctx;
        mips_dec_t d;
        int rc;

        (void)memset(&ctx, 0, sizeof ctx);
        ctx.is_be = 0U;
        ctx.is_n32 = 0U;
        ctx.fpr[4] = (uint64_t)cases[i].a;
        ctx.fpr[6] = (uint64_t)cases[i].b;
        ctx.fcsr = cases[i].rm;
        (void)memset(&d, 0, sizeof d);
        d.rs = 0x10u;
        d.funct = (uint8_t)cases[i].funct;
        d.sa = 2u;
        d.rd = 4u;
        d.rt = 6u;
        rc = fp_cop1(&ctx, 0U, &d);
        (void)snprintf(name, sizeof name, "fp-swallow-%u-%s-rm%u",
            (unsigned)i,
            cases[i].funct == 0x01u ? "sub" : "add", cases[i].rm);
        R3_CHECK(name, rc == 0);
        (void)snprintf(name, sizeof name, "fp-swallow-%u-bits", (unsigned)i);
        R3_CHECK64(name, (uint32_t)ctx.fpr[2], cases[i].want);
        (void)snprintf(name, sizeof name, "fp-swallow-%u-fcsr", (unsigned)i);
        R3_CHECK64(name, ctx.fcsr, cases[i].fcsr);
    }
}

/* R3-1: same-value copyout still clears the reservation. */
static void t_sc_copyout_llsc(void)
{
    static const uint8_t img[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
    int64_t rc;

    (void)memcpy(mips64_guest_ptr(&g_ctx, R3_WORD), img, sizeof img);
    R3_CHECK("copyout-ll", do_ll(&g_ctx, R3_WORD, 8u) == 0);
    R3_CHECK("copyout-llbit", g_ctx.llbit == 1u);
    rc = do_sc(&g_ctx, R3_WORD, 9u);
    R3_CHECK("copyout-sc-baseline", rc == 0 && g_ctx.gpr[9] == 1u);
    R3_CHECK("copyout-ll2", do_ll(&g_ctx, R3_WORD, 8u) == 0);
    rc = mips_sc_copyout(&g_ctx, R3_WORD, img, sizeof img);
    R3_CHECK("copyout-rc", rc == 0);
    R3_CHECK("copyout-clears-llbit", g_ctx.llbit == 0u);
    R3_CHECK("copyout-bytes",
        memcmp(mips64_guest_ptr(&g_ctx, R3_WORD), img, sizeof img) == 0);
    rc = do_sc(&g_ctx, R3_WORD, 9u);
    R3_CHECK("copyout-sc-fails", rc == 0 && g_ctx.gpr[9] == 0u);
    rc = mips_sc_copyout(&g_ctx, R3_NOMAP, img, sizeof img);
    R3_CHECK("copyout-efault", rc == -(int64_t)EFAULT);
}

/* R3-3: 65 iovecs go out as one datagram. */
static void t_vec_single_call(void)
{
    int sv[2];
    uint8_t *e;
    uint64_t k;
    int64_t rc;
    uint8_t rx[1024];
    ssize_t n;
    int flags;

    R3_CHECK("vec-socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    if (sv[0] < 0) {
        return;
    }
    for (k = 0U; k < 65U; k++) {
        e = (uint8_t *)mips64_guest_ptr(&g_ctx, R3_IOV + k * 16U);
        putn(e, R3_DATA, 8, 0);
        putn(e + 8, 8U, 8, 0);
    }
    (void)memset(mips64_guest_ptr(&g_ctx, R3_DATA), 0xA5, 8u);
    rc = mips_sc_vec(&g_ctx, (uint64_t)sv[0], R3_IOV, 65U, 0U, 0, 1);
    R3_CHECK64("vec-writev-rc", (uint64_t)rc, 520U);
    n = recv(sv[1], (char *)rx, sizeof rx, 0);
    R3_CHECK("vec-one-datagram", n == 520);
    if (n == 520) {
        R3_CHECK("vec-bytes", rx[0] == 0xA5u && rx[519] == 0xA5u);
    }
    flags = fcntl(sv[1], F_GETFL, 0);
    (void)fcntl(sv[1], F_SETFL, flags | O_NONBLOCK);
    n = recv(sv[1], (char *)rx, sizeof rx, 0);
    R3_CHECK("vec-no-second-datagram", n < 0 && errno == EAGAIN);
    (void)close(sv[0]);
    (void)close(sv[1]);
}

/* R3-4: committed bytes survive a later copyout fault. */
static void t_vec_copyout_accounting(void)
{
    uint64_t gva[2];
    uint64_t glen[2];
    uint8_t *kbuf[2];
    int64_t rc;

    kbuf[0] = (uint8_t *)malloc(32u);
    kbuf[1] = (uint8_t *)malloc(32u);
    R3_CHECK("copyout-malloc", kbuf[0] != NULL && kbuf[1] != NULL);
    if (kbuf[0] == NULL || kbuf[1] == NULL) {
        free(kbuf[0]);
        free(kbuf[1]);
        return;
    }
    (void)memset(kbuf[0], 0xA5, 32u);
    (void)memset(kbuf[1], 0x5A, 32u);
    gva[0] = R3_DST;
    glen[0] = 32U;
    gva[1] = R3_NOMAP;
    glen[1] = 32U;
    rc = l2a_vec_copyout(&g_ctx, gva, glen, kbuf, 2U, 64U);
    R3_CHECK64("copyout-committed", (uint64_t)rc, 32U);
    R3_CHECK("copyout-committed-bytes",
        memcmp(mips64_guest_ptr(&g_ctx, R3_DST), kbuf[0], 32u) == 0);
    rc = l2a_vec_copyout(&g_ctx, gva + 1, glen + 1, kbuf + 1, 1U, 32U);
    R3_CHECK("copyout-efault-empty", rc == -(int64_t)EFAULT);
    rc = l2a_vec_copyout(&g_ctx, gva, glen, kbuf, 1U, 32U);
    R3_CHECK64("copyout-full", (uint64_t)rc, 32U);
    free(kbuf[0]);
    free(kbuf[1]);
}

int main(void)
{
    r3_setup();
    t_fp_swallow();
    t_sc_copyout_llsc();
    t_vec_single_call();
    t_vec_copyout_accounting();
    (void)printf("R3-RESULT: %s (pass=%d fail=%d)\n",
        g_fail == 0 ? "PASS" : "FAIL", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
