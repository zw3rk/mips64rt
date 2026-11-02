/*
 * src/os/syscalls_time.c — Static-libc clock family (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * clock_gettime (+ the N32 clock_gettime64 glibc uses for it),
 * nanosleep (+ clock_nanosleep, which is what glibc nanosleep lowers
 * to, and its N32 time64 companion). N32 clock/nanosleep take the
 * 8-byte {s32, s32} timespec, the time64 companions the 16-byte one
 * (both verified live under qemu). Shared helpers (l2a_ret, putn,
 * getn, guest_range) live in src/os/syscalls.c.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/syscall_nr.h"

#include <errno.h>
#include <stdint.h>
#include <time.h>

/* Quiescence lease hooks (src/os/quiesce.c): a blocking sleep must
 * not hold the dispatch lease, or a concurrent VM mutation stalls
 * forever on a thread that is not touching memory. */
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

/* Shared helpers owned by src/os/syscalls.c. */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);

#define L2A_NSEC_PER_SEC 1000000000L

/* Guest timespec transfer in either layout. Reads use the direct
 * guest window; writes stage in host memory and commit through
 * mips_sc_copyout (R3-1) so bytes and LL/SC invalidation land
 * together under sc_lock. */
static int64_t xfer_ts(mips64_ctx_t *ctx, uint64_t va, int is64,
                       struct timespec *ts, int write)
{
    int be = ctx->is_be != 0U;

    if (!write) {
        const uint8_t *p = guest_range(ctx, va, is64 ? 16U : 8U, 0);

        if (p == NULL) {
            return -(int64_t)EFAULT;
        }
        if (is64) {
            ts->tv_sec = (time_t)getn(p, 8, be);
            ts->tv_nsec = (long)getn(p + 8, 8, be);
        } else {
            ts->tv_sec = (time_t)(int32_t)getn(p, 4, be);
            ts->tv_nsec = (long)(int32_t)getn(p + 4, 4, be);
        }
        return 0;
    }
    {
        uint8_t img[16];

        if (is64) {
            putn(img, (uint64_t)(int64_t)ts->tv_sec, 8, be);
            putn(img + 8, (uint64_t)(int64_t)ts->tv_nsec, 8, be);
        } else {
            putn(img, (uint64_t)(uint32_t)(int32_t)ts->tv_sec, 4, be);
            putn(img + 4, (uint64_t)(uint32_t)(int32_t)ts->tv_nsec,
                 4, be);
        }
        if (mips_sc_copyout(ctx, va, img, is64 ? 16U : 8U) != 0) {
            return -(int64_t)EFAULT;
        }
    }
    return 0;
}

int64_t mips_sc_clock_gettime(mips64_ctx_t *ctx, uint64_t clk,
                              uint64_t ts_va, int is64)
{
    struct timespec ts;
    clockid_t host_clk = (clockid_t)(int)clk;
#ifdef __APPLE__
    host_clk = (clk == 0U) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
#endif

    if (clock_gettime(host_clk, &ts) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (xfer_ts(ctx, ts_va, is64, &ts, 1) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_nanosleep(mips64_ctx_t *ctx, uint64_t clk, uint64_t req_va,
                          uint64_t rem_va, int is64, int use_clock)
{
    struct timespec rq;
    struct timespec rm;
    struct timespec *remp = NULL;
    int64_t rc;

    /* The kernel validates both pointers before sleeping. */
    if (xfer_ts(ctx, req_va, is64, &rq, 0) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    if (rem_va != 0U) {
        if (!mips_mem_ok(ctx, rem_va, is64 ? 16U : 8U,
                         (uint32_t)MIPS_PROT_WRITE)) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        remp = &rm;
    }
    if (rq.tv_nsec < 0 || rq.tv_nsec >= L2A_NSEC_PER_SEC) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    /* Relative sleep only; TIMER_ABSTIME waits for Phase 4.
     * Park with 0 leases across the blocking sleep. */
    mips_qs_lease_exit(ctx);
#if defined(__linux__)
    rc = use_clock ? (int64_t)clock_nanosleep((clockid_t)(int)clk, 0, &rq,
                                              remp) :
                     (int64_t)nanosleep(&rq, remp);
#else
    /* No clock_nanosleep(2) on this host: every relative sleep
     * lowers to nanosleep(2). */
    (void)use_clock;
    (void)clk;
    rc = (int64_t)nanosleep(&rq, remp);
#endif
    mips_qs_lease_enter(ctx);
    if (rc != 0) {
        rc = -(int64_t)errno;
        if (remp != NULL && errno == EINTR) {
            (void)xfer_ts(ctx, rem_va, is64, remp, 1);
        }
        return l2a_ret(ctx, rc);
    }
    return l2a_ret(ctx, 0);
}
