/*
 * src/os/syscalls_extra.c — Static-libc directory + residual clock
 * syscalls (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * getdents64, clock_getres, and clock_nanosleep live here (rather than
 * src/os/syscalls.c) to keep every TU under the 900-line ceiling.
 * All guest writes stage in host memory first and commit through
 * mips_sc_copyout (R3-1): bytes and LL/SC invalidation land together
 * under sc_lock, so a peer LL/SC pair observes all or none of them.
 * No lock is held across a blocking host call.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/host_args.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Non-Linux host fallbacks (getdents64/clock shapes). */
#include "os/host_compat.h"

/* Guest window check owned by src/os/mem.c. */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

/* Shared helpers owned by src/os/syscalls.c. */
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);

/* Quiescence lease hooks (src/os/quiesce.c): a blocking sleep must
 * not hold the dispatch lease. */
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

/* getdents64 records are arch-independent; only BE guests need a
 * fixup walk over the host fill. The records stage in host memory so
 * the BE fixup runs before the serialized copyout (R3-1); only the
 * bytes the host produced are committed. */
int64_t mips_sc_getdents64(mips64_ctx_t *ctx, uint64_t fd, uint64_t dirp_va,
                           uint64_t count)
{
    uint8_t *stage;
    long n;

    if (count == 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (!mips_mem_ok(ctx, dirp_va, count, (uint32_t)MIPS_PROT_WRITE)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    stage = (uint8_t *)malloc((size_t)count);
    if (stage == NULL) {
        return l2a_ret(ctx, -(int64_t)ENOMEM);
    }
    n = l2a_getdents64_host((int)fd, stage, (size_t)count);
    if (n < 0) {
        int e = errno;

        free(stage);
        return l2a_ret(ctx, -(int64_t)e);
    }
    if (n > 0 && ctx->is_be != 0U) {
        int64_t off = 0;

        while (off + 19 <= n) {
            uint64_t reclen = getn(stage + off + 16, 2, 0);

            if (reclen < 19U || off + (int64_t)reclen > n) {
                break;
            }
            putn(stage + off, getn(stage + off, 8, 0), 8, 1);
            putn(stage + off + 8, getn(stage + off + 8, 8, 0), 8, 1);
            putn(stage + off + 16, reclen, 2, 1);
            off += (int64_t)reclen;
        }
    }
    if (n > 0 && mips_sc_copyout(ctx, dirp_va, stage, (uint64_t)n) != 0) {
        free(stage);
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    free(stage);
    return l2a_ret(ctx, (int64_t)n);
}

/* clock_getres (N64 5223 / N32 6227): same timespec write layout as
 * the clock family in src/os/syscalls_time.c (16-byte N64/time64,
 * 8-byte N32 {s32, s32} pair). */
int64_t mips_sc_clock_getres(mips64_ctx_t *ctx, uint64_t clk,
                             uint64_t ts_va, int is64)
{
    struct timespec ts;
    uint8_t img[16];
    uint64_t n = is64 ? 16U : 8U;
    int be;

    if (clock_getres((clockid_t)(int)clk, &ts) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (ts_va == 0U) {
        return l2a_ret(ctx, 0);
    }
    be = ctx->is_be != 0U;
    if (is64) {
        putn(img, (uint64_t)(int64_t)ts.tv_sec, 8, be);
        putn(img + 8, (uint64_t)(int64_t)ts.tv_nsec, 8, be);
    } else {
        putn(img, (uint64_t)(uint32_t)(int32_t)ts.tv_sec, 4, be);
        putn(img + 4, (uint64_t)(uint32_t)(int32_t)ts.tv_nsec, 4, be);
    }
    if (mips_sc_copyout(ctx, ts_va, img, n) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

/* clock_nanosleep with the true 4-arg ABI (clk, flags, req, rem)
 * (N64 5224 / N32 6228, N32 time64 6407). */
int64_t mips_sc_clock_nanosleep(mips64_ctx_t *ctx, uint64_t clk,
                                uint64_t flags, uint64_t req_va,
                                uint64_t rem_va, int is64)
{
    struct timespec rq;
    struct timespec rm;
    struct timespec *remp = NULL;
    uint8_t *p;
    int64_t rc;
    int be;
    int saved_err;

    if ((flags & ~(uint64_t)TIMER_ABSTIME) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    p = guest_range(ctx, req_va, is64 ? 16U : 8U, 0);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    be = ctx->is_be != 0U;
    if (is64) {
        rq.tv_sec = (time_t)getn(p, 8, be);
        rq.tv_nsec = (long)getn(p + 8, 8, be);
    } else {
        rq.tv_sec = (time_t)(int32_t)getn(p, 4, be);
        rq.tv_nsec = (long)(int32_t)getn(p + 4, 4, be);
    }
    if (rem_va != 0U) {
        if (!mips_mem_ok(ctx, rem_va, is64 ? 16U : 8U,
                         (uint32_t)MIPS_PROT_WRITE)) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        remp = &rm;
    }
    if (rq.tv_nsec < 0 || rq.tv_nsec >= 1000000000L) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    mips_qs_lease_exit(ctx);
#if defined(__linux__)
    rc = (int64_t)clock_nanosleep((clockid_t)(int)clk, (int)flags, &rq,
                                  remp);
    saved_err = (int)rc;
#else
    rc = l2a_clock_sleep_fallback(clk, flags, &rq, remp);
    saved_err = errno;
#endif
    mips_qs_lease_enter(ctx);
    if (rc != 0) {
        rc = -(int64_t)saved_err;
        if (remp != NULL && saved_err == EINTR &&
            (flags & (uint64_t)TIMER_ABSTIME) == 0U) {
            uint8_t img[16];

            if (is64) {
                putn(img, (uint64_t)(int64_t)remp->tv_sec, 8, be);
                putn(img + 8, (uint64_t)(int64_t)remp->tv_nsec, 8, be);
            } else {
                putn(img, (uint64_t)(uint32_t)(int32_t)remp->tv_sec,
                     4, be);
                putn(img + 4,
                     (uint64_t)(uint32_t)(int32_t)remp->tv_nsec, 4, be);
            }
            /* Best-effort rem write under sc_lock (R3-1); EINTR
             * stays the result even when the mapping is gone. */
            (void)mips_sc_copyout(ctx, rem_va, img, is64 ? 16U : 8U);
        }
        return l2a_ret(ctx, rc);
    }
    return l2a_ret(ctx, 0);
}

/* R5 canonical names (M64-R5-1/10). */
int64_t mips_sys_clock_nanosleep4(mips64_ctx_t *ctx, uint64_t clk,
    uint64_t flags, uint64_t req_va, uint64_t rem_va, int is_time64)
{
    return mips_sc_clock_nanosleep(ctx, clk, flags, req_va, rem_va,
        is_time64);
}
int64_t mips_sys_clock_getres(mips64_ctx_t *ctx, uint64_t clk,
    uint64_t res_va, int is64)
{
    return mips_sc_clock_getres(ctx, clk, res_va, is64);
}
