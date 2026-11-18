/*
 * src/os/syscalls_poll.c — poll/ppoll/select/pselect6 (T14 userland
 * qualification; split from syscalls_misc.c for the line ceiling).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * struct pollfd, fd_set, and the MIPS POLL* bits are translated here;
 * guest memory is staged on the host and committed with
 * mips_sc_copyout. Blocking waits drop the dispatch lease.
 *
 * N32 notes: _newselect/pselect6/ppoll take the 8-byte compat pair
 * (two int32, like the N32 timespec in syscalls_time.c), and fd_set
 * is an array of 32-bit words, so both ABIs use a 4-byte stride on
 * N32 (64-bit words would swap fd 0..31 with fd 32..63 on N32 BE).
 * Under __linux__ the MIPS POLLWRNORM (0x004, aliases POLLOUT) and
 * POLLWRBAND (0x100) are translated to the generic 0x100/0x200 and
 * back (Darwin already uses the MIPS values).
 *
 * A deliverable guest SIGCHLD never hides ready fds: when the wait
 * pre-check reports a pending deliverable signal, one zero-timeout
 * host probe runs first and its ready count wins over EINTR. A host
 * EINTR with no deliverable guest signal behind it re-enters the
 * wait against a monotonic deadline instead of surfacing.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/errno_map.h"
#include "os/signal_core.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

#define POLL_NFDS_MAX 65536U
#define POLL_NSEC_PER_SEC 1000000000L
#define POLL_USEC_PER_SEC 1000000L
#define POLL_MS_CAP 2000000000

/* Host side of a blocking select/poll once the host SIGCHLD bridge is
 * armed: host SIGCHLD stays blocked across the pre-check and is
 * unblocked only inside the atomic host pselect/ppoll (when the guest
 * mask in ctx->sig_blocked leaves SIGCHLD deliverable), so a child exit
 * landing between check and sleep still interrupts the sleep. */
typedef struct {
    sigset_t hold;
    sigset_t wait;
    int active;
} poll_wait_t;

/* Returns 1 when a handled signal is already deliverable under the
 * current guest mask: the wait must end with EINTR without sleeping.
 * The deliverable pre-check always runs (a software-pending signal
 * unblocked by a temporary mask has no host-side event); only the
 * host SIGCHLD mask dance is gated on the armed bridge. */
static int poll_wait_begin(mips64_ctx_t *ctx, poll_wait_t *w)
{
    sigset_t chld;
    uint64_t bit = UINT64_C(1) << (MIPS64_SIGCHLD - 1);

    w->active = 0;
    if (mips64_host_sigchld_armed()) {
        (void)sigemptyset(&chld);
        (void)sigaddset(&chld, SIGCHLD);
        if (pthread_sigmask(SIG_BLOCK, &chld, &w->hold) != 0) {
            return mips64_sig_deliverable(ctx, ctx->sig_blocked);
        }
        w->active = 1;
        w->wait = w->hold;
        if ((ctx->sig_blocked[0] & bit) == 0U) {
            (void)sigdelset(&w->wait, SIGCHLD);
        }
        mips64_host_sigchld_poll(ctx);
    }
    return mips64_sig_deliverable(ctx, ctx->sig_blocked);
}

static void poll_wait_end(poll_wait_t *w)
{
    if (w->active) {
        (void)pthread_sigmask(SIG_SETMASK, &w->hold, NULL);
    }
}

static struct timespec poll_ms_ts(int ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    return ts;
}

/* Monotonic milliseconds for wait deadlines. */
static int64_t poll_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000L);
}

/* ppoll where the host has it (Linux); elsewhere the mask swap around
 * poll is not atomic, which only widens the wakeup window. */
static int poll_host_ppoll(struct pollfd *pf, nfds_t nfds, int timeout_ms,
                           const poll_wait_t *w)
{
#if defined(__linux__)
    struct timespec ts = poll_ms_ts(timeout_ms);

    return ppoll(pf, nfds, timeout_ms < 0 ? NULL : &ts,
                 w->active ? &w->wait : NULL);
#else
    int n;
    int e;

    if (w->active) {
        (void)pthread_sigmask(SIG_SETMASK, &w->wait, NULL);
    }
    n = poll(pf, nfds, timeout_ms);
    e = errno;
    if (w->active) {
        (void)pthread_sigmask(SIG_SETMASK, &w->hold, NULL);
    }
    errno = e;
    return n;
#endif
}

/* MIPS <-> Linux-generic poll event bits (only WRBAND differs in
 * value; WRNORM aliases POLLOUT on both, but the host reports it as
 * generic 0x100, which the guest must see as POLLOUT/WRNORM 0x004). */
static short poll_to_host(short e)
{
#if defined(__linux__)
    if ((e & 0x100) != 0) {
        e = (short)((e & ~0x100) | 0x200);
    }
#endif
    return e;
}

static short poll_to_guest(short r)
{
#if defined(__linux__)
    if ((r & 0x100) != 0) {
        r = (short)((r & ~0x100) | 0x004);
    }
    if ((r & 0x200) != 0) {
        r = (short)((r & ~0x200) | 0x100);
    }
#endif
    return r;
}

/* Guest timeout struct to milliseconds; -1 for NULL (block forever).
 * N32 passes the 8-byte compat pair (two int32); N64 two 64-bit words.
 * Negative tv_sec and out-of-range sub-second fields are EINVAL (the
 * kernel rejects them); a positive sub-millisecond timeout rounds up
 * to 1 ms instead of truncating to a non-blocking return. */
static int64_t poll_get_timeout(mips64_ctx_t *ctx, uint64_t va, int is_usec,
                                int *ms)
{
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    int n32 = ctx->is_n32 != 0U;
    int64_t sec;
    int64_t sub;
    int64_t total;

    if (va == 0U) {
        *ms = -1;
        return 0;
    }
    g = guest_range(ctx, va, n32 ? 8U : 16U, 0);
    if (g == NULL) {
        return -(int64_t)EFAULT;
    }
    if (n32) {
        sec = (int64_t)(int32_t)getn(g, 4, be);
        sub = (int64_t)(int32_t)getn(g + 4, 4, be);
    } else {
        sec = (int64_t)getn(g, 8, be);
        sub = (int64_t)getn(g + 8, 8, be);
    }
    if (sec < 0 || sub < 0 ||
        (is_usec ? sub >= (int64_t)POLL_USEC_PER_SEC
                 : sub >= (int64_t)POLL_NSEC_PER_SEC)) {
        return -(int64_t)EINVAL;
    }
    if (sec > 1000000) {
        total = POLL_MS_CAP;
    } else {
        total = sec * 1000 +
                (is_usec ? sub / 1000 : sub / 1000000L);
        if (total > POLL_MS_CAP) {
            total = POLL_MS_CAP;
        } else if (total == 0 && sub > 0) {
            total = 1;
        }
    }
    *ms = (int)total;
    return 0;
}

/* SIGKILL (9) and SIGSTOP (23 on MIPS) can never be blocked. */
#define POLL_UNBLOCKABLE ((UINT64_C(1) << 8) | (UINT64_C(1) << 22))

/* Install the guest's temporary wait mask from set_va (16-byte kernel
 * sigset, N32 as 32-bit words), saving the caller's mask in old. */
static int64_t poll_temp_mask(mips64_ctx_t *ctx, uint64_t set_va,
                              uint64_t old[2])
{
    const uint8_t *p = guest_range(ctx, set_va, 16U, 0);
    int be = ctx->is_be != 0U;

    if (p == NULL) {
        return -(int64_t)EFAULT;
    }
    old[0] = ctx->sig_blocked[0];
    old[1] = ctx->sig_blocked[1];
    if (ctx->is_n32 != 0U) {
        ctx->sig_blocked[0] = getn(p, 4, be) | (getn(p + 4, 4, be) << 32);
        ctx->sig_blocked[1] = getn(p + 8, 4, be) | (getn(p + 12, 4, be)
                                                    << 32);
    } else {
        ctx->sig_blocked[0] = getn(p, 8, be);
        ctx->sig_blocked[1] = getn(p + 8, 8, be);
    }
    ctx->sig_blocked[0] &= ~POLL_UNBLOCKABLE;
    return 0;
}

/* End of a temporary-mask wait (Linux restore_saved_sigmask_unless):
 * on EINTR the caller's mask is parked so the pending handler runs
 * under the wait mask and its frame records the caller's mask for
 * rt_sigreturn; otherwise old is restored at once. */
static void poll_temp_mask_done(mips64_ctx_t *ctx, int64_t rc,
                                const uint64_t old[2])
{
    if (rc == -(int64_t)EINTR) {
        mips64_sig_defer_restore(old);
        return;
    }
    ctx->sig_blocked[0] = old[0];
    ctx->sig_blocked[1] = old[1];
}

/* poll core: fds_va holds nfds {int fd; short events; short revents}.
 * Returns a raw negative errno (or a ready count); the ppoll wrapper
 * and the direct poll entry each apply l2a_ret exactly once. */
int64_t mips_poll_wait(mips64_ctx_t *ctx, uint64_t fds_va, uint64_t nfds,
                       int timeout_ms)
{
    struct pollfd *pf;
    uint8_t *img;
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    int n;
    uint64_t i;
    int64_t ret;
    int64_t deadline = 0;

    if (nfds > POLL_NFDS_MAX) {
        return -(int64_t)EINVAL;
    }
    g = nfds == 0U ? (const uint8_t *)"" : guest_range(ctx, fds_va, nfds * 8U, 0);
    if (g == NULL) {
        return -(int64_t)EFAULT;
    }
    pf = (struct pollfd *)calloc((size_t)nfds + 1U, sizeof *pf);
    img = (uint8_t *)malloc((size_t)nfds * 8U + 1U);
    if (pf == NULL || img == NULL) {
        free(pf);
        free(img);
        return -(int64_t)ENOMEM;
    }
    for (i = 0U; i < nfds; i++) {
        pf[i].fd = (int)(int32_t)getn(g + i * 8U, 4, be);
        pf[i].events = poll_to_host((short)getn(g + i * 8U + 4U, 2, be));
    }
    if (timeout_ms >= 0) {
        deadline = poll_now_ms() + (int64_t)timeout_ms;
    }
    mips_qs_lease_exit(ctx);
    for (;;) {
        poll_wait_t w;
        int wait_ms = timeout_ms;

        if (wait_ms >= 0) {
            wait_ms = (int)(deadline - poll_now_ms());
            if (wait_ms < 0) {
                wait_ms = 0;
            }
        }
        if (poll_wait_begin(ctx, &w)) {
            /* Deliverable signal pending: one zero-timeout probe
             * first, so ready fds report their count instead of
             * EINTR. */
            n = poll_host_ppoll(pf, (nfds_t)nfds, 0, &w);
            if (n <= 0) {
                n = -1;
                errno = EINTR;
            }
            poll_wait_end(&w);
            break;
        }
        n = poll_host_ppoll(pf, (nfds_t)nfds, wait_ms, &w);
        {
            int e = errno;

            poll_wait_end(&w);
            if (n >= 0) {
                break;
            }
            if (e != EINTR) {
                errno = e;
                break;
            }
            /* EINTR: a deliverable guest signal ends the wait;
             * anything else re-enters it against the deadline. */
            errno = e;
            mips64_host_sigchld_poll(ctx);
            if (mips64_sig_deliverable(ctx, ctx->sig_blocked)) {
                n = -1;
                break;
            }
            if (timeout_ms >= 0 &&
                poll_now_ms() >= deadline) {
                n = 0;
                break;
            }
        }
    }
    ret = n < 0 ? -(int64_t)errno : (int64_t)n;
    mips_qs_lease_enter(ctx);
    if (n >= 0) {
        for (i = 0U; i < nfds; i++) {
            putn(img + i * 8U, (uint64_t)(uint32_t)pf[i].fd, 4, be);
            putn(img + i * 8U + 4U,
                 (uint64_t)(uint16_t)poll_to_guest(pf[i].events), 2, be);
            putn(img + i * 8U + 6U,
                 (uint64_t)(uint16_t)poll_to_guest(pf[i].revents), 2, be);
        }
        if (nfds != 0U && mips_sc_copyout(ctx, fds_va, img, nfds * 8U) != 0) {
            ret = -(int64_t)EFAULT;
        }
    }
    free(pf);
    free(img);
    return ret;
}

/* ppoll(fds=a0, nfds=a1, tsp=a2, sigmask=a3, sigsetsize=a4). */
int64_t mips_ppoll_wait(mips64_ctx_t *ctx, uint64_t fds, uint64_t nfds,
                        uint64_t ts_va, uint64_t set_va, uint64_t setsize)
{
    int ms;
    uint64_t old[2];
    int64_t rc = poll_get_timeout(ctx, ts_va, 0, &ms);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if (set_va == 0U) {
        return l2a_ret(ctx, mips_poll_wait(ctx, fds, nfds, ms));
    }
    if (setsize != 16U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    rc = poll_temp_mask(ctx, set_va, old);
    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    /* Raw rc reaches the temporary-mask verdict (a raw -EINTR parks
     * the caller's mask); l2a_ret runs exactly once, here. */
    rc = mips_poll_wait(ctx, fds, nfds, ms);
    poll_temp_mask_done(ctx, rc, old);
    return l2a_ret(ctx, rc);
}

/* select/pselect6 share one body; the three bitmaps stage on the
 * host. A pselect6 mask is already installed in ctx->sig_blocked.
 * Returns a raw negative errno (or a ready count); the pselect6
 * wrapper and the direct select entry each apply l2a_ret once. */
int64_t mips_select_wait(mips64_ctx_t *ctx, uint64_t nfds, uint64_t r_va,
                         uint64_t w_va, uint64_t e_va, uint64_t t_va,
                         int is_usec)
{
    fd_set sets[3];
    uint64_t va[3];
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    int ws = ctx->is_n32 != 0U ? 4 : 8;
    int ms;
    int64_t rc;
    int i;
    int n;
    int64_t deadline = 0;
    uint64_t nbytes;
    uint8_t out[sizeof(fd_set)];

    if (nfds > FD_SETSIZE) {
        return -(int64_t)EINVAL;
    }
    va[0] = r_va;
    va[1] = w_va;
    va[2] = e_va;
    nbytes = ((nfds + (uint64_t)ws * 8U - 1U) / ((uint64_t)ws * 8U)) *
             (uint64_t)ws;
    rc = poll_get_timeout(ctx, t_va, is_usec, &ms);
    if (rc < 0) {
        return rc;
    }
    for (i = 0; i < 3; i++) {
        uint64_t w;

        FD_ZERO(&sets[i]);
        if (va[i] == 0U) {
            continue;
        }
        g = guest_range(ctx, va[i], nbytes, 0);
        if (g == NULL) {
            return -(int64_t)EFAULT;
        }
        for (w = 0U; w < nbytes / (uint64_t)ws; w++) {
            uint64_t word = getn(g + w * (uint64_t)ws, (unsigned)ws, be);
            unsigned b;

            for (b = 0U; b < (unsigned)ws * 8U; b++) {
                if (((word >> b) & 1U) != 0U &&
                    w * (uint64_t)ws * 8U + b < nfds) {
                    FD_SET((int)(w * (uint64_t)ws * 8U + b), &sets[i]);
                }
            }
        }
    }
    if (ms >= 0) {
        deadline = poll_now_ms() + (int64_t)ms;
    }
    mips_qs_lease_exit(ctx);
    for (;;) {
        poll_wait_t wt;
        struct timespec ts;
        struct timespec *tsp;
        int cur = ms;

        if (cur >= 0) {
            cur = (int)(deadline - poll_now_ms());
            if (cur < 0) {
                cur = 0;
            }
            ts = poll_ms_ts(cur);
            tsp = &ts;
        } else {
            tsp = NULL;
        }
        if (poll_wait_begin(ctx, &wt)) {
            /* Deliverable signal pending: probe readiness at
             * zero timeout before reporting EINTR. */
            struct timespec zero = { 0, 0 };

            n = pselect((int)nfds, va[0] ? &sets[0] : NULL,
                        va[1] ? &sets[1] : NULL, va[2] ? &sets[2] : NULL,
                        &zero, NULL);
            if (n <= 0) {
                n = -1;
                errno = EINTR;
            } else {
                errno = 0;
            }
            poll_wait_end(&wt);
            break;
        }
        n = pselect((int)nfds, va[0] ? &sets[0] : NULL,
                    va[1] ? &sets[1] : NULL, va[2] ? &sets[2] : NULL,
                    tsp, wt.active ? &wt.wait : NULL);
        {
            int e = errno;

            poll_wait_end(&wt);
            if (n >= 0) {
                break;
            }
            if (e != EINTR) {
                errno = e;
                break;
            }
            errno = e;
            mips64_host_sigchld_poll(ctx);
            if (mips64_sig_deliverable(ctx, ctx->sig_blocked)) {
                n = -1;
                break;
            }
            if (ms >= 0 && poll_now_ms() >= deadline) {
                n = 0;
                break;
            }
        }
    }
    {
        int e = n < 0 ? errno : 0;

        mips_qs_lease_enter(ctx);
        if (n < 0) {
            return -(int64_t)e;
        }
    }
    if (n == 0) {
        /* Timeout (including the EINTR-retry-then-deadline path, where
         * the host leaves the sets unspecified): Linux reports zeroed
         * sets alongside the zero count, not the stale input bits. */
        FD_ZERO(&sets[0]);
        FD_ZERO(&sets[1]);
        FD_ZERO(&sets[2]);
    }
    for (i = 0; i < 3; i++) {
        uint64_t w;

        if (va[i] == 0U) {
            continue;
        }
        memset(out, 0, sizeof out);
        for (w = 0U; w < nfds; w++) {
            if (FD_ISSET((int)w, &sets[i])) {
                uint64_t wi = w / ((uint64_t)ws * 8U);
                uint64_t word =
                    getn(out + wi * (uint64_t)ws, (unsigned)ws, be);

                word |= (uint64_t)1U << (w % ((uint64_t)ws * 8U));
                putn(out + wi * (uint64_t)ws, word, (unsigned)ws, be);
            }
        }
        if (mips_sc_copyout(ctx, va[i], out, nbytes) != 0) {
            return -(int64_t)EFAULT;
        }
    }
    return (int64_t)n;
}

/* pselect6: a5 points at {sigset_ptr, sigsetsize}. The guest mask is
 * emulated in ctx->sig_blocked (the host mask stays untouched apart
 * from the SIGCHLD bridge, so translator-reserved signals such as
 * SIGUSR2/SIGSEGV remain live); SIGKILL/SIGSTOP are stripped. */
int64_t mips_pselect6_wait(mips64_ctx_t *ctx, uint64_t nfds, uint64_t r,
                           uint64_t w, uint64_t e, uint64_t ts_va)
{
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    int n32 = ctx->is_n32 != 0U;
    int ws = n32 ? 4 : 8;
    uint64_t arg_va = ctx->gpr[9];
    uint64_t set_va;
    uint64_t old[2];
    int64_t rc;

    if (arg_va == 0U) {
        return l2a_ret(ctx, mips_select_wait(ctx, nfds, r, w, e, ts_va,
                                            0));
    }
    g = guest_range(ctx, arg_va, (uint64_t)ws * 2U, 0);
    if (g == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    set_va = getn(g, ws, be);
    if (set_va == 0U) {
        return l2a_ret(ctx, mips_select_wait(ctx, nfds, r, w, e, ts_va,
                                            0));
    }
    if (getn(g + ws, ws, be) != 16U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    rc = poll_temp_mask(ctx, set_va, old);
    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    /* Raw rc reaches the temporary-mask verdict (a raw -EINTR parks
     * the caller's mask); l2a_ret runs exactly once, here. */
    rc = mips_select_wait(ctx, nfds, r, w, e, ts_va, 0);
    poll_temp_mask_done(ctx, rc, old);
    return l2a_ret(ctx, rc);
}
