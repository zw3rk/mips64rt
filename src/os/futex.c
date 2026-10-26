/*
 * src/os/futex.c — Guest futex(2) over host futex(2) (lane L4b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 lane L4b: FUTEX_WAIT/WAKE/BITSET/REQUEUE_CMP (+_PRIVATE) on
 * guest-shared memory. Guest VAs translate to host VAs through the
 * Phase 1 reservation (guest_base + va, shared by every host thread by
 * construction), so the host futex(2) implements the queueing with
 * identical arch-independent op numbers; FUTEX_WAKE_OP and the
 * TID-addressed ops (LOCK_PI/UNLOCK_PI/TRYLOCK_PI/WAIT_REQUEUE_PI/
 * CMP_REQUEUE_PI, FUTEX_FD) return -ENOSYS. N32 truncates every pointer
 * argument to 32 bits (the frozen N32 pointer rule).
 *
 * Raw slot convention (matches Linux futex(2)): the timeout_va slot is
 * a guest timespec pointer for WAIT/WAIT_BITSET (NULL = infinite), is
 * ignored for WAKE/WAKE_BITSET/REQUEUE, and is an integer requeue count
 * for CMP_REQUEUE; val3 is the expected value for CMP_REQUEUE and the
 * bitset for WAIT_BITSET/WAKE_BITSET.
 *
 * Limitation: N32 futex_time64 (64-bit timespec on the 32-bit-pointer
 * ABI) is out of scope for this seam; N32 reads the classic 8-byte
 * {sec, nsec} timespec.
 */

#define _GNU_SOURCE

#include "core/cpu.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Guest futex ops (Linux arch-independent values, shared by MIPS64). */
#define L4F_WAIT 0U
#define L4F_WAKE 1U
#define L4F_FD 2U
#define L4F_REQUEUE 3U
#define L4F_CMP_REQUEUE 4U
#define L4F_WAKE_OP 5U
#define L4F_LOCK_PI 6U
#define L4F_UNLOCK_PI 7U
#define L4F_TRYLOCK_PI 8U
#define L4F_WAIT_BITSET 9U
#define L4F_WAKE_BITSET 10U
#define L4F_WAIT_REQUEUE_PI 11U
#define L4F_CMP_REQUEUE_PI 12U
#define L4F_PRIVATE_FLAG 128U
#define L4F_CLOCK_REALTIME 256U
#define L4F_FLAG_BITS (L4F_PRIVATE_FLAG | L4F_CLOCK_REALTIME)

/* Shared helpers owned by sibling files (same pattern as
 * src/os/syscalls_sync.c): the $a3 return convention + endian-aware
 * field load (syscalls.c) and the validated guest window (mem.c). */
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

/* N32 carries 32-bit pointers: truncate to the low word (N64 VAs use
 * the full 64 bits). */
static uint64_t l4f_trunc_va(const mips64_ctx_t *ctx, uint64_t va)
{
    if (ctx->is_n32 != 0U) {
        return va & UINT64_C(0xFFFFFFFF);
    }
    return va;
}

/* Darwin futex table: __ulock_wait/__ulock_wake are private SPI
 * (no SDK headers) and their wake-count semantics proved
 * unreliable under probing (single wakes landing on 0 of 3
 * barrier-synced waiters), so the blocking path rendezvouses on
 * public primitives instead: 64 address-keyed slots with a mutex +
 * condvar each. Broadcast wakes all (a safe superset — futex
 * waiters always re-check), REQUEUE degrades to wake-all on the
 * source (same reason), and a full table degrades to an immediate
 * spurious return (also legal). Guest VAs key the slots; the arena
 * keeps them stable while mapped. */
#if !defined(__linux__) || !defined(SYS_futex)
#define L4F_DARWIN_SLOTS 64u

typedef struct {
    int used;
    uint64_t va;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int waiters;
} l4f_dslot_t;

static l4f_dslot_t l4f_dslots[L4F_DARWIN_SLOTS];

static l4f_dslot_t *l4f_dslot_for(uint64_t va, int create)
{
    size_t i;
    size_t at = (size_t)((va >> 2u) & (uint64_t)(L4F_DARWIN_SLOTS - 1u));

    for (i = 0u; i < L4F_DARWIN_SLOTS; i++) {
        l4f_dslot_t *s = &l4f_dslots[(at + i) & (L4F_DARWIN_SLOTS - 1u)];

        if (s->used != 0 && s->va == va) {
            return s;
        }
        if (s->used == 0) {
            if (!create) {
                return NULL;
            }
            s->used = 1;
            s->va = va;
            s->waiters = 0;
            (void)pthread_mutex_init(&s->mu, NULL);
            (void)pthread_cond_init(&s->cv, NULL);
            return s;
        }
    }
    return NULL;
}

/* Absolute REALTIME deadline for cond_timedwait from a relative
 * span (WAIT) or an absolute stamp on either clock (WAIT_BITSET:
 * hop bit 0x100 selects REALTIME, otherwise MONOTONIC). */
static void l4f_deadline(const struct timespec *rel_or_abs, int is_abs,
                         int realtime, struct timespec *out)
{
    struct timespec now;

    if (!is_abs) {
        (void)clock_gettime(CLOCK_REALTIME, &now);
        out->tv_sec = now.tv_sec + rel_or_abs->tv_sec;
        out->tv_nsec = now.tv_nsec + rel_or_abs->tv_nsec;
    } else if (realtime) {
        *out = *rel_or_abs;
    } else {
        struct timespec mono;

        (void)clock_gettime(CLOCK_MONOTONIC, &mono);
        out->tv_sec = rel_or_abs->tv_sec - mono.tv_sec;
        out->tv_nsec = rel_or_abs->tv_nsec - mono.tv_nsec;
        (void)clock_gettime(CLOCK_REALTIME, &now);
        out->tv_sec += now.tv_sec;
        out->tv_nsec += now.tv_nsec;
    }
    while (out->tv_nsec >= 1000000000L) {
        out->tv_sec++;
        out->tv_nsec -= 1000000000L;
    }
    while (out->tv_nsec < 0L) {
        out->tv_sec--;
        out->tv_nsec += 1000000000L;
    }
}

/* Raw word without endian handling (the table rechecks raw
 * against raw: the dispatch already validated the logical value). */
static uint32_t l4f_word_raw(uint32_t *hp)
{
    uint32_t v;

    (void)memcpy(&v, hp, sizeof v);
    return v;
}

static long l4f_darwin_wait(uint64_t va, uint32_t *hp, uint32_t val,
                            int be,
                            const struct timespec *to, int is_abs,
                            int realtime)
{
    l4f_dslot_t *s = l4f_dslot_for(va, 1);
    struct timespec dl;
    int have_dl = 0;
    int rc;

    if (s == NULL) {
        return 0;
    }
    if (to != NULL) {
        l4f_deadline(to, is_abs, realtime, &dl);
        have_dl = 1;
    }
    (void)pthread_mutex_lock(&s->mu);
    /* Check-and-queue atomically under the slot lock (the kernel
     * does the same under its bucket lock): a broadcast racing this
     * wait either lands before the check (value already changed) or
     * wakes the queued sleep. No lost wakeups. */
    if ((uint32_t)getn((const uint8_t *)hp, 4U, be) != val) {
        (void)pthread_mutex_unlock(&s->mu);
        errno = EAGAIN;
        return -1;
    }
    s->waiters++;
    if (have_dl) {
        rc = pthread_cond_timedwait(&s->cv, &s->mu, &dl);
    } else {
        rc = pthread_cond_wait(&s->cv, &s->mu);
    }
    s->waiters--;
    (void)pthread_mutex_unlock(&s->mu);
    /* A wakeup always finishes the wait like the kernel primitive:
     * the caller re-checks the word and re-waits on spurious
     * wakeups (standard futex protocol). */
    if (rc == ETIMEDOUT) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

static long l4f_darwin_wake(uint64_t va, int nr)
{
    l4f_dslot_t *s = l4f_dslot_for(va, 0);
    long n;

    if (s == NULL || nr <= 0) {
        return 0;
    }
    (void)pthread_mutex_lock(&s->mu);
    n = (long)(s->waiters < nr ? s->waiters : nr);
    if (n > 0) {
        (void)pthread_cond_broadcast(&s->cv);
    }
    (void)pthread_mutex_unlock(&s->mu);
    return n;
}

static long l4f_darwin(uint32_t *uaddr, uint64_t va, int op, int val,
                       int be, const struct timespec *timeout, int is_abs,
                       int realtime, uint32_t *uaddr2, uint64_t va2,
                       int req_nr, int check_exp, uint32_t expected)
{
    int base = op & 0x7F;

    (void)uaddr2;
    (void)va2;
    if (base == L4F_WAIT || base == L4F_WAIT_BITSET) {
        return l4f_darwin_wait(va, uaddr, (uint32_t)val, be, timeout,
                               is_abs, realtime);
    }
    if (base == L4F_WAKE || base == L4F_WAKE_BITSET) {
        return l4f_darwin_wake(va, val);
    }
    /* REQUEUE / CMP_REQUEUE degrade to wake-all on the source (the
     * guest protocol always re-waits, so moved waiters still make
     * progress; see the table comment). */
    if (check_exp && l4f_word_raw(uaddr) != expected) {
        errno = EAGAIN;
        return -1;
    }
    return l4f_darwin_wake(va, req_nr > 0 ? req_nr : INT_MAX);
}
#endif

/* Host futex(2) once: every op number is arch-independent, so the
 * masked guest op passes through unchanged. Non-Linux hosts queue
 * on the Darwin table above. */
#if defined(__linux__) && defined(SYS_futex)
static long l4f_host(uint32_t *uaddr, int op, int val,
                     const struct timespec *timeout, uint32_t *uaddr2,
                     uint32_t val3)
{
    return syscall((long)SYS_futex, uaddr, op, val, timeout, uaddr2,
                   val3);
}
#endif

/* Current 32-bit futex word (caller validated the mapping). */
static uint32_t l4f_word(const mips64_ctx_t *ctx, uint32_t *hp)
{
    return (uint32_t)getn((const uint8_t *)hp, 4U, ctx->is_be != 0U);
}

/*
 * Read a guest timespec at va into host form. N64: 16-byte {tv_sec,
 * tv_nsec} longs; N32: 8-byte {sec, nsec} ints (classic 32-bit
 * time_t). Returns 0, -EFAULT on a bad window, -EINVAL on a bad
 * value (negative sec, nsec out of range).
 */
static int l4f_timeout(const mips64_ctx_t *ctx, uint64_t va,
                       struct timespec *out)
{
    const uint8_t *p;
    int64_t sec;
    int64_t nsec;
    int be = ctx->is_be != 0U;

    if (ctx->is_n32 != 0U) {
        if (!mips_mem_ok(ctx, va, 8U, (uint32_t)MIPS_PROT_READ)) {
            return -EFAULT;
        }
        p = (const uint8_t *)mips64_guest_ptr(ctx, va);
        sec = (int64_t)(int32_t)getn(p, 4U, be);
        nsec = (int64_t)(int32_t)getn(p + 4U, 4U, be);
    } else {
        if (!mips_mem_ok(ctx, va, 16U, (uint32_t)MIPS_PROT_READ)) {
            return -EFAULT;
        }
        p = (const uint8_t *)mips64_guest_ptr(ctx, va);
        sec = (int64_t)getn(p, 8U, be);
        nsec = (int64_t)getn(p + 8U, 8U, be);
    }
    if (sec < 0 || nsec < 0 || nsec >= 1000000000L) {
        return -EINVAL;
    }
    out->tv_sec = (time_t)sec;
    out->tv_nsec = (long)nsec;
    return 0;
}

/*
 * Full futex dispatch (phase-4.md seam). Returns the wake count (or 0)
 * with the guest $a3 convention, or a negative Linux errno: -EAGAIN
 * on value mismatch, -ETIMEDOUT on expiry, -EINVAL/-EFAULT on bad
 * args/addresses, -ENOSYS for unimplemented ops.
 */
int64_t mips_futex_op(mips64_ctx_t *ctx, uint64_t uaddr, uint64_t op,
                      uint64_t val, uint64_t timeout_va, uint64_t uaddr2,
                      uint64_t val3)
{
    uint64_t base;
    uint32_t *hp;
    long rc;
    int hop;

    if (ctx == NULL) {
        return -(int64_t)EINVAL;
    }
    uaddr = l4f_trunc_va(ctx, uaddr);
    uaddr2 = l4f_trunc_va(ctx, uaddr2);
    timeout_va = l4f_trunc_va(ctx, timeout_va);
    /* Only the base op + PRIVATE/REALTIME bits are defined; anything
     * above bit 8 is -EINVAL, unimplemented base ops are -ENOSYS. */
    if ((op & ~(uint64_t)0x1FFU) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    base = op & (uint64_t)0x7FU;
    switch (base) {
    case L4F_WAIT:
    case L4F_WAKE:
    case L4F_REQUEUE:
    case L4F_CMP_REQUEUE:
    case L4F_WAIT_BITSET:
    case L4F_WAKE_BITSET:
        break;
    default:
        /* FUTEX_FD, FUTEX_WAKE_OP, and every TID-addressed PI op. */
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    if ((uaddr & 3U) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (!mips_mem_ok(ctx, uaddr, 4U, (uint32_t)MIPS_PROT_READ)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    hp = (uint32_t *)mips64_guest_ptr(ctx, uaddr);
    hop = (int)(op & (uint64_t)0x1FFU);
    if (base == L4F_WAIT || base == L4F_WAIT_BITSET) {
        struct timespec to;
        const struct timespec *top = NULL;
        int trc;

        if (l4f_word(ctx, hp) != (uint32_t)val) {
            return l2a_ret(ctx, -(int64_t)EAGAIN);
        }
        if (timeout_va != 0U) {
            trc = l4f_timeout(ctx, timeout_va, &to);
            if (trc != 0) {
                return l2a_ret(ctx, (int64_t)trc);
            }
            top = &to;
        }
#if defined(__linux__) && defined(SYS_futex)
        rc = l4f_host(hp, hop, (int)(uint32_t)val, top, NULL,
                      (uint32_t)val3);
#else
        /* WAIT takes a relative span, WAIT_BITSET an absolute stamp
         * (hop bit 0x100 selects the REALTIME clock). */
        rc = l4f_darwin(hp, uaddr, hop, (int)(uint32_t)val,
                        ctx->is_be != 0, top,
                        base == L4F_WAIT_BITSET ? 1 : 0,
                        (hop & 0x100) != 0 ? 1 : 0, NULL, 0U, 0, 0,
                        0u);
#endif
        if (rc < 0L) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        return l2a_ret(ctx, (int64_t)rc);
    }
    if (base == L4F_WAKE || base == L4F_WAKE_BITSET) {
        int nr;

        if (val > (uint64_t)INT_MAX) {
            nr = INT_MAX;
        } else {
            nr = (int)(uint32_t)val;
        }
#if defined(__linux__) && defined(SYS_futex)
        rc = l4f_host(hp, hop, nr, NULL, NULL, (uint32_t)val3);
#else
        rc = l4f_darwin(hp, uaddr, hop, nr, ctx->is_be != 0, NULL, 0,
                        0, NULL, 0U, 0, 0, 0u);
#endif
        if (rc < 0L) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        return l2a_ret(ctx, (int64_t)rc);
    }
    /* REQUEUE / CMP_REQUEUE: val is the wake count, val3 the requeue
     * count (REQUEUE) or the expected word value (CMP_REQUEUE); the
     * timeout slot carries the integer requeue count for CMP_REQUEUE
     * (same slot the raw syscall reinterprets). */
    {
        uint32_t *hp2;
        const struct timespec *nrq = NULL;

        if (val > (uint64_t)INT_MAX || val3 > (uint64_t)INT_MAX) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        if (base == L4F_CMP_REQUEUE) {
            if (timeout_va > (uint64_t)INT_MAX) {
                return l2a_ret(ctx, -(int64_t)EINVAL);
            }
            nrq = (const struct timespec *)(uintptr_t)timeout_va;
        }
        if ((uaddr2 & 3U) != 0U) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        if (!mips_mem_ok(ctx, uaddr2, 4U, (uint32_t)MIPS_PROT_READ)) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        hp2 = (uint32_t *)mips64_guest_ptr(ctx, uaddr2);
#if defined(__linux__) && defined(SYS_futex)
        rc = l4f_host(hp, hop, (int)(uint32_t)val, nrq, hp2,
                      (uint32_t)val3);
#else
        /* REQUEUE/CMP_REQUEUE degrade to wake-all on the source;
         * req_nr is val3 (REQUEUE) or the integer timeout_va slot
         * (CMP_REQUEUE, already range-checked); CMP_REQUEUE also
         * checks the expected word. */
        (void)nrq;
        rc = l4f_darwin(hp, uaddr, hop, (int)(uint32_t)val,
                        ctx->is_be != 0, NULL, 0,
                        0, hp2, uaddr2,
                        base == L4F_CMP_REQUEUE ? (int)(uint32_t)timeout_va :
                                                  (int)(uint32_t)val3,
                        base == L4F_CMP_REQUEUE ? 1 : 0,
                        (uint32_t)val3);
#endif
        if (rc < 0L) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        return l2a_ret(ctx, (int64_t)rc);
    }
}
