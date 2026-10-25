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

/* Host futex(2) once: every op number is arch-independent, so the
 * masked guest op passes through unchanged. Non-Linux hosts cannot
 * queue; they report -ENOSYS for the blocking path. */
static long l4f_host(uint32_t *uaddr, int op, int val,
                     const struct timespec *timeout, uint32_t *uaddr2,
                     uint32_t val3)
{
#if defined(__linux__) && defined(SYS_futex)
    return syscall((long)SYS_futex, uaddr, op, val, timeout, uaddr2,
                   val3);
#else
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout;
    (void)uaddr2;
    (void)val3;
    errno = ENOSYS;
    return -1;
#endif
}

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
        rc = l4f_host(hp, hop, (int)(uint32_t)val, top, NULL,
                      (uint32_t)val3);
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
        rc = l4f_host(hp, hop, nr, NULL, NULL, (uint32_t)val3);
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
        rc = l4f_host(hp, hop, (int)(uint32_t)val, nrq, hp2,
                      (uint32_t)val3);
        if (rc < 0L) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        return l2a_ret(ctx, (int64_t)rc);
    }
}
