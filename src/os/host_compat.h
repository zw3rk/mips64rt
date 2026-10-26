/*
 * src/os/host_compat.h — Non-Linux host fallbacks for the L2a syscall
 * layer (lane U12).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The translator targets AArch64 Linux; `build-darwin` compiles the
 * same TU list with the host compiler so the macOS dev loop keeps
 * type-checking the whole tree. Linux-only facilities get a small,
 * honest fallback here (flag declined, `-ENOSYS`, or a same-shape
 * libc loop). Guest execution on macOS stays unsupported: anything
 * the host cannot honor fails with `-EINVAL`/`-ENOSYS` instead of
 * silently changing semantics. Curated C11 only.
 */

#ifndef MIPS64RT_OS_HOST_COMPAT_H
#define MIPS64RT_OS_HOST_COMPAT_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__)
#include <sys/random.h>
#else
#include <sys/syscall.h>
#endif

/* linux/time.h value (arch-independent); macOS has no clock_nanosleep
 * at all, so the flag only matters where the Linux call compiles. */
#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

/* The five helpers below only exist off Linux (their call sites
 * are the `#else` of `#if defined(__linux__)`), so they are compiled
 * out where the direct syscalls exist. */
#if !defined(__linux__)

/* dup2 plus FD_CLOEXEC (stands in for dup3(2)). Returns the new fd
 * or -1 with errno set. */
static int l2a_dup_cloexec(int oldfd, int newfd, int cloexec)
{
    int rc = dup2(oldfd, newfd);

    if (rc >= 0 && cloexec != 0 && fcntl(rc, F_SETFD, FD_CLOEXEC) != 0) {
        return -1;
    }
    return rc;
}

/* pipe(2) plus fcntl for O_CLOEXEC/O_NONBLOCK (stands in for
 * pipe2(2)). `hflags` carries only those two bits; anything else was
 * declined by the caller. Returns 0 or -1 with errno set. */
static int l2a_pipe_flags(int fds[2], int hflags)
{
    if (pipe(fds) != 0) {
        return -1;
    }
    if ((hflags & O_CLOEXEC) != 0 &&
        (fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 ||
         fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0)) {
        return -1;
    }
    if ((hflags & O_NONBLOCK) != 0 &&
        (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
         fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0)) {
        return -1;
    }
    return 0;
}

/* Linear close over [first, last] (stands in for close_range(2)).
 * EBADF holes are skipped; the first other errno wins. Returns 0 or
 * -(errno). Compiled wherever the direct call is unavailable. */
#if !defined(__linux__) || !defined(SYS_close_range)
static int64_t l2a_close_range_loop(uint64_t first, uint64_t last)
{
    uint64_t f;
    int64_t rc = 0;

    for (f = first; f <= last; f++) {
        if (close((int)f) != 0 && errno != EBADF && rc == 0) {
            rc = -(int64_t)errno;
        }
    }
    return rc;
}
#endif /* close_range loop wherever SYS_close_range is unavailable. */

/* getentropy(2) stream over `len` bytes (stands in for getrandom(2);
 * getentropy caps at 256 bytes per call). Returns (int64_t)len or
 * -(errno). */
static int64_t l2a_getentropy_fill(uint8_t *p, size_t len)
{
    size_t off = 0u;

    while (off < len) {
        size_t chunk = len - off > 256u ? 256u : len - off;

        if (getentropy(p + off, chunk) != 0) {
            return -(int64_t)errno;
        }
        off += chunk;
    }
    return (int64_t)len;
}

/* Relative CLOCK_REALTIME sleep via nanosleep(2) (stands in for
 * clock_nanosleep(2)). Absolute sleeps and other clocks are -EINVAL.
 * Returns the raw nanosleep result (0/-1 with errno set). */
static int64_t l2a_clock_sleep_fallback(uint64_t clk, uint64_t flags,
                                        const struct timespec *rq,
                                        struct timespec *remp)
{
    if (flags != 0U || (clockid_t)(int)clk != CLOCK_REALTIME) {
        errno = EINVAL;
        return -1;
    }
    return (int64_t)nanosleep(rq, remp);
}
#endif /* !defined(__linux__): the five pure fallbacks above. */

/* Linux uapi GRND bits (asm-generic/unistd.h): NONBLOCK=1, RANDOM=2,
 * INSECURE=4. The fallback honors none of the modes. */
#define L2A_GRND_KNOWN_MASK 0x07U

/* Portable thread id (mirrors src/os/threads.c): the host tid on
 * Linux, the pid elsewhere. */
static int64_t l2a_host_tid(void)
{
#if defined(__linux__) && defined(SYS_gettid)
    return (int64_t)gettid();
#else
    return (int64_t)getpid();
#endif
}

/* close_range(2) where it exists, linear close elsewhere (any flag is
 * declined off Linux: CLOEXEC/UNSHARE cannot be honored). Returns the
 * l2a_ret-ready value (0/rc or -(errno)). */
static int64_t l2a_close_range_host(uint64_t first, uint64_t last,
                                    uint64_t flags)
{
#if defined(__linux__) && defined(SYS_close_range)
    long rc = syscall(SYS_close_range, (unsigned)first, (unsigned)last,
                      (unsigned)flags);

    if (rc < 0) {
        return -(int64_t)errno;
    }
    return (int64_t)rc;
#else
    if (flags != 0U) {
        return -(int64_t)EINVAL;
    }
    return l2a_close_range_loop(first, last);
#endif
}

/* getdents64(2) where it exists, -ENOSYS elsewhere (mirrors
 * src/os/futex.c: the blocking path reports -ENOSYS off Linux).
 * Returns the byte count or -1 with errno set. */
static long l2a_getdents64_host(int fd, uint8_t *p, size_t count)
{
#if defined(__linux__) && defined(SYS_getdents64)
    return syscall(SYS_getdents64, fd, p, count);
#else
    (void)fd;
    (void)p;
    (void)count;
    errno = ENOSYS;
    return -1;
#endif
}

#endif /* MIPS64RT_OS_HOST_COMPAT_H */
