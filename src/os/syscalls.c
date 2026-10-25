/*
 * src/os/syscalls.c — Static-libc syscall layer, core (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared helpers (guest $a3 convention, endian-aware field access,
 * validated guest windows, MIPS open-flag translation) plus the
 * descriptor/path/identity handlers: openat, fcntl, ioctl (verbatim
 * passthrough), lseek, dup/dup2/dup3, pipe2, access/faccessat,
 * readlinkat, unlinkat, close_range, the getpid/getppid/getuid/getgid
 * identity family, getrandom, and getdents64. Sibling files hold the
 * stat family (syscalls_stat.c), the clock family (syscalls_time.c),
 * and futex/signal-mask/robust/vectored-I/O (syscalls_sync.c); all are
 * wired through the mips_syscall dispatch in src/os/syscall_min.c.
 *
 * Verified in a debian:stable-slim container against
 * arch/mips/include/uapi/asm/unistd_n64.h / unistd_n32.h with live
 * fills under qemu-mips64el / qemu-mipsn32el 10.0.13. MIPS O_ and F_
 * flag values and the 1/2/3 SIG how values come from arch/mips UAPI
 * asm/fcntl.h and asm/signal.h. Guest byte order goes through
 * putn/getn keyed on ctx->is_be (the host is little-endian). Every
 * range is validated with mips_mem_ok; bad addresses return -EFAULT
 * with $a3=1 (never mips_fault: a bad syscall address is recoverable).
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/syscall_nr.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* linux/close_range.h values (arch-independent); this toolchain's
 * headers predate the macros, so define them when missing. */
#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

/* Guest window check owned by src/os/mem.c. */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

/* MIPS open flags (UAPI asm/fcntl.h). N64 and N32 agree except
 * O_LARGEFILE, which is 0 on N64 and 0x2000 on N32. */
#define MIPS_O_RDONLY    0x000000U
#define MIPS_O_WRONLY    0x000001U
#define MIPS_O_RDWR      0x000002U
#define MIPS_O_ACCMODE   0x000003U
#define MIPS_O_CREAT     0x000100U
#define MIPS_O_EXCL      0x000400U
#define MIPS_O_NOCTTY    0x000800U
#define MIPS_O_TRUNC     0x000200U
#define MIPS_O_APPEND    0x000008U
#define MIPS_O_NONBLOCK  0x000080U
#define MIPS_O_SYNC      0x004010U
#define MIPS_O_DSYNC     0x000010U
#define MIPS_O_DIRECT    0x008000U
#define MIPS_O_LARGEFILE 0x002000U
#define MIPS_O_DIRECTORY 0x010000U
#define MIPS_O_NOFOLLOW  0x020000U
#define MIPS_O_CLOEXEC   0x080000U
#define MIPS_O_NOATIME   0x040000U
#define MIPS_O_PATH      0x200000U
#define MIPS_O_TMPFILE   0x410000U

/* MIPS fcntl commands (UAPI, verified). */
#define MIPS_F_DUPFD         0
#define MIPS_F_GETFD         1
#define MIPS_F_SETFD         2
#define MIPS_F_GETFL         3
#define MIPS_F_SETFL         4
#define MIPS_F_DUPFD_CLOEXEC 1030

/* Selectors for the shared mips_sc_getid / mips_sc_dup entries. */
#define L2A_ID_PID   0
#define L2A_ID_PPID  1
#define L2A_ID_UID   2
#define L2A_ID_EUID  3
#define L2A_ID_GID   4
#define L2A_ID_EGID  5
#define L2A_ID_TID   6
#define L2A_DUP_DUP  0
#define L2A_DUP_DUP2 1
#define L2A_DUP_DUP3 2

#define L2A_PATH_MAX 4096U

/* MIPS errno: shares asm-generic values except ENOSYS (MIPS 89, host
 * 38). Mirrors mips_errno_from_host in src/os/syscall_min.c. */
static int32_t l2a_errno_from_host(int host_errno)
{
    return host_errno == 38 ? 89 : (int32_t)host_errno;
}

/* Record the $a3 convention; return raw host value. Shared with the
 * sibling syscalls_*.c files. */
int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw)
{
    int64_t e;

    if (raw >= 0) {
        ctx->gpr[MIPS64_REG_V0] = (uint64_t)raw;
        ctx->gpr[MIPS64_REG_A3] = 0U;
        return raw;
    }
    e = -raw > 4095 ? 4095 : -raw;
    ctx->gpr[MIPS64_REG_V0] = (uint64_t)l2a_errno_from_host((int)e);
    ctx->gpr[MIPS64_REG_A3] = 1U;
    return raw;
}

/* Alignment-free endian-aware field access (n = 2, 4, or 8). Shared
 * with the sibling syscalls_*.c files. */
void putn(uint8_t *p, uint64_t v, unsigned n, int be)
{
    unsigned i;

    for (i = 0U; i < n; i++) {
        p[be ? n - 1U - i : i] = (uint8_t)(v >> (8U * i));
    }
}

uint64_t getn(const uint8_t *p, unsigned n, int be)
{
    uint64_t v = 0U;
    unsigned i;

    for (i = 0U; i < n; i++) {
        v |= (uint64_t)p[be ? n - 1U - i : i] << (8U * i);
    }
    return v;
}

/* Validated guest window (NULL with len>0 means -EFAULT). Zero length
 * never touches memory. Shared with the sibling syscalls_*.c files. */
uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                     int write)
{
    uint32_t need =
        write ? (uint32_t)MIPS_PROT_WRITE : (uint32_t)MIPS_PROT_READ;

    if (len == 0U) {
        return (uint8_t *)mips64_guest_ptr(ctx, va);
    }
    if (!mips_mem_ok(ctx, va, len, need)) {
        return NULL;
    }
    return (uint8_t *)mips64_guest_ptr(ctx, va);
}

/* NUL-terminated guest string; returns length or -EFAULT/-ENAMETOOLONG.
 * Shared with the sibling syscalls_*.c files. */
int64_t guest_str(mips64_ctx_t *ctx, uint64_t va, char *out)
{
    uint64_t i;

    for (i = 0U; i < L2A_PATH_MAX; i++) {
        uint8_t *p = guest_range(ctx, va + i, 1U, 0);

        if (p == NULL) {
            return -(int64_t)EFAULT;
        }
        out[i] = (char)p[0];
        if (p[0] == 0U) {
            return (int64_t)i;
        }
    }
    return -(int64_t)ENAMETOOLONG;
}

/* Master MIPS -> host open-flag table; each caller passes its allowed
 * subset. O_LARGEFILE is dropped (64-bit host: always largefile). */
static const struct {
    uint64_t mf;
    int hf;
} l2a_oflags[] = {
    { MIPS_O_CREAT, O_CREAT }, { MIPS_O_EXCL, O_EXCL },
    { MIPS_O_NOCTTY, O_NOCTTY }, { MIPS_O_TRUNC, O_TRUNC },
    { MIPS_O_APPEND, O_APPEND }, { MIPS_O_NONBLOCK, O_NONBLOCK },
    { MIPS_O_DIRECT, O_DIRECT }, { MIPS_O_DIRECTORY, O_DIRECTORY },
    { MIPS_O_NOFOLLOW, O_NOFOLLOW }, { MIPS_O_CLOEXEC, O_CLOEXEC },
    { MIPS_O_NOATIME, O_NOATIME }, { MIPS_O_PATH, O_PATH },
    { MIPS_O_TMPFILE, O_TMPFILE },
};

/* Translate mf (masked to allowed) to host flags; -EINVAL on the rest. */
static int64_t map_open_flags(uint64_t mf, uint64_t allowed, int *host_out)
{
    uint64_t known = (uint64_t)(MIPS_O_ACCMODE | MIPS_O_SYNC |
        MIPS_O_DSYNC | MIPS_O_LARGEFILE);
    size_t i;
    int h;

    for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
        known |= l2a_oflags[i].mf;
    }
    if ((mf & ~known) != 0U || (mf & ~allowed) != 0U) {
        return -(int64_t)EINVAL;
    }
    h = (int)(mf & (uint64_t)MIPS_O_ACCMODE);
    if ((mf & (uint64_t)MIPS_O_SYNC) != 0U) {
        h |= O_SYNC;
    } else if ((mf & (uint64_t)MIPS_O_DSYNC) != 0U) {
        h |= O_DSYNC;
    }
    for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
        if ((mf & l2a_oflags[i].mf) != 0U) {
            h |= l2a_oflags[i].hf;
        }
    }
    *host_out = h;
    return 0;
}

#define L2A_OPEN_ALLOWED \
    ((uint64_t)(MIPS_O_ACCMODE | MIPS_O_CREAT | MIPS_O_EXCL | \
                 MIPS_O_NOCTTY | MIPS_O_TRUNC | MIPS_O_APPEND | \
                 MIPS_O_NONBLOCK | MIPS_O_SYNC | MIPS_O_DSYNC | \
                 MIPS_O_DIRECT | MIPS_O_LARGEFILE | MIPS_O_DIRECTORY | \
                 MIPS_O_NOFOLLOW | MIPS_O_CLOEXEC | MIPS_O_NOATIME | \
                 MIPS_O_PATH | MIPS_O_TMPFILE))

int64_t mips_sc_openat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                       uint64_t flags, uint64_t mode)
{
    char path[L2A_PATH_MAX + 1U];
    int64_t rc = guest_str(ctx, path_va, path);
    int hflags;
    int fd;

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    rc = map_open_flags(flags, L2A_OPEN_ALLOWED, &hflags);
    if (rc != 0) {
        return l2a_ret(ctx, rc);
    }
    fd = openat((int)dirfd, path, hflags, (mode_t)(mode & 0777U));
    if (fd < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)fd);
}

int64_t mips_sc_fcntl(mips64_ctx_t *ctx, uint64_t fd, uint64_t cmd,
                      uint64_t arg)
{
    int rc;

    switch (cmd) {
    case MIPS_F_DUPFD:
    case MIPS_F_DUPFD_CLOEXEC:
        rc = fcntl((int)fd, cmd == (uint64_t)MIPS_F_DUPFD ?
                   F_DUPFD : F_DUPFD_CLOEXEC, (int)arg);
        return rc < 0 ? l2a_ret(ctx, -(int64_t)errno) :
                        l2a_ret(ctx, (int64_t)rc);
    case MIPS_F_GETFD:
        rc = fcntl((int)fd, F_GETFD);
        return rc < 0 ? l2a_ret(ctx, -(int64_t)errno) :
                        l2a_ret(ctx, (int64_t)rc);
    case MIPS_F_SETFD:
        rc = fcntl((int)fd, F_SETFD, (int)arg);
        return rc < 0 ? l2a_ret(ctx, -(int64_t)errno) : l2a_ret(ctx, 0);
    case MIPS_F_GETFL:
        rc = fcntl((int)fd, F_GETFL);
        if (rc < 0) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        return l2a_ret(ctx, (int64_t)((rc & O_ACCMODE) |
            ((rc & O_APPEND) != 0 ? (int)MIPS_O_APPEND : 0) |
            ((rc & O_NONBLOCK) != 0 ? (int)MIPS_O_NONBLOCK : 0) |
            ((rc & O_SYNC) != 0 ? (int)MIPS_O_SYNC :
             (rc & O_DSYNC) != 0 ? (int)MIPS_O_DSYNC : 0) |
            ((rc & O_DIRECT) != 0 ? (int)MIPS_O_DIRECT : 0) |
            ((rc & O_NOATIME) != 0 ? (int)MIPS_O_NOATIME : 0)));
    case MIPS_F_SETFL: {
        const uint64_t settable = (uint64_t)(MIPS_O_APPEND |
            MIPS_O_NONBLOCK | MIPS_O_DIRECT | MIPS_O_NOATIME |
            MIPS_O_LARGEFILE);
        int hfl = 0;
        size_t i;

        if ((arg & ~settable) != 0U) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
            if ((arg & l2a_oflags[i].mf & settable) != 0U) {
                hfl |= l2a_oflags[i].hf;
            }
        }
        rc = fcntl((int)fd, F_SETFL, hfl);
        return rc < 0 ? l2a_ret(ctx, -(int64_t)errno) : l2a_ret(ctx, 0);
    }
    default:
        break;
    }
    /* Valid-but-unimplemented lock/ownership commands are ENOSYS;
     * bogus commands are EINVAL, matching Linux. */
    if (cmd == 6U || cmd == 7U || cmd == 14U || cmd == 33U || cmd == 34U ||
        cmd == 35U || cmd == 23U || cmd == 24U) {
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    return l2a_ret(ctx, -(int64_t)EINVAL);
}

/* Verbatim ioctl passthrough. Differing struct layouts (termios) are
 * deferred: on pipes/files the kernel answers ENOTTY before touching
 * the buffer (the static-libc isatty path), and pointer ioctls on real
 * ttys fail safe with EFAULT. */
int64_t mips_sc_ioctl(mips64_ctx_t *ctx, uint64_t fd, uint64_t cmd,
                      uint64_t arg)
{
    int rc = ioctl((int)fd, (unsigned long)cmd, (void *)(uintptr_t)arg);

    if (rc < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)rc);
}

/* N64 and N32 both carry the 64-bit offset in one register (E01: no
 * O32 even-pair rule). */
int64_t mips_sc_lseek(mips64_ctx_t *ctx, uint64_t fd, uint64_t offset,
                      uint64_t whence)
{
    off_t rc = lseek((int)fd, (off_t)offset, (int)whence);

    if (rc == (off_t)-1) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)rc);
}

int64_t mips_sc_dup(mips64_ctx_t *ctx, uint64_t oldfd, uint64_t newfd,
                    uint64_t flags, int op)
{
    int rc;

    if (op == L2A_DUP_DUP3) {
        if ((flags & ~(uint64_t)MIPS_O_CLOEXEC) != 0U ||
            oldfd == newfd) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        rc = dup3((int)oldfd, (int)newfd,
                  (flags & (uint64_t)MIPS_O_CLOEXEC) != 0U ? O_CLOEXEC :
                                                             0);
    } else if (op == L2A_DUP_DUP2) {
        rc = dup2((int)oldfd, (int)newfd);
    } else {
        rc = dup((int)oldfd);
    }
    if (rc < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)rc);
}

int64_t mips_sc_pipe2(mips64_ctx_t *ctx, uint64_t fds_va, uint64_t flags)
{
    const uint64_t allowed = (uint64_t)(MIPS_O_CLOEXEC | MIPS_O_NONBLOCK |
        MIPS_O_DIRECT);
    uint8_t *p;
    int hflags = 0;
    size_t i;
    int fds[2];

    if ((flags & ~allowed) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
        if ((flags & l2a_oflags[i].mf) != 0U) {
            hflags |= l2a_oflags[i].hf;
        }
    }
    p = guest_range(ctx, fds_va, 8U, 1);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    if (pipe2(fds, hflags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    putn(p, (uint64_t)(uint32_t)fds[0], 4, ctx->is_be != 0U);
    putn(p + 4, (uint64_t)(uint32_t)fds[1], 4, ctx->is_be != 0U);
    return l2a_ret(ctx, 0);
}

/* access (dirfd=AT_FDCWD, flags=0) and faccessat share faccessat(2). */
int64_t mips_sc_access_at(mips64_ctx_t *ctx, uint64_t dirfd,
                          uint64_t path_va, uint64_t mode, uint64_t flags)
{
    char path[L2A_PATH_MAX + 1U];
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)(AT_SYMLINK_NOFOLLOW | AT_EACCESS)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (faccessat((int)dirfd, path, (int)mode, (int)flags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_readlinkat(mips64_ctx_t *ctx, uint64_t dirfd,
                           uint64_t path_va, uint64_t buf_va, uint64_t size)
{
    char path[L2A_PATH_MAX + 1U];
    uint8_t *p;
    int64_t rc = guest_str(ctx, path_va, path);
    ssize_t n;

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    p = guest_range(ctx, buf_va, size, 1);
    if (size != 0U && p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    n = readlinkat((int)dirfd, path, (char *)p, (size_t)size);
    if (n < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)n);
}

int64_t mips_sc_unlinkat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                         uint64_t flags)
{
    char path[L2A_PATH_MAX + 1U];
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)AT_REMOVEDIR) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (unlinkat((int)dirfd, path, (int)flags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_close_range(mips64_ctx_t *ctx, uint64_t first, uint64_t last,
                            uint64_t flags)
{
    long rc;

    if ((flags & ~(uint64_t)(CLOSE_RANGE_UNSHARE |
                             CLOSE_RANGE_CLOEXEC)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (first > last || first > (uint64_t)UINT_MAX ||
        last > (uint64_t)UINT_MAX) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    rc = syscall(SYS_close_range, (unsigned)first, (unsigned)last,
                 (unsigned)flags);
    if (rc < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, rc);
}

int64_t mips_sc_getid(mips64_ctx_t *ctx, int which)
{
    int64_t v;

    switch (which) {
    case L2A_ID_PID:
        v = (int64_t)getpid();
        break;
    case L2A_ID_PPID:
        v = (int64_t)getppid();
        break;
    case L2A_ID_UID:
        v = (int64_t)getuid();
        break;
    case L2A_ID_EUID:
        v = (int64_t)geteuid();
        break;
    case L2A_ID_GID:
        v = (int64_t)getgid();
        break;
    case L2A_ID_EGID:
        v = (int64_t)getegid();
        break;
    case L2A_ID_TID:
        v = (int64_t)gettid();
        break;
    default:
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    return l2a_ret(ctx, v);
}

int64_t mips_sc_getrandom(mips64_ctx_t *ctx, uint64_t buf_va, uint64_t len,
                          uint64_t flags)
{
    uint8_t *p;
    ssize_t n;

    if ((flags & ~(uint64_t)(GRND_NONBLOCK | GRND_RANDOM |
                             GRND_INSECURE)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    p = guest_range(ctx, buf_va, len, 1);
    if (len != 0U && p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    n = getrandom(p, (size_t)len, (unsigned)flags);
    if (n < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, (int64_t)n);
}

/* getdents64 records are arch-independent; only BE guests need a
 * fixup walk over the host fill. */
int64_t mips_sc_getdents64(mips64_ctx_t *ctx, uint64_t fd, uint64_t dirp_va,
                           uint64_t count)
{
    uint8_t *p;
    long n;

    if (count == 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    p = guest_range(ctx, dirp_va, count, 1);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    n = syscall(SYS_getdents64, (int)fd, p, (size_t)count);
    if (n < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (n > 0 && ctx->is_be != 0U) {
        int64_t off = 0;

        while (off + 19 <= n) {
            uint64_t reclen = getn(p + off + 16, 2, 0);

            if (reclen < 19U || off + (int64_t)reclen > n) {
                break;
            }
            putn(p + off, getn(p + off, 8, 0), 8, 1);
            putn(p + off + 8, getn(p + off + 8, 8, 0), 8, 1);
            putn(p + off + 16, reclen, 2, 1);
            off += (int64_t)reclen;
        }
    }
    return l2a_ret(ctx, (int64_t)n);
}
