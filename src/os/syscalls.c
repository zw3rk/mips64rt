/*
 * src/os/syscalls.c — Static-libc syscall layer, core (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared guest accessors, open-flag translation, and core descriptor,
 * path, and identity syscalls.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/host_args.h"
#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "os/proc.h"

/* Non-Linux host fallbacks (dup3/pipe2/close_range/getrandom/
 * clock_nanosleep shapes); Linux keeps the direct syscalls. */
#include "os/errno_map.h"
#include "os/host_compat.h"

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

/* MIPS errno translation lives in os/errno_map.h
 * (l2a_errno_from_host, shared with syscall_min.c). */

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

void putn(uint8_t *p, uint64_t v, unsigned n, int be)
{
    for (unsigned i = 0U; i < n; i++)
        p[be ? n - 1U - i : i] = (uint8_t)(v >> (8U * i));
}

uint64_t getn(const uint8_t *p, unsigned n, int be)
{
    uint64_t v = 0U;
    for (unsigned i = 0U; i < n; i++)
        v |= (uint64_t)p[be ? n - 1U - i : i] << (8U * i);
    return v;
}

extern void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va,
                                     uint64_t len);
extern void mips_llsc_note_write(uint64_t addr, uint64_t size);
extern void mips_llsc_write_lock(void);
extern void mips_llsc_write_unlock(void);
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

/* Serialized syscall copyout (R3-1): the caller stages the output in
 * host memory first — never holding sc_lock across a blocking host
 * call — then commits guest bytes and LL/SC invalidation together
 * under sc_lock, so a peer LL/SC pair observes either all or none of
 * the bytes (same-value writes included). Mirrors the guest_st*
 * discipline in src/os/mem.c. Returns 0, or -EFAULT when the range
 * fails revalidation (nothing committed). */
int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va, const void *src,
                        uint64_t len)
{
    if (ctx == NULL || src == NULL) {
        return -(int64_t)EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    if (!mips_mem_ok(ctx, va, len, (uint32_t)MIPS_PROT_WRITE)) {
        return -(int64_t)EFAULT;
    }
    mips_llsc_write_lock();
    memcpy(mips64_guest_ptr(ctx, va), src, (size_t)len);
    mips_llsc_note_write(va, len);
    mips_llsc_write_unlock();
    mips_vm_pages_clear(va, len, (unsigned)MIPS_VM_PAGE_COW_CLEAN);
    mips_vm_pages_retire_code(va, len);
    mips_vm_file_shared_sync(ctx, va, len);
    ctx->llbit = 0U; /* E05: an ordinary store clears the reservation */
    return 0;
}

uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len, int write)
{
    uint32_t need =
        write ? (uint32_t)MIPS_PROT_WRITE : (uint32_t)MIPS_PROT_READ;
    if (len == 0U)
        return (uint8_t *)mips64_guest_ptr(ctx, va);
    if (!mips_mem_ok(ctx, va, len, need))
        return NULL;
    /* Read-only view: writes commit via mips_sc_copyout, which owns
     * range validation, LL invalidation, COW clearing, code
     * retirement, and shared-file sync. */
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
 * subset. O_LARGEFILE is dropped (64-bit host: always largefile).
 * O_TMPFILE is absent here on purpose (see map_open_flags): it is the
 * combination O_DIRECTORY | __O_TMPFILE, and a subset test would also
 * fire on a plain O_DIRECTORY. */
static const struct {
    uint64_t mf;
    int hf;
} l2a_oflags[] = {
    { MIPS_O_CREAT, O_CREAT }, { MIPS_O_EXCL, O_EXCL },
    { MIPS_O_NOCTTY, O_NOCTTY }, { MIPS_O_TRUNC, O_TRUNC },
    { MIPS_O_APPEND, O_APPEND }, { MIPS_O_NONBLOCK, O_NONBLOCK },
/* macOS lacks these Linux open flags: the rows compile out and the
 * `known` mask below declines those guest bits with -EINVAL. */
#ifdef O_DIRECT
    { MIPS_O_DIRECT, O_DIRECT },
#endif
    { MIPS_O_DIRECTORY, O_DIRECTORY },
    { MIPS_O_NOFOLLOW, O_NOFOLLOW }, { MIPS_O_CLOEXEC, O_CLOEXEC },
#ifdef O_NOATIME
    { MIPS_O_NOATIME, O_NOATIME },
#endif
#ifdef O_PATH
    { MIPS_O_PATH, O_PATH },
#endif
};

/* Translate mf (masked to allowed) to host flags; -EINVAL on the rest. */
static int64_t map_open_flags(uint64_t mf, uint64_t allowed, int *host_out)
{
    uint64_t known = (uint64_t)(MIPS_O_ACCMODE | MIPS_O_SYNC |
        MIPS_O_DSYNC | MIPS_O_LARGEFILE | MIPS_O_TMPFILE);
    size_t i;
    int h;

    for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
        known |= l2a_oflags[i].mf;
    }
    if ((mf & ~known) != 0U || (mf & ~allowed) != 0U) {
        return -(int64_t)EINVAL;
    }
    /* O_TMPFILE is O_DIRECTORY | __O_TMPFILE on both sides; the table
     * loop below tests subsets, so a plain O_DIRECTORY would also
     * match a TMPFILE row and poison the host flags with __O_TMPFILE
     * (the kernel then fails the open with EINVAL: O_TMPFILE demands
     * write access). Require the full combination here; a lone
     * __O_TMPFILE bit is EINVAL on Linux, so reject it the same way. */
    h = (int)(mf & (uint64_t)MIPS_O_ACCMODE);
    if ((mf & (uint64_t)MIPS_O_TMPFILE) == (uint64_t)MIPS_O_TMPFILE) {
#ifdef O_TMPFILE
        h |= O_TMPFILE;
#else
        /* No O_TMPFILE on this host: the combination is not admittable. */
        return -(int64_t)EINVAL;
#endif
    } else if ((mf & (uint64_t)(MIPS_O_TMPFILE ^ MIPS_O_DIRECTORY)) !=
               0U) {
        return -(int64_t)EINVAL;
    }
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
    char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];
    int64_t rc = guest_str(ctx, path_va, path);
    int hflags;
    int fd;

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    /* Lane L5a: /proc/self/<name> serves guest-accurate content from
     * translator state (see src/os/proc.c); anything else falls
     * through to the host. */
    {
        long procfd = mips_proc_open(path, flags);

        if (procfd >= 0 || procfd < -1) {
            return l2a_ret(ctx, (int64_t)procfd);
        }
    }
    rc = map_open_flags(flags, L2A_OPEN_ALLOWED, &hflags);
    if (rc != 0) {
        return l2a_ret(ctx, rc);
    }
    /* Guest-absolute paths resolve against the start-up sysroot (no
     * sysroot: byte-identical copy). */
    if (mips64_sysroot_join(mips64_host_sysroot(), path, full,
                            sizeof full) != 0) {
        return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
    }
    fd = openat(l2a_host_dirfd(dirfd), full, hflags,
              (mode_t)(mode & 0777U));
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
             (rc & O_DSYNC) != 0 ? (int)MIPS_O_DSYNC : 0)
#ifdef O_DIRECT
            | ((rc & O_DIRECT) != 0 ? (int)MIPS_O_DIRECT : 0)
#endif
#ifdef O_NOATIME
            | ((rc & O_NOATIME) != 0 ? (int)MIPS_O_NOATIME : 0)
#endif
            ));
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
#if defined(__linux__)
        rc = dup3((int)oldfd, (int)newfd,
                  (flags & (uint64_t)MIPS_O_CLOEXEC) != 0U ? O_CLOEXEC :
                                                             0);
#else
        rc = l2a_dup_cloexec((int)oldfd, (int)newfd,
                             (flags & (uint64_t)MIPS_O_CLOEXEC) != 0U);
#endif
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
    uint8_t img[8];
    int hflags = 0;
    size_t i;
    int fds[2];
    int be;

    if ((flags & ~allowed) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    for (i = 0U; i < sizeof l2a_oflags / sizeof l2a_oflags[0]; i++) {
        if ((flags & l2a_oflags[i].mf) != 0U) {
            hflags |= l2a_oflags[i].hf;
        }
    }
    be = ctx->is_be != 0U;
#if defined(__linux__)
    if (pipe2(fds, hflags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
#else
    /* No pipe2(2) on this host: pipe plus fcntl (`hflags` only ever
     * carries O_CLOEXEC/O_NONBLOCK; the O_DIRECT row compiles out
     * where the host lacks it). */
    if (l2a_pipe_flags(fds, hflags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
#endif
    /* Stage in host memory, then commit under sc_lock (R3-1). */
    putn(img, (uint64_t)(uint32_t)fds[0], 4, be);
    putn(img + 4, (uint64_t)(uint32_t)fds[1], 4, be);
    if (mips_sc_copyout(ctx, fds_va, img, sizeof img) != 0) {
        close(fds[0]);
        close(fds[1]);
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

/* access (dirfd=AT_FDCWD, flags=0) and faccessat share faccessat(2). */
int64_t mips_sc_access_at(mips64_ctx_t *ctx, uint64_t dirfd,
                          uint64_t path_va, uint64_t mode, uint64_t flags)
{
    char path[L2A_PATH_MAX + 1U];
    char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)(L2A_AT_SYMLINK_NOFOLLOW |
                             L2A_AT_EACCESS)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (mips64_sysroot_join(mips64_host_sysroot(), path, full,
                            sizeof full) != 0) {
        return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
    }
    if (faccessat(l2a_host_dirfd(dirfd), full, (int)mode,
                  l2a_host_at_nofollow(flags) |
                      l2a_host_at_eaccess(flags)) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_readlinkat(mips64_ctx_t *ctx, uint64_t dirfd,
                           uint64_t path_va, uint64_t buf_va, uint64_t size)
{
    char path[L2A_PATH_MAX + 1U];
    uint8_t zero = 0U;
    uint8_t *stage = &zero;
    int64_t rc = guest_str(ctx, path_va, path);
    ssize_t n;

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    /* Lane L5a: readlink of /proc/self/exe reports the guest path. */
    {
        long linkn = mips_proc_readlink(path, buf_va, size);

        if (linkn != -1) {
            return l2a_ret(ctx, (int64_t)linkn);
        }
    }
    if (size != 0U) {
        if (!mips_mem_ok(ctx, buf_va, size,
                         (uint32_t)MIPS_PROT_WRITE)) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        stage = (uint8_t *)malloc((size_t)size);
        if (stage == NULL) {
            return l2a_ret(ctx, -(int64_t)ENOMEM);
        }
    }
    {
        char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];

        if (mips64_sysroot_join(mips64_host_sysroot(), path, full,
                               sizeof full) != 0) {
            if (stage != &zero) {
                free(stage);
            }
            return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
        }
        n = readlinkat(l2a_host_dirfd(dirfd), full, (char *)stage,
                       (size_t)size);
    }
    if (n < 0) {
        if (stage != &zero) {
            free(stage);
        }
        return l2a_ret(ctx, -(int64_t)errno);
    }
    /* Commit only the bytes the host produced, under sc_lock (R3-1). */
    if (stage != &zero) {
        rc = mips_sc_copyout(ctx, buf_va, stage, (uint64_t)n);
        free(stage);
        if (rc != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, (int64_t)n);
}

int64_t mips_sc_unlinkat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                         uint64_t flags)
{
    char path[L2A_PATH_MAX + 1U];
    char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)L2A_AT_REMOVEDIR) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (mips64_sysroot_join(mips64_host_sysroot(), path, full,
                            sizeof full) != 0) {
        return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
    }
    if (unlinkat(l2a_host_dirfd(dirfd), full,
                 l2a_host_at_removedir(flags)) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_close_range(mips64_ctx_t *ctx, uint64_t first, uint64_t last,
                            uint64_t flags)
{
    if ((flags & ~(uint64_t)(CLOSE_RANGE_UNSHARE |
                             CLOSE_RANGE_CLOEXEC)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (first > last || first > (uint64_t)UINT_MAX ||
        last > (uint64_t)UINT_MAX) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    return l2a_ret(ctx, l2a_close_range_host(first, last, flags));
}

int64_t mips_sc_getid(mips64_ctx_t *ctx, int which)
{
    int64_t v;

    switch (which) {
    case L2A_ID_PID:
        v = (int64_t)(ctx->difftest_enabled ? getppid() : getpid());
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
        if (ctx->difftest_enabled) {
            v = (int64_t)getppid();
        } else if (ctx->host_tid > 0) {
            v = (int64_t)ctx->host_tid;
        } else {
            v = l2a_host_tid();
        }
        break;
    default:
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    return l2a_ret(ctx, v);
}

/* Deterministic getrandom stream for MIPS64RT_RANDSEED runs (difftest):
 * xorshift64 seeded from the knob; the per-boot call counter keeps
 * successive calls distinct. Fork duplicates the counter, so siblings
 * repeat the stream from the fork point — identical on both engines. */
static uint64_t l2a_rand_calls;

int64_t mips_sc_getrandom(mips64_ctx_t *ctx, uint64_t buf_va, uint64_t len,
                          uint64_t flags)
{
    uint8_t zero = 0U;
    uint8_t *stage = &zero;
#if defined(__linux__)
    ssize_t n;
#endif
    const char *env = getenv("MIPS64RT_RANDSEED");
    uint64_t i;

#if defined(GRND_NONBLOCK) && defined(GRND_RANDOM) && \
    defined(GRND_INSECURE)
    if ((flags & ~(uint64_t)(GRND_NONBLOCK | GRND_RANDOM |
                             GRND_INSECURE)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
#else
    if ((flags & ~(uint64_t)L2A_GRND_KNOWN_MASK) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
#endif
    if (len != 0U) {
        if (!mips_mem_ok(ctx, buf_va, len,
                         (uint32_t)MIPS_PROT_WRITE)) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        stage = (uint8_t *)malloc((size_t)len);
        if (stage == NULL) {
            return l2a_ret(ctx, -(int64_t)ENOMEM);
        }
    }
    if (env != NULL && env[0] != '\0') {
        uint64_t s = (uint64_t)strtoull(env, NULL, 0) +
            (uint64_t)0x9E3779B97F4A7C15ULL * ++l2a_rand_calls;

        if (s == 0U) {
            s = (uint64_t)0x9E3779B97F4A7C15ULL;
        }
        for (i = 0U; i < len; i++) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            stage[i] = (uint8_t)s;
        }
        /* The deterministic stream fills the whole range; commit
         * it under sc_lock (R3-1). */
        if (stage != &zero) {
            if (mips_sc_copyout(ctx, buf_va, stage, len) != 0) {
                free(stage);
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
            free(stage);
        }
        return l2a_ret(ctx, (int64_t)len);
    }
#if defined(__linux__)
    n = getrandom(stage, (size_t)len, (unsigned)flags);
    if (n < 0) {
        if (stage != &zero) {
            free(stage);
        }
        return l2a_ret(ctx, -(int64_t)errno);
    }
    /* Commit only the bytes the host produced, under sc_lock (R3-1). */
    if (stage != &zero) {
        int64_t cr = mips_sc_copyout(ctx, buf_va, stage, (uint64_t)n);

        free(stage);
        if (cr != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, (int64_t)n);
#else
    {
        int64_t gn = l2a_getentropy_fill(stage, (size_t)len);

        if (stage != &zero) {
            if (gn >= 0 &&
                mips_sc_copyout(ctx, buf_va, stage, (uint64_t)gn) != 0) {
                free(stage);
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
            free(stage);
        }
        return l2a_ret(ctx, gn);
    }
#endif
}

/* Lane H2 helpers (unlink/truncate/ftruncate/symlinkat): same
 * l2a_ret/guest_str/sysroot conventions. getdents64, clock_getres,
 * and clock_nanosleep live in src/os/syscalls_extra.c (line-limit
 * split, same staged-copyout discipline). Dispatch arms live in
 * syscall_min.c (RC-H wires them). N32 fcntl64 stays -ENOSYS (needs
 * a frozen syscall_nr.h number). */

/* Legacy unlink(2) (N64 5085 / N32 6085): unlinkat(AT_FDCWD).
 * glibc unlink() still emits the legacy number (qemu-observed). */
int64_t mips_sc_unlink(mips64_ctx_t *ctx, uint64_t path_va)
{
    return mips_sc_unlinkat(ctx, L2A_AT_FDCWD, path_va, 0U);
}

/* Lane U12 Provider A mutation hooks (src/vm/vm_file.c). */
extern void mips_vm_file_post_truncate_path(mips64_ctx_t *ctx,
                                            const char *host_path,
                                            uint64_t newsize);
extern void mips_vm_file_post_truncate_fd(mips64_ctx_t *ctx, int fd,
                                          uint64_t newsize);

int64_t mips_sc_truncate(mips64_ctx_t *ctx, uint64_t path_va,
                         uint64_t len)
{
    char path[L2A_PATH_MAX + 1U];
    char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if (mips64_sysroot_join(mips64_host_sysroot(), path, full,
                            sizeof full) != 0) {
        return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
    }
    if (truncate(full, (off_t)len) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    /* Lane U12: EOF tracking + discarded-tail zeroing + SMC retire. */
    mips_vm_file_post_truncate_path(ctx, full, len);
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_ftruncate(mips64_ctx_t *ctx, uint64_t fd, uint64_t len)
{
    if (ftruncate((int)fd, (off_t)len) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    mips_vm_file_post_truncate_fd(ctx, (int)fd, len);
    return l2a_ret(ctx, 0);
}

/* symlinkat (N64 5256 / N32 6260; glibc symlink() lowers to
 * symlinkat(AT_FDCWD)): Linux stores the target verbatim without
 * resolving it at creation, so only the link path joins the sysroot
 * while the target passes through untouched. */
int64_t mips_sc_symlinkat(mips64_ctx_t *ctx, uint64_t target_va,
                          uint64_t dirfd, uint64_t link_va)
{
    char target[L2A_PATH_MAX + 1U];
    char link[L2A_PATH_MAX + 1U];
    char full[L2A_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U];
    int64_t rc = guest_str(ctx, target_va, target);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    rc = guest_str(ctx, link_va, link);
    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if (mips64_sysroot_join(mips64_host_sysroot(), link, full,
                            sizeof full) != 0) {
        return l2a_ret(ctx, -(int64_t)ENAMETOOLONG);
    }
    if (symlinkat(target, l2a_host_dirfd(dirfd), full) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
}

/* getdents64, clock_getres, and clock_nanosleep live in
 * src/os/syscalls_extra.c (line-limit split). */
