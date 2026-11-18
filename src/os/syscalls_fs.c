/*
 * src/os/syscalls_fs.c — Legacy path-mutation, attribute, limit, and
 * process-accounting syscalls (T14 userland qualification).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * glibc on MIPS N64/N32 still emits the legacy (non-*at) numbers for
 * mkdir, rmdir, rename, link, symlink, chmod, chown, lchown, pipe, and
 * the like, so a real userland (dash, coreutils, tar, git, gcc) needs
 * them. Every path joins the host sysroot like the rest of the
 * syscall layer; guest writes commit through mips_sc_copyout. The
 * MIPS-specific numbers (RLIMIT_*, struct statfs, pipe in $v0/$v1)
 * are translated here; everything else is a thin host passthrough.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/errno_map.h"
#include "os/host_args.h"
#include "vm/vm_file.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/mount.h>
#else
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#endif

extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern int64_t guest_str(mips64_ctx_t *ctx, uint64_t va, char *out);
extern int64_t mips_sc_unlinkat(mips64_ctx_t *ctx, uint64_t dirfd,
                                uint64_t path_va, uint64_t flags);
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

#define FS_PATH_MAX 4096U
#define FS_FULL_MAX (FS_PATH_MAX + MIPS64RT_HOST_ARGS_PATH_MAX + 2U)
#define FS_AT_SYMLINK_NOFOLLOW 0x100U
#define FS_AT_REMOVEDIR 0x200U

/* Fetch a guest path and join it to the host sysroot. Returns 0 or a
 * negative errno. Only absolute guest paths are rebased onto the
 * sysroot (relative paths pass through), so a relative path with a
 * real dirfd resolves against that fd, like openat. */
static int64_t fs_path(mips64_ctx_t *ctx, uint64_t va, char *full)
{
    char path[FS_PATH_MAX + 1U];
    int64_t rc = guest_str(ctx, va, path);

    if (rc < 0) {
        return rc;
    }
    if (mips64_sysroot_join(mips64_host_sysroot(), path, full, FS_FULL_MAX) !=
        0) {
        return -(int64_t)ENAMETOOLONG;
    }
    return 0;
}

static int64_t fs_done(mips64_ctx_t *ctx, int host_rc)
{
    return l2a_ret(ctx, host_rc != 0 ? -(int64_t)errno : 0);
}

static int fs_nofollow(uint64_t flags)
{
    return (flags & FS_AT_SYMLINK_NOFOLLOW) != 0U ? AT_SYMLINK_NOFOLLOW : 0;
}

static int64_t fs_mkdirat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                          uint64_t mode)
{
    char full[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, path_va, full);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    return fs_done(ctx, mkdirat(l2a_host_dirfd(dirfd), full, (mode_t)mode));
}

/* mknod/mknodat: only FIFO and regular nodes are portable to the host
 * (device nodes need privileges and a different dev_t encoding). */
static int64_t fs_mknodat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                          uint64_t mode)
{
    char full[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, path_va, full);
    int hd;

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    hd = l2a_host_dirfd(dirfd);
    switch ((mode_t)mode & S_IFMT) {
    case 0:
    case S_IFREG: {
        int fd = openat(hd, full, O_WRONLY | O_CREAT | O_EXCL,
                        (mode_t)mode & 07777);
        if (fd < 0) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        (void)close(fd);
        return l2a_ret(ctx, 0);
    }
    case S_IFIFO:
        return fs_done(ctx, mkfifoat(hd, full, (mode_t)mode & 07777));
    case S_IFSOCK:
        /* Socket nodes are unprivileged on Linux (tar/rsync restore). */
        return fs_done(ctx, mknodat(hd, full,
                                    (mode_t)((mode_t)mode & (S_IFMT | 07777)),
                                    0));
    default:
        return l2a_ret(ctx, -(int64_t)EPERM);
    }
}

static int64_t fs_renameat(mips64_ctx_t *ctx, uint64_t od, uint64_t op,
                           uint64_t nd, uint64_t np, uint64_t flags)
{
    char of[FS_FULL_MAX];
    char nf[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, op, of);

    if (rc >= 0) {
        rc = fs_path(ctx, np, nf);
    }
    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if (flags != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    return fs_done(ctx, renameat(l2a_host_dirfd(od), of, l2a_host_dirfd(nd),
                                 nf));
}

static int64_t fs_linkat(mips64_ctx_t *ctx, uint64_t od, uint64_t op,
                         uint64_t nd, uint64_t np, uint64_t flags)
{
    char of[FS_FULL_MAX];
    char nf[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, op, of);

    if (rc >= 0) {
        rc = fs_path(ctx, np, nf);
    }
    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    return fs_done(ctx, linkat(l2a_host_dirfd(od), of, l2a_host_dirfd(nd), nf,
                               (flags & 0x400U) != 0U ? AT_SYMLINK_FOLLOW : 0));
}

static int64_t fs_chmodat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                          uint64_t mode, uint64_t flags)
{
    char full[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, path_va, full);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    return fs_done(ctx, fchmodat(l2a_host_dirfd(dirfd), full, (mode_t)mode,
                                 fs_nofollow(flags)));
}

static int64_t fs_chownat(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                          uint64_t uid, uint64_t gid, uint64_t flags)
{
    char full[FS_FULL_MAX];
    int64_t rc = fs_path(ctx, path_va, full);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    return fs_done(ctx, fchownat(l2a_host_dirfd(dirfd), full, (uid_t)uid,
                                 (gid_t)gid, fs_nofollow(flags)));
}

/* Linux UTIME_* values (asm-generic), shared by the MIPS guest. */
#define FS_UTIME_NOW ((long)0x3fffffffL)
#define FS_UTIME_OMIT ((long)0x3ffffffeL)
#define FS_NSEC_PER_SEC 1000000000L

/* utimensat(dirfd, path|NULL, timespec[2], flags). N32 takes the
 * 16-byte old_timespec32 pair; N64 the 32-byte pair. */
static int64_t fs_utimensat(mips64_ctx_t *ctx, int n32, uint64_t dirfd,
                            uint64_t path_va, uint64_t ts_va, uint64_t flags)
{
    char full[FS_FULL_MAX];
    struct timespec ts[2];
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    int64_t rc = 0;
    int i;

    if (path_va != 0U) {
        rc = fs_path(ctx, path_va, full);
        if (rc < 0) {
            return l2a_ret(ctx, rc);
        }
    }
    if (ts_va != 0U) {
        g = guest_range(ctx, ts_va, n32 ? 16U : 32U, 0);
        if (g == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        for (i = 0; i < 2; i++) {
            int64_t sec;
            int64_t nsec;

            if (n32) {
                sec = (int64_t)(int32_t)getn(g + 8 * (unsigned)i, 4, be);
                nsec =
                    (int64_t)(int32_t)getn(g + 8 * (unsigned)i + 4, 4, be);
            } else {
                sec = (int64_t)getn(g + 16 * (unsigned)i, 8, be);
                nsec = (int64_t)getn(g + 16 * (unsigned)i + 8, 8, be);
            }
            /* Negative tv_sec is legal (pre-1970 stamps); only
             * tv_nsec is validated, like Linux do_utimes. */
            if (nsec != (int64_t)FS_UTIME_NOW &&
                nsec != (int64_t)FS_UTIME_OMIT &&
                (nsec < 0 || nsec >= (int64_t)FS_NSEC_PER_SEC)) {
                return l2a_ret(ctx, -(int64_t)EINVAL);
            }
            ts[i].tv_sec = (time_t)sec;
            ts[i].tv_nsec = (long)nsec;
        }
    }
#if defined(__APPLE__)
    /* No utimensat on Darwin: Linux UTIME_NOW/OMIT become -1/-2, and
     * paths stamp via lutimes/utimes when expressible (no fd, so no
     * FIFO hang and nofollow honored), else via an O_NONBLOCK fd. */
    {
        struct timespec dts[2];
        struct timeval tv[2];
        int nofollow = (flags & FS_AT_SYMLINK_NOFOLLOW) != 0U;
        int concrete = ts_va == 0U ||
            ((ts[0].tv_nsec != FS_UTIME_NOW &&
              ts[0].tv_nsec != FS_UTIME_OMIT) &&
             (ts[1].tv_nsec != FS_UTIME_NOW &&
              ts[1].tv_nsec != FS_UTIME_OMIT));
        int fd;
        int j;

        for (j = 0; j < 2; j++) {
            dts[j].tv_sec = ts_va != 0U ? ts[j].tv_sec : 0;
            dts[j].tv_nsec = ts_va == 0U ? UTIME_OMIT :
                ts[j].tv_nsec == FS_UTIME_NOW ? UTIME_NOW :
                ts[j].tv_nsec == FS_UTIME_OMIT ? UTIME_OMIT :
                ts[j].tv_nsec;
            tv[j].tv_sec = dts[j].tv_sec;
            tv[j].tv_usec = (suseconds_t)(dts[j].tv_nsec / 1000L);
        }
        if (path_va == 0U) {
            return fs_done(ctx, futimens((int)dirfd,
                                        ts_va != 0U ? dts : NULL));
        }
        if (concrete != 0 && (dirfd == L2A_AT_FDCWD || full[0] == '/') &&
            (nofollow != 0 ? lutimes(full, ts_va != 0U ? tv : NULL) :
                             utimes(full, ts_va != 0U ? tv : NULL)) == 0) {
            return l2a_ret(ctx, 0);
        }
        fd = openat(l2a_host_dirfd(dirfd), full,
                    O_RDONLY | O_NONBLOCK |
                        (nofollow != 0 ? O_SYMLINK : 0));
        if (fd < 0) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
        rc = futimens(fd, ts_va != 0U ? dts : NULL);
        {
            int e = errno;

            (void)close(fd);
            if (rc != 0) {
                return l2a_ret(ctx, -(int64_t)e);
            }
        }
        return l2a_ret(ctx, 0);
    }
#else
    if (path_va == 0U) {
        return fs_done(ctx, futimens((int)dirfd, ts_va != 0U ? ts : NULL));
    }
    return fs_done(ctx, utimensat(l2a_host_dirfd(dirfd), full,
                                  ts_va != 0U ? ts : NULL,
                                  fs_nofollow(flags)));
#endif
}

/* madvise(2): only MADV_DONTNEED (ABI value 4) discards pages so a
 * later read sees zeros (glibc calloc relies on this); every other
 * advice is accepted as a no-op. Writable-mapped ranges only, so
 * JIT/code pages are never touched. */
static int64_t fs_madvise(mips64_ctx_t *ctx, uint64_t addr, uint64_t len,
                          uint64_t advice)
{
    if (advice != 4U) {
        return l2a_ret(ctx, 0);
    }
    if ((addr & UINT64_C(4095)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (len == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, addr, len, (uint32_t)MIPS_PROT_WRITE)) {
        return l2a_ret(ctx, -(int64_t)ENOMEM);
    }
#if defined(__linux__)
    if (madvise(mips64_guest_ptr(ctx, addr), (size_t)len, MADV_DONTNEED) !=
        0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
#else
    /* Darwin has no zeroing DONTNEED (a memset would corrupt private
     * file data and fault on COW pages): MADV_FREE elsewhere, no-op
     * on shared file ranges (never synchronously zeroed). */
    if (mips_vm_file_has_shared(addr, len) == 0 &&
        madvise(mips64_guest_ptr(ctx, addr), (size_t)len,
                MADV_FREE) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return l2a_ret(ctx, 0);
#endif
}

/* Legacy pipe(2): MIPS returns the fds in $v0/$v1, not through memory. */
static int64_t fs_pipe(mips64_ctx_t *ctx)
{
    int fds[2];

    if (pipe(fds) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    (void)l2a_ret(ctx, fds[0]);
    ctx->gpr[MIPS64_REG_V1] = (uint64_t)(uint32_t)fds[1];
    return fds[0];
}

/* MIPS64 statfs: 128 bytes (type@0, bsize@8, frsize@16, blocks@24,
 * bfree@32, files@40, ffree@48, bavail@56, fsid@64, namelen@72,
 * flags@80, spare@88..128). N32 uses the 68-byte MIPS compat_statfs
 * (type@0, bsize@4, frsize@8, blocks@12, bfree@16, files@20,
 * ffree@24, bavail@28, fsid@32, namelen@40, flags@44, spare@48..68).
 * Darwin reports namelen 255, frsize f_bsize. */
static int64_t fs_put_statfs(mips64_ctx_t *ctx, int n32, uint64_t va,
                             const struct statfs *s)
{
    uint8_t img[128];
    int be = ctx->is_be != 0U;
#if defined(__APPLE__)
    uint64_t frsize = (uint64_t)s->f_bsize;
    uint32_t namelen = 255U;
    uint64_t flags = (uint64_t)s->f_flags;
#else
    uint64_t frsize = (uint64_t)s->f_frsize;
    uint64_t namelen = (uint64_t)s->f_namelen;
    uint64_t flags = (uint64_t)s->f_flags;
#endif

    memset(img, 0, sizeof img);
    if (n32) {
        uint32_t id0;
        uint32_t id1;

#if defined(__APPLE__)
        id0 = (uint32_t)s->f_fsid.val[0];
        id1 = (uint32_t)s->f_fsid.val[1];
#else
        id0 = (uint32_t)s->f_fsid.__val[0];
        id1 = (uint32_t)s->f_fsid.__val[1];
#endif
        putn(img + 0, (uint64_t)(uint32_t)s->f_type, 4, be);
        putn(img + 4, (uint64_t)(uint32_t)s->f_bsize, 4, be);
        putn(img + 8, (uint64_t)(uint32_t)frsize, 4, be);
        putn(img + 12, (uint64_t)(uint32_t)s->f_blocks, 4, be);
        putn(img + 16, (uint64_t)(uint32_t)s->f_bfree, 4, be);
        putn(img + 20, (uint64_t)(uint32_t)s->f_files, 4, be);
        putn(img + 24, (uint64_t)(uint32_t)s->f_ffree, 4, be);
        putn(img + 28, (uint64_t)(uint32_t)s->f_bavail, 4, be);
        putn(img + 32, (uint64_t)id0, 4, be);
        putn(img + 36, (uint64_t)id1, 4, be);
        putn(img + 40, (uint64_t)(uint32_t)namelen, 4, be);
        putn(img + 44, (uint64_t)(uint32_t)flags, 4, be);
        /* spare[5] @48..67 stays zeroed by the memset above. */
        if (mips_sc_copyout(ctx, va, img, 68U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        return l2a_ret(ctx, 0);
    }
    /* __kernel_fsid_t is int val[2] at 64/68 on every endianness
     * (never one packed 8-byte word: it swaps the halves for BE). */
#if defined(__APPLE__)
    putn(img + 64, (uint64_t)(uint32_t)s->f_fsid.val[0], 4, be);
    putn(img + 68, (uint64_t)(uint32_t)s->f_fsid.val[1], 4, be);
#else
    putn(img + 64, (uint64_t)(uint32_t)s->f_fsid.__val[0], 4, be);
    putn(img + 68, (uint64_t)(uint32_t)s->f_fsid.__val[1], 4, be);
#endif
    putn(img + 0, (uint64_t)s->f_type, 8, be);
    putn(img + 8, (uint64_t)s->f_bsize, 8, be);
    putn(img + 16, frsize, 8, be);
    putn(img + 24, (uint64_t)s->f_blocks, 8, be);
    putn(img + 32, (uint64_t)s->f_bfree, 8, be);
    putn(img + 40, (uint64_t)s->f_files, 8, be);
    putn(img + 48, (uint64_t)s->f_ffree, 8, be);
    putn(img + 56, (uint64_t)s->f_bavail, 8, be);
    putn(img + 72, namelen, 8, be);
    putn(img + 80, flags, 8, be);
    if (mips_sc_copyout(ctx, va, img, sizeof img) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

static int64_t fs_statfs(mips64_ctx_t *ctx, int n32, uint64_t path_va,
                         uint64_t buf_va)
{
    char full[FS_FULL_MAX];
    struct statfs s;
    int64_t rc = fs_path(ctx, path_va, full);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if (statfs(full, &s) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return fs_put_statfs(ctx, n32, buf_va, &s);
}

static int64_t fs_fstatfs(mips64_ctx_t *ctx, int n32, uint64_t fd,
                          uint64_t buf_va)
{
    struct statfs s;

    if (fstatfs((int)fd, &s) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    return fs_put_statfs(ctx, n32, buf_va, &s);
}

/* MIPS RLIMIT_* to host resource; -2 is synthetic unlimited (MIPS
 * 10..15 off Linux), -1 invalid. MIPS 10..15 match Linux numbers. */
static int fs_rlimit_res(uint64_t g)
{
    switch (g) {
    case 0: return RLIMIT_CPU;
    case 1: return RLIMIT_FSIZE;
    case 2: return RLIMIT_DATA;
    case 3: return RLIMIT_STACK;
    case 4: return RLIMIT_CORE;
    case 5: return RLIMIT_NOFILE;
    case 6: return RLIMIT_AS;
    case 7: return RLIMIT_RSS;
    case 8: return RLIMIT_NPROC;
    case 9: return RLIMIT_MEMLOCK;
#if defined(__linux__)
    case 10: return RLIMIT_LOCKS;
    case 11: return RLIMIT_SIGPENDING;
    case 12: return RLIMIT_MSGQUEUE;
    case 13: return RLIMIT_NICE;
    case 14: return RLIMIT_RTPRIO;
    case 15: return RLIMIT_RTTIME;
#else
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
        return -2;
#endif
    default: return -1;
    }
}

/* 32-bit rlimit infinity (prlimit64 uses all-ones 64-bit words). */
#define FS_RLIM32_INFINITY UINT64_C(0x7fffffff)

/* prlimit64(pid, res, new, old) and getrlimit(res, old); new limits
 * apply to the calling process only. wide selects 64-bit words
 * (prlimit64, and legacy calls on N64); legacy N32 calls use the
 * 32-bit compat pair. */
static int64_t fs_prlimit(mips64_ctx_t *ctx, int wide, uint64_t pid,
                          uint64_t res, uint64_t new_va, uint64_t old_va)
{
    struct rlimit rl;
    int hr = fs_rlimit_res(res);
    int be = ctx->is_be != 0U;
    uint8_t img[16];
    const uint8_t *g;
    uint64_t inf;

    if (hr == -1 || (pid != 0U && pid != (uint64_t)getpid())) {
        return l2a_ret(ctx, hr == -1 ? -(int64_t)EINVAL : -(int64_t)ESRCH);
    }
    inf = wide ? ~(uint64_t)0 : FS_RLIM32_INFINITY;
    if (hr == -2) {
        /* Synthetic unlimited (Darwin lacks LOCKS..RTTIME): report
         * infinity, accept (no-op) a new limit. */
        if (old_va != 0U) {
            if (wide) {
                putn(img, inf, 8, be);
                putn(img + 8, inf, 8, be);
            } else {
                putn(img, inf, 4, be);
                putn(img + 4, inf, 4, be);
            }
            if (mips_sc_copyout(ctx, old_va, img,
                                wide ? 16U : 8U) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        }
        return l2a_ret(ctx, 0);
    }
    if (getrlimit((__typeof__(RLIMIT_CPU))hr, &rl) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (old_va != 0U) {
        uint64_t cur = rl.rlim_cur == RLIM_INFINITY ? inf :
                       (uint64_t)rl.rlim_cur > inf ? inf :
                       (uint64_t)rl.rlim_cur;
        uint64_t max = rl.rlim_max == RLIM_INFINITY ? inf :
                       (uint64_t)rl.rlim_max > inf ? inf :
                       (uint64_t)rl.rlim_max;

        if (wide) {
            putn(img, cur, 8, be);
            putn(img + 8, max, 8, be);
        } else {
            putn(img, cur, 4, be);
            putn(img + 4, max, 4, be);
        }
        if (mips_sc_copyout(ctx, old_va, img, wide ? 16U : 8U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    if (new_va != 0U) {
        struct rlimit nl;
        uint64_t c;
        uint64_t m;

        g = guest_range(ctx, new_va, wide ? 16U : 8U, 0);
        if (g == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        if (wide) {
            c = getn(g, 8, be);
            m = getn(g + 8, 8, be);
        } else {
            c = getn(g, 4, be);
            m = getn(g + 4, 4, be);
        }
        nl.rlim_cur = c == inf ? RLIM_INFINITY : (rlim_t)c;
        nl.rlim_max = m == inf ? RLIM_INFINITY : (rlim_t)m;
        if (setrlimit((__typeof__(RLIMIT_CPU))hr, &nl) != 0) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
    }
    return l2a_ret(ctx, 0);
}

/* N32 takes the 8-byte compat_timeval (two int32); N64 the 16-byte
 * pair of 64-bit words. */
static int64_t fs_gettimeofday(mips64_ctx_t *ctx, int n32, uint64_t tv_va,
                               uint64_t tz_va)
{
    struct timeval tv;
    uint8_t img[16];
    int be = ctx->is_be != 0U;

    if (gettimeofday(&tv, NULL) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (tv_va != 0U) {
        if (n32) {
            putn(img, (uint64_t)(uint32_t)(int32_t)tv.tv_sec, 4, be);
            putn(img + 4, (uint64_t)(uint32_t)tv.tv_usec, 4, be);
            if (mips_sc_copyout(ctx, tv_va, img, 8U) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        } else {
            putn(img, (uint64_t)tv.tv_sec, 8, be);
            putn(img + 8, (uint64_t)tv.tv_usec, 8, be);
            if (mips_sc_copyout(ctx, tv_va, img, sizeof img) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        }
    }
    if (tz_va != 0U) {
        memset(img, 0, 8);
        if (mips_sc_copyout(ctx, tz_va, img, 8U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

/* N32 takes the 16-byte compat_tms (four int32); N64 32 bytes. */
static int64_t fs_times(mips64_ctx_t *ctx, int n32, uint64_t buf_va)
{
    struct tms t;
    uint8_t img[32];
    int be = ctx->is_be != 0U;
    clock_t r = times(&t);

    if (r == (clock_t)-1) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (buf_va != 0U) {
        if (n32) {
            putn(img, (uint64_t)(uint32_t)t.tms_utime, 4, be);
            putn(img + 4, (uint64_t)(uint32_t)t.tms_stime, 4, be);
            putn(img + 8, (uint64_t)(uint32_t)t.tms_cutime, 4, be);
            putn(img + 12, (uint64_t)(uint32_t)t.tms_cstime, 4, be);
            if (mips_sc_copyout(ctx, buf_va, img, 16U) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        } else {
            putn(img, (uint64_t)t.tms_utime, 8, be);
            putn(img + 8, (uint64_t)t.tms_stime, 8, be);
            putn(img + 16, (uint64_t)t.tms_cutime, 8, be);
            putn(img + 24, (uint64_t)t.tms_cstime, 8, be);
            if (mips_sc_copyout(ctx, buf_va, img, sizeof img) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        }
    }
    return l2a_ret(ctx, (int64_t)r);
}

/* N64 rusage is 144 bytes; N32 the 72-byte compat_rusage. Darwin
 * reports ru_maxrss in bytes (Linux: KiB), divided by 1024 here. */
static int64_t fs_getrusage(mips64_ctx_t *ctx, int n32, uint64_t who,
                            uint64_t buf_va)
{
    struct rusage ru;
    uint8_t img[144];
    int be = ctx->is_be != 0U;
    int hw = who == 0U ? RUSAGE_SELF : (who == (uint64_t)-1 ? RUSAGE_CHILDREN
                                                              : -99);
    long maxrss;

    if (hw == -99) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (getrusage(hw, &ru) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
#if defined(__APPLE__)
    maxrss = ru.ru_maxrss / 1024L;
#else
    maxrss = ru.ru_maxrss;
#endif
    memset(img, 0, sizeof img);
    if (n32) {
        putn(img + 0, (uint64_t)(uint32_t)(int32_t)ru.ru_utime.tv_sec, 4,
             be);
        putn(img + 4, (uint64_t)(uint32_t)ru.ru_utime.tv_usec, 4, be);
        putn(img + 8, (uint64_t)(uint32_t)(int32_t)ru.ru_stime.tv_sec, 4,
             be);
        putn(img + 12, (uint64_t)(uint32_t)ru.ru_stime.tv_usec, 4, be);
        putn(img + 16, (uint64_t)(uint32_t)maxrss, 4, be);
        putn(img + 20, (uint64_t)(uint32_t)ru.ru_ixrss, 4, be);
        putn(img + 24, (uint64_t)(uint32_t)ru.ru_idrss, 4, be);
        putn(img + 28, (uint64_t)(uint32_t)ru.ru_isrss, 4, be);
        putn(img + 32, (uint64_t)(uint32_t)ru.ru_minflt, 4, be);
        putn(img + 36, (uint64_t)(uint32_t)ru.ru_majflt, 4, be);
        putn(img + 40, (uint64_t)(uint32_t)ru.ru_nswap, 4, be);
        putn(img + 44, (uint64_t)(uint32_t)ru.ru_inblock, 4, be);
        putn(img + 48, (uint64_t)(uint32_t)ru.ru_oublock, 4, be);
        putn(img + 52, (uint64_t)(uint32_t)ru.ru_msgsnd, 4, be);
        putn(img + 56, (uint64_t)(uint32_t)ru.ru_msgrcv, 4, be);
        putn(img + 60, (uint64_t)(uint32_t)ru.ru_nsignals, 4, be);
        putn(img + 64, (uint64_t)(uint32_t)ru.ru_nvcsw, 4, be);
        putn(img + 68, (uint64_t)(uint32_t)ru.ru_nivcsw, 4, be);
        if (mips_sc_copyout(ctx, buf_va, img, 72U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        return l2a_ret(ctx, 0);
    }
    putn(img + 0, (uint64_t)ru.ru_utime.tv_sec, 8, be);
    putn(img + 8, (uint64_t)ru.ru_utime.tv_usec, 8, be);
    putn(img + 16, (uint64_t)ru.ru_stime.tv_sec, 8, be);
    putn(img + 24, (uint64_t)ru.ru_stime.tv_usec, 8, be);
    putn(img + 32, (uint64_t)maxrss, 8, be);
    putn(img + 40, (uint64_t)ru.ru_ixrss, 8, be);
    putn(img + 48, (uint64_t)ru.ru_idrss, 8, be);
    putn(img + 56, (uint64_t)ru.ru_isrss, 8, be);
    putn(img + 64, (uint64_t)ru.ru_minflt, 8, be);
    putn(img + 72, (uint64_t)ru.ru_majflt, 8, be);
    putn(img + 80, (uint64_t)ru.ru_nswap, 8, be);
    putn(img + 88, (uint64_t)ru.ru_inblock, 8, be);
    putn(img + 96, (uint64_t)ru.ru_oublock, 8, be);
    putn(img + 104, (uint64_t)ru.ru_msgsnd, 8, be);
    putn(img + 112, (uint64_t)ru.ru_msgrcv, 8, be);
    putn(img + 120, (uint64_t)ru.ru_nsignals, 8, be);
    putn(img + 128, (uint64_t)ru.ru_nvcsw, 8, be);
    putn(img + 136, (uint64_t)ru.ru_nivcsw, 8, be);
    if (mips_sc_copyout(ctx, buf_va, img, sizeof img) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

/* sysinfo(2): synthetic figures, uptime from the host clock.
 * N32 takes the 64-byte compat_sysinfo of 32-bit fields. */
static int64_t fs_sysinfo(mips64_ctx_t *ctx, int n32, uint64_t buf_va)
{
    uint8_t img[112];
    int be = ctx->is_be != 0U;
    struct timespec ts;
    long pg = sysconf(_SC_PAGESIZE);
    long np = sysconf(_SC_PHYS_PAGES);
    uint64_t total;

    memset(img, 0, sizeof img);
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        ts.tv_sec = 0;
    }
    total = (uint64_t)(np > 0 ? np : 1) * (uint64_t)(pg > 0 ? pg : 4096);
    if (n32) {
        uint64_t total32 = total > UINT64_C(0xffffffff) ?
                           UINT64_C(0xffffffff) : total;

        putn(img + 0, (uint64_t)(uint32_t)ts.tv_sec, 4, be);
        putn(img + 16, total32, 4, be);
        putn(img + 20, total32 / 2U, 4, be);
        putn(img + 40, 1U, 2, be);
        putn(img + 52, 1U, 4, be);
        if (mips_sc_copyout(ctx, buf_va, img, 64U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        return l2a_ret(ctx, 0);
    }
    putn(img + 0, (uint64_t)ts.tv_sec, 8, be);
    putn(img + 32, total, 8, be);
    putn(img + 40, total / 2U, 8, be);
    putn(img + 80, 1U, 2, be);
    putn(img + 104, 1U, 4, be);
    if (mips_sc_copyout(ctx, buf_va, img, sizeof img) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, 0);
}

/* Same index on both ABIs (legacy calls) vs. per-ABI index (*at). */
#define FS_L(a, idx) ((a) == (uint64_t)(5000U + (idx)) || \
                      (a) == (uint64_t)(6000U + (idx)))
#define FS_A(a, i64, i32) ((a) == (uint64_t)(n32 ? 6000U + (i32) \
                                                 : 5000U + (i64)))

/* Dispatch tail for the legacy fs/misc family; *claimed reports
 * whether nr was handled (return already guest-convention adjusted). */
int64_t mips_sc_fs_extra(mips64_ctx_t *ctx, int n32, uint64_t nr, uint64_t a0,
                         uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *claimed)
{
    const uint64_t cwd = L2A_AT_FDCWD;

    *claimed = 1;
    if (FS_L(nr, 81)) { /* mkdir */
        return fs_mkdirat(ctx, cwd, a0, a1);
    }
    if (FS_A(nr, 248, 252)) { /* mkdirat */
        return fs_mkdirat(ctx, a0, a1, a2);
    }
    if (FS_L(nr, 131)) { /* mknod */
        return fs_mknodat(ctx, cwd, a0, a1);
    }
    if (FS_A(nr, 249, 253)) { /* mknodat */
        return fs_mknodat(ctx, a0, a1, a2);
    }
    if (FS_L(nr, 82)) { /* rmdir */
        return mips_sc_unlinkat(ctx, cwd, a0, FS_AT_REMOVEDIR);
    }
    if (FS_L(nr, 80)) { /* rename */
        return fs_renameat(ctx, cwd, a0, cwd, a1, 0U);
    }
    if (FS_A(nr, 254, 258)) { /* renameat */
        return fs_renameat(ctx, a0, a1, a2, a3, 0U);
    }
    if (FS_A(nr, 311, 315)) { /* renameat2 */
        return fs_renameat(ctx, a0, a1, a2, a3, a4);
    }
    if (FS_L(nr, 84)) { /* link */
        return fs_linkat(ctx, cwd, a0, cwd, a1, 0U);
    }
    if (FS_A(nr, 255, 259)) { /* linkat */
        return fs_linkat(ctx, a0, a1, a2, a3, a4);
    }
    if (FS_L(nr, 88)) { /* chmod */
        return fs_chmodat(ctx, cwd, a0, a1, 0U);
    }
    if (FS_A(nr, 258, 262)) { /* fchmodat */
        return fs_chmodat(ctx, a0, a1, a2, 0U);
    }
    if (FS_L(nr, 89)) { /* fchmod */
        return fs_done(ctx, fchmod((int)a0, (mode_t)a1));
    }
    if (FS_L(nr, 90)) { /* chown */
        return fs_chownat(ctx, cwd, a0, a1, a2, 0U);
    }
    if (FS_L(nr, 92)) { /* lchown */
        return fs_chownat(ctx, cwd, a0, a1, a2, FS_AT_SYMLINK_NOFOLLOW);
    }
    if (FS_A(nr, 250, 254)) { /* fchownat */
        return fs_chownat(ctx, a0, a1, a2, a3, a4);
    }
    if (FS_L(nr, 91)) { /* fchown */
        return fs_done(ctx, fchown((int)a0, (uid_t)a1, (gid_t)a2));
    }
    if (FS_L(nr, 93)) { /* umask */
        return l2a_ret(ctx, (int64_t)umask((mode_t)a0));
    }
    if (FS_A(nr, 275, 279)) { /* utimensat */
        return fs_utimensat(ctx, n32, a0, a1, a2, a3);
    }
    if (FS_L(nr, 21)) { /* pipe */
        return fs_pipe(ctx);
    }
    if (FS_L(nr, 72)) { /* fsync */
        return fs_done(ctx, fsync((int)a0));
    }
    if (FS_L(nr, 73)) { /* fdatasync */
        return fs_done(ctx, fsync((int)a0));
    }
    if (FS_L(nr, 71)) { /* flock */
        return fs_done(ctx, flock((int)a0, (int)a1));
    }
    if (FS_L(nr, 23)) { /* sched_yield */
        return l2a_ret(ctx, sched_yield() == 0 ? 0 : -(int64_t)errno);
    }
    if (FS_L(nr, 27)) { /* madvise */
        return fs_madvise(ctx, a0, a1, a2);
    }
    if (FS_L(nr, 25) || FS_L(nr, 146) || FS_L(nr, 147)) {
        /* msync / mlock / munlock: advisory, accepted. */
        return l2a_ret(ctx, 0);
    }
    if (FS_L(nr, 134)) { /* statfs */
        return fs_statfs(ctx, n32, a0, a1);
    }
    if (FS_L(nr, 135)) { /* fstatfs */
        return fs_fstatfs(ctx, n32, a0, a1);
    }
    if (FS_L(nr, 95)) { /* getrlimit */
        return fs_prlimit(ctx, n32 ? 0 : 1, 0U, a0, 0U, a1);
    }
    if (FS_L(nr, 155)) { /* setrlimit */
        return fs_prlimit(ctx, n32 ? 0 : 1, 0U, a0, a1, 0U);
    }
    if (FS_A(nr, 297, 302)) { /* prlimit64 */
        return fs_prlimit(ctx, 1, a0, a1, a2, a3);
    }
    if (FS_L(nr, 94)) { /* gettimeofday */
        return fs_gettimeofday(ctx, n32, a0, a1);
    }
    if (FS_L(nr, 98)) { /* times */
        return fs_times(ctx, n32, a0);
    }
    if (FS_L(nr, 96)) { /* getrusage */
        return fs_getrusage(ctx, n32, a0, a1);
    }
    if (FS_L(nr, 97)) { /* sysinfo */
        return fs_sysinfo(ctx, n32, a0);
    }
    *claimed = 0;
    return -(int64_t)ENOSYS;
}
