/*
 * src/os/syscalls_stat.c — Static-libc stat family (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * stat/fstat/lstat/newfstatat plus statx. Live qemu fills show the
 * four older calls fill the same 104-byte new_stat layout on N64 and
 * N32 (offsets locked to mips64_n64_stat_t via the table below); the
 * 256-byte statx layout is arch-independent (linux/stat.h, offsets
 * verified against the live N32 fill). Modern glibc routes
 * stat/fstat/lstat to statx, so both paths are wired. Shared helpers
 * (l2a_ret, putn, guest_range, guest_str) live in src/os/syscalls.c.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/syscall_nr.h"
#include "os/sigframe_mips64rt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

/* Shared helpers owned by src/os/syscalls.c. */
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t guest_str(mips64_ctx_t *ctx, uint64_t va, char *out);

/* sys/stat.h maps st_atime -> st_atim.tv_sec (and st_mtime/st_ctime
 * likewise); undo it so the MIPS UAPI member names below resolve to
 * the frozen struct, and use st_atim.tv_sec/nsec for the host side. */
#undef st_atime
#undef st_mtime
#undef st_ctime

#define L2A_PATH_MAX 4096U

/* 32-bit device encoding (linux/kdev_t.h new_encode_dev), verified
 * against the live qemu fill (0x42 for the /tmp fs). */
static uint32_t new_encode_dev(uint64_t dev)
{
    uint64_t major = (uint64_t)major((dev_t)dev);
    uint64_t minor = (uint64_t)minor((dev_t)dev);

    return (uint32_t)(((minor & 0xFFU) | (major << 8)) +
                      ((minor & ~0xFFU) << 12));
}

/* Field table for the MIPS 104-byte new_stat layout: (offset, size)
 * pairs using the frozen mips64_n64_stat_t members. */
#define L2A_ST_OFF(m) (unsigned)offsetof(mips64_n64_stat_t, m)
static const struct {
    unsigned off;
    unsigned sz;
} l2a_stat_fields[] = {
    { L2A_ST_OFF(st_dev), 4 }, { L2A_ST_OFF(st_ino), 8 },
    { L2A_ST_OFF(st_mode), 4 }, { L2A_ST_OFF(st_nlink), 4 },
    { L2A_ST_OFF(st_uid), 4 }, { L2A_ST_OFF(st_gid), 4 },
    { L2A_ST_OFF(st_rdev), 4 }, { L2A_ST_OFF(st_size), 8 },
    { L2A_ST_OFF(st_atime), 4 }, { L2A_ST_OFF(st_atime_nsec), 4 },
    { L2A_ST_OFF(st_mtime), 4 }, { L2A_ST_OFF(st_mtime_nsec), 4 },
    { L2A_ST_OFF(st_ctime), 4 }, { L2A_ST_OFF(st_ctime_nsec), 4 },
    { L2A_ST_OFF(st_blksize), 4 }, { L2A_ST_OFF(st_blocks), 8 },
};

static int64_t emit_stat(mips64_ctx_t *ctx, const struct stat *hs,
                         uint64_t buf_va)
{
    const uint64_t v[] = {
        (uint64_t)new_encode_dev((uint64_t)hs->st_dev),
        (uint64_t)hs->st_ino, (uint64_t)hs->st_mode,
        (uint64_t)hs->st_nlink, (uint64_t)hs->st_uid,
        (uint64_t)hs->st_gid,
        (uint64_t)new_encode_dev((uint64_t)hs->st_rdev),
        (uint64_t)hs->st_size,
        (uint64_t)(uint32_t)hs->st_atim.tv_sec,
        (uint64_t)hs->st_atim.tv_nsec,
        (uint64_t)(uint32_t)hs->st_mtim.tv_sec,
        (uint64_t)hs->st_mtim.tv_nsec,
        (uint64_t)(uint32_t)hs->st_ctim.tv_sec,
        (uint64_t)hs->st_ctim.tv_nsec,
        (uint64_t)hs->st_blksize, (uint64_t)hs->st_blocks,
    };
    uint8_t img[104];
    uint8_t *dst = guest_range(ctx, buf_va, sizeof img, 1);
    size_t i;
    int be;

    _Static_assert(sizeof l2a_stat_fields / sizeof l2a_stat_fields[0] ==
                   sizeof v / sizeof v[0], "stat field/value count");
    if (dst == NULL) {
        return -(int64_t)EFAULT;
    }
    be = ctx->is_be != 0U;
    memset(img, 0, sizeof img);
    for (i = 0U; i < sizeof v / sizeof v[0]; i++) {
        putn(img + l2a_stat_fields[i].off, v[i], l2a_stat_fields[i].sz,
             be);
    }
    memcpy(dst, img, sizeof img);
    return 0;
}

/* stat/lstat/newfstatat share fstatat; only follow differs. */
int64_t mips_sc_stat_at(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                        uint64_t buf_va, uint64_t flags)
{
    char path[L2A_PATH_MAX + 1U];
    struct stat hs;
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH |
                             AT_NO_AUTOMOUNT)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (fstatat((int)dirfd, path, &hs, (int)flags) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    rc = emit_stat(ctx, &hs, buf_va);
    if (rc != 0) {
        return l2a_ret(ctx, rc);
    }
    return l2a_ret(ctx, 0);
}

int64_t mips_sc_fstat(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf_va)
{
    struct stat hs;
    int64_t rc;

    if (fstat((int)fd, &hs) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    rc = emit_stat(ctx, &hs, buf_va);
    if (rc != 0) {
        return l2a_ret(ctx, rc);
    }
    return l2a_ret(ctx, 0);
}

/* Field table for the 256-byte statx. This toolchain's struct statx
 * predates stx_mnt_id and the dio fields, so those three come from
 * stable kernel-UAPI byte offsets after the tabled loop. */
static const struct {
    unsigned off;
    unsigned sz;
} l2a_statx_fields[] = {
    { 0, 4 }, { 4, 4 }, { 8, 8 }, { 16, 4 },
    { 20, 4 }, { 24, 4 }, { 28, 2 }, { 32, 8 },
    { 40, 8 }, { 48, 8 }, { 56, 8 }, { 64, 8 },
    { 72, 4 }, { 80, 8 }, { 88, 4 }, { 96, 8 },
    { 104, 4 }, { 112, 8 }, { 120, 4 }, { 128, 4 },
    { 132, 4 }, { 136, 4 }, { 140, 4 },
};

static int64_t emit_statx(mips64_ctx_t *ctx, const struct statx *hs,
                          uint64_t buf_va)
{
    const uint64_t v[] = {
        hs->stx_mask, hs->stx_blksize, hs->stx_attributes, hs->stx_nlink,
        hs->stx_uid, hs->stx_gid, hs->stx_mode, hs->stx_ino, hs->stx_size,
        (uint64_t)(int64_t)hs->stx_blocks, hs->stx_attributes_mask,
        (uint64_t)(int64_t)hs->stx_atime.tv_sec, hs->stx_atime.tv_nsec,
        (uint64_t)(int64_t)hs->stx_btime.tv_sec, hs->stx_btime.tv_nsec,
        (uint64_t)(int64_t)hs->stx_ctime.tv_sec, hs->stx_ctime.tv_nsec,
        (uint64_t)(int64_t)hs->stx_mtime.tv_sec, hs->stx_mtime.tv_nsec,
        hs->stx_rdev_major, hs->stx_rdev_minor, hs->stx_dev_major,
        hs->stx_dev_minor,
    };
    const uint8_t *hp = (const uint8_t *)hs;
    uint8_t img[256];
    uint8_t *dst = guest_range(ctx, buf_va, sizeof img, 1);
    size_t i;
    int be;

    _Static_assert(sizeof l2a_statx_fields / sizeof l2a_statx_fields[0] ==
                   sizeof v / sizeof v[0], "statx field/value count");
    if (dst == NULL) {
        return -(int64_t)EFAULT;
    }
    be = ctx->is_be != 0U;
    memset(img, 0, sizeof img);
    for (i = 0U; i < sizeof v / sizeof v[0]; i++) {
        putn(img + l2a_statx_fields[i].off, v[i],
             l2a_statx_fields[i].sz, be);
    }
    /* The host kernel always fills the layout-stable mnt/dio fields
     * at 144/152/156 even when libc's struct cannot name them. */
    putn(img + 144, getn(hp + 144, 8, 0), 8, be);
    putn(img + 152, getn(hp + 152, 4, 0), 4, be);
    putn(img + 156, getn(hp + 156, 4, 0), 4, be);
    memcpy(dst, img, sizeof img);
    return 0;
}

int64_t mips_sc_statx(mips64_ctx_t *ctx, uint64_t dirfd, uint64_t path_va,
                      uint64_t flags, uint64_t mask, uint64_t buf_va)
{
    char path[L2A_PATH_MAX + 1U];
    struct statx hsx;
    int64_t rc = guest_str(ctx, path_va, path);

    if (rc < 0) {
        return l2a_ret(ctx, rc);
    }
    if ((flags & ~(uint64_t)(AT_EMPTY_PATH | AT_NO_AUTOMOUNT |
                             AT_SYMLINK_NOFOLLOW | AT_STATX_SYNC_TYPE |
                             AT_STATX_FORCE_SYNC |
                             AT_STATX_DONT_SYNC)) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (statx((int)dirfd, path, (int)flags, (unsigned)mask, &hsx) != 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    rc = emit_statx(ctx, &hsx, buf_va);
    if (rc != 0) {
        return l2a_ret(ctx, rc);
    }
    return l2a_ret(ctx, 0);
}
