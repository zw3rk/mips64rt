/*
 * src/os/errno_map.h — Guest/host ABI number translation (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * MIPS follows the asm-generic numbers except ENOSYS (89, not 38).
 * Darwin renumbers several more (notably the EAGAIN 35 / EDEADLK 11
 * swap and ETIMEDOUT 60); map every host errno the current syscall
 * set can produce. Linux hosts differ only on ENOSYS. The *at(2)
 * dirfd/flag values differ too (Darwin AT_FDCWD is -2, not -100;
 * NOFOLLOW/EACCESS/REMOVEDIR bits move); the l2a_host_at_* helpers
 * translate those per call flavor. static inline throughout so
 * includers that need only part of the table draw no
 * -Wunused-function errors. Shared by syscalls.c, syscall_min.c,
 * and syscalls_stat.c. Curated C11 only.
 */

#ifndef MIPS64RT_OS_ERRNO_MAP_H
#define MIPS64RT_OS_ERRNO_MAP_H

#include <stdint.h>

static inline int32_t l2a_errno_from_host(int host_errno)
{
#if defined(__APPLE__)
    switch (host_errno) {
    case 11:
        return 35; /* EDEADLK */
    case 35:
        return 11; /* EAGAIN (== EWOULDBLOCK) */
    case 36:
        return 115; /* EINPROGRESS */
    case 37:
        return 114; /* EALREADY */
    case 38:
        return 88; /* ENOTSOCK (Linux 38 is ENOSYS) */
    case 60:
        return 110; /* ETIMEDOUT */
    case 62:
        return 40; /* ELOOP */
    case 63:
        return 36; /* ENAMETOOLONG */
    case 66:
        return 39; /* ENOTEMPTY */
    case 69:
        return 122; /* EDQUOT */
    case 77:
        return 37; /* ENOLCK */
    case 78:
        return 89; /* ENOSYS */
    case 84:
        return 75; /* EOVERFLOW */
    default:
        return (int32_t)host_errno;
    }
#else
    return (host_errno == 38) ? 89 : (int32_t)host_errno;
#endif
}

/* Guest (Linux) AT_* values for *at validation and mapping (host
 * fcntl.h differs on Darwin, so the raw names are unusable). */
#define L2A_AT_SYMLINK_NOFOLLOW 0x100U
#define L2A_AT_REMOVEDIR 0x200U
#define L2A_AT_EACCESS 0x200U
#define L2A_AT_EMPTY_PATH 0x1000U
#define L2A_AT_NO_AUTOMOUNT 0x800U
#define L2A_AT_FDCWD ((uint64_t)(int64_t)-100)

/* Guest dirfd (-100 AT_FDCWD, else a live fd) to host dirfd. */
static inline int l2a_host_dirfd(uint64_t guest_dirfd)
{
#if defined(__APPLE__)
    if (guest_dirfd == L2A_AT_FDCWD) {
        return -2; /* Darwin AT_FDCWD */
    }
#endif
    return (int)guest_dirfd;
}

/* Guest AT_SYMLINK_NOFOLLOW bit (0x100) to the host bit. */
static inline int l2a_host_at_nofollow(uint64_t guest_flags)
{
    if ((guest_flags & L2A_AT_SYMLINK_NOFOLLOW) == 0U) {
        return 0;
    }
#if defined(__APPLE__)
    return 0x20;
#else
    return 0x100;
#endif
}

/* Guest AT_EACCESS bit (0x200; faccessat only) to the host bit. */
static inline int l2a_host_at_eaccess(uint64_t guest_flags)
{
    if ((guest_flags & L2A_AT_EACCESS) == 0U) {
        return 0;
    }
#if defined(__APPLE__)
    return 0x10;
#else
    return 0x200;
#endif
}

/* Guest AT_REMOVEDIR bit (0x200; unlinkat only) to the host bit. */
static inline int l2a_host_at_removedir(uint64_t guest_flags)
{
    if ((guest_flags & L2A_AT_REMOVEDIR) == 0U) {
        return 0;
    }
#if defined(__APPLE__)
    return 0x80;
#else
    return 0x200;
#endif
}

#endif /* MIPS64RT_OS_ERRNO_MAP_H */
