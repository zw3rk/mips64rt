/*
 * src/os/errno_map.h — Guest/host ABI number translation (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * MIPS renumbers several errnos relative to asm-generic (e.g. ENOSYS 89,
 * EDEADLK 45, ENAMETOOLONG 78, EOVERFLOW 79, ELOOP 90, ENOTEMPTY 93,
 * EOPNOTSUPP 122, EDQUOT 1133).
 * Darwin renumbers several more (notably the EAGAIN 35 / EDEADLK 11
 * swap and ETIMEDOUT 60); map every host errno the current syscall
 * set can produce. The *at(2)
 * dirfd/flag values differ too (Darwin AT_FDCWD is -2, not -100;
 * NOFOLLOW/EACCESS/REMOVEDIR bits move); the l2a_host_at_* helpers
 * translate those per call flavor. static inline throughout so
 * includers that need only part of the table draw no
 * -Wunused-function errors. Shared by syscalls.c, syscall_min.c,
 * and syscalls_stat.c. Curated C11 only.
 */

#ifndef MIPS64RT_OS_ERRNO_MAP_H
#define MIPS64RT_OS_ERRNO_MAP_H

#include <errno.h>
#include <stdint.h>

/* Linux generic errno numbers (asm-generic/errno.h) to the MIPS
 * numbering (arch/mips asm/errno.h): the two agree up to 34 (and on
 * 11/EAGAIN) and diverge from ENOLCK/ENOSYS/ETIMEDOUT onward. The
 * table is generated from the two UAPI headers by name. */
static inline int32_t l2a_errno_generic_to_mips(int e)
{
    switch (e) {
    case 35:
        return 45; /* EDEADLK */
    case 36:
        return 78; /* ENAMETOOLONG */
    case 37:
        return 46; /* ENOLCK */
    case 38:
        return 89; /* ENOSYS */
    case 39:
        return 93; /* ENOTEMPTY */
    case 40:
        return 90; /* ELOOP */
    case 42:
        return 35; /* ENOMSG */
    case 43:
        return 36; /* EIDRM */
    case 44:
        return 37; /* ECHRNG */
    case 45:
        return 38; /* EL2NSYNC */
    case 46:
        return 39; /* EL3HLT */
    case 47:
        return 40; /* EL3RST */
    case 48:
        return 41; /* ELNRNG */
    case 49:
        return 42; /* EUNATCH */
    case 50:
        return 43; /* ENOCSI */
    case 51:
        return 44; /* EL2HLT */
    case 52:
        return 50; /* EBADE */
    case 53:
        return 51; /* EBADR */
    case 54:
        return 52; /* EXFULL */
    case 55:
        return 53; /* ENOANO */
    case 56:
        return 54; /* EBADRQC */
    case 57:
        return 55; /* EBADSLT */
    case 72:
        return 74; /* EMULTIHOP */
    case 74:
        return 77; /* EBADMSG */
    case 75:
        return 79; /* EOVERFLOW */
    case 76:
        return 80; /* ENOTUNIQ */
    case 77:
        return 81; /* EBADFD */
    case 78:
        return 82; /* EREMCHG */
    case 79:
        return 83; /* ELIBACC */
    case 80:
        return 84; /* ELIBBAD */
    case 81:
        return 85; /* ELIBSCN */
    case 82:
        return 86; /* ELIBMAX */
    case 83:
        return 87; /* ELIBEXEC */
    case 84:
        return 88; /* EILSEQ */
    case 85:
        return 91; /* ERESTART */
    case 86:
        return 92; /* ESTRPIPE */
    case 87:
        return 94; /* EUSERS */
    case 88:
        return 95; /* ENOTSOCK */
    case 89:
        return 96; /* EDESTADDRREQ */
    case 90:
        return 97; /* EMSGSIZE */
    case 91:
        return 98; /* EPROTOTYPE */
    case 92:
        return 99; /* ENOPROTOOPT */
    case 93:
        return 120; /* EPROTONOSUPPORT */
    case 94:
        return 121; /* ESOCKTNOSUPPORT */
    case 95:
        return 122; /* EOPNOTSUPP */
    case 96:
        return 123; /* EPFNOSUPPORT */
    case 97:
        return 124; /* EAFNOSUPPORT */
    case 98:
        return 125; /* EADDRINUSE */
    case 99:
        return 126; /* EADDRNOTAVAIL */
    case 100:
        return 127; /* ENETDOWN */
    case 101:
        return 128; /* ENETUNREACH */
    case 102:
        return 129; /* ENETRESET */
    case 103:
        return 130; /* ECONNABORTED */
    case 104:
        return 131; /* ECONNRESET */
    case 105:
        return 132; /* ENOBUFS */
    case 106:
        return 133; /* EISCONN */
    case 107:
        return 134; /* ENOTCONN */
    case 108:
        return 143; /* ESHUTDOWN */
    case 109:
        return 144; /* ETOOMANYREFS */
    case 110:
        return 145; /* ETIMEDOUT */
    case 111:
        return 146; /* ECONNREFUSED */
    case 112:
        return 147; /* EHOSTDOWN */
    case 113:
        return 148; /* EHOSTUNREACH */
    case 114:
        return 149; /* EALREADY */
    case 115:
        return 150; /* EINPROGRESS */
    case 116:
        return 151; /* ESTALE */
    case 117:
        return 135; /* EUCLEAN */
    case 118:
        return 137; /* ENOTNAM */
    case 119:
        return 138; /* ENAVAIL */
    case 120:
        return 139; /* EISNAM */
    case 121:
        return 140; /* EREMOTEIO */
    case 122:
        return 1133; /* EDQUOT */
    case 123:
        return 159; /* ENOMEDIUM */
    case 124:
        return 160; /* EMEDIUMTYPE */
    case 125:
        return 158; /* ECANCELED */
    case 126:
        return 161; /* ENOKEY */
    case 127:
        return 162; /* EKEYEXPIRED */
    case 128:
        return 163; /* EKEYREVOKED */
    case 129:
        return 164; /* EKEYREJECTED */
    case 130:
        return 165; /* EOWNERDEAD */
    case 131:
        return 166; /* ENOTRECOVERABLE */
    case 132:
        return 167; /* ERFKILL */
    case 133:
        return 168; /* EHWPOISON */
    default:
        return (int32_t)e;
    }
}

/* Host errno (Linux generic, or Darwin mapped to the Linux generic
 * number by name) to the MIPS guest errno. Every Darwin case is keyed
 * on the symbolic macro (verified against the macOS SDK sys/errno.h),
 * so a Darwin errno can never fall through into the Linux generic
 * integer table under a wrong name. Unlisted Darwin-specific errnos
 * (EBADRPC, EFTYPE, EBADMACHO, EQFULL and friends) return EIO (5);
 * the low errnos shared with Linux-generic (1..34) pass through. */
static inline int32_t l2a_errno_from_host(int host_errno)
{
#if defined(__APPLE__)
    switch (host_errno) {
#ifdef EDEADLK
    case EDEADLK:
        host_errno = 35; /* EDEADLK */
        break;
#endif
#ifdef EAGAIN
    case EAGAIN:
        host_errno = 11; /* EAGAIN (== EWOULDBLOCK) */
        break;
#endif
#ifdef EINPROGRESS
    case EINPROGRESS:
        host_errno = 115; /* EINPROGRESS */
        break;
#endif
#ifdef EALREADY
    case EALREADY:
        host_errno = 114; /* EALREADY */
        break;
#endif
#ifdef ENOTSOCK
    case ENOTSOCK:
        host_errno = 88; /* ENOTSOCK (Linux 38 is ENOSYS) */
        break;
#endif
#ifdef EDESTADDRREQ
    case EDESTADDRREQ:
        host_errno = 89; /* EDESTADDRREQ */
        break;
#endif
#ifdef EMSGSIZE
    case EMSGSIZE:
        host_errno = 90; /* EMSGSIZE */
        break;
#endif
#ifdef EPROTOTYPE
    case EPROTOTYPE:
        host_errno = 91; /* EPROTOTYPE */
        break;
#endif
#ifdef ENOPROTOOPT
    case ENOPROTOOPT:
        host_errno = 92; /* ENOPROTOOPT */
        break;
#endif
#ifdef EPROTONOSUPPORT
    case EPROTONOSUPPORT:
        host_errno = 93; /* EPROTONOSUPPORT */
        break;
#endif
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT:
        host_errno = 94; /* ESOCKTNOSUPPORT */
        break;
#endif
#ifdef ENOTSUP
    case ENOTSUP:
        host_errno = 95; /* ENOTSUP */
        break;
#endif
#ifdef EOPNOTSUPP
    case EOPNOTSUPP:
        host_errno = 95; /* EOPNOTSUPP */
        break;
#endif
#ifdef EPFNOSUPPORT
    case EPFNOSUPPORT:
        host_errno = 96; /* EPFNOSUPPORT */
        break;
#endif
#ifdef EAFNOSUPPORT
    case EAFNOSUPPORT:
        host_errno = 97; /* EAFNOSUPPORT */
        break;
#endif
#ifdef EADDRINUSE
    case EADDRINUSE:
        host_errno = 98; /* EADDRINUSE */
        break;
#endif
#ifdef EADDRNOTAVAIL
    case EADDRNOTAVAIL:
        host_errno = 99; /* EADDRNOTAVAIL */
        break;
#endif
#ifdef ENETDOWN
    case ENETDOWN:
        host_errno = 100; /* ENETDOWN */
        break;
#endif
#ifdef ENETUNREACH
    case ENETUNREACH:
        host_errno = 101; /* ENETUNREACH */
        break;
#endif
#ifdef ENETRESET
    case ENETRESET:
        host_errno = 102; /* ENETRESET */
        break;
#endif
#ifdef ECONNABORTED
    case ECONNABORTED:
        host_errno = 103; /* ECONNABORTED */
        break;
#endif
#ifdef ECONNRESET
    case ECONNRESET:
        host_errno = 104; /* ECONNRESET */
        break;
#endif
#ifdef ENOBUFS
    case ENOBUFS:
        host_errno = 105; /* ENOBUFS */
        break;
#endif
#ifdef EISCONN
    case EISCONN:
        host_errno = 106; /* EISCONN */
        break;
#endif
#ifdef ENOTCONN
    case ENOTCONN:
        host_errno = 107; /* ENOTCONN */
        break;
#endif
#ifdef ESHUTDOWN
    case ESHUTDOWN:
        host_errno = 108; /* ESHUTDOWN */
        break;
#endif
#ifdef ETOOMANYREFS
    case ETOOMANYREFS:
        host_errno = 109; /* ETOOMANYREFS */
        break;
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
        host_errno = 110; /* ETIMEDOUT */
        break;
#endif
#ifdef ECONNREFUSED
    case ECONNREFUSED:
        host_errno = 111; /* ECONNREFUSED */
        break;
#endif
#ifdef ELOOP
    case ELOOP:
        host_errno = 40; /* ELOOP */
        break;
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
        host_errno = 36; /* ENAMETOOLONG */
        break;
#endif
#ifdef EHOSTDOWN
    case EHOSTDOWN:
        host_errno = 112; /* EHOSTDOWN */
        break;
#endif
#ifdef EHOSTUNREACH
    case EHOSTUNREACH:
        host_errno = 113; /* EHOSTUNREACH */
        break;
#endif
#ifdef ENOTEMPTY
    case ENOTEMPTY:
        host_errno = 39; /* ENOTEMPTY */
        break;
#endif
#ifdef EPROCLIM
    case EPROCLIM: /* no Linux counterpart; closest is EAGAIN */
        host_errno = 11; /* EAGAIN */
        break;
#endif
#ifdef EUSERS
    case EUSERS:
        host_errno = 87; /* EUSERS */
        break;
#endif
#ifdef EDQUOT
    case EDQUOT:
        host_errno = 122; /* EDQUOT */
        break;
#endif
#ifdef ESTALE
    case ESTALE:
        host_errno = 116; /* ESTALE */
        break;
#endif
#ifdef EREMOTE
    case EREMOTE: /* no Linux counterpart; closest is ELOOP */
        host_errno = 40; /* ELOOP */
        break;
#endif
#ifdef ENOLCK
    case ENOLCK:
        host_errno = 37; /* ENOLCK */
        break;
#endif
#ifdef ENOSYS
    case ENOSYS:
        host_errno = 38; /* ENOSYS */
        break;
#endif
#ifdef EOVERFLOW
    case EOVERFLOW:
        host_errno = 75; /* EOVERFLOW */
        break;
#endif
#ifdef ECANCELED
    case ECANCELED:
        host_errno = 125; /* ECANCELED */
        break;
#endif
#ifdef EIDRM
    case EIDRM:
        host_errno = 43; /* EIDRM */
        break;
#endif
#ifdef ENOMSG
    case ENOMSG:
        host_errno = 42; /* ENOMSG */
        break;
#endif
#ifdef EILSEQ
    case EILSEQ:
        host_errno = 84; /* EILSEQ */
        break;
#endif
#ifdef EBADMSG
    case EBADMSG:
        host_errno = 74; /* EBADMSG */
        break;
#endif
#ifdef EMULTIHOP
    case EMULTIHOP:
        host_errno = 72; /* EMULTIHOP */
        break;
#endif
#ifdef ENODATA
    case ENODATA:
        host_errno = 61; /* ENODATA */
        break;
#endif
#ifdef ENOLINK
    case ENOLINK:
        host_errno = 67; /* ENOLINK */
        break;
#endif
#ifdef ENOSR
    case ENOSR:
        host_errno = 63; /* ENOSR */
        break;
#endif
#ifdef ENOSTR
    case ENOSTR:
        host_errno = 60; /* ENOSTR */
        break;
#endif
#ifdef EPROTO
    case EPROTO:
        host_errno = 71; /* EPROTO */
        break;
#endif
#ifdef ETIME
    case ETIME:
        host_errno = 62; /* ETIME */
        break;
#endif
#ifdef ENOTRECOVERABLE
    case ENOTRECOVERABLE:
        host_errno = 131; /* ENOTRECOVERABLE */
        break;
#endif
#ifdef EOWNERDEAD
    case EOWNERDEAD:
        host_errno = 130; /* EOWNERDEAD */
        break;
#endif
#ifdef ENOATTR
    case ENOATTR: /* Darwin 93: xattr missing; Linux reports ENODATA */
        host_errno = 61; /* ENODATA (also 61 on MIPS) */
        break;
#endif
    default:
        /* Unlisted Darwin-specific errnos (EBADRPC 72, EFTYPE 79,
         * EBADMACHO 88, EQFULL 106, ...) must never reach the Linux
         * generic table (72 would misread as EMULTIHOP, 79 as
         * ELIBACC, 93 as EPROTONOSUPPORT, ...): report EIO. The low
         * errnos (1..34 save the EDEADLK/EAGAIN swap cased above)
         * coincide on Darwin, Linux-generic, and MIPS, so they keep
         * the identity pass-through below. */
        if (host_errno >= 35) {
            return 5; /* EIO */
        }
        break;
    }
#endif
    return l2a_errno_generic_to_mips(host_errno);
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
