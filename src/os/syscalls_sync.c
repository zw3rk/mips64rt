/*
 * src/os/syscalls_sync.c — Futex, signal mask, robust lists, and
 * vectored I/O (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-threaded futex minimum (WAIT/WAKE), the recorded
 * rt_sigprocmask mask (no delivery until Phase 4), set_robust_list /
 * get_robust_list (recorded in ctx, never installed on the host), and
 * readv/writev/preadv/pwritev over the MIPS {base, len} iovec (16
 * bytes N64, 8 bytes N32, verified live under qemu). Shared helpers
 * (l2a_ret, putn, getn, guest_range) live in src/os/syscalls.c.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/quiesce.h"
#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* Lane U12 Provider A write hooks (src/vm/vm_file.c). */
extern void mips_vm_file_post_write(mips64_ctx_t *ctx, int fd, uint64_t off,
                                    uint64_t n);
extern void mips_vm_file_post_write_seq(mips64_ctx_t *ctx, int fd,
                                        uint64_t n);
extern void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va,
                                     uint64_t len);
extern void mips_llsc_note_write(uint64_t addr, uint64_t size);
extern void mips_llsc_write_lock(void);
extern void mips_llsc_write_unlock(void);

/* Shared helpers owned by src/os/syscalls.c. */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
/* Lane H2 file-mutation bodies owned by src/os/syscalls.c. */
extern int64_t mips_sc_truncate(mips64_ctx_t *ctx, uint64_t path_va,
                                uint64_t len);
extern int64_t mips_sc_ftruncate(mips64_ctx_t *ctx, uint64_t fd,
                                 uint64_t len);
extern int64_t mips_sc_unlink(mips64_ctx_t *ctx, uint64_t path_va);
extern int64_t mips_sc_symlinkat(mips64_ctx_t *ctx, uint64_t target_va,
                                 uint64_t dirfd, uint64_t link_va);
/* TIF_FIXADE control hook owned by the OS backend TU. */
extern int mips_fixade_ctl(mips64_ctx_t *ctx, unsigned long cmd,
                           unsigned long arg);

/* Guest sysmips(2) numbers, absent from the frozen
 * src/os/syscall_nr.h (added here with the kernel-header values:
 * N64 5199 = 5000+199, N32 6199 = 6000+199; arch/mips UAPI
 * asm/unistd_{n64,n32}.h, verified against Debian trixie kernel
 * headers). */
#define MIPS64_NR_sysmips 5199u
#define MIPS64_NR32_sysmips 6199u

/* Guest sysmips MIPS_FIXADE command (arch/mips UAPI asm/sysmips.h;
 * matches MIPS_SYS_MIPS_FIXADE in src/os/backend.h). */
#define MIPS_SYNC_FIXADE 7u

/* MIPS futex ops (linux/futex.h, arch-independent) and signal-mask ops
 * (UAPI asm/signal.h: 1/2/3 on MIPS, unlike asm-generic 0/1/2). */
#define MIPS_FUTEX_WAIT         0
#define MIPS_FUTEX_WAKE         1
#define MIPS_FUTEX_PRIVATE_FLAG 0x80
#define MIPS_SIG_BLOCK          1
#define MIPS_SIG_UNBLOCK        2
#define MIPS_SIG_SETMASK        3

/* Robust lists are recorded in ctx, never installed on the host.
 * len is sizeof(struct robust_list_head): 24 on N64 (3x8), 12 on N32. */
int64_t mips_sc_robust(mips64_ctx_t *ctx, int set, uint64_t a0, uint64_t a1,
                       uint64_t a2)
{
    unsigned ws = ctx->is_n32 != 0U ? 4U : 8U;
    int be = ctx->is_be != 0U;

    if (set) {
        if (a1 != (uint64_t)(3U * ws)) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        ctx->robust_list_head = a0;
        ctx->robust_list_len = a1;
        return l2a_ret(ctx, 0);
    }
    /* Only the calling thread's own list; anything else needs ptrace. */
    if (a0 != 0U) {
        return l2a_ret(ctx, -(int64_t)EPERM);
    }
    {
        uint8_t hb[8];
        uint8_t lb[8];

        putn(hb, ctx->robust_list_head, ws, be);
        putn(lb, ctx->robust_list_len, ws, be);
        if (mips_sc_copyout(ctx, a1, hb, (uint64_t)ws) != 0 ||
            mips_sc_copyout(ctx, a2, lb, (uint64_t)ws) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

#define L2A_IO_MAX UINT64_C(0x7FFFF000)

static void l2a_commit_guest_write(mips64_ctx_t *ctx, uint64_t va,
                                   const uint8_t *src, uint64_t n)
{
    /* Single shared commit path (R3-1): range validation, LL-bit
     * clearing, LL reservation invalidation, COW clearing, code
     * retirement, and shared-file sync live in mips_sc_copyout. */
    (void)mips_sc_copyout(ctx, va, src, n);
}

static void l2a_vec_free(uint8_t **kbuf, uint64_t n)
{
    uint64_t k;

    for (k = 0U; k < n; k++) {
        free(kbuf[k]);
    }
}

static void l2a_vec_free_desc(struct iovec *hv, uint64_t *gva,
                              uint64_t *glen, uint8_t **kbuf,
                              uint64_t iovcnt)
{
    l2a_vec_free(kbuf, iovcnt);
    if (iovcnt > 64U) {
        free(hv);
        free(gva);
        free(glen);
        free(kbuf);
    }
}

/* Copy staged read bytes into guest destinations (R3-4): returns
 * the committed byte count, or -EFAULT when nothing was committed.
 * A later destination fault (mapping changed across the blocking
 * host call) reports the bytes already committed instead of hiding
 * them behind an error. Raw return (the caller applies l2a_ret). */
int64_t l2a_vec_copyout(mips64_ctx_t *ctx, const uint64_t *gva,
                        const uint64_t *glen, uint8_t **kbuf,
                        uint64_t iovcnt, uint64_t nbytes)
{
    uint64_t rem = nbytes;
    uint64_t committed = 0U;
    uint64_t k;

    for (k = 0U; k < iovcnt && rem > 0U; k++) {
        uint64_t take = glen[k] < rem ? glen[k] : rem;

        if (take == 0U) {
            continue;
        }
        if (!mips_mem_ok(ctx, gva[k], take, MIPS_PROT_WRITE)) {
            break;
        }
        l2a_commit_guest_write(ctx, gva[k], kbuf[k], take);
        committed += take;
        rem -= take;
    }
    if (rem > 0U) {
        return committed != 0U ? (int64_t)committed : -(int64_t)EFAULT;
    }
    return (int64_t)(nbytes - rem);
}

/* Vectored I/O for readv/writev/preadv/pwritev. The MIPS iovec is
 * {base, len} in the ABI word size. The complete guest vector is
 * imported and issued as a single host call (R3-3): splitting a
 * 65-entry writev into two host calls would emit two datagrams and
 * lose small-pipe-write atomicity. The L2A_IO_MAX cap applies to the
 * aggregate request, not to each element. Staging buffers allow
 * releasing the quiescence lease across the blocking host call;
 * guest mappings are revalidated before copyout, and bytes already
 * committed are reported when a later destination faults (R3-4). */
int64_t mips_sc_vec(mips64_ctx_t *ctx, uint64_t fd, uint64_t iov_va,
                    uint64_t iovcnt, uint64_t off, int is_p, int is_write)
{
    struct iovec hv_st[64];
    uint64_t gva_st[64];
    uint64_t glen_st[64];
    uint8_t *kbuf_st[64];
    struct iovec *hv = hv_st;
    uint64_t *gva = gva_st;
    uint64_t *glen = glen_st;
    uint8_t **kbuf = kbuf_st;
    uint64_t want = 0U;
    uint64_t k;
    ssize_t rc;
    int saved_err;
    int be = ctx->is_be != 0U;
    int n32 = ctx->is_n32 != 0U;
    uint64_t step = n32 ? 8U : 16U;

    if (iovcnt > (uint64_t)IOV_MAX) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (iovcnt == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, iov_va, iovcnt * step,
                      (uint32_t)MIPS_PROT_READ)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    if (iovcnt > 64U) {
        hv = (struct iovec *)calloc((size_t)iovcnt, sizeof *hv);
        gva = (uint64_t *)calloc((size_t)iovcnt, sizeof *gva);
        glen = (uint64_t *)calloc((size_t)iovcnt, sizeof *glen);
        kbuf = (uint8_t **)calloc((size_t)iovcnt, sizeof *kbuf);
        if (hv == NULL || gva == NULL || glen == NULL || kbuf == NULL) {
            free(hv);
            free(gva);
            free(glen);
            free(kbuf);
            return l2a_ret(ctx, -(int64_t)ENOMEM);
        }
    } else {
        memset(kbuf_st, 0, sizeof kbuf_st);
    }
    for (k = 0U; k < iovcnt; k++) {
        const uint8_t *e = (const uint8_t *)mips64_guest_ptr(
            ctx, iov_va + k * step);
        uint64_t base;
        uint64_t len;

        if (n32) {
            base = getn(e, 4, be);
            len = getn(e + 4, 4, be);
        } else {
            base = getn(e, 8, be);
            len = getn(e + 8, 8, be);
        }
        if (want >= L2A_IO_MAX) {
            len = 0U;
        } else if (len > L2A_IO_MAX - want) {
            len = L2A_IO_MAX - want;
        }
        gva[k] = base;
        glen[k] = len;
        hv[k].iov_len = (size_t)len;
        hv[k].iov_base = NULL;
        if (len == 0U) {
            continue;
        }
        if (!mips_mem_ok(ctx, base, len,
                         is_write ? MIPS_PROT_READ : MIPS_PROT_WRITE)) {
            l2a_vec_free_desc(hv, gva, glen, kbuf, iovcnt);
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        kbuf[k] = (uint8_t *)malloc((size_t)len);
        if (kbuf[k] == NULL) {
            l2a_vec_free_desc(hv, gva, glen, kbuf, iovcnt);
            return l2a_ret(ctx, -(int64_t)ENOMEM);
        }
        if (is_write != 0) {
            memcpy(kbuf[k], mips64_guest_ptr(ctx, base), (size_t)len);
        }
        hv[k].iov_base = kbuf[k];
        want += len;
    }
    mips_qs_lease_exit(ctx);
    if (is_p) {
        rc = is_write ? pwritev((int)fd, hv, (int)iovcnt, (off_t)off) :
                        preadv((int)fd, hv, (int)iovcnt, (off_t)off);
    } else {
        rc = is_write ? writev((int)fd, hv, (int)iovcnt) :
                        readv((int)fd, hv, (int)iovcnt);
    }
    saved_err = errno;
    mips_qs_lease_enter(ctx);
    if (rc < 0) {
        l2a_vec_free_desc(hv, gva, glen, kbuf, iovcnt);
        return l2a_ret(ctx, -(int64_t)saved_err);
    }
    if (rc > 0 && is_write == 0) {
        int64_t cr = l2a_vec_copyout(ctx, gva, glen, kbuf, iovcnt,
                                     (uint64_t)rc);

        l2a_vec_free_desc(hv, gva, glen, kbuf, iovcnt);
        return l2a_ret(ctx, cr);
    }
    l2a_vec_free_desc(hv, gva, glen, kbuf, iovcnt);
    if (rc > 0 && is_write != 0) {
        if (is_p != 0) {
            mips_vm_file_post_write(ctx, (int)fd, off, (uint64_t)rc);
        } else {
            mips_vm_file_post_write_seq(ctx, (int)fd, (uint64_t)rc);
        }
    }
    return l2a_ret(ctx, (int64_t)rc);
}

/* Scalar read/write and pread64/pwrite64: stage through a temporary
 * host buffer so the quiescence lease can be released across blocking
 * host I/O and guest mappings are revalidated before copyout. */
static int64_t l2a_io_common(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                             uint64_t count, uint64_t off, int is_p,
                             int is_write)
{
    uint8_t sbuf[4096];
    uint8_t *kbuf = sbuf;
    uint64_t cap;
    ssize_t n;
    int saved_err;

    if (count == 0U) {
        return l2a_ret(ctx, 0);
    }
    cap = count > L2A_IO_MAX ? L2A_IO_MAX : count;
    if (!mips_mem_ok(ctx, buf, cap,
                     is_write ? MIPS_PROT_READ : MIPS_PROT_WRITE)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    if (cap > sizeof sbuf) {
        kbuf = (uint8_t *)malloc((size_t)cap);
        if (kbuf == NULL) {
            kbuf = sbuf;
            cap = sizeof sbuf;
        }
    }
    if (is_write != 0) {
        memcpy(kbuf, mips64_guest_ptr(ctx, buf), (size_t)cap);
    }
    mips_qs_lease_exit(ctx);
    if (is_p != 0) {
        n = is_write ? pwrite((int)fd, kbuf, (size_t)cap, (off_t)off) :
                       pread((int)fd, kbuf, (size_t)cap, (off_t)off);
    } else {
        n = is_write ? write((int)fd, kbuf, (size_t)cap) :
                       read((int)fd, kbuf, (size_t)cap);
    }
    saved_err = errno;
    mips_qs_lease_enter(ctx);
    if (n < 0) {
        if (kbuf != sbuf) {
            free(kbuf);
        }
        return l2a_ret(ctx, -(int64_t)saved_err);
    }
    if (n > 0) {
        if (is_write == 0) {
            if (!mips_mem_ok(ctx, buf, (uint64_t)n, MIPS_PROT_WRITE)) {
                if (kbuf != sbuf) {
                    free(kbuf);
                }
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
            l2a_commit_guest_write(ctx, buf, kbuf, (uint64_t)n);
        } else if (is_p != 0) {
            mips_vm_file_post_write(ctx, (int)fd, off, (uint64_t)n);
        } else {
            mips_vm_file_post_write_seq(ctx, (int)fd, (uint64_t)n);
        }
    }
    if (kbuf != sbuf) {
        free(kbuf);
    }
    return l2a_ret(ctx, (int64_t)n);
}

int64_t mips_sc_read(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                     uint64_t count)
{
    return l2a_io_common(ctx, fd, buf, count, 0U, 0, 0);
}

int64_t mips_sc_write(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                      uint64_t count)
{
    return l2a_io_common(ctx, fd, buf, count, 0U, 0, 1);
}

static int64_t l2a_pio(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf_va,
                       uint64_t count, uint64_t off, int is_write)
{
    return l2a_io_common(ctx, fd, buf_va, count, off, 1, is_write);
}

/* Lane H2 file-mutation + sysmips dispatch tail: truncate, ftruncate,
 * pread64, pwrite64, and sysmips(MIPS_FIXADE). *claimed reports 1
 * when nr was handled (the return value is already guest-convention
 * adjusted) and 0 when the caller must keep dispatching (the return
 * is then -ENOSYS). */
int64_t mips_sc_file_extra(mips64_ctx_t *ctx, int n32, uint64_t nr,
                           uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, int *claimed)
{
    if (claimed != NULL) {
        *claimed = 0;
    }
    if (ctx == NULL || claimed == NULL) {
        return -(int64_t)EINVAL;
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_truncate : MIPS64_NR_truncate)) {
        *claimed = 1;
        return mips_sc_truncate(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_ftruncate
                             : MIPS64_NR_ftruncate)) {
        *claimed = 1;
        return mips_sc_ftruncate(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_unlink : MIPS64_NR_unlink)) {
        *claimed = 1;
        return mips_sc_unlink(ctx, a0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_symlinkat
                             : MIPS64_NR_symlinkat)) {
        *claimed = 1;
        return mips_sc_symlinkat(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_pread64 : MIPS64_NR_pread64)) {
        *claimed = 1;
        return l2a_pio(ctx, a0, a1, a2, a3, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_pwrite64 : MIPS64_NR_pwrite64)) {
        *claimed = 1;
        return l2a_pio(ctx, a0, a1, a2, a3, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_sysmips : MIPS64_NR_sysmips)) {
        int frc;

        *claimed = 1;
        /* Only the FIXADE control is implemented; SETNAME,
         * FLUSH_CACHE, and unknown commands are -EINVAL, matching
         * Linux sysmips(2). */
        if (a0 != (uint64_t)MIPS_SYNC_FIXADE) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        frc = mips_fixade_ctl(ctx, (unsigned long)a0, (unsigned long)a1);
        if (frc != 0) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        return l2a_ret(ctx, 0);
    }
    return -(int64_t)ENOSYS;
}
