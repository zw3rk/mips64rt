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

#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
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
extern void mips_guest_range_flush(mips64_ctx_t *ctx);

/* Shared helpers owned by src/os/syscalls.c. */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
/* Lane H2 file-mutation bodies owned by src/os/syscalls.c. */
extern int64_t mips_sc_truncate(mips64_ctx_t *ctx, uint64_t path_va,
                                uint64_t len);
extern int64_t mips_sc_ftruncate(mips64_ctx_t *ctx, uint64_t fd,
                                 uint64_t len);
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

/* Single-threaded futex minimum: WAIT mismatches get EAGAIN, matches
 * return 0 (a legal spurious wakeup); WAKE has nobody to wake. Beyond
 * WAIT/WAKE (+PRIVATE_FLAG): ENOSYS. */
int64_t mips_sc_futex(mips64_ctx_t *ctx, uint64_t uaddr, uint64_t op,
                      uint64_t val, uint64_t timeout_va, uint64_t uaddr2,
                      uint64_t val3)
{
    uint8_t *p;
    uint32_t cur;
    uint64_t cmd;

    (void)timeout_va;
    (void)uaddr2;
    (void)val3;
    if ((uaddr & 3U) != 0U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    cmd = op & ~(uint64_t)MIPS_FUTEX_PRIVATE_FLAG;
    if (cmd != (uint64_t)MIPS_FUTEX_WAIT &&
        cmd != (uint64_t)MIPS_FUTEX_WAKE) {
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    p = guest_range(ctx, uaddr, 4U, 0);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    cur = (uint32_t)getn(p, 4, ctx->is_be != 0U);
    if (cmd == (uint64_t)MIPS_FUTEX_WAIT && cur != (uint32_t)val) {
        return l2a_ret(ctx, -(int64_t)EAGAIN);
    }
    return l2a_ret(ctx, 0);
}

/* Recorded guest signal mask (no delivery until Phase 4). The kernel
 * mask is 16 bytes on both ABIs, so other sigsetsizes are -EINVAL. */
static uint64_t l2a_sigmask[2];

int64_t mips_sc_rt_sigprocmask(mips64_ctx_t *ctx, uint64_t how,
                               uint64_t set_va, uint64_t oldset_va,
                               uint64_t sigsetsize)
{
    uint8_t *p;
    int be;

    if (sigsetsize != 16U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    be = ctx->is_be != 0U;
    if (set_va != 0U) {
        uint64_t nw0;
        uint64_t nw1;

        p = guest_range(ctx, set_va, 16U, 0);
        if (p == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        /* Opaque 16-byte record in guest byte order; Phase 4 splits
         * it into words at delivery time. */
        nw0 = getn(p, 8, be);
        nw1 = getn(p + 8, 8, be);
        if (how == (uint64_t)MIPS_SIG_BLOCK) {
            l2a_sigmask[0] |= nw0;
            l2a_sigmask[1] |= nw1;
        } else if (how == (uint64_t)MIPS_SIG_UNBLOCK) {
            l2a_sigmask[0] &= ~nw0;
            l2a_sigmask[1] &= ~nw1;
        } else if (how == (uint64_t)MIPS_SIG_SETMASK) {
            l2a_sigmask[0] = nw0;
            l2a_sigmask[1] = nw1;
        } else {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
    }
    if (oldset_va != 0U) {
        p = guest_range(ctx, oldset_va, 16U, 1);
        if (p == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        putn(p, l2a_sigmask[0], 8, be);
        putn(p + 8, l2a_sigmask[1], 8, be);
    }
    return l2a_ret(ctx, 0);
}

/* Robust lists are recorded in ctx, never installed on the host:
 * single-threaded guests never contend, so the host kernel has nothing
 * to clean up. Phase 4 installs a real host-side list for threads. */
int64_t mips_sc_robust(mips64_ctx_t *ctx, int set, uint64_t a0, uint64_t a1,
                       uint64_t a2)
{
    unsigned ws = ctx->is_n32 != 0U ? 4U : 8U;
    uint8_t *hp;
    uint8_t *lp;
    int be = ctx->is_be != 0U;

    if (set) {
        if (a1 != (uint64_t)ws) {
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
    hp = guest_range(ctx, a1, (uint64_t)ws, 1);
    lp = guest_range(ctx, a2, (uint64_t)ws, 1);
    if (hp == NULL || lp == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    putn(hp, ctx->robust_list_head, ws, be);
    putn(lp, ctx->robust_list_len, ws, be);
    return l2a_ret(ctx, 0);
}

/* Vectored I/O for readv/writev/preadv/pwritev. The MIPS iovec is
 * {base, len} in the ABI word size; entries stream to the host in
 * 64-entry chunks with the offset advanced, preserving short-count
 * semantics. */
int64_t mips_sc_vec(mips64_ctx_t *ctx, uint64_t fd, uint64_t iov_va,
                    uint64_t iovcnt, uint64_t off, int is_p, int is_write)
{
    uint64_t total = 0U;
    uint64_t idx = 0U;
    uint64_t cur = off;
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
    while (idx < iovcnt) {
        struct iovec hv[64];
        uint64_t n = iovcnt - idx;
        uint64_t want = 0U;
        uint64_t k;
        ssize_t rc;

        if (n > 64U) {
            n = 64U;
        }
        for (k = 0U; k < n; k++) {
            const uint8_t *e = (const uint8_t *)mips64_guest_ptr(
                ctx, iov_va + (idx + k) * step);
            uint64_t base;
            uint64_t len;

            if (n32) {
                base = getn(e, 4, be);
                len = getn(e + 4, 4, be);
            } else {
                base = getn(e, 8, be);
                len = getn(e + 8, 8, be);
            }
            hv[k].iov_len = (size_t)len;
            want += len;
            hv[k].iov_base = guest_range(ctx, base, len, is_write ? 0 : 1);
            if (len != 0U && hv[k].iov_base == NULL) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        }
        if (is_p) {
            rc = is_write ? pwritev((int)fd, hv, (int)n, (off_t)cur) :
                            preadv((int)fd, hv, (int)n, (off_t)cur);
        } else {
            rc = is_write ? writev((int)fd, hv, (int)n) :
                            readv((int)fd, hv, (int)n);
        }
        if (rc < 0) {
            if (total != 0U) {
                if (is_write != 0) {
                    if (is_p != 0) {
                        mips_vm_file_post_write(ctx, (int)fd, off,
                                                total);
                    } else {
                        mips_vm_file_post_write_seq(ctx, (int)fd,
                                                    total);
                    }
                }
                return l2a_ret(ctx, (int64_t)total);
            }
            return l2a_ret(ctx, -(int64_t)errno);
        }
        if (rc > 0 && is_write == 0) {
            mips_guest_range_flush(ctx);
        }
        total += (uint64_t)rc;
        cur += (uint64_t)rc;
        idx += n;
        if ((uint64_t)rc < want || rc == 0) {
            break;
        }
    }
    if (total != 0U && is_write != 0) {
        if (is_p != 0) {
            mips_vm_file_post_write(ctx, (int)fd, off, total);
        } else {
            mips_vm_file_post_write_seq(ctx, (int)fd, total);
        }
    }
    return l2a_ret(ctx, (int64_t)total);
}

/* Scalar read/write (moved from syscall_min.c so the whole
 * dispatch can lease in one place): one validated guest window, one
 * host call, short counts as-is. errno translation mirrors sc_ret
 * (l2a_ret is its twin). */
int64_t mips_sc_read(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                     uint64_t count)
{
    uint8_t *host_buf;
    ssize_t n;

    if (count == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, buf, count, MIPS_PROT_WRITE)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    host_buf = (uint8_t *)mips64_guest_ptr(ctx, buf);
    n = read((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (n > 0) {
        mips_vm_pages_clear(buf, (uint64_t)n,
                            (unsigned)MIPS_VM_PAGE_COW_CLEAN);
        mips_vm_file_shared_sync(ctx, buf, (uint64_t)n);
    }
    return l2a_ret(ctx, (int64_t)n);
}

int64_t mips_sc_write(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                      uint64_t count)
{
    const uint8_t *host_buf;
    ssize_t n;

    if (count == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, buf, count, MIPS_PROT_READ)) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    host_buf = (const uint8_t *)mips64_guest_ptr(ctx, buf);
    n = write((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (n > 0) {
        mips_vm_file_post_write_seq(ctx, (int)fd, (uint64_t)n);
    }
    return l2a_ret(ctx, (int64_t)n);
}

/* Positional scalar I/O (pread64/pwrite64): one validated guest
 * window, one host call, short counts returned as-is. The
 * file-mutation hook for pwrite64 (inode size/EOF tracking) lands
 * with the Provider A wiring; until then the bytes are written and
 * truncation coherence is the caller's (ftruncate) business. */
static int64_t l2a_pio(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf_va,
                       uint64_t count, uint64_t off, int is_write)
{
    uint8_t *p;
    ssize_t rc;

    if (count == 0U) {
        return l2a_ret(ctx, 0);
    }
    p = guest_range(ctx, buf_va, count, is_write ? 0 : 1);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    rc = is_write ? pwrite((int)fd, p, (size_t)count, (off_t)off) :
                    pread((int)fd, p, (size_t)count, (off_t)off);
    if (rc < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (rc > 0 && is_write != 0) {
        mips_vm_file_post_write(ctx, (int)fd, off, (uint64_t)rc);
    }
    return l2a_ret(ctx, (int64_t)rc);
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
