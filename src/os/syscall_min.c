/*
 * src/os/syscall_min.c — Minimal N64/N32 syscall dispatcher (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the Phase 1 subset per SPEC 2.2 and the phase-1 lane card:
 * exit, exit_group, read, write, brk, mmap, munmap, mprotect, uname,
 * set_tid_address, plus the RC1 test-harness minimum: fork, the
 * fork-equivalent clone subset musl's fork() uses, and wait4 with NULL
 * rusage (full clone/threads/signals stay Phase 4, lane L4b). Dual
 * numbers from src/os/syscall_nr.h (N64 base 5000, N32 base 6000)
 * selected by ctx->is_n32. Unknown syscalls report -ENOSYS with $a3=1.
 *
 * N64/N32 convention (E01 FINDINGS): the number arrives in $v0, args
 * 1..6 in $a0..$a5 (full 64-bit registers, no O32 stack slots, no
 * even-pair rule); success is $a3=0 with $v0=ret, error is $a3=1 with
 * $v0=positive MIPS errno. The return value of mips_syscall is the raw
 * host-style result (negative errno on error) for the engine; the guest
 * registers always follow the $a3 convention above.
 *
 * errno mapping: MIPS shares asm-generic errno values for every error
 * produced here except ENOSYS (MIPS asm/errno.h: ENOSYS 89 vs host 38);
 * mips_errno_from_host maps 38->89 and passes the rest through.
 *
 * Guest mapping flags are MIPS N64/N32 values (arch/mips UAPI
 * asm/mman.h): MAP_SHARED 0x01, MAP_PRIVATE 0x02, MAP_FIXED 0x10,
 * MAP_ANONYMOUS 0x20. The O32-compat MAP_ANONYMOUS alias 0x800 is also
 * accepted as anonymous. Mappings live in the Phase 1 reservation via
 * the mips_mem_* helpers (src/os/mem.c); MAP_FIXED_NOREPLACE is
 * honoured, file-backed pages are filled from the fd (Linux semantics:
 * file content with zeros past EOF), and the host side never gains
 * PROT_EXEC (W^X).
 */

#include "core/cpu.h"

#include "os/syscall_nr.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* Region helpers owned by src/os/mem.c (lane L1c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
/* Static-libc layer owned by src/os/syscalls.c (lane L2a). Each entry
 * takes the decoded guest args and returns the raw host result with the
 * $a3 convention already recorded in the guest regs. */
extern int64_t mips_sc_openat(mips64_ctx_t *ctx, uint64_t dirfd,
                              uint64_t path_va, uint64_t flags,
                              uint64_t mode);
extern int64_t mips_sc_fcntl(mips64_ctx_t *ctx, uint64_t fd, uint64_t cmd,
                             uint64_t arg);
extern int64_t mips_sc_clock_gettime(mips64_ctx_t *ctx, uint64_t clk,
                                     uint64_t ts_va, int is64);
extern int64_t mips_sc_nanosleep(mips64_ctx_t *ctx, uint64_t clk,
                                 uint64_t req_va, uint64_t rem_va, int is64,
                                 int use_clock);
extern int64_t mips_sc_getrandom(mips64_ctx_t *ctx, uint64_t buf_va,
                                 uint64_t len, uint64_t flags);
extern int64_t mips_sc_futex(mips64_ctx_t *ctx, uint64_t uaddr, uint64_t op,
                             uint64_t val, uint64_t timeout_va,
                             uint64_t uaddr2, uint64_t val3);
extern int64_t mips_sc_rt_sigprocmask(mips64_ctx_t *ctx, uint64_t how,
                                      uint64_t set_va, uint64_t oldset_va,
                                      uint64_t sigsetsize);
extern int64_t mips_sc_ioctl(mips64_ctx_t *ctx, uint64_t fd, uint64_t cmd,
                             uint64_t arg);
extern int64_t mips_sc_lseek(mips64_ctx_t *ctx, uint64_t fd, uint64_t offset,
                             uint64_t whence);
extern int64_t mips_sc_stat_at(mips64_ctx_t *ctx, uint64_t dirfd,
                               uint64_t path_va, uint64_t buf_va,
                               uint64_t flags);
extern int64_t mips_sc_fstat(mips64_ctx_t *ctx, uint64_t fd,
                             uint64_t buf_va);
extern int64_t mips_sc_statx(mips64_ctx_t *ctx, uint64_t dirfd,
                             uint64_t path_va, uint64_t flags, uint64_t mask,
                             uint64_t buf_va);
extern int64_t mips_sc_getdents64(mips64_ctx_t *ctx, uint64_t fd,
                                  uint64_t dirp_va, uint64_t count);
extern int64_t mips_sc_readlinkat(mips64_ctx_t *ctx, uint64_t dirfd,
                                  uint64_t path_va, uint64_t buf_va,
                                  uint64_t size);
extern int64_t mips_sc_access_at(mips64_ctx_t *ctx, uint64_t dirfd,
                                 uint64_t path_va, uint64_t mode,
                                 uint64_t flags);
extern int64_t mips_sc_pipe2(mips64_ctx_t *ctx, uint64_t fds_va,
                             uint64_t flags);
extern int64_t mips_sc_dup(mips64_ctx_t *ctx, uint64_t oldfd, uint64_t newfd,
                           uint64_t flags, int op);
extern int64_t mips_sc_getid(mips64_ctx_t *ctx, int which);
extern int64_t mips_sc_robust(mips64_ctx_t *ctx, int set, uint64_t a0,
                              uint64_t a1, uint64_t a2);
extern int64_t mips_sc_unlinkat(mips64_ctx_t *ctx, uint64_t dirfd,
                                uint64_t path_va, uint64_t flags);
extern int64_t mips_sc_close_range(mips64_ctx_t *ctx, uint64_t first,
                                   uint64_t last, uint64_t flags);
extern int64_t mips_sc_vec(mips64_ctx_t *ctx, uint64_t fd, uint64_t iov_va,
                           uint64_t iovcnt, uint64_t off, int is_p,
                           int is_write);
/* Phase 4 seams (lanes L4a/L4b/L4c). The (ctx, sp) signal seams read
 * their arguments from the guest registers; sp is reserved. */
extern int64_t mips_sc_rt_sigaction(mips64_ctx_t *ctx, uint64_t sp);
extern int64_t mips_l4a_rt_sigprocmask(mips64_ctx_t *ctx, uint64_t sp);
extern int64_t mips_sc_sigaltstack(mips64_ctx_t *ctx, uint64_t sp);
extern int64_t mips_rt_sigreturn(mips64_ctx_t *ctx);
extern int mips_signal_has_handler(int signo);
extern int mips_raise_guest(mips64_ctx_t *ctx, int signo,
                            uint64_t fault_addr);
extern int64_t mips_sc_sig_syscall(mips64_ctx_t *ctx, uint64_t nr,
                                   uint64_t a0, uint64_t a1, uint64_t a2,
                                   uint64_t a3);
extern int64_t mips_clone_full(mips64_ctx_t *ctx, uint64_t flags,
                               uint64_t stack_va, uint64_t parent_tid_va,
                               uint64_t tls_va, uint64_t child_tid_va);
extern int64_t mips_futex_op(mips64_ctx_t *ctx, uint64_t uaddr, uint64_t op,
                             uint64_t val, uint64_t timeout_va,
                             uint64_t uaddr2, uint64_t val3);
extern int64_t mips_sc_exec(mips64_ctx_t *ctx, uint64_t nr, uint64_t path_va,
                            uint64_t argv_va, uint64_t envp_va, uint64_t a3,
                            uint64_t a4);
extern int64_t mips_sc_waitid(mips64_ctx_t *ctx, uint64_t which, uint64_t pid,
                              uint64_t infop_va, uint64_t options,
                              uint64_t rusage_va);
extern int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                        uint32_t prot, const char *tag);
extern int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
extern int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            uint32_t prot);
extern int64_t mips_mem_remap(mips64_ctx_t *ctx, uint64_t old_va,
                              uint64_t old_len, uint64_t new_len,
                              uint64_t flags, uint64_t new_va);

/* Guest prot bits (Linux asm-generic, shared with the target). */
#define MIPS_PROT_READ 1U
#define MIPS_PROT_WRITE 2U
#define MIPS_PROT_EXEC 4U

/* Guest mmap flags (MIPS N64/N32 UAPI asm/mman.h). */
#define MIPS_MAP_SHARED 0x01U
#define MIPS_MAP_PRIVATE 0x02U
#define MIPS_MAP_FIXED 0x10U
#define MIPS_MAP_ANONYMOUS 0x20U
#define MIPS_MAP_ANON_O32 0x800U /* O32-compat alias, accepted as anon */
#define MIPS_MAP_FIXED_NOREPLACE 0x100000U

/* MIPS new_utsname: 6 fields of 65 bytes (Linux UAPI, all arches). */
#define MIPS_UTS_FIELD 65U
#define MIPS_UTS_SIZE (6U * MIPS_UTS_FIELD)

static int32_t mips_errno_from_host(int host_errno)
{
    if (host_errno == 38) {
        return 89; /* MIPS ENOSYS (asm/errno.h), not asm-generic 38 */
    }
    return (int32_t)host_errno;
}

/* Record the $a3 convention in the guest regs; return raw host value. */
static int64_t sc_ret(mips64_ctx_t *ctx, int64_t raw)
{
    if (raw < 0) {
        int64_t e = -raw;

        if (e > 4095) {
            e = 4095;
        }
        ctx->gpr[MIPS64_REG_V0] =
            (uint64_t)mips_errno_from_host((int)e);
        ctx->gpr[MIPS64_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS64_REG_V0] = (uint64_t)raw;
        ctx->gpr[MIPS64_REG_A3] = 0U;
    }
    return raw;
}

static void copy_uts_field(uint8_t *dst, const char *src)
{
    size_t i;

    for (i = 0; i < MIPS_UTS_FIELD; i++) {
        if (src[i] == '\0') {
            break;
        }
        dst[i] = (uint8_t)src[i];
    }
    for (; i < MIPS_UTS_FIELD; i++) {
        dst[i] = 0U;
    }
}

static int64_t sc_read(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                       uint64_t count)
{
    uint8_t *host_buf;
    ssize_t n;

    if (count == 0U) {
        return sc_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, buf, count, MIPS_PROT_WRITE)) {
        return sc_ret(ctx, -EFAULT);
    }
    host_buf = (uint8_t *)mips64_guest_ptr(ctx, buf);
    n = read((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    return sc_ret(ctx, (int64_t)n);
}

static int64_t sc_write(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                        uint64_t count)
{
    const uint8_t *host_buf;
    ssize_t n;

    if (count == 0U) {
        return sc_ret(ctx, 0);
    }
    if (!mips_mem_ok(ctx, buf, count, MIPS_PROT_READ)) {
        return sc_ret(ctx, -EFAULT);
    }
    host_buf = (const uint8_t *)mips64_guest_ptr(ctx, buf);
    n = write((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    return sc_ret(ctx, (int64_t)n);
}

static int64_t sc_brk(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t aligned;
    uint64_t have;
    int rc;

    if (addr == 0U || addr == ctx->brk_curr) {
        return sc_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (addr <= ctx->brk_base) {
        return sc_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (addr < ctx->brk_curr) {
        ctx->brk_curr = addr; /* shrink: keep mappings, move the mark */
        return sc_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (ctx->brk_base == 0U) {
        return sc_ret(ctx, (int64_t)ctx->brk_curr);
    }
    aligned = (addr + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
    if (aligned < addr) {
        return sc_ret(ctx, -(int64_t)ENOMEM);
    }
    if (aligned > ctx->task_size) {
        return sc_ret(ctx, -(int64_t)ENOMEM);
    }
    /* RC1 integration: map only the not-yet-mapped extension. */
    have = ctx->brk_curr > ctx->brk_base ?
           ((ctx->brk_curr + (MIPS64_PAGE_SIZE - 1U)) &
            MIPS64_PAGE_MASK) : ctx->brk_base;
    if (aligned > have) {
        rc = mips_mem_map(ctx, have, aligned - have,
                          MIPS_PROT_READ | MIPS_PROT_WRITE, "heap");
        if (rc == -EEXIST &&
            !mips_mem_ok(ctx, have, aligned - have,
                         MIPS_PROT_READ | MIPS_PROT_WRITE)) {
            return sc_ret(ctx, -(int64_t)ENOMEM);
        }
        if (rc != 0 && rc != -EEXIST) {
            return sc_ret(ctx, -(int64_t)rc);
        }
    }
    ctx->brk_curr = addr;
    return sc_ret(ctx, (int64_t)ctx->brk_curr);
}

/* First gap of at least size bytes at or after cand (page granular). */
static uint64_t hole_from(const mips64_ctx_t *ctx, uint64_t cand,
                          uint64_t size)
{
    size_t i;

    if (cand + size < cand || cand + size > ctx->task_size) {
        return 0U;
    }
    for (i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].end <= cand) {
            continue;
        }
        if (ctx->regions[i].start >= cand + size) {
            return cand;
        }
        cand = ctx->regions[i].end;
        if (cand + size < cand) {
            return 0U;
        }
    }
    if (cand + size < cand || cand + size > ctx->task_size) {
        return 0U;
    }
    return cand;
}

/* Unhinted search starts at mmap_base and falls back to it when the
 * hint finds nothing. VA 0 is never handed out (Linux reserves it);
 * an unset mmap_base degrades to the first page for the same reason. */
static uint64_t pick_hole(mips64_ctx_t *ctx, uint64_t hint, uint64_t size)
{
    uint64_t base = ctx->mmap_base != 0U ? ctx->mmap_base
                                         : MIPS64_PAGE_SIZE;
    uint64_t va;

    if (hint != 0U) {
        va = hole_from(ctx, hint & MIPS64_PAGE_MASK, size);
        if (va != 0U) {
            return va;
        }
    }
    va = hole_from(ctx, base, size);
    if (va == 0U) {
        return 0U;
    }
    return va;
}

static int64_t sc_mmap(mips64_ctx_t *ctx, uint64_t addr, uint64_t len,
                       uint64_t prot, uint64_t flags, uint64_t fd,
                       uint64_t offset)
{
    uint64_t size;
    uint64_t va;
    int rc;
    int anon;

    if (len == 0U || (prot & ~(uint64_t)7U) != 0U) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    size = (len + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
    if (size == 0U || size > ctx->task_size) {
        return sc_ret(ctx, -(int64_t)ENOMEM);
    }
    anon = (flags & (MIPS_MAP_ANONYMOUS | MIPS_MAP_ANON_O32)) != 0U;
    if (!anon && (offset & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    if ((flags & MIPS_MAP_FIXED) != 0U) {
        if ((addr & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        va = addr;
        if (va + size < va || va + size > ctx->task_size) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        rc = mips_mem_unmap(ctx, va, size);
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
        rc = mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map");
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
    } else if ((flags & MIPS_MAP_FIXED_NOREPLACE) != 0U && addr != 0U) {
        if ((addr & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        va = addr;
        if (va + size < va || va + size > ctx->task_size) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        if (mips_mem_ok(ctx, va, 1U, 0U) ||
            hole_from(ctx, va, size) != va) {
            return sc_ret(ctx, -(int64_t)EEXIST);
        }
        rc = mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map");
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
    } else {
        va = pick_hole(ctx, addr, size);
        if (va == 0U) {
            return sc_ret(ctx, -(int64_t)ENOMEM);
        }
        rc = mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map");
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
    }
    if (!anon) {
        /* File-backed maps always show file content (Linux semantics:
         * pages are filled from the file with zeros past EOF). The
         * region is writable exactly when the guest asked for it; a
         * read-only file fill goes through a temporary host-side
         * writable window so the fill itself never faults. */
        uint8_t *dst = (uint8_t *)mips64_guest_ptr(ctx, va);
        uint64_t left = size;
        uint64_t off = 0U;
        int made_writable = 0;

        if (((uint32_t)prot & MIPS_PROT_WRITE) == 0U) {
            if (mprotect(dst, (size_t)size, PROT_READ | PROT_WRITE) != 0) {
                (void)mips_mem_unmap(ctx, va, size);
                return sc_ret(ctx, -(int64_t)EFAULT);
            }
            made_writable = 1;
        }
        while (left > 0U) {
            ssize_t got;

            if (offset + off < off) {
                break;
            }
            got = pread((int)fd, dst + off, (size_t)left,
                        (off_t)(offset + off));
            if (got < 0) {
                int e = errno;

                if (made_writable) {
                    (void)mprotect(dst, (size_t)size, PROT_READ);
                }
                (void)mips_mem_unmap(ctx, va, size);
                return sc_ret(ctx, -(int64_t)e);
            }
            if (got == 0) {
                break;
            }
            off += (uint64_t)got;
            left -= (uint64_t)got;
        }
        if (made_writable &&
            mprotect(dst, (size_t)size, PROT_READ) != 0) {
            (void)mips_mem_unmap(ctx, va, size);
            return sc_ret(ctx, -(int64_t)ENOMEM);
        }
    }
    return sc_ret(ctx, (int64_t)va);
}

static int64_t sc_uname(mips64_ctx_t *ctx, uint64_t va)
{
    uint8_t *dst;
    struct utsname un;

    if (!mips_mem_ok(ctx, va, MIPS_UTS_SIZE, MIPS_PROT_WRITE)) {
        return sc_ret(ctx, -(int64_t)EFAULT);
    }
    if (uname(&un) != 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    dst = (uint8_t *)mips64_guest_ptr(ctx, va);
    copy_uts_field(dst + 0U * MIPS_UTS_FIELD, un.sysname);
    copy_uts_field(dst + 1U * MIPS_UTS_FIELD, un.nodename);
    copy_uts_field(dst + 2U * MIPS_UTS_FIELD, un.release);
    copy_uts_field(dst + 3U * MIPS_UTS_FIELD, un.version);
    copy_uts_field(dst + 4U * MIPS_UTS_FIELD, un.machine);
#if defined(__linux__) && !defined(__GLIBC__)
    /* musl spells the sixth utsname field with leading underscores. */
    copy_uts_field(dst + 5U * MIPS_UTS_FIELD, un.__domainname);
#elif defined(__linux__)
    copy_uts_field(dst + 5U * MIPS_UTS_FIELD, un.domainname);
#else
    memset(dst + 5U * MIPS_UTS_FIELD, 0, MIPS_UTS_FIELD);
#endif
    return sc_ret(ctx, 0);
}

/* close(2): pass through to the host (RC4: the test's exec/pipe
 * round-trip closes the write end so the reader sees EOF). */
static int64_t sc_close(mips64_ctx_t *ctx, uint64_t fd)
{
    if (close((int)fd) != 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    return sc_ret(ctx, 0);
}

/* Plain fork(): every guest mapping is MAP_PRIVATE (COW), so host
 * fork() diverges parent and child with no extra work. Full clone(2)
 * (thread sharing included) is lane L4b's mips_clone_full. */
static int64_t sc_fork(mips64_ctx_t *ctx)
{
    pid_t pid = fork();

    if (pid < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    if (pid == 0) {
        return sc_ret(ctx, 0); /* child */
    }
    return sc_ret(ctx, (int64_t)pid); /* parent */
}

/* wait4(): waitpid with a guest status word. The wait status is a plain
 * int with the kernel layout on every arch, so it stores unconverted.
 * Non-NULL rusage is Phase 4 and reports ENOSYS. */
static int64_t sc_wait4(mips64_ctx_t *ctx, uint64_t pid, uint64_t status_va,
                        uint64_t options, uint64_t rusage_va)
{
    int status = 0;
    pid_t ret;

    if (rusage_va != 0U) {
        return sc_ret(ctx, -(int64_t)ENOSYS);
    }
    if (status_va != 0U &&
        ((status_va & 3U) != 0U ||
         !mips_mem_ok(ctx, status_va, 4U, MIPS_PROT_WRITE))) {
        return sc_ret(ctx, -(int64_t)EFAULT);
    }
    ret = waitpid((pid_t)(int64_t)pid, status_va != 0U ? &status : NULL,
                  (int)(options & 0xFFFFFFFFU));
    if (ret < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    if (status_va != 0U) {
        /* The wait status is a plain int with the kernel layout on
         * every arch, but the bytes must follow guest endianness:
         * a BE LW over host-native bytes reads garbage. */
        guest_st32(ctx, status_va, (uint64_t)(uint32_t)status);
    }
    return sc_ret(ctx, (int64_t)ret);
}

/* RC4: deliver the first queued signal with a live unblocked handler.
 * The interrupted syscall already completed, so pc advances past it
 * before the frame is built (sc_pc resumes after the syscall). Runs at
 * the end of every mips_syscall; both engines observe the redirected pc
 * via their pc-moved checks. */
static void sc_deliver_pending(mips64_ctx_t *ctx)
{
    uint32_t i;

    if (ctx == NULL || ctx->pend_count == 0U) {
        return;
    }
    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t slot = (ctx->pend_head + i) % 16U;
        int signo = (int)ctx->pend_queue[slot].signo;
        unsigned w;
        uint64_t bit;

        if (signo < 1 || signo > 128) {
            continue;
        }
        if (mips_signal_has_handler(signo) == 0) {
            continue;
        }
        w = (unsigned)(signo - 1) / 64U;
        bit = (uint64_t)1U << ((unsigned)(signo - 1) % 64U);
        if ((ctx->sig_blocked[w] & bit) != 0U) {
            continue;
        }
        ctx->pc += 4U; /* syscall done; resume after it on sigreturn */
        ctx->next_pc = ctx->pc + 4U;
        if (mips_raise_guest(ctx, signo,
                             ctx->pend_queue[slot].addr) == 0) {
            return;
        }
        break;
    }
}

static int64_t mips_syscall_inner(mips64_ctx_t *ctx)
{
    uint64_t nr;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    int n32;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    ctx->llbit = 0U; /* SPEC 2.2: any syscall clears the LL reservation */
    ctx->syscalls_executed++;
    n32 = mips_is_n32(ctx);
    nr = ctx->gpr[MIPS64_REG_V0];
    a0 = ctx->gpr[MIPS64_REG_A0];
    a1 = ctx->gpr[MIPS64_REG_A1];
    a2 = ctx->gpr[MIPS64_REG_A2];
    a3 = ctx->gpr[MIPS64_REG_A3];
    a4 = ctx->gpr[MIPS64_REG_A4];
    a5 = ctx->gpr[MIPS64_REG_A5];

    if (nr == (uint64_t)(n32 ? MIPS64_NR32_exit : MIPS64_NR_exit) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_exit_group
                             : MIPS64_NR_exit_group)) {
        int is_group = (nr == (uint64_t)(n32 ? MIPS64_NR32_exit_group
                                             : MIPS64_NR_exit_group));

        /* RC4: raw exit(2) from a thread-group member ends only that
         * thread (musl thread teardown relies on this; qemu-observed),
         * while exit_group — or exit from the main thread — ends the
         * process. The guest already ran its own exit handlers; the
         * translator holds no buffered guest output. */
        if (!is_group && ctx->is_thread_clone) {
            mips_thread_exit(ctx, (int)(a0 & 0xFFU));
            return sc_ret(ctx, 0); /* unreachable */
        }
        if (getenv("MIPS64RT_DUMPSTATE") != NULL) {
            /* RC2 difftest: exit-state dump shared by both engines. */
            mips_dump_regs(ctx, stderr);
        }
        _Exit((int)(a0 & 0xFFU));
        return sc_ret(ctx, 0); /* unreachable */
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_read : MIPS64_NR_read)) {
        return sc_read(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_write : MIPS64_NR_write)) {
        return sc_write(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_brk : MIPS64_NR_brk)) {
        return sc_brk(ctx, a0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_mmap : MIPS64_NR_mmap)) {
        return sc_mmap(ctx, a0, a1, a2, a3, a4, a5);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_munmap : MIPS64_NR_munmap)) {
        int rc;

        if (a1 == 0U || (a0 & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        rc = mips_mem_unmap(ctx, a0, a1);
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
        return sc_ret(ctx, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_mremap : MIPS64_NR_mremap)) {
        int64_t rc = mips_mem_remap(ctx, a0, a1, a2, a3, a4);

        return sc_ret(ctx, rc);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_mprotect : MIPS64_NR_mprotect)) {
        int rc;

        if ((a0 & (MIPS64_PAGE_SIZE - 1U)) != 0U ||
            (a2 & ~(uint64_t)7U) != 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        /* A zero length is a no-op success (contract section 2.1);
         * mips_mem_protect rounds positive lengths up to 4 KiB. */
        rc = mips_mem_protect(ctx, a0, a1, (uint32_t)(a2 & 7U));
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
        return sc_ret(ctx, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_uname : MIPS64_NR_uname)) {
        return sc_uname(ctx, a0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_fork : MIPS64_NR_fork)) {
        /* RC1 integration: the P1 gate forks children for fault
         * tests (full clone(2) is Phase 4, lane L4b). */
        return sc_fork(ctx);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_clone : MIPS64_NR_clone)) {
        /* RC4: full clone(2) via lane L4b (thread-group sharing and
         * the fork-equivalent subset alike). */
        return mips_clone_full(ctx, a0, a1, a2, a3, a4);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_wait4 : MIPS64_NR_wait4)) {
        /* RC1 integration: waitpid(2) is wait4 with NULL rusage. */
        return sc_wait4(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_set_tid_address
                             : MIPS64_NR_set_tid_address)) {
        if (a0 != 0U && !mips_mem_ok(ctx, a0, 4U, MIPS_PROT_WRITE)) {
            return sc_ret(ctx, -(int64_t)EFAULT);
        }
        ctx->clear_child_tid = a0;
        /* Single-threaded Phase 1: pid is the tid (real tids in
         * Phase 4). E06: the N64 number is 5212, the N32 number 6213. */
        return sc_ret(ctx, (int64_t)getpid());
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_set_thread_area
                             : MIPS64_NR_set_thread_area)) {
        /* RC1 integration (mips32rt precedent): glibc static startup
         * installs its TLS/TCB address here before touching thread
         * variables. E06: N64 5242 / N32 6246; rdhwr $29 reads it
         * back via ctx->ulr. */
        ctx->ulr = a0;
        return sc_ret(ctx, 0);
    }
    /* ---- Lane L2a: static-libc layer (src/os/syscalls.c). The -100
     * dirfd below is AT_FDCWD; 0x100 is AT_SYMLINK_NOFOLLOW (both
     * arch-independent, verified in the UAPI container). ---- */
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_openat : MIPS64_NR_openat)) {
        return mips_sc_openat(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_fcntl : MIPS64_NR_fcntl)) {
        return mips_sc_fcntl(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_clock_gettime
                             : MIPS64_NR_clock_gettime)) {
        return mips_sc_clock_gettime(ctx, a0, a1, n32 ? 0 : 1);
    }
    if (n32 && nr == (uint64_t)MIPS64_NR32_clock_gettime64) {
        return mips_sc_clock_gettime(ctx, a0, a1, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_nanosleep
                             : MIPS64_NR_nanosleep)) {
        return mips_sc_nanosleep(ctx, 0U, a0, a1, n32 ? 0 : 1, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_clock_nanosleep
                             : MIPS64_NR_clock_nanosleep)) {
        return mips_sc_nanosleep(ctx, a0, a1, a2, n32 ? 0 : 1, 1);
    }
    if (n32 && nr == (uint64_t)MIPS64_NR32_clock_nanosleep_time64) {
        return mips_sc_nanosleep(ctx, a0, a1, a2, 1, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getrandom
                             : MIPS64_NR_getrandom)) {
        return mips_sc_getrandom(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_futex : MIPS64_NR_futex)) {
        /* RC4: full futex(2) via lane L4b (shared-memory wait/wake). */
        return mips_futex_op(ctx, a0, a1, a2, a3, a4, a5);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigaction
                             : MIPS64_NR_rt_sigaction)) {
        return mips_sc_rt_sigaction(ctx, ctx->gpr[MIPS64_REG_SP]);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigprocmask
                             : MIPS64_NR_rt_sigprocmask)) {
        /* RC4: the lane L4a ctx-resident mask supersedes the Phase 2
         * recorded mask (delivery now observes it). */
        return mips_l4a_rt_sigprocmask(ctx, ctx->gpr[MIPS64_REG_SP]);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigreturn
                             : MIPS64_NR_rt_sigreturn)) {
        return mips_rt_sigreturn(ctx);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_sigaltstack
                             : MIPS64_NR_sigaltstack)) {
        return mips_sc_sigaltstack(ctx, ctx->gpr[MIPS64_REG_SP]);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigpending
                             : MIPS64_NR_rt_sigpending) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigtimedwait
                             : MIPS64_NR_rt_sigtimedwait) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigqueueinfo
                             : MIPS64_NR_rt_sigqueueinfo) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_rt_tgsigqueueinfo
                             : MIPS64_NR_rt_tgsigqueueinfo) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_kill : MIPS64_NR_kill) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_tkill : MIPS64_NR_tkill) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_tgkill : MIPS64_NR_tgkill)) {
        return mips_sc_sig_syscall(ctx, nr, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_execve : MIPS64_NR_execve) ||
        nr == (uint64_t)(n32 ? MIPS64_NR32_execveat : MIPS64_NR_execveat)) {
        return mips_sc_exec(ctx, nr, a0, a1, a2, a3, a4);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_waitid : MIPS64_NR_waitid)) {
        return mips_sc_waitid(ctx, a0, a1, a2, a3, a4);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_ioctl : MIPS64_NR_ioctl)) {
        return mips_sc_ioctl(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_lseek : MIPS64_NR_lseek)) {
        return mips_sc_lseek(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_stat : MIPS64_NR_stat)) {
        return mips_sc_stat_at(ctx, (uint64_t)(int64_t)-100, a0, a1, 0U);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_fstat : MIPS64_NR_fstat)) {
        return mips_sc_fstat(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_lstat : MIPS64_NR_lstat)) {
        return mips_sc_stat_at(ctx, (uint64_t)(int64_t)-100, a0, a1, 0x100U);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_newfstatat
                             : MIPS64_NR_newfstatat)) {
        return mips_sc_stat_at(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_statx : MIPS64_NR_statx)) {
        return mips_sc_statx(ctx, a0, a1, a2, a3, a4);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getdents64
                             : MIPS64_NR_getdents64)) {
        return mips_sc_getdents64(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_readlinkat
                             : MIPS64_NR_readlinkat)) {
        return mips_sc_readlinkat(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_readlink
                             : MIPS64_NR_readlink)) {
        /* Lane L5a: glibc readlink(2) still emits the legacy number
         * (qemu-observed); serve it as readlinkat(AT_FDCWD). */
        return mips_sc_readlinkat(ctx, (uint64_t)(int64_t)-100, a0, a1,
                                  a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_access : MIPS64_NR_access)) {
        return mips_sc_access_at(ctx, (uint64_t)(int64_t)-100, a0, a1, 0U);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_faccessat
                             : MIPS64_NR_faccessat)) {
        return mips_sc_access_at(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_pipe2 : MIPS64_NR_pipe2)) {
        return mips_sc_pipe2(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_dup : MIPS64_NR_dup)) {
        return mips_sc_dup(ctx, a0, 0U, 0U, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_dup2 : MIPS64_NR_dup2)) {
        return mips_sc_dup(ctx, a0, a1, 0U, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_dup3 : MIPS64_NR_dup3)) {
        return mips_sc_dup(ctx, a0, a1, a2, 2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_close : MIPS64_NR_close)) {
        return sc_close(ctx, a0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getpid : MIPS64_NR_getpid)) {
        return mips_sc_getid(ctx, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getppid : MIPS64_NR_getppid)) {
        return mips_sc_getid(ctx, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getuid : MIPS64_NR_getuid)) {
        return mips_sc_getid(ctx, 2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_geteuid : MIPS64_NR_geteuid)) {
        return mips_sc_getid(ctx, 3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getgid : MIPS64_NR_getgid)) {
        return mips_sc_getid(ctx, 4);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_getegid : MIPS64_NR_getegid)) {
        return mips_sc_getid(ctx, 5);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_gettid : MIPS64_NR_gettid)) {
        return mips_sc_getid(ctx, 6);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_set_robust_list
                             : MIPS64_NR_set_robust_list)) {
        return mips_sc_robust(ctx, 1, a0, a1, 0U);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_get_robust_list
                             : MIPS64_NR_get_robust_list)) {
        return mips_sc_robust(ctx, 0, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_unlinkat
                             : MIPS64_NR_unlinkat)) {
        return mips_sc_unlinkat(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_close_range
                             : MIPS64_NR_close_range)) {
        return mips_sc_close_range(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_readv : MIPS64_NR_readv)) {
        return mips_sc_vec(ctx, a0, a1, a2, 0U, 0, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_writev : MIPS64_NR_writev)) {
        return mips_sc_vec(ctx, a0, a1, a2, 0U, 0, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_preadv : MIPS64_NR_preadv)) {
        return mips_sc_vec(ctx, a0, a1, a2, a3, 1, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_pwritev : MIPS64_NR_pwritev)) {
        return mips_sc_vec(ctx, a0, a1, a2, a3, 1, 1);
    }
    return sc_ret(ctx, -(int64_t)ENOSYS);
}

/* Public dispatcher: the inner body above, then the RC4 pending-signal
 * sweep (which may redirect pc into a handler; both engines treat the
 * moved pc as final and resume there). */
int64_t mips_syscall(mips64_ctx_t *ctx)
{
    int64_t rc = mips_syscall_inner(ctx);

    sc_deliver_pending(ctx);
    return rc;
}
