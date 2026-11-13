/*
 * src/os/syscall_min.c — Minimal N64/N32 syscall dispatcher (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * N64/N32 syscall dispatcher ($v0 number, $a0..$a5 args, $a3=0/1 error
 * flag, ENOSYS 38->89). Runs under a quiescence memory lease.
 */

#define _POSIX_C_SOURCE 200809L

#include "core/cpu.h"
#include "os/errno_map.h"
#include "os/syscall_nr.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
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
extern int64_t mips_sc_nanosleep(mips64_ctx_t *ctx, uint64_t req_va,
                                 uint64_t rem_va, int is64);
extern int64_t mips_sc_clock_nanosleep(mips64_ctx_t *ctx, uint64_t clk,
                                       uint64_t flags, uint64_t req_va,
                                       uint64_t rem_va, int is64);
extern int64_t mips_sc_clock_getres(mips64_ctx_t *ctx, uint64_t clk,
                                    uint64_t ts_va, int is64);
extern int mips_thread_group_live(void);
extern void mips_thread_exit(mips64_ctx_t *ctx, int status);
extern int64_t mips_sc_getrandom(mips64_ctx_t *ctx, uint64_t buf_va,
                                 uint64_t len, uint64_t flags);
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
/* Lane H2 file-mutation + sysmips tail (src/os/syscalls_sync.c). */
extern int64_t mips_sc_file_extra(mips64_ctx_t *ctx, int n32, uint64_t nr,
                                  uint64_t a0, uint64_t a1, uint64_t a2,
                                  uint64_t a3, int *claimed);
/* Lane U12 scalar read/write (src/os/syscalls_sync.c). */
extern int64_t mips_sc_read(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                            uint64_t count);
extern int64_t mips_sc_write(mips64_ctx_t *ctx, uint64_t fd, uint64_t buf,
                             uint64_t count);
/* Lane U12 quiescence lease (src/os/quiesce.c). */
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);
/* Lane U12 Provider A file-map hook (src/vm/vm_file.c). */
extern void mips_vm_file_map_hook(mips64_ctx_t *ctx, int fd, uint64_t va,
                                  uint64_t len, uint64_t file_offset,
                                  uint32_t prot, int is_shared);
extern void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va,
                                     uint64_t len);
extern void mips_vm_file_reconcile(mips64_ctx_t *ctx);
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
extern int mips_mem_map_replace(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                                uint32_t prot, const char *tag);
extern int mips_mem_map_shared(mips64_ctx_t *ctx, uint64_t va, uint64_t len, uint32_t prot, const char *tag);
extern int mips_mem_map_replace_shared(mips64_ctx_t *ctx, uint64_t va, uint64_t len, uint32_t prot, const char *tag);
extern int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
extern int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            uint32_t prot);
extern int64_t mips_mem_remap(mips64_ctx_t *ctx, uint64_t old_va,
                              uint64_t old_len, uint64_t new_len,
                              uint64_t flags, uint64_t new_va);
extern uint64_t mips_mem_hole_after(const mips64_ctx_t *ctx, uint64_t cand,
                                    uint64_t size);
extern void mips_threads_atfork_child(mips64_ctx_t *ctx);
extern void mips_llsc_note_write(uint64_t addr, uint64_t size);
extern void mips_llsc_write_lock(void);
extern void mips_llsc_write_unlock(void);
/* Phase 7 H1: DBT SMC hook (weak; strong def in src/dbt/dbt.c). */
__attribute__((weak)) void dbt_invalidate_range(uint64_t va, uint64_t len);

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

/* MIPS errno translation lives in os/errno_map.h
 * (l2a_errno_from_host, shared with syscalls.c). */

/* Record the $a3 convention in the guest regs; return raw host value. */
static int64_t sc_ret(mips64_ctx_t *ctx, int64_t raw)
{
    if (raw < 0) {
        int64_t e = -raw;

        if (e > 4095) {
            e = 4095;
        }
        ctx->gpr[MIPS64_REG_V0] =
            (uint64_t)l2a_errno_from_host((int)e);
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

/* NOTE: the scalar read/write bodies live in src/os/syscalls_sync.c
 * as mips_sc_read/mips_sc_write (lane U12 file-I/O home); the lease
 * wraps the whole dispatch in mips_syscall below. */

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
    /* Map only the not-yet-mapped extension. */
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

/* First gap of at least size bytes at or after cand (page granular).
 * Served from the process-global table (lane H4): a per-context copy
 * goes stale at clone and could hand out a live mapping. */
static uint64_t hole_from(const mips64_ctx_t *ctx, uint64_t cand,
                          uint64_t size)
{
    return mips_mem_hole_after(ctx, cand, size);
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
    uint8_t *fbuf = NULL;
    int rc;
    int anon, shared;

    if (len == 0U || (prot & ~(uint64_t)7U) != 0U) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    if ((flags & (MIPS_MAP_SHARED | MIPS_MAP_PRIVATE)) == 0U ||
        (flags & (MIPS_MAP_SHARED | MIPS_MAP_PRIVATE)) ==
            (MIPS_MAP_SHARED | MIPS_MAP_PRIVATE)) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    size = (len + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
    if (size == 0U || size > ctx->task_size) {
        return sc_ret(ctx, -(int64_t)ENOMEM);
    }
    anon = (flags & (MIPS_MAP_ANONYMOUS | MIPS_MAP_ANON_O32)) != 0U;
    shared = (anon != 0 && (flags & MIPS_MAP_SHARED) != 0U) ? 1 : 0;
    if (!anon && (offset & (MIPS64_PAGE_SIZE - 1U)) != 0U) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    if ((flags & (MIPS_MAP_FIXED | MIPS_MAP_FIXED_NOREPLACE)) != 0U) {
        if (addr == 0U || (addr & (MIPS64_PAGE_SIZE - 1U)) != 0U ||
            addr + size < addr || addr + size > ctx->task_size) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        if ((flags & MIPS_MAP_FIXED_NOREPLACE) != 0U &&
            (mips_mem_ok(ctx, addr, 1U, 0U) ||
             hole_from(ctx, addr, size) != addr)) {
            return sc_ret(ctx, -(int64_t)EEXIST);
        }
    }
    /* Pre-stage file bytes first (MAP_FIXED stays clean on bad fd). */
    if (!anon) {
        uint64_t left = size;
        uint64_t off = 0U;

        fbuf = (uint8_t *)calloc(1U, (size_t)size);
        if (fbuf == NULL) {
            return sc_ret(ctx, -(int64_t)ENOMEM);
        }
        while (left > 0U && offset + off >= off) {
            ssize_t got = pread((int)fd, fbuf + off, (size_t)left,
                                (off_t)(offset + off));

            if (got < 0) {
                int e = errno;

                free(fbuf);
                return sc_ret(ctx, -(int64_t)e);
            }
            if (got == 0) {
                break;
            }
            off += (uint64_t)got;
            left -= (uint64_t)got;
        }
    }
    if ((flags & MIPS_MAP_FIXED_NOREPLACE) != 0U) {
        va = addr;
        rc = shared != 0 ? mips_mem_map_shared(ctx, va, size, (uint32_t)(prot & 7U), "map") : mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map");
    } else if ((flags & MIPS_MAP_FIXED) != 0U) {
        va = addr;
        rc = shared != 0 ? mips_mem_map_replace_shared(ctx, va, size, (uint32_t)(prot & 7U), "map") : mips_mem_map_replace(ctx, va, size, (uint32_t)(prot & 7U), "map");
        if (rc == -ENOMEM &&
            sysconf(_SC_PAGESIZE) > (long)MIPS64_PAGE_SIZE) {
            /* Big-host fallback: unmap then re-add (2nd quiescence). */
            rc = mips_mem_unmap(ctx, va, size);
            if (rc == 0) {
                rc = shared != 0 ? mips_mem_map_shared(ctx, va, size, (uint32_t)(prot & 7U), "map") : mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map");
            }
        }
    } else {
        va = pick_hole(ctx, addr, size);
        rc = va == 0U ? -ENOMEM : (shared != 0 ? mips_mem_map_shared(ctx, va, size, (uint32_t)(prot & 7U), "map") : mips_mem_map(ctx, va, size, (uint32_t)(prot & 7U), "map"));
    }
    if (rc != 0) {
        free(fbuf);
        return sc_ret(ctx, (int64_t)rc);
    }
    if (!anon) {
        uint8_t *dst = (uint8_t *)mips64_guest_ptr(ctx, va);
        int hp = (((uint32_t)prot & MIPS_PROT_READ) != 0U ? PROT_READ : 0) |
                 (((uint32_t)prot & MIPS_PROT_WRITE) != 0U ? PROT_WRITE : 0);

        if ((hp & PROT_WRITE) == 0 &&
            mprotect(dst, (size_t)size, PROT_READ | PROT_WRITE) != 0) {
            int e = errno;
            mips_mem_unmap(ctx, va, size);
            free(fbuf);
            return sc_ret(ctx, -(int64_t)e);
        }
        memcpy(dst, fbuf, (size_t)size);
        if ((hp & PROT_WRITE) == 0 &&
            mprotect(dst, (size_t)size, hp) != 0) {
            int e = errno;
            mips_mem_unmap(ctx, va, size);
            free(fbuf);
            return sc_ret(ctx, -(int64_t)e);
        }
        free(fbuf);
        mips_vm_file_map_hook(ctx, (int)fd, va, size, offset,
                              (uint32_t)(prot & 7U),
                              (flags & MIPS_MAP_SHARED) != 0U ? 1 : 0);
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
    mips_llsc_write_lock();
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
    mips_llsc_note_write(va, MIPS_UTS_SIZE);
    mips_llsc_write_unlock();
    mips_vm_pages_clear(va, MIPS_UTS_SIZE, (unsigned)MIPS_VM_PAGE_COW_CLEAN);
    mips_vm_pages_retire_code(va, MIPS_UTS_SIZE);
    mips_vm_file_shared_sync(ctx, va, MIPS_UTS_SIZE);
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

/* Plain fork(): private guest mappings are MAP_PRIVATE (COW) while
 * MAP_SHARED|MAP_ANONYMOUS keeps host MAP_SHARED backing, so host
 * fork() diverges the former and preserves sharing in the latter.
 * Full clone(2) (thread sharing included) is lane L4b's mips_clone_full. */
static int64_t sc_fork(mips64_ctx_t *ctx)
{
    pid_t pid = fork();

    if (pid < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    if (pid == 0) {
        ctx->is_thread_clone = false;
        ctx->host_tid = 0;
        mips_threads_atfork_child(ctx);
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
    /* A blocking wait must not hold the dispatch lease: park with 0
     * leases so a concurrent VM mutation is never stalled by a
     * thread that is not touching memory. */
    mips_qs_lease_exit(ctx);
    ret = waitpid((pid_t)(int64_t)pid, status_va != 0U ? &status : NULL,
                  (int)(options & 0xFFFFFFFFU));
    mips_qs_lease_enter(ctx);
    if (ret < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    if (status_va != 0U) {
        if (!mips_mem_ok(ctx, status_va, 4U, MIPS_PROT_WRITE)) {
            return sc_ret(ctx, -(int64_t)EFAULT);
        }
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

        /* R5: raw exit ends only the caller; exit_group ends all.
         * A leader raw exit with live siblings waits (no _Exit kill). */
        if (!is_group && ctx->is_thread_clone) {
            mips_thread_exit(ctx, (int)(a0 & 0xFFU));
            return sc_ret(ctx, 0); /* unreachable */
        }
        if (!is_group && !ctx->is_thread_clone &&
            mips_thread_group_live() > 0) {
            if (getenv("MIPS64RT_DUMPSTATE") != NULL) {
                mips_dump_regs(ctx, stderr);
            }
            mips_qs_lease_exit(ctx);
            mips_thread_exit(ctx, (int)a0);
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
        return mips_sc_read(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_write : MIPS64_NR_write)) {
        return mips_sc_write(ctx, a0, a1, a2);
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
        /* Fault-test fork (full clone(2) is lane L4b). */
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
        return sc_ret(ctx, (int64_t)(ctx->difftest_enabled ? getppid()
                                                           : getpid()));
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
        return mips_sc_nanosleep(ctx, a0, a1, n32 ? 0 : 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_clock_getres
                             : MIPS64_NR_clock_getres)) {
        return mips_sc_clock_getres(ctx, a0, a1, n32 ? 0 : 1);
    }
    if (n32 && nr == (uint64_t)MIPS64_NR32_clock_getres_time64) {
        return mips_sc_clock_getres(ctx, a0, a1, 1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_clock_nanosleep
                             : MIPS64_NR_clock_nanosleep)) {
        return mips_sc_clock_nanosleep(ctx, a0, a1, a2, a3,
                                       n32 ? 0 : 1);
    }
    if (n32 && nr == (uint64_t)MIPS64_NR32_clock_nanosleep_time64) {
        return mips_sc_clock_nanosleep(ctx, a0, a1, a2, a3, 1);
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
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_cacheflush : MIPS64_NR_cacheflush)) {
        /* H1: cacheflush(addr, len, kind) retires [addr, addr+len). */
        if (a1 != 0U && dbt_invalidate_range != NULL) {
            dbt_invalidate_range(a0, a1);
        }
        return sc_ret(ctx, 0);
    }
    {
        /* Lane H2: truncate, ftruncate, pread64, pwrite64, and
         * sysmips(MIPS_FIXADE) live in the file-extra tail. */
        int claimed = 0;
        int64_t extra =
            mips_sc_file_extra(ctx, n32 ? 1 : 0, nr, a0, a1, a2, a3,
                               &claimed);

        if (claimed != 0) {
            return extra;
        }
    }
    return sc_ret(ctx, -(int64_t)ENOSYS);
}

/* Public dispatcher: the whole body runs under a quiescence memory
 * lease (lane U12: Dekker handshake against VM mutations), then the
 * RC4 pending-signal sweep (which may redirect pc into a handler;
 * both engines treat the moved pc as final and resume there). */
int64_t mips_syscall(mips64_ctx_t *ctx)
{
    int64_t rc;

    mips_qs_lease_enter(ctx);
    mips_vm_file_reconcile(ctx);
    rc = mips_syscall_inner(ctx);
    mips_qs_lease_exit(ctx);
    sc_deliver_pending(ctx);
    return rc;
}
