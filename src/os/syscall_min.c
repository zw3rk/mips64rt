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
extern int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                        uint32_t prot, const char *tag);
extern int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
extern int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            uint32_t prot);

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
        va = addr & MIPS64_PAGE_MASK;
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
        va = addr & MIPS64_PAGE_MASK;
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

/* MIPS clone flags (Linux kernel ABI, arch-independent). Phase 1
 * supports only the fork-equivalent subset musl's fork() uses. */
#define MIPS_CLONE_VM 0x100U
#define MIPS_CLONE_FS 0x200U
#define MIPS_CLONE_FILES 0x400U
#define MIPS_CLONE_SIGHAND 0x800U
#define MIPS_CLONE_PTRACE 0x2000U
#define MIPS_CLONE_VFORK 0x4000U
#define MIPS_CLONE_PARENT 0x8000U
#define MIPS_CLONE_THREAD 0x10000U
#define MIPS_CLONE_SYSVSEM 0x40000U
#define MIPS_CLONE_SETTLS 0x80000U
#define MIPS_CLONE_PARENT_SETTID 0x100000U
#define MIPS_CLONE_CHILD_CLEARTID 0x200000U
#define MIPS_CLONE_CHILD_SETTID 0x1000000U
/* MIPS signal numbers (asm/signal.h) differ from asm-generic: SIGCHLD
 * is 18 on MIPS, not 17. musl's fork() passes it as clone's signal. */
#define MIPS_SIGCHLD 18U
#define MIPS_CLONE_SHARE_MASK \
    (MIPS_CLONE_VM | MIPS_CLONE_FS | MIPS_CLONE_FILES | \
     MIPS_CLONE_SIGHAND | MIPS_CLONE_PTRACE | MIPS_CLONE_VFORK | \
     MIPS_CLONE_PARENT | MIPS_CLONE_THREAD | MIPS_CLONE_SYSVSEM | \
     MIPS_CLONE_SETTLS)

/* Plain fork(): every guest mapping is MAP_PRIVATE (COW), so host
 * fork() diverges parent and child with no extra work. */
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

/* Minimal clone(): only the fork-equivalent form (SIGCHLD exit signal,
 * optional child-tid bookkeeping). Address-space or thread sharing is
 * Phase 4 (L4b) and reports ENOSYS. */
static int64_t sc_clone(mips64_ctx_t *ctx, uint64_t flags,
                        uint64_t parent_tid, uint64_t ctid)
{
    pid_t pid;

    if ((flags & 0xFFU) != (uint64_t)MIPS_SIGCHLD) {
        return sc_ret(ctx, -(int64_t)EINVAL);
    }
    if ((flags & (uint64_t)MIPS_CLONE_SHARE_MASK) != 0U) {
        return sc_ret(ctx, -(int64_t)ENOSYS);
    }
    pid = fork();
    if (pid < 0) {
        return sc_ret(ctx, -(int64_t)errno);
    }
    if (pid == 0) {
        int32_t tid;

        if ((flags & (uint64_t)MIPS_CLONE_CHILD_CLEARTID) != 0U) {
            ctx->clear_child_tid = ctid;
        }
        if ((flags & (uint64_t)MIPS_CLONE_CHILD_SETTID) != 0U &&
            ctid != 0U) {
            tid = (int32_t)getpid();
            if ((ctid & 3U) != 0U ||
                !mips_mem_ok(ctx, ctid, 4U, MIPS_PROT_WRITE)) {
                mips_fault(ctx, ctid);
                return sc_ret(ctx, -(int64_t)EFAULT);
            }
            /* guest_st32: endian-correct store (BE guests must see
             * the scalar value, not host-native bytes). */
            guest_st32(ctx, ctid, (uint64_t)(uint32_t)tid);
        }
        return sc_ret(ctx, 0); /* child */
    }
    if ((flags & (uint64_t)MIPS_CLONE_PARENT_SETTID) != 0U &&
        parent_tid != 0U) {
        int32_t tid = (int32_t)pid;

        if ((parent_tid & 3U) != 0U ||
            !mips_mem_ok(ctx, parent_tid, 4U, MIPS_PROT_WRITE)) {
            return sc_ret(ctx, -(int64_t)EFAULT);
        }
        guest_st32(ctx, parent_tid, (uint64_t)(uint32_t)tid);
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

int64_t mips_syscall(mips64_ctx_t *ctx)
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
        /* Single-threaded Phase 1: exit() and exit_group() both end
         * the process. The guest already ran its own exit handlers;
         * the translator holds no buffered guest output. */
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

        if (a1 == 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        rc = mips_mem_unmap(ctx, a0 & MIPS64_PAGE_MASK, a1);
        if (rc != 0) {
            return sc_ret(ctx, (int64_t)rc);
        }
        return sc_ret(ctx, 0);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_mprotect : MIPS64_NR_mprotect)) {
        int rc;

        if (a1 == 0U || (a2 & ~(uint64_t)7U) != 0U) {
            return sc_ret(ctx, -(int64_t)EINVAL);
        }
        rc = mips_mem_protect(ctx, a0 & MIPS64_PAGE_MASK, a1,
                              (uint32_t)(a2 & 7U));
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
        /* RC1 integration: musl's fork() arrives here (a0 = flags,
         * a1 = stack, a2 = parent_tid, a3 = child_tid). Only the
         * fork-equivalent subset is served; thread sharing is ENOSYS
         * until Phase 4 (L4b). */
        return sc_clone(ctx, a0, a2, a3);
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
    return sc_ret(ctx, -(int64_t)ENOSYS);
}
