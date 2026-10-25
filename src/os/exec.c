/*
 * src/os/exec.c — Process-image replacement: execve/execveat + waitid (lane L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the lane L4c translator seam:
 *
 *   int64_t mips_sc_exec(mips64_ctx_t *ctx, uint64_t nr, uint64_t path_va,
 *                        uint64_t argv_va, uint64_t envp_va, uint64_t a3,
 *                        uint64_t a4)
 *
 * for execve (N64 5057 / N32 6057) and execveat (N64 5316 / N32 6320),
 * plus the extended wait4 coverage:
 *
 *   int64_t mips_sc_waitid(mips64_ctx_t *ctx, uint64_t which, uint64_t pid,
 *                          uint64_t infop_va, uint64_t options,
 *                          uint64_t rusage_va)
 *
 * Reference behavior mirrors ../rvrt/src/linux/{signal_exec,file_exec,
 * wait}.c and ../rvrt/src/runtime/{exec_state,exec_launch}.c:
 * validated guest vectors are copied while the caller still holds the
 * guest-memory guard, signal state is captured/reset only on success,
 * and WEXITED status decodes into the 128-byte MIPS guest siginfo_t.
 *
 * execve calling convention: a0 = path_va, a1 = argv_va, a2 = envp_va.
 * execveat convention: a0 = dirfd, a1 = path_va, a2 = argv_va,
 * a3 = envp_va, a4 = flags. Only AT_FDCWD-relative lookups are served
 * here (absolute paths or dirfd == AT_FDCWD); anything else reports
 * EBADF so the coordinator can layer the file-capability broker on top.
 * Only AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW flags are accepted.
 *
 * On success the old reservation is torn down, the image is reloaded
 * through the Phase 1 loader (mips_load_elf, which rebuilds the stack
 * and auxv via exec_args), every signal action returns to SIG_DFL,
 * sig_blocked / pend_queue / sigaltstack / clear_child_tid are cleared,
 * and the LL/SC reservation is invalidated. Under CLONE_THREAD the
 * request is refused with -EPERM. On failure the previous image is
 * restored intact and a negative errno is returned with the $a3 = 1 /
 * $v0 = +errno convention.
 *
 * A file the loader rejects as "not a MIPS image" (ENOEXEC: host-arch
 * ELF, script, directory) falls through to a host execve (qemu-user
 * behavior): the translator process is already the forked child, so
 * replacing it is exactly right, and the parent's wait4/waitid
 * collects the host exit. Host-only env (LD_*, MIPS64RT_*) is
 * scrubbed from the delegated vector so a stale guest LD_PRELOAD
 * cannot divert the host binary.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/syscall_nr.h"
#include "rt64/linux/signal_core.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Loader entry (src/loader.c, lane L1c). Rebuilds stack/auxv and sets pc. */
extern int mips_load_elf(mips64_ctx_t *ctx, const char *path, char **argv,
                         char **envp);
/* Guest exe path noted by the /proc/self layer (src/os/proc.c). */
extern const char *mips_proc_exe_path(void);
/* Guest window + endian-aware accessors (src/os/mem.c, lane L1c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int guest_ld32(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
extern int guest_ld64(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
extern int guest_st32(mips64_ctx_t *ctx, uint64_t va, uint64_t val);

/* Linux AT constants (arch-independent). */
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

/* MIPS signal numbers (asm/signal.h): SIGCHLD is 18 on MIPS. */
#define MIPS_SIGCHLD_NUM 18
/* waitid id types (Linux generic). */
#define P_ALL 0
#define P_PID 1
#define P_PGID 2
/* waitid options (Linux generic). */
#define W_NOHANG_OPT 1U
#define W_UNTRACED_OPT 2U
#define W_EXITED_OPT 4U
#define W_CONTINUED_OPT 8U
#define W_NOWAIT_OPT 0x01000000U
/* siginfo CLD_ codes (Linux generic, arch-independent). */
#define CLD_EXIT_CODE 1
#define CLD_KILL_CODE 2
#define CLD_DUMP_CODE 3
#define CLD_TRAP_CODE 4
#define CLD_STOP_CODE 5
#define CLD_CONT_CODE 6

#define EXEC_PATH_MAX ((size_t)4096)
#define EXEC_VEC_MAX ((size_t)2048)
#define EXEC_BYTES_MAX ((size_t)131072)

/* Record the $a3 convention; return raw host value. */
static int64_t exec_ret(mips64_ctx_t *ctx, int64_t raw)
{
    int64_t e;

    if (raw >= 0) {
        ctx->gpr[MIPS64_REG_V0] = (uint64_t)raw;
        ctx->gpr[MIPS64_REG_A3] = 0U;
        return raw;
    }
    e = -raw;
    if (e > 4095) {
        e = 4095;
    }
    if (e == 38) {
        e = 89; /* MIPS ENOSYS, not asm-generic 38 */
    }
    ctx->gpr[MIPS64_REG_V0] = (uint64_t)e;
    ctx->gpr[MIPS64_REG_A3] = 1U;
    return raw;
}

static int is_n32_ctx(const mips64_ctx_t *ctx)
{
    return ctx->is_n32 != 0U;
}

/* N32 guests carry 32-bit pointers: reject non-zero high halves. */
static int ptr_ok(const mips64_ctx_t *ctx, uint64_t va)
{
    if (is_n32_ctx(ctx) && (va >> 32) != 0U) {
        return 0;
    }
    return 1;
}

/* Copy a NUL-terminated guest string bounded by EXEC_PATH_MAX. */
static int copy_guest_str(mips64_ctx_t *ctx, uint64_t va, char *out,
                          size_t cap, size_t *budget)
{
    size_t n = 0;

    if (va == 0U || !ptr_ok(ctx, va)) {
        return -EFAULT;
    }
    while (n + 1 < cap && n < EXEC_PATH_MAX) {
        uint8_t b;
        const uint8_t *hp;

        if (!mips_mem_ok(ctx, va + n, 1U, MIPS_PROT_READ)) {
            return -EFAULT;
        }
        hp = (const uint8_t *)mips64_guest_ptr(ctx, va + n);
        b = *hp;
        out[n] = (char)b;
        n++;
        if (*budget == 0) {
            return -E2BIG;
        }
        (*budget)--;
        if (b == 0U) {
            return 0;
        }
    }
    return -ENAMETOOLONG;
}

/* Load one guest pointer (4 bytes N32, 8 bytes N64), endian-correct. */
static int load_guest_ptr(mips64_ctx_t *ctx, uint64_t va, uint64_t *out)
{
    uint64_t v = 0;

    if (va == 0U) {
        return -EFAULT;
    }
    if (!ptr_ok(ctx, va)) {
        return -EFAULT;
    }
    if (is_n32_ctx(ctx)) {
        if ((va & 3U) != 0U) {
            return -EFAULT;
        }
        if (guest_ld32(ctx, va, &v) != 0) {
            return -EFAULT;
        }
        *out = v & 0xFFFFFFFFULL;
        return 0;
    }
    if ((va & 7U) != 0U) {
        return -EFAULT;
    }
    if (guest_ld64(ctx, va, &v) != 0) {
        return -EFAULT;
    }
    *out = v;
    return 0;
}

/* Copy a guest argv/envp vector into owned host memory. NULL vector
 * means empty (envp) or a synthesized argv[0] = "" (argv with NULL). */
static int copy_guest_vec(mips64_ctx_t *ctx, uint64_t vec_va, char ***out,
                          size_t *outc, size_t *budget, int is_argv)
{
    char **vec = NULL;
    size_t n = 0;
    size_t i;
    size_t step;

    step = is_n32_ctx(ctx) ? 4U : 8U;
    if (vec_va == 0U) {
        vec = (char **)calloc(1, sizeof *vec);
        if (vec == NULL) {
            return -ENOMEM;
        }
        if (is_argv) {
            char *empty = (char *)calloc(1, 1);
            if (empty == NULL) {
                free(vec);
                return -ENOMEM;
            }
            vec[0] = empty;
        } else {
            vec[0] = NULL;
        }
        *out = vec;
        *outc = 0;
        return 0;
    }
    if (!ptr_ok(ctx, vec_va)) {
        return -EFAULT;
    }
    /* Count first (bounded), validating the pointer array window. */
    while (n < EXEC_VEC_MAX) {
        uint64_t p = 0;

        if (!mips_mem_ok(ctx, vec_va + n * step, step, MIPS_PROT_READ)) {
            return -EFAULT;
        }
        if (load_guest_ptr(ctx, vec_va + n * step, &p) != 0) {
            return -EFAULT;
        }
        if (p == 0U) {
            break;
        }
        n++;
    }
    if (n >= EXEC_VEC_MAX) {
        return -E2BIG;
    }
    vec = (char **)calloc(n + 1, sizeof *vec);
    if (vec == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < n; i++) {
        uint64_t p = 0;
        char buf[EXEC_PATH_MAX];
        char *dup;
        size_t len;

        if (load_guest_ptr(ctx, vec_va + i * step, &p) != 0) {
            goto fail;
        }
        if (copy_guest_str(ctx, p, buf, sizeof buf, budget) != 0) {
            goto fail;
        }
        len = strlen(buf);
        dup = (char *)malloc(len + 1);
        if (dup == NULL) {
            goto fail;
        }
        memcpy(dup, buf, len + 1);
        vec[i] = dup;
    }
    vec[n] = NULL;
    *out = vec;
    *outc = n;
    return 0;
fail:
    for (i = 0; vec[i] != NULL && i < n; i++) {
        free(vec[i]);
    }
    free(vec);
    return -EFAULT;
}

static void free_vec(char **vec, size_t n)
{
    size_t i;

    if (vec == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {
        free(vec[i]);
    }
    free(vec);
}

/* Clear exec-sensitive state on success: all actions to SIG_DFL, masks
 * and queues empty, altstack off, clear_child_tid forgotten, LL gone. */
static void reset_state_for_exec(mips64_ctx_t *ctx)
{
    mips64_signals_reset_for_exec(ctx);
    ctx->sig_blocked[0] = 0U;
    ctx->sig_blocked[1] = 0U;
    ctx->pend_head = 0U;
    ctx->pend_count = 0U;
    ctx->sigalt_sp = 0U;
    ctx->sigalt_size = 0U;
    ctx->sigalt_flags = 0U;
    ctx->clear_child_tid = 0U;
    ctx->robust_list_head = 0U;
    ctx->robust_list_len = 0U;
    mips64_ctx_clear_ll(ctx);
}

int64_t mips_sc_exec(mips64_ctx_t *ctx, uint64_t nr, uint64_t path_va,
                     uint64_t argv_va, uint64_t envp_va, uint64_t a3,
                     uint64_t a4)
{
    int n32;
    int is_at;
    uint64_t dirfd = 0;
    uint64_t path = 0;
    uint64_t argv = 0;
    uint64_t envp = 0;
    uint64_t flags = 0;
    char path_buf[EXEC_PATH_MAX];
    char **host_argv = NULL;
    char **host_envp = NULL;
    size_t argc = 0;
    size_t envc = 0;
    size_t budget = EXEC_BYTES_MAX;
    mips64_ctx_t *backup = NULL;
    uint64_t old_base;
    uint64_t old_size;
    int rc;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    n32 = is_n32_ctx(ctx) ? 1 : 0;
    is_at = (nr == (uint64_t)(n32 ? MIPS64_NR32_execveat
                                  : MIPS64_NR_execveat)) ? 1 : 0;
    if (!is_at &&
        nr != (uint64_t)(n32 ? MIPS64_NR32_execve : MIPS64_NR_execve)) {
        return exec_ret(ctx, -(int64_t)ENOSYS);
    }
    /* Refuse with -EPERM under CLONE_THREAD (Linux execve semantics). */
    if (ctx->is_thread_clone) {
        return exec_ret(ctx, -(int64_t)EPERM);
    }
    if (is_at) {
        dirfd = path_va;
        path = argv_va;
        argv = envp_va;
        envp = a3;
        flags = a4;
        if ((flags & ~(uint64_t)(AT_EMPTY_PATH |
                                 AT_SYMLINK_NOFOLLOW)) != 0U) {
            return exec_ret(ctx, -(int64_t)EINVAL);
        }
        if (dirfd != (uint64_t)(int64_t)AT_FDCWD) {
            return exec_ret(ctx, -(int64_t)EBADF);
        }
    } else {
        /* execve takes three arguments; $a3/$a4 ($7/$8) hold caller
         * residue the kernel never reads, so they must not be
         * validated (busybox faults otherwise while qemu passes). */
        path = path_va;
        argv = argv_va;
        envp = envp_va;
        flags = 0U;
    }
    (void)flags;
    if (copy_guest_str(ctx, path, path_buf, sizeof path_buf,
                       &budget) != 0) {
        int e = path == 0U ? ENOENT : EFAULT;
        if (path != 0U && !ptr_ok(ctx, path)) {
            e = EFAULT;
        }
        return exec_ret(ctx, -(int64_t)e);
    }
    if (path_buf[0] == '\0') {
        return exec_ret(ctx, -(int64_t)ENOENT);
    }
    /* /proc/self/exe names the current guest image (qemu-user re-execs
     * the guest, never the host translator). Resolve it through the
     * noted guest path before the loader opens anything: opening the
     * host's /proc/self/exe would admit the translator itself. */
    if (strcmp(path_buf, "/proc/self/exe") == 0) {
        const char *exe = mips_proc_exe_path();
        size_t k = 0U;

        if (exe == NULL) {
            return exec_ret(ctx, -(int64_t)ENOENT);
        }
        while (exe[k] != '\0' && k + 1U < sizeof path_buf) {
            path_buf[k] = exe[k];
            k++;
        }
        path_buf[k] = '\0';
    }
    rc = copy_guest_vec(ctx, argv, &host_argv, &argc, &budget, 1);
    if (rc != 0) {
        return exec_ret(ctx, (int64_t)rc);
    }
    rc = copy_guest_vec(ctx, envp, &host_envp, &envc, &budget, 0);
    if (rc != 0) {
        free_vec(host_argv, argc);
        return exec_ret(ctx, (int64_t)rc);
    }
    /* Snapshot for atomic failure: the loader wipes ctx up front, so a
     * mid-load failure must restore the old image byte-for-byte. */
    backup = (mips64_ctx_t *)malloc(sizeof *backup);
    if (backup == NULL) {
        free_vec(host_argv, argc);
        free_vec(host_envp, envc);
        return exec_ret(ctx, -(int64_t)ENOMEM);
    }
    memcpy(backup, ctx, sizeof *backup);
    old_base = backup->guest_base;
    old_size = backup->task_size;
    rc = mips_load_elf(ctx, path_buf, host_argv, host_envp);
    if (rc != 0) {
        int e = errno != 0 ? errno : ENOEXEC;
        /* Tear down the partial new window, restore the old image. */
        if (ctx->guest_base != 0U && ctx->task_size != 0U) {
            (void)munmap((void *)(uintptr_t)ctx->guest_base,
                         (size_t)ctx->task_size);
        }
        memcpy(ctx, backup, sizeof *backup);
        /* Not a MIPS image: delegate to the host kernel (scripts run
         * through their #! line there). The restore above runs first
         * so a failed host exec still returns with the old image
         * intact; on success this process is replaced outright. */
        if (e == ENOEXEC) {
            size_t w = 0U;
            size_t r;

            for (r = 0U; r < envc; r++) {
                if (strncmp(host_envp[r], "LD_", 3) != 0 &&
                    strncmp(host_envp[r], "MIPS64RT_", 9) != 0) {
                    host_envp[w++] = host_envp[r];
                } else {
                    free(host_envp[r]);
                }
            }
            host_envp[w] = NULL;
            envc = w;
            (void)execve(path_buf, host_argv, host_envp);
            e = errno != 0 ? errno : ENOEXEC;
        }
        free_vec(host_argv, argc);
        free_vec(host_envp, envc);
        free(backup);
        if (e == 38) {
            e = 89;
        }
        return exec_ret(ctx, -(int64_t)e);
    }
    free_vec(host_argv, argc);
    free_vec(host_envp, envc);
    /* Old reservation is now orphaned (the loader zeroed ctx first):
     * release it; the new window owns the address space. */
    if (old_base != 0U && old_size != 0U && old_base != ctx->guest_base) {
        (void)munmap((void *)(uintptr_t)old_base, (size_t)old_size);
    }
    free(backup);
    reset_state_for_exec(ctx);
    return exec_ret(ctx, 0);
}

/* Write one 32-bit guest word in guest byte order. */
static int store_info_word(mips64_ctx_t *ctx, uint64_t base, uint64_t off,
                           uint32_t v)
{
    if (base == 0U) {
        return 0;
    }
    if (!ptr_ok(ctx, base + off)) {
        return -EFAULT;
    }
    if (((base + off) & 3U) != 0U ||
        !mips_mem_ok(ctx, base + off, 4U, MIPS_PROT_WRITE)) {
        return -EFAULT;
    }
    return guest_st32(ctx, base + off, (uint64_t)v) == 0 ? 0 : -EFAULT;
}

/* Decode a waitpid status into (CLD_ cause, exit status) for siginfo. */
static void decode_status(int status, uint32_t *cause, uint32_t *st)
{
    if (WIFEXITED(status)) {
        *cause = CLD_EXIT_CODE;
        *st = (uint32_t)WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *cause = WCOREDUMP(status) ? CLD_DUMP_CODE : CLD_KILL_CODE;
        *st = (uint32_t)WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        *cause = CLD_STOP_CODE;
        *st = (uint32_t)WSTOPSIG(status);
    } else if (WIFCONTINUED(status)) {
        *cause = CLD_CONT_CODE;
        *st = 0U;
    } else {
        *cause = (uint32_t)CLD_TRAP_CODE;
        *st = 0U;
    }
}

int64_t mips_sc_waitid(mips64_ctx_t *ctx, uint64_t which, uint64_t pid,
                       uint64_t infop_va, uint64_t options,
                       uint64_t rusage_va)
{
    uint32_t opt;
    pid_t want;
    int want_pid;
    int nohang;
    int nowait;
    pid_t got;
    int status = 0;
    int wflags = 0;
    uint32_t cause = 0;
    uint32_t st = 0;
    int rc;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    if (rusage_va != 0U) {
        return exec_ret(ctx, -(int64_t)ENOSYS);
    }
    opt = (uint32_t)options;
    if ((options >> 32) != 0U) {
        return exec_ret(ctx, -(int64_t)EINVAL);
    }
    if ((opt & ~(W_NOHANG_OPT | W_UNTRACED_OPT | W_EXITED_OPT |
                 W_CONTINUED_OPT | W_NOWAIT_OPT)) != 0U) {
        return exec_ret(ctx, -(int64_t)EINVAL);
    }
    if ((opt & (W_EXITED_OPT | W_UNTRACED_OPT | W_CONTINUED_OPT)) == 0U) {
        return exec_ret(ctx, -(int64_t)EINVAL);
    }
    if (which == (uint64_t)P_ALL) {
        want = -1;
        want_pid = 0;
    } else if (which == (uint64_t)P_PID) {
        if (pid == 0U || pid > (uint64_t)INT_MAX) {
            return exec_ret(ctx, -(int64_t)EINVAL);
        }
        want = (pid_t)pid;
        want_pid = 1;
    } else if (which == (uint64_t)P_PGID) {
        if (pid > (uint64_t)INT_MAX) {
            return exec_ret(ctx, -(int64_t)EINVAL);
        }
        want = (pid_t)(-(int64_t)pid);
        want_pid = 0;
    } else {
        return exec_ret(ctx, -(int64_t)ENOSYS);
    }
    (void)want_pid;
    nohang = (opt & W_NOHANG_OPT) != 0U ? 1 : 0;
    nowait = (opt & W_NOWAIT_OPT) != 0U ? 1 : 0;
    /* WEXITED is waitid-only: the host wait4 family rejects it with
     * EINVAL, and reporting exited children is its default anyway. */
    if ((opt & W_UNTRACED_OPT) != 0U) {
        wflags |= WUNTRACED;
    }
    if ((opt & W_CONTINUED_OPT) != 0U) {
        wflags |= WCONTINUED;
    }
    if (nohang) {
        wflags |= WNOHANG;
    }
    if (nowait) {
        wflags |= WNOWAIT;
    }
    got = waitpid(want, &status, wflags);
    if (got < 0) {
        return exec_ret(ctx, -(int64_t)errno);
    }
    if (got == 0) {
        /* WNOHANG with no state change: siginfo records si_pid 0. */
        if (infop_va != 0U) {
            if (!ptr_ok(ctx, infop_va) ||
                !mips_mem_ok(ctx, infop_va, 128U, MIPS_PROT_WRITE)) {
                return exec_ret(ctx, -(int64_t)EFAULT);
            }
            {
                uint8_t *p =
                    (uint8_t *)mips64_guest_ptr(ctx, infop_va);
                memset(p, 0, 128);
            }
        }
        return exec_ret(ctx, 0);
    }
    decode_status(status, &cause, &st);
    if (infop_va != 0U) {
        uid_t uid = getuid();
        if (!ptr_ok(ctx, infop_va) ||
            !mips_mem_ok(ctx, infop_va, 128U, MIPS_PROT_WRITE)) {
            return exec_ret(ctx, -(int64_t)EFAULT);
        }
        /* MIPS siginfo (musl, qemu-verified offsets): signo@0 code@4
         * errno@8, then the SIGCHLD cluster at base+0/+4/+8 where
         * base is 16 (N64: 8-byte pointer alignment) or 12 (N32:
         * 4-byte pointers need no pad). */
        uint64_t base_off = is_n32_ctx(ctx) ? 12U : 16U;

        rc = store_info_word(ctx, infop_va, 0, MIPS_SIGCHLD_NUM);
        if (rc == 0) {
            rc = store_info_word(ctx, infop_va, 4, cause);
        }
        if (rc == 0) {
            rc = store_info_word(ctx, infop_va, 8, 0U);
        }
        if (rc == 0) {
            rc = store_info_word(ctx, infop_va, base_off, (uint32_t)got);
        }
        if (rc == 0) {
            rc = store_info_word(ctx, infop_va, base_off + 4U,
                                 (uint32_t)uid);
        }
        if (rc == 0) {
            rc = store_info_word(ctx, infop_va, base_off + 8U, st);
        }
        if (rc != 0) {
            return exec_ret(ctx, (int64_t)rc);
        }
        {
            uint8_t *p = (uint8_t *)mips64_guest_ptr(ctx, infop_va);
            memset(p + base_off + 12U, 0,
                   (size_t)(128U - base_off - 12U));
        }
    }
    return exec_ret(ctx, 0);
}
