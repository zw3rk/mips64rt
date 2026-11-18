/*
 * src/os/syscalls_misc.c — process-group ids, creds, fcntl locks, and
 * small prctl/affinity shims (T14 userland qualification).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * poll/ppoll/select/pselect6 live in src/os/syscalls_poll.c;
 * open/creat lower to mips_sc_openat. Guest memory is staged on the
 * host and committed with mips_sc_copyout. Blocking waits drop the
 * dispatch lease. uid_t/gid_t are 32-bit on guest and host.
 */
#define _GNU_SOURCE

#include "core/cpu.h"

#include "os/errno_map.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern int64_t mips_sc_openat(mips64_ctx_t *ctx, uint64_t dirfd,
                              uint64_t path_va, uint64_t flags,
                              uint64_t mode);
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

extern int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                        uint32_t prot, const char *tag);
extern int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

/* poll/select entry points owned by src/os/syscalls_poll.c. */
extern int64_t mips_poll_wait(mips64_ctx_t *ctx, uint64_t fds_va,
                              uint64_t nfds, int timeout_ms);
extern int64_t mips_ppoll_wait(mips64_ctx_t *ctx, uint64_t fds,
                               uint64_t nfds, uint64_t ts_va,
                               uint64_t set_va, uint64_t setsize);
extern int64_t mips_select_wait(mips64_ctx_t *ctx, uint64_t nfds,
                                uint64_t r_va, uint64_t w_va,
                                uint64_t e_va, uint64_t t_va, int is_usec);
extern int64_t mips_pselect6_wait(mips64_ctx_t *ctx, uint64_t nfds,
                                  uint64_t r, uint64_t w, uint64_t e,
                                  uint64_t ts_va);

#define MISC_PROT_RW 3U

#define MISC_O_WRONLY 0x1U
#define MISC_O_CREAT 0x100U
#define MISC_O_TRUNC 0x200U

static int64_t misc_put32s(mips64_ctx_t *ctx, const uint32_t *v, int n,
                           const uint64_t *va)
{
    uint8_t img[4];
    int be = ctx->is_be != 0U;
    int i;

    for (i = 0; i < n; i++) {
        if (va[i] == 0U) {
            continue;
        }
        putn(img, v[i], 4, be);
        if (mips_sc_copyout(ctx, va[i], img, 4U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

static int64_t misc_getresid(mips64_ctx_t *ctx, int is_gid, uint64_t a,
                             uint64_t b, uint64_t c)
{
    uint32_t v[3];
    uint64_t va[3];

    va[0] = a;
    va[1] = b;
    va[2] = c;
    v[0] = is_gid ? (uint32_t)getgid() : (uint32_t)getuid();
    v[1] = is_gid ? (uint32_t)getegid() : (uint32_t)geteuid();
    v[2] = v[1];
    return misc_put32s(ctx, v, 3, va);
}

/* set*id family (n64/n32 index 103/104 setuid/setgid, 111/112
 * setreuid/setregid, 115/117 setresuid/setresgid). glibc posix_spawn
 * with POSIX_SPAWN_RESETIDS issues seteuid(getuid()) as
 * setresuid(-1, uid, -1) in the child and _exit(127)s on failure.
 * uid_t/gid_t are 32-bit on guest and host; the guest passes -1
 * sign-extended, so the low word is the "unchanged" sentinel. Darwin
 * has no setres*id: it lowers to setre*id (saved id follows POSIX). */
static int64_t misc_setid(mips64_ctx_t *ctx, int is_gid, int nargs,
                          uint64_t a, uint64_t b, uint64_t c)
{
    unsigned int r = (unsigned int)(uint32_t)a;
    unsigned int e = (unsigned int)(uint32_t)b;
    int rc;

    if (nargs == 1) {
        rc = is_gid ? setgid((gid_t)r) : setuid((uid_t)r);
    } else if (nargs == 2) {
        rc = is_gid ? setregid((gid_t)r, (gid_t)e)
                    : setreuid((uid_t)r, (uid_t)e);
    } else {
#if defined(__linux__)
        unsigned int sv = (unsigned int)(uint32_t)c;

        rc = is_gid ? setresgid((gid_t)r, (gid_t)e, (gid_t)sv)
                    : setresuid((uid_t)r, (uid_t)e, (uid_t)sv);
#else
        (void)c;
        rc = is_gid ? setregid((gid_t)r, (gid_t)e)
                    : setreuid((uid_t)r, (uid_t)e);
#endif
    }
    return l2a_ret(ctx, rc == 0 ? 0 : -(int64_t)errno);
}

static int64_t misc_getgroups(mips64_ctx_t *ctx, uint64_t n,
                              uint64_t list_va)
{
    gid_t gl[256];
    uint8_t img[256 * 4];
    int be = ctx->is_be != 0U;
    int cnt = getgroups(256, gl);
    int i;

    if (cnt < 0) {
        return l2a_ret(ctx, -(int64_t)errno);
    }
    if (n == 0U) {
        return l2a_ret(ctx, cnt);
    }
    if (n < (uint64_t)cnt) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    for (i = 0; i < cnt; i++) {
        putn(img + 4 * i, (uint64_t)gl[i], 4, be);
    }
    if (cnt > 0 && mips_sc_copyout(ctx, list_va, img, (uint64_t)cnt * 4U) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, cnt);
}

/* sched_getaffinity: report every online CPU as guest unsigned long
 * words (4 bytes on N32, 8 on N64) in guest endianness, so a
 * big-endian guest sees CPU 0 at 1UL << 0; returns bytes written. */
static int64_t misc_getaffinity(mips64_ctx_t *ctx, uint64_t len,
                                uint64_t va)
{
    uint8_t img[128];
    uint64_t words[32];
    unsigned ws = ctx->is_n32 != 0U ? 4U : 8U;
    int be = ctx->is_be != 0U;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    long i;
    unsigned k;

    if (len < 8U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (len > sizeof img) {
        len = sizeof img;
    }
    len &= ~(uint64_t)(ws - 1U);
    memset(words, 0, sizeof words);
    for (i = 0; i < (ncpu > 0 ? ncpu : 1) && (uint64_t)i < len * 8U; i++) {
        words[(unsigned)i / (ws * 8U)] |=
            (uint64_t)1U << ((unsigned)i % (ws * 8U));
    }
    memset(img, 0, sizeof img);
    for (k = 0U; k < len / ws; k++) {
        putn(img + k * ws, words[k], ws, be);
    }
    if (mips_sc_copyout(ctx, va, img, len) != 0) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    return l2a_ret(ctx, (int64_t)len);
}

/* prctl option numbers (Linux UAPI, arch-independent). Only the
 * options below are honoured; everything else (PR_SET_SECCOMP,
 * PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_SET_CHILD_SUBREAPER,
 * PR_GET_CHILD_SUBREAPER, PR_GET_TID_ADDRESS, ...) reports -EINVAL,
 * like the kernel for unknown or denied options. */
#define MISC_PR_GET_DUMPABLE 3U
#define MISC_PR_SET_DUMPABLE 4U
#define MISC_PR_SET_NAME 15U
#define MISC_PR_GET_NAME 16U
#define MISC_PR_SET_TIMERSLACK 29U
#define MISC_PR_SET_NO_NEW_PRIVS 38U
#define MISC_PR_GET_NO_NEW_PRIVS 39U
#define MISC_PR_SET_THP_DISABLE 41U
#define MISC_PR_COMM_SIZE 16U

/* Tracked NO_NEW_PRIVS bit (authoritative on hosts without a prctl
 * query; on Linux the host value is read back instead). */
static int misc_no_new_privs;

static int64_t misc_prctl(mips64_ctx_t *ctx, uint64_t opt, uint64_t a1,
                          uint64_t a2, uint64_t a3, uint64_t a4)
{
    if (opt == MISC_PR_SET_NAME) {
        uint64_t i;

        memset(ctx->comm, 0, sizeof ctx->comm);
        /* Copy up to 15 bytes plus the NUL, faulting like the kernel
         * when the source bytes are unmapped (stops at the NUL, so a
         * short name never over-reads the page tail). */
        for (i = 0U; i < MISC_PR_COMM_SIZE - 1U; i++) {
            const uint8_t *p = guest_range(ctx, a1 + i, 1U, 0);

            if (p == NULL) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
            ctx->comm[i] = (char)p[0];
            if (p[0] == 0U) {
                break;
            }
        }
        return l2a_ret(ctx, 0);
    }
    if (opt == MISC_PR_GET_NAME) {
        uint8_t img[MISC_PR_COMM_SIZE];
        const char *src = ctx->comm[0] != 0 ? ctx->comm : "mips64rt";
        uint64_t i;

        memset(img, 0, sizeof img);
        for (i = 0U; i < MISC_PR_COMM_SIZE && src[i] != 0; i++) {
            img[i] = (uint8_t)src[i];
        }
        if (mips_sc_copyout(ctx, a1, img, sizeof img) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        return l2a_ret(ctx, 0);
    }
    if (opt == MISC_PR_GET_DUMPABLE) {
        return l2a_ret(ctx, 1);
    }
    if (opt == MISC_PR_SET_DUMPABLE) {
        return l2a_ret(ctx, a1 <= 1U ? 0 : -(int64_t)EINVAL);
    }
    if (opt == MISC_PR_SET_NO_NEW_PRIVS) {
        if (a1 != 1U || a2 != 0U || a3 != 0U || a4 != 0U) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
#if defined(__linux__)
        if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
            return l2a_ret(ctx, -(int64_t)errno);
        }
#endif
        misc_no_new_privs = 1;
        return l2a_ret(ctx, 0);
    }
    if (opt == MISC_PR_GET_NO_NEW_PRIVS) {
#if defined(__linux__)
        {
            int rc = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);

            if (rc < 0) {
                return l2a_ret(ctx, -(int64_t)errno);
            }
            return l2a_ret(ctx, rc);
        }
#else
        return l2a_ret(ctx, misc_no_new_privs);
#endif
    }
    if (opt == MISC_PR_SET_TIMERSLACK) {
        return l2a_ret(ctx, 0);
    }
    if (opt == MISC_PR_SET_THP_DISABLE) {
        if (a2 != 0U || a3 != 0U || a4 != 0U) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        return l2a_ret(ctx, 0);
    }
    return l2a_ret(ctx, -(int64_t)EINVAL);
}

/* fcntl record locks. N64 (and the N32 64-bit commands 33/34/35, which
 * carry the same 32-byte flock64): short l_type @0, short l_whence @2,
 * off_t l_start @8, off_t l_len @16, pid_t l_pid @24. Plain N32
 * F_GETLK/F_SETLK/F_SETLKW (14/6/7) use the 36-byte MIPS compat_flock:
 * l_type @0, l_whence @2, l_start @4, l_len @8, l_sysid @12,
 * l_pid @16, pad @20..35. F_RDLCK/F_WRLCK/F_UNLCK are 0/1/2 on MIPS
 * and Linux; Darwin uses 1/3/2 with its own 24-byte flock layout.
 * Unknown commands and unknown lock types return EINVAL, matching
 * Linux. */
int64_t mips_sc_fcntl_lock(mips64_ctx_t *ctx, int n32, uint64_t fd,
                           uint64_t cmd, uint64_t arg)
{
    uint8_t img[36];
    const uint8_t *g;
    int be = ctx->is_be != 0U;
    unsigned imglen;
    unsigned ltype;
    unsigned lwhence;
    int64_t lstart;
    int64_t llen;
    uint32_t lpid;
    int is_get;
    int is_wait;
    int rc;
    int e;

    if (n32 && (cmd == 14U || cmd == 6U || cmd == 7U)) {
        g = guest_range(ctx, arg, 36U, 0);
        if (g == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        ltype = (unsigned)getn(g, 2, be);
        lwhence = (unsigned)getn(g + 2, 2, be);
        lstart = (int64_t)(int32_t)getn(g + 4, 4, be);
        llen = (int64_t)(int32_t)getn(g + 8, 4, be);
        lpid = (uint32_t)getn(g + 16, 4, be);
        imglen = 36U;
    } else if (cmd == 14U || cmd == 6U || cmd == 7U || cmd == 33U ||
               cmd == 34U || cmd == 35U) {
        g = guest_range(ctx, arg, 32U, 0);
        if (g == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        ltype = (unsigned)getn(g, 2, be);
        lwhence = (unsigned)getn(g + 2, 2, be);
        lstart = (int64_t)getn(g + 8, 8, be);
        llen = (int64_t)getn(g + 16, 8, be);
        lpid = (uint32_t)getn(g + 24, 4, be);
        imglen = 32U;
    } else {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (ltype > 2U) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    memcpy(img, g, imglen);
    is_get = (cmd == 14U || cmd == 33U) != 0;
    is_wait = (cmd == 7U || cmd == 35U) != 0;
#if defined(__APPLE__)
    {
        /* Darwin flock: start@0, len@8, pid@16, type@20, whence@22. */
        uint8_t himg[24];
        int64_t hs = lstart;
        int64_t hl = llen;
        int32_t hp = (int32_t)lpid;
        uint16_t ht = ltype == 0U ? 1U : (ltype == 1U ? 3U : 2U);
        uint16_t hw = (uint16_t)lwhence;
        int hcmd = is_get ? F_GETLK : (is_wait ? F_SETLKW : F_SETLK);

        memcpy(himg, &hs, 8);
        memcpy(himg + 8, &hl, 8);
        memcpy(himg + 16, &hp, 4);
        memcpy(himg + 20, &ht, 2);
        memcpy(himg + 22, &hw, 2);
        if (is_wait) {
            mips_qs_lease_exit(ctx);
        }
        rc = fcntl((int)fd, hcmd, himg);
        e = errno;
        if (is_wait) {
            mips_qs_lease_enter(ctx);
        }
        if (rc < 0) {
            return l2a_ret(ctx, -(int64_t)e);
        }
        if (is_get) {
            uint16_t rt;
            int64_t rs;
            int64_t rl;
            int32_t rp;

            memcpy(&rs, himg, 8);
            memcpy(&rl, himg + 8, 8);
            memcpy(&rp, himg + 16, 4);
            memcpy(&rt, himg + 20, 2);
            memcpy(&hw, himg + 22, 2);
            ltype = rt == 1U ? 0U : (rt == 3U ? 1U : 2U);
            lstart = rs;
            llen = rl;
            lpid = (uint32_t)rp;
            lwhence = (unsigned)hw;
        }
    }
#else
    {
        struct flock fl;
        int hcmd = is_get ? F_GETLK : (is_wait ? F_SETLKW : F_SETLK);

        memset(&fl, 0, sizeof fl);
        fl.l_type = (short)ltype;
        fl.l_whence = (short)lwhence;
        fl.l_start = (off_t)lstart;
        fl.l_len = (off_t)llen;
        fl.l_pid = (pid_t)lpid;
        if (is_wait) {
            mips_qs_lease_exit(ctx);
        }
        rc = fcntl((int)fd, hcmd, &fl);
        e = errno;
        if (is_wait) {
            mips_qs_lease_enter(ctx);
        }
        if (rc < 0) {
            return l2a_ret(ctx, -(int64_t)e);
        }
        if (is_get) {
            ltype = (unsigned)(uint16_t)fl.l_type;
            lwhence = (unsigned)(uint16_t)fl.l_whence;
            lstart = (int64_t)fl.l_start;
            llen = (int64_t)fl.l_len;
            lpid = (uint32_t)fl.l_pid;
        }
    }
#endif
    if (is_get) {
        if (imglen == 36U) {
            putn(img, (uint64_t)ltype, 2, be);
            putn(img + 2, (uint64_t)lwhence, 2, be);
            putn(img + 4, (uint64_t)(uint32_t)(int32_t)lstart, 4, be);
            putn(img + 8, (uint64_t)(uint32_t)(int32_t)llen, 4, be);
            putn(img + 12, 0U, 4, be);
            putn(img + 16, (uint64_t)lpid, 4, be);
        } else {
            putn(img, (uint64_t)ltype, 2, be);
            putn(img + 2, (uint64_t)lwhence, 2, be);
            putn(img + 8, (uint64_t)lstart, 8, be);
            putn(img + 16, (uint64_t)llen, 8, be);
            putn(img + 24, (uint64_t)lpid, 4, be);
        }
        if (mips_sc_copyout(ctx, arg, img, imglen) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

/* brk(2): like the kernel, failure returns the unchanged break (the
 * libc wrapper detects it by comparing against the request). */
int64_t mips_sc_brk(mips64_ctx_t *ctx, uint64_t addr)
{
    uint64_t aligned;
    uint64_t have;
    int rc;

    if (addr == 0U || addr == ctx->brk_curr) {
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    /* Below the base the request fails; exactly the base shrinks the
     * heap back to empty (the shrink path below unmaps everything
     * above it, guarded by keep >= ctx->brk_base). */
    if (addr < ctx->brk_base) {
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (addr < ctx->brk_curr) {
        /* Shrink: release whole pages above the new mark so a later
         * grow re-maps from a consistent boundary. */
        uint64_t keep = (addr + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
        uint64_t top = (ctx->brk_curr + (MIPS64_PAGE_SIZE - 1U)) &
                       MIPS64_PAGE_MASK;

        if (top > keep && keep >= ctx->brk_base) {
            (void)mips_mem_unmap(ctx, keep, top - keep);
        }
        ctx->brk_curr = addr;
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (ctx->brk_base == 0U) {
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    aligned = (addr + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
    if (aligned < addr) {
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    if (aligned > ctx->task_size) {
        return l2a_ret(ctx, (int64_t)ctx->brk_curr);
    }
    /* Map only the not-yet-mapped extension. Any mapping failure
     * (including -EEXIST over a pre-existing foreign mapping, which
     * the kernel rejects) leaves the break unchanged. */
    have = ctx->brk_curr > ctx->brk_base ?
           ((ctx->brk_curr + (MIPS64_PAGE_SIZE - 1U)) &
            MIPS64_PAGE_MASK) : ctx->brk_base;
    if (aligned > have) {
        rc = mips_mem_map(ctx, have, aligned - have,
                          MISC_PROT_RW, "heap");
        if (rc != 0) {
            return l2a_ret(ctx, (int64_t)ctx->brk_curr);
        }
    }
    ctx->brk_curr = addr;
    return l2a_ret(ctx, (int64_t)ctx->brk_curr);
}

#define MS_L(a, idx) ((a) == (uint64_t)(5000U + (idx)) || \
                      (a) == (uint64_t)(6000U + (idx)))
#define MS_A(a, i64, i32) ((a) == (uint64_t)(n32 ? 6000U + (i32) \
                                                 : 5000U + (i64)))

int64_t mips_sc_misc_extra(mips64_ctx_t *ctx, int n32, uint64_t nr,
                           uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, int *claimed)
{
    *claimed = 1;
    if (MS_L(nr, 2)) { /* open */
        return mips_sc_openat(ctx, L2A_AT_FDCWD, a0, a1, a2);
    }
    if (MS_L(nr, 83)) { /* creat */
        return mips_sc_openat(ctx, L2A_AT_FDCWD, a0,
                              MISC_O_CREAT | MISC_O_TRUNC | MISC_O_WRONLY,
                              a1);
    }
    if (MS_L(nr, 7)) { /* poll */
        return l2a_ret(ctx, mips_poll_wait(ctx, a0, a1,
                                          (int)(int32_t)a2));
    }
    if (MS_A(nr, 261, 265)) { /* ppoll */
        return mips_ppoll_wait(ctx, a0, a1, a2, a3, a4);
    }
    if (MS_L(nr, 22)) { /* _newselect */
        return l2a_ret(ctx, mips_select_wait(ctx, a0, a1, a2, a3, a4,
                                            1));
    }
    if (MS_A(nr, 260, 264)) { /* pselect6 */
        return mips_pselect6_wait(ctx, a0, a1, a2, a3, a4);
    }
    if (MS_L(nr, 109)) { /* getpgrp */
        return l2a_ret(ctx, getpgrp());
    }
    if (MS_L(nr, 119)) { /* getpgid */
        pid_t r = getpgid((pid_t)a0);

        return l2a_ret(ctx, r < 0 ? -(int64_t)errno : r);
    }
    if (MS_L(nr, 107)) { /* setpgid */
        return l2a_ret(ctx, setpgid((pid_t)a0, (pid_t)a1) == 0
                                ? 0 : -(int64_t)errno);
    }
    if (MS_L(nr, 110)) { /* setsid */
        pid_t r = setsid();

        return l2a_ret(ctx, r < 0 ? -(int64_t)errno : r);
    }
    if (MS_L(nr, 122)) { /* getsid */
        pid_t r = getsid((pid_t)a0);

        return l2a_ret(ctx, r < 0 ? -(int64_t)errno : r);
    }
    if (MS_L(nr, 113)) { /* getgroups */
        return misc_getgroups(ctx, a0, a1);
    }
    if (MS_L(nr, 116) || MS_L(nr, 118)) { /* getresuid / getresgid */
        return misc_getresid(ctx, MS_L(nr, 118), a0, a1, a2);
    }
    if (MS_L(nr, 103) || MS_L(nr, 104)) { /* setuid / setgid */
        return misc_setid(ctx, MS_L(nr, 104), 1, a0, a1, a2);
    }
    if (MS_L(nr, 111) || MS_L(nr, 112)) { /* setreuid / setregid */
        return misc_setid(ctx, MS_L(nr, 112), 2, a0, a1, a2);
    }
    if (MS_L(nr, 115) || MS_L(nr, 117)) { /* setresuid / setresgid */
        return misc_setid(ctx, MS_L(nr, 117), 3, a0, a1, a2);
    }
    if (MS_L(nr, 196)) { /* sched_getaffinity */
        return misc_getaffinity(ctx, a1, a2);
    }
    if (MS_L(nr, 195) || MS_A(nr, 215, 216) || MS_L(nr, 179)) {
        /* sched_setaffinity / fadvise64 / readahead: advisory. */
        return l2a_ret(ctx, 0);
    }
    if (MS_L(nr, 153)) { /* prctl */
        return misc_prctl(ctx, a0, a1, a2, a3, a4);
    }
    *claimed = 0;
    return -(int64_t)ENOSYS;
}
