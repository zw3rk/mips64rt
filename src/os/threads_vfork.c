/*
 * src/os/threads_vfork.c — CLONE_VFORK parent-stack-window diff replay.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 lane L4b: glibc posix_spawn error reporting (args->err written
 * on the parent's stack before _exit(127)) across COW fork(). Follows
 * the s390xrt (src/os/thread.c) pattern: before fork(), the parent
 * snapshots a guest window (up to 64 KiB) around its $sp; the child
 * diffs the window against the snapshot and streams {va, len, bytes}
 * records over a CLOEXEC pipe; the parent replays them into its own
 * guest memory until EOF (child exit or exec). A lone CLONE_VM without
 * CLONE_VFORK still reports -ENOSYS (fork cannot share an address
 * space); the parent suspension (the observable half of the vfork
 * contract) is exact.
 */

#define _GNU_SOURCE

#include "core/cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Shared helpers owned by sibling files: the validated guest window
 * (mem.c), the guest commit path (syscalls.c), and the dispatch lease
 * (quiesce.c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern void mips_qs_lease_enter(mips64_ctx_t *ctx);
extern void mips_qs_lease_exit(mips64_ctx_t *ctx);

/* Guest window around the parent $sp at clone time (64 KiB max): large
 * enough for the posix_spawn args frame, small enough to bound the
 * pre-fork page walk. Records coalesce runs separated by VF_GAP bytes
 * or less so sparse stack writes travel in one chunk. */
#define VF_WINDOW 65536U
#define VF_GAP 16U
/* Guest CLONE_VFORK bit (Linux arch-independent value, shared by
 * MIPS64; mirrors src/os/threads.c L4B_CLONE_VFORK). */
#define VF_CLONE_VFORK UINT64_C(0x00004000)

/* Child side of a CLONE_VFORK channel: the write end, the snapshotted
 * window, and the window as it was at clone time (diffs go to the
 * parent). Only ever set in a fork child; the parent keeps its ends in
 * l4b_clone_fork locals (which fork copies, so no cross-thread static
 * races when two threads vfork at once). */
static struct {
    int fd;
    uint64_t va;
    size_t len;
    uint8_t *snap;
} g_vf = { -1, 0U, 0U, NULL };

/* Blocking write with EINTR retry (child diff records). */
static int vf_write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;

    while (n > 0U) {
        ssize_t w = write(fd, p, n);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return 0;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 1;
}

/* Blocking read with EINTR retry: 1 when the full record arrived,
 * 0 on EOF (child exited) or error (both end the parent wait). */
static int vf_read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;

    while (n > 0U) {
        ssize_t r = read(fd, p, n);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return 0;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 1;
}

/* Drop the channel without delivering diffs (nested-vfork inheritance,
 * or a successful in-process exec that replaced the window the snapshotted
 * bytes came from: a success-path child wrote nothing to the parent
 * window, so closing (EOF) is the whole resume). */
void mips64_vfork_drop(void)
{
    if (g_vf.fd >= 0) {
        (void)close(g_vf.fd);
    }
    free(g_vf.snap);
    g_vf.fd = -1;
    g_vf.va = 0U;
    g_vf.len = 0U;
    g_vf.snap = NULL;
}

/* The child write-end fd, so guest close/close_range can skip it (a
 * child dup2 over it, or a close, must not strand the parent). -1 when
 * no channel is live. */
int mips64_vfork_pipe_fd(void)
{
    return g_vf.fd;
}

/* Child: send the window bytes that changed since the snapshot as
 * {va:u64 LE, len:u32 LE, data} records, then advance the snapshot to
 * the bytes just sent (a later flush only replays newer writes).
 * Shared by the pre-exec flush (channel stays live) and the exit-path
 * flush (which drops the channel after). A vanished window or a
 * failed snapshot sends nothing (the parent still resumes). */
static void vf_emit(mips64_ctx_t *ctx)
{
    uint8_t *cur = NULL;
    size_t i = 0U;

    if (ctx != NULL && g_vf.snap != NULL && g_vf.len != 0U &&
        mips_mem_ok(ctx, g_vf.va, (uint64_t)g_vf.len,
                    (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE))) {
        cur = (uint8_t *)malloc(g_vf.len);
        if (cur != NULL) {
            memcpy(cur, mips64_guest_ptr(ctx, g_vf.va), g_vf.len);
        }
    }
    while (cur != NULL && i < g_vf.len) {
        size_t j;
        size_t end;
        uint8_t hdr[12];
        uint64_t va;
        unsigned k;

        if (cur[i] == g_vf.snap[i]) {
            i++;
            continue;
        }
        end = i + 1U;
        for (j = i + 1U; j < g_vf.len && j - end < VF_GAP; j++) {
            if (cur[j] != g_vf.snap[j]) {
                end = j + 1U;
            }
        }
        va = g_vf.va + (uint64_t)i;
        for (k = 0U; k < 8U; k++) {
            hdr[k] = (uint8_t)(va >> (8U * k));
        }
        for (k = 0U; k < 4U; k++) {
            hdr[8U + k] = (uint8_t)((uint32_t)(end - i) >> (8U * k));
        }
        if (vf_write_all(g_vf.fd, hdr, sizeof hdr) == 0 ||
            vf_write_all(g_vf.fd, cur + i, end - i) == 0) {
            break;
        }
        i = end;
    }
    if (cur != NULL && g_vf.snap != NULL && g_vf.len != 0U) {
        memcpy(g_vf.snap, cur, g_vf.len);
    }
    free(cur);
}

/* Pre-execve flush: replay the window diffs but keep g_vf.fd and
 * g_vf.snap open/live. A successful execve closes the pipe via
 * CLOEXEC (waking the parent); a failed execve leaves the channel
 * for the child's args->err = errno; _exit(127) path, which flushes
 * the error and closes the channel. */
void mips64_vfork_flush_pre_exec(mips64_ctx_t *ctx)
{
    if (g_vf.fd < 0) {
        return;
    }
    vf_emit(ctx);
}

/* Child exit-path flush: replay the window diffs (posix_spawn
 * args->err) and drop the channel; closing the pipe is what resumes
 * the parent. */
void mips64_vfork_flush(mips64_ctx_t *ctx)
{
    if (g_vf.fd < 0) {
        return;
    }
    vf_emit(ctx);
    mips64_vfork_drop();
}

/* Snapshot [va, va+len) around sp: walk page-by-page over the 64 KiB
 * span starting 16 KiB below sp's page, keeping the contiguous run
 * that contains sp and satisfies READ|WRITE. The sp page itself must
 * be mapped (else no snapshot); the span is best-effort (a short run
 * still carries args->err). */
static void vf_snapshot(mips64_ctx_t *ctx, uint64_t *vva, size_t *vlen,
                        uint8_t **vsnap)
{
    uint64_t sp = ctx->gpr[MIPS64_REG_SP];
    uint64_t page = sp & ~(uint64_t)4095U;
    uint64_t lo = (sp >= 16384U) ? page - 16384U : page;
    uint64_t hi = lo + (uint64_t)VF_WINDOW;
    uint64_t start = page;
    uint64_t end = page + 4096U;
    uint8_t *snap = NULL;

    *vva = 0U;
    *vlen = 0U;
    *vsnap = NULL;
    if (hi < lo) {
        hi = ~(uint64_t)0U;
    }
    if (!mips_mem_ok(ctx, page, 4096U,
                     (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE))) {
        return;
    }
    while (start > lo) {
        uint64_t p = start - 4096U;

        if (!mips_mem_ok(ctx, p, 4096U,
                         (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE))) {
            break;
        }
        start = p;
    }
    while (end < hi) {
        if (!mips_mem_ok(ctx, end, 4096U,
                         (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE))) {
            break;
        }
        end += 4096U;
    }
    if (end <= start || end - start > (uint64_t)VF_WINDOW) {
        return;
    }
    snap = (uint8_t *)malloc((size_t)(end - start));
    if (snap == NULL) {
        return;
    }
    memcpy(snap, mips64_guest_ptr(ctx, start), (size_t)(end - start));
    *vva = start;
    *vlen = (size_t)(end - start);
    *vsnap = snap;
}

/* Parent side of fork preparation (called before fork, still single
 * address space): open the resume pipe above the low fd numbers (so
 * child dup2 file actions on fds 0..10 never close it) and snapshot
 * the parent stack window. Returns 1 with the out params set (snap may
 * be NULL: the pipe alone still suspends the parent), 0 when flags carry
 * no CLONE_VFORK (plain fork: nothing to do), or a negative errno when
 * the pipe failed (caller reports it like before). */
int64_t mips64_vfork_pre(mips64_ctx_t *ctx, uint64_t flags, int *rfd,
                         int *wfd, uint64_t *va, size_t *len,
                         uint8_t **snap)
{
    int pfd[2];
    int w;

    if ((flags & VF_CLONE_VFORK) == 0U) {
        return 0;
    }
    if (pipe(pfd) != 0) {
        return -(int64_t)errno;
    }
    /* Park the write end above the child file-action range; the pipe
     * is CLOEXEC either way so an exec still resumes the parent. */
    w = fcntl(pfd[1], F_DUPFD_CLOEXEC, 512);
    if (w < 0) {
        w = pfd[1];
        if (fcntl(w, F_SETFD, FD_CLOEXEC) != 0) {
            int e = errno;

            (void)close(pfd[0]);
            (void)close(pfd[1]);
            return -(int64_t)e;
        }
    } else {
        (void)close(pfd[1]);
    }
    if (fcntl(pfd[0], F_SETFD, FD_CLOEXEC) != 0) {
        int e = errno;

        (void)close(pfd[0]);
        (void)close(w);
        return -(int64_t)e;
    }
    vf_snapshot(ctx, va, len, snap);
    *rfd = pfd[0];
    *wfd = w;
    return 1;
}

/* Tear down a prepared (but unused: fork failed) channel. */
void mips64_vfork_pre_abort(int rfd, int wfd, uint8_t *snap)
{
    (void)close(rfd);
    (void)close(wfd);
    free(snap);
}

/* Fork child: install the channel (the read end stays with the parent;
 * our write end closes on execve via CLOEXEC, or on exit via flush).
 * Drops any inherited older channel first (nested vfork resumes the
 * outer parent, like the reference). */
void mips64_vfork_child(uint64_t va, size_t len, uint8_t *snap, int rfd,
                        int wfd)
{
    (void)close(rfd);
    mips64_vfork_drop();
    g_vf.fd = wfd;
    g_vf.va = va;
    g_vf.len = len;
    g_vf.snap = snap;
}

/* Fork parent: block until the child closes the channel (exit or exec),
 * replaying {va, len, bytes} diff records into guest memory. The VM
 * lease is released across the blocking read (like the old 1-byte
 * wait); each record commits via the lock-safe copyout path. */
void mips64_vfork_parent(mips64_ctx_t *ctx, int rfd, int wfd)
{
    uint8_t *buf = NULL;

    (void)close(wfd);
    buf = (uint8_t *)malloc(VF_WINDOW);
    mips_qs_lease_exit(ctx);
    while (buf != NULL) {
        uint8_t hdr[12];
        uint64_t va = 0U;
        uint32_t n = 0U;
        unsigned k;

        if (vf_read_all(rfd, hdr, sizeof hdr) == 0) {
            break;
        }
        for (k = 0U; k < 8U; k++) {
            va |= (uint64_t)hdr[k] << (8U * k);
        }
        for (k = 0U; k < 4U; k++) {
            n |= (uint32_t)hdr[8U + k] << (8U * k);
        }
        if (n == 0U) {
            continue;
        }
        if (n > VF_WINDOW || vf_read_all(rfd, buf, n) == 0) {
            break;
        }
        (void)mips_sc_copyout(ctx, va, buf, n);
    }
    mips_qs_lease_enter(ctx);
    free(buf);
    (void)close(rfd);
}
