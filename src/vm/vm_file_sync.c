/*
 * src/vm/vm_file_sync.c -- File-backed writeback + reconcile (lane U12).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/vm/vm_file.c (R4-4) so every TU stays <= 860 lines.
 * Shares the inode table and locked helpers via vm_file_int.h; this TU
 * owns the sync side (shared writeback, reconcile, page read, and the
 * post-mutation entry points), while vm_file.c owns the hooks.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "vm/vm_file.h"
#include "vm/vm_file_int.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/backend.h"
#include "vm/vm_pages.h"

void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va, uint64_t len)
{
    vm_inode_t *tab;
    pid_t self = getpid();
    size_t k;
    int synced = 0;
    if (ctx == NULL || len == 0u || !vm_has_shared_fallback)
        return;
    vm_lock();
    tab = vm_inode_table();
    for (k = 0u; tab != NULL && k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i;
        for (i = 0; in->used != 0 && i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            uint64_t lo = va > m->va ? va : m->va;
            uint64_t hi = (va + len) < (m->va + m->len) ? (va + len) :
                                                         (m->va + m->len);
            uint64_t foff = m->file_offset + (lo - m->va);
            uint64_t n = 0u, done = 0u;
            const uint8_t *base;
            int ok = 1;
            if (m->pid != self || m->shared == 0 || m->native != 0 ||
                m->fd_dup < 0 || lo >= hi)
                continue;
            /* Never extend the file past EOF via a mapped store
             * (R4-2): the zero-filled tail of the final mapped page
             * is not file content. Bytes at or past EOF are not
             * written back. */
            if (foff >= in->size)
                continue;
            n = hi - lo;
            if (n > in->size - foff)
                n = in->size - foff;
            if (n == 0u)
                continue;
            base = (const uint8_t *)mips64_guest_ptr(ctx, lo);
            if (base == NULL)
                continue;
            /* Loop on short writes; publish clean/coherent state
             * only after every byte below EOF landed (R4-2). */
            while (done < n) {
                ssize_t w = pwrite(m->fd_dup, base + done,
                                   (size_t)(n - done),
                                   (off_t)(foff + done));

                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    ok = 0;
                    break;
                }
                if (w == 0) {
                    ok = 0;
                    break;
                }
                done += (uint64_t)w;
            }
            if (ok == 0)
                continue;
            mips_vm_pages_mark(lo, n, (unsigned)MIPS_VM_PAGE_COW_CLEAN);
            in->write_seq++;
            m->seen_write_seq = in->write_seq;
            vm_inode_apply_write_locked(ctx, in, m->fd_dup, foff, n);
            synced = 1;
        }
    }
    vm_unlock();
    if (synced != 0)
        mips_soft_tlb_invalidate_all();
}

void mips_vm_file_reconcile(mips64_ctx_t *ctx)
{
    vm_inode_t *tab;
    pid_t self = getpid();
    size_t k;
    if (ctx == NULL || !vm_inode_table_tried || vm_inode_table_ptr == NULL)
        return;
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        uint64_t min_sz = in->size;
        int i, need_trunc = 0, need_write = 0;
        if (in->used == 0)
            continue;
        for (i = 0; i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            if (m->pid != self || m->native != 0)
                continue;
            if (m->seen_resize_seq < in->resize_seq) {
                need_trunc = 1;
                if (m->min_size < min_sz)
                    min_sz = m->min_size;
                m->min_size = in->size;
            }
            if (m->seen_write_seq != in->write_seq)
                need_write = 1;
        }
        if (need_trunc != 0) {
            vm_inode_post_truncate_locked(ctx, in, min_sz);
            if (in->size != min_sz) {
                vm_inode_post_truncate_locked(ctx, in, in->size);
                need_write = 1;
            }
        }
        if (need_write != 0)
            vm_inode_apply_write_locked(ctx, in, -1, 0u, ~(uint64_t)0u);
    }
    vm_unlock();
}

int mips_vm_file_read_page(mips64_ctx_t *ctx, uint64_t page_va,
                           uint8_t *out_page)
{
    vm_inode_t *tab;
    pid_t self = getpid();
    size_t k;
    int done = 0;
    (void)ctx;
    if (out_page == NULL || !vm_inode_table_tried || vm_inode_table_ptr == NULL)
        return 0;
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX && done == 0; k++) {
        vm_inode_t *in = &tab[k];
        int i;
        for (i = 0; in->used != 0 && i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            if (m->pid != self || page_va < m->va || page_va >= m->va + m->len)
                continue;
            if (m->native != 0 || m->shared != 0 ||
                (mips_vm_page_flags(page_va >> 12) &
                 (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                uint64_t foff = m->file_offset + (page_va - m->va);
                ssize_t got = (m->fd_dup >= 0) ?
                    pread(m->fd_dup, out_page, 4096u, (off_t)foff) : 0;
                if (got < 0)
                    got = 0;
                if ((size_t)got < 4096u)
                    (void)memset(out_page + got, 0, 4096u - (size_t)got);
                done = 1;
            }
            break;
        }
    }
    vm_unlock();
    return done;
}

/* LL/SC shared-backing identity (R7-2): resolve va to the shared
 * file mapping covering it (any pid: the (dev, ino) identity is
 * per-file) with the inode's current LL/SC generation. */
int mips_vm_file_backing_seq(uint64_t va, uint64_t *devp, uint64_t *inop,
                             uint64_t *seqp)
{
    vm_inode_t *tab;
    size_t k;

    if (devp == NULL || inop == NULL || seqp == NULL ||
        !vm_inode_table_tried || vm_inode_table_ptr == NULL) {
        return 0;
    }
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; tab != NULL && k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i;

        for (i = 0; in->used != 0 && i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];

            if (m->shared == 0) {
                continue;
            }
            if (va >= m->va && va - m->va < m->len) {
                *devp = in->dev;
                *inop = in->ino;
                *seqp = in->llsc_seq;
                vm_unlock();
                return 1;
            }
        }
    }
    vm_unlock();
    return 0;
}

/* True when the shared LL/SC generation of (dev, ino) still equals
 * seq. Unknown inodes report 0 so the reservation fails safely. */
int mips_vm_file_llsc_seq_ok(uint64_t dev, uint64_t ino, uint64_t seq)
{
    vm_inode_t *in;
    int ok = 0;

    if (!vm_inode_table_tried || vm_inode_table_ptr == NULL) {
        return 0;
    }
    vm_lock();
    in = vm_inode_lookup(dev, ino, 0, 0u);
    if (in != NULL && in->llsc_seq == seq) {
        ok = 1;
    }
    vm_unlock();
    return ok;
}

/* Advance the shared LL/SC generation of every shared inode that
 * [va, va+len) overlaps. Called for every guest store (via
 * mips_llsc_note_write), so an interfering write through another
 * MAP_SHARED alias — same or another process — breaks LL snapshots
 * even when it restores the old value. Same-file cross-offset writes
 * only cause safe spurious SC failures. */
void mips_vm_file_bump_llsc(uint64_t va, uint64_t len)
{
    vm_inode_t *tab;
    size_t k;

    if (len == 0u || !vm_inode_table_tried || vm_inode_table_ptr == NULL) {
        return;
    }
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; tab != NULL && k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i;
        int hit = 0;

        if (in->used == 0) {
            continue;
        }
        for (i = 0; i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            uint64_t mhi = m->va + m->len;
            uint64_t end = va + len;

            if (m->shared == 0) {
                continue;
            }
            if (end < va) {
                end = ~(uint64_t)0u;
            }
            if (mhi < m->va) {
                mhi = ~(uint64_t)0u;
            }
            if (m->va < end && va < mhi) {
                hit = 1;
                break;
            }
        }
        if (hit != 0) {
            in->llsc_seq++;
        }
    }
    vm_unlock();
}

void mips_vm_file_post_write(mips64_ctx_t *ctx, int fd, uint64_t off, uint64_t n)
{
    struct stat st;
    vm_inode_t *in;
    pid_t self = getpid();
    if (ctx == NULL || fd < 0 || n == 0u || fstat(fd, &st) != 0)
        return;
    vm_lock();
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0u);
    if (in != NULL) {
        if (in->size != (uint64_t)st.st_size)
            vm_inode_note_resize_locked(in, (uint64_t)st.st_size, self);
        in->write_seq++;
        vm_inode_apply_write_locked(ctx, in, fd, off, n);
    }
    vm_unlock();
}

void mips_vm_file_post_write_seq(mips64_ctx_t *ctx, int fd, uint64_t n)
{
    off_t cur = (ctx != NULL && fd >= 0 && n != 0u) ? lseek(fd, 0, SEEK_CUR) : -1;
    if (ctx != NULL && fd >= 0 && n != 0u)
        mips_vm_file_post_write(ctx, fd,
                                (cur < 0 || (uint64_t)cur < n) ? 0u : (uint64_t)cur - n,
                                (cur < 0 || (uint64_t)cur < n) ? ~(uint64_t)0u : n);
}

void mips_vm_file_post_truncate_fd(mips64_ctx_t *ctx, int fd, uint64_t newsize)
{
    struct stat st;
    vm_inode_t *in;
    pid_t self = getpid();
    if (ctx == NULL || fd < 0 || fstat(fd, &st) != 0)
        return;
    vm_lock();
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0u);
    if (in != NULL) {
        vm_inode_note_resize_locked(in, newsize, self);
        vm_inode_post_truncate_locked(ctx, in, newsize);
    }
    vm_unlock();
}

void mips_vm_file_post_truncate_path(mips64_ctx_t *ctx, const char *host_path,
                                     uint64_t newsize)
{
    int fd = (host_path != NULL) ? open(host_path, O_RDONLY | O_CLOEXEC) : -1;
    if (fd >= 0) {
        mips_vm_file_post_truncate_fd(ctx, fd, newsize);
        (void)close(fd);
    }
}
