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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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

/* LL/SC shared-backing identity (R7-2): resolve va to this
 * process's shared file mapping covering it (pid-filtered like every
 * other VA-keyed scan: a sibling's coincident mapping of another file
 * must not supply the reservation identity) with the inode's current
 * LL/SC generation. */
int mips_vm_file_backing_seq(uint64_t va, uint64_t *devp, uint64_t *inop,
                             uint64_t *seqp)
{
    vm_inode_t *tab;
    pid_t cur_pid = getpid();
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

            if (m->pid != cur_pid || m->shared == 0) {
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
    pid_t cur_pid = getpid();
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

            if (m->pid != cur_pid || m->shared == 0) {
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
            /* Cross-process visible: bump atomically so a racing
             * increment is never lost (a lost bump could hide an
             * ABA from an LL armed on the old generation). */
            __atomic_add_fetch(&in->llsc_seq, 1u, __ATOMIC_SEQ_CST);
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

/* ---- R9-5: pre-lock file-page snapshot for moving mremap ----
 *
 * The moving-mremap span copy runs under mem_lock, so it must not
 * take vm_lock (mem->vm) while the file remap hook takes mem_lock
 * under vm_lock (vm->mem). The mover therefore snapshots every
 * file-supplied page of both spans BEFORE mem_lock; the copy below
 * consults the snapshot with no locking at all. Coverage matches
 * mips_vm_file_read_page exactly: only pages a self-owned record
 * supplies (native, shared, or COW-clean) are cached, so a cache
 * miss means "copy the host bytes" exactly as before. Pages are
 * sorted once for binary search; a NULL snapshot is a universal
 * miss. */
typedef struct {
    uint64_t va;
    uint8_t data[4096];
} vm_file_snap_page_t;

typedef struct {
    size_t count;
    size_t cap;
    vm_file_snap_page_t *pages;
} vm_file_snap_t;

static int snap_cmp(const void *a, const void *b)
{
    uint64_t va = ((const vm_file_snap_page_t *)a)->va;
    uint64_t vb = ((const vm_file_snap_page_t *)b)->va;
    return va < vb ? -1 : va > vb ? 1 : 0;
}

static void snap_add(vm_file_snap_t *s, uint64_t page_va,
                     const uint8_t *data)
{
    if (s->count >= s->cap) {
        size_t ncap = s->cap != 0U ? s->cap * 2U : 16U;
        vm_file_snap_page_t *np = (vm_file_snap_page_t *)realloc(
            s->pages, ncap * sizeof *np);
        if (np == NULL)
            return;
        s->pages = np;
        s->cap = ncap;
    }
    s->pages[s->count].va = page_va;
    memcpy(s->pages[s->count].data, data, 4096U);
    s->count++;
}

/* Caller holds vm_lock. Mirrors the read_page coverage rule. */
static void snap_one_span(vm_file_snap_t *s, uint64_t span_va,
                          uint64_t span_len, pid_t self)
{
    vm_inode_t *tab = vm_inode_table_ptr;
    uint64_t end = (span_va + span_len < span_va) ? ~(uint64_t)0u :
                   span_va + span_len;
    uint64_t page;
    size_t k;
    if (tab == NULL || span_len == 0u)
        return;
    for (page = span_va; page < end; page += 4096u) {
        for (k = 0u; k < VM_INODE_MAX; k++) {
            vm_inode_t *in = &tab[k];
            int i;
            for (i = 0; in->used != 0 && i < in->nmaps; i++) {
                vm_inode_map_t *m = &in->maps[i];
                if (m->pid != self || page < m->va ||
                    page >= m->va + m->len)
                    continue;
                if (m->native != 0 || m->shared != 0 ||
                    (mips_vm_page_flags(page >> 12) &
                     (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                    uint8_t tmp[4096];
                    uint64_t foff = m->file_offset + (page - m->va);
                    ssize_t got = (m->fd_dup >= 0) ?
                        pread(m->fd_dup, tmp, 4096u, (off_t)foff) : 0;
                    if (got < 0)
                        got = 0;
                    if ((size_t)got < 4096u)
                        (void)memset(tmp + got, 0, 4096u - (size_t)got);
                    snap_add(s, page, tmp);
                }
                break;
            }
        }
        if (page + 4096u < page)
            break;
    }
}

void *mips_vm_file_snapshot_spans(mips64_ctx_t *ctx, uint64_t va1,
                                  uint64_t len1, uint64_t va2,
                                  uint64_t len2)
{
    vm_file_snap_t *s;
    pid_t self = getpid();
    (void)ctx;
    if ((!vm_inode_table_tried || vm_inode_table_ptr == NULL) ||
        (len1 == 0u && len2 == 0u))
        return NULL;
    s = (vm_file_snap_t *)calloc(1U, sizeof *s);
    if (s == NULL)
        return NULL;
    vm_lock();
    snap_one_span(s, va1, len1, self);
    snap_one_span(s, va2, len2, self);
    vm_unlock();
    if (s->count == 0u) {
        free(s->pages);
        free(s);
        return NULL;
    }
    qsort(s->pages, s->count, sizeof s->pages[0], snap_cmp);
    return s;
}

int mips_vm_file_snapshot_fetch(const void *snap, uint64_t page_va,
                                uint8_t *out_page)
{
    const vm_file_snap_t *s = (const vm_file_snap_t *)snap;
    vm_file_snap_page_t key;
    const vm_file_snap_page_t *hit;
    if (s == NULL || out_page == NULL || s->count == 0u)
        return 0;
    key.va = page_va;
    hit = (const vm_file_snap_page_t *)bsearch(&key, s->pages, s->count,
        sizeof s->pages[0], snap_cmp);
    if (hit == NULL)
        return 0;
    memcpy(out_page, hit->data, 4096U);
    return 1;
}

void mips_vm_file_snapshot_free(void *snap)
{
    vm_file_snap_t *s = (vm_file_snap_t *)snap;
    if (s == NULL)
        return;
    free(s->pages);
    free(s);
}

/* Moving-mremap span copy (moved from src/os/mem_table.c for R9-5):
 * runs under mem_lock and takes no lock itself. fsnap is the
 * pre-lock snapshot above (NULL when no file pages are involved);
 * a snapshot hit supplies file bytes, a miss copies host bytes. */
static int copy_host_prot(uint32_t prot)
{
    return ((prot & 1u) ? PROT_READ : 0) | ((prot & 2u) ? PROT_WRITE : 0);
}

static int copy_host_prot_at(const mips64_region_t *regs, size_t nregs,
                             uint64_t hlo_va, uint64_t hhi_va)
{
    size_t i;
    int hp = 0;
    for (i = 0u; i < nregs; i++)
        if (regs[i].end > hlo_va && regs[i].start < hhi_va)
            hp |= copy_host_prot(regs[i].prot);
    return hp;
}

int mips_vm_file_copy_span(mips64_ctx_t *ctx, uint8_t *buf,
                           const mips64_region_t *regs, size_t nregs,
                           uint64_t span_va, uint64_t span_len,
                           const void *fsnap)
{
    long ps = sysconf(_SC_PAGESIZE);
    uint64_t hpsz = (uint64_t)(ps > 4096L ? ps : 4096L), hmask = hpsz - 1u;
    size_t ri;
    for (ri = 0u; ri < nregs; ri++) {
        uint64_t lo = regs[ri].start > span_va ? regs[ri].start : span_va;
        uint64_t hi = regs[ri].end < span_va + span_len ?
                      regs[ri].end : span_va + span_len;
        uint64_t pva;
        for (pva = lo; pva < hi; pva += MIPS64_PAGE_SIZE) {
            uint8_t *out = buf + (pva - span_va);
            uint8_t *hp = (uint8_t *)mips64_guest_ptr(ctx, pva);
            uintptr_t haddr = (uintptr_t)hp & ~(uintptr_t)hmask;
            uint64_t hlo = (haddr > (uintptr_t)ctx->guest_base) ?
                           (uint64_t)(haddr - (uintptr_t)ctx->guest_base) : 0u;
            int oprot = copy_host_prot_at(regs, nregs, hlo, hlo + hpsz);
            if (mips_vm_file_snapshot_fetch(fsnap, pva, out) != 0)
                continue;
            /* Widen the host page to RW before saving a sub-page
             * (R4-7): a PROT_NONE guest page faults the memcpy when
             * read through its host cover. */
            if ((regs[ri].prot & MIPS_PROT_READ) == 0U &&
                mprotect((void *)haddr, (size_t)hpsz,
                         PROT_READ | PROT_WRITE) != 0)
                return -errno;
            memcpy(out, hp, MIPS64_PAGE_SIZE);
            if ((regs[ri].prot & MIPS_PROT_READ) == 0U &&
                mprotect((void *)haddr, (size_t)hpsz, oprot) != 0)
                return -errno;
        }
    }
    return 0;
}

/* R9-5: region-prot snapshot + lock-free apply (see vm_file_int.h).
 * The snapshot takes mem_lock only and runs before vm_lock; the
 * apply is a pure mprotect loop over the snapshot. Coverage matches
 * vm_inode_apply_region_prots exactly (per-region [lo,hi) clips, so
 * host-page granularity behavior is unchanged). */
size_t mips_vm_prot_snapshot(mips_vm_prot_t *out, size_t cap)
{
    size_t n, i, w = 0u;
    if (out == NULL || cap == 0u)
        return 0u;
    n = mips_mem_region_count();
    for (i = 0u; i < n && w < cap; i++) {
        uint64_t s = 0u, e = 0u;
        uint32_t p = 0u;
        if (mips_mem_region_at(i, &s, &e, &p) != 0)
            break;
        out[w].start = s;
        out[w].end = e;
        out[w].prot = p;
        w++;
    }
    return w;
}

int mips_vm_prot_apply(mips64_ctx_t *ctx, uint64_t lo, uint64_t hi,
                       const mips_vm_prot_t *snap, size_t n)
{
    size_t i;
    if (ctx == NULL || snap == NULL)
        return -1;
    for (i = 0u; i < n; i++) {
        uint64_t a = snap[i].start > lo ? snap[i].start : lo;
        uint64_t b = snap[i].end < hi ? snap[i].end : hi;
        if (a < b &&
            mprotect((void *)(uintptr_t)(ctx->guest_base + a),
                     (size_t)(b - a),
                     copy_host_prot(snap[i].prot)) != 0)
            return -1;
    }
    return 0;
}
