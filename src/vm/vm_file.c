/*
 * src/vm/vm_file.c — File-backed provider for the 6-step contract.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "vm/vm_file.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "os/backend.h"
#include "os/quiesce.h"
#include "vm/vm_file_int.h"
#include "vm/vm_pages.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

static int u0f_host_prot(uint32_t prot)
{
    return (((prot & 1u) != 0u) ? PROT_READ : 0) | (((prot & 2u) != 0u) ? PROT_WRITE : 0);
}

static long u0f_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    return (ps < 4096L) ? 4096L : ps;
}

extern int mips_vm_inode_page_host_prot(uint64_t page_va);
extern int mips_vm_inode_zero_span(mips64_ctx_t *ctx, uint64_t page_va, uint64_t from, uint64_t to);
extern int mips_vm_inode_refresh_span(mips64_ctx_t *ctx, int fd, uint64_t page_va, uint64_t glo, uint64_t ghi, uint64_t fpos);

/* ---- Lane U12 family-shared inode/EOF tracking ---- */
typedef struct {
    uint32_t lock, next_ticket;
    vm_inode_t inodes[VM_INODE_MAX];
} vm_shm_t;

static vm_shm_t *vm_shm_ptr;
/* Shared with src/vm/vm_file_sync.c via vm_file_int.h. */
vm_inode_t *vm_inode_table_ptr;
int vm_inode_table_tried, vm_has_shared_fallback;
static int vm_saved_errno;
static pid_t vm_pending_ticket;
static int vm_fork_pipe[2] = { -1, -1 };
static int vm_reserve_fds[2] = { -1, -1 };
static pthread_mutex_t vm_inode_mu = PTHREAD_MUTEX_INITIALIZER;

static void vm_inode_fork_sync_locked(pid_t self);

static void vm_reserve_init(void)
{
    int p[2], i;

    if (vm_reserve_fds[0] >= 0 || pipe(p) != 0)
        return;
    for (i = 0; i < 2; i++) {
        int fd = fcntl(p[i], F_DUPFD_CLOEXEC, 512);
        if (fd >= 0) {
            (void)close(p[i]);
            vm_reserve_fds[i] = fd;
        } else {
            (void)fcntl(p[i], F_SETFD, FD_CLOEXEC);
            vm_reserve_fds[i] = p[i];
        }
    }
}

static void vm_shm_lock(void)
{
    while (vm_shm_ptr != NULL &&
           __atomic_exchange_n(&vm_shm_ptr->lock, 1u, __ATOMIC_ACQUIRE) != 0u)
        (void)sched_yield();
}

static void vm_shm_unlock(void)
{
    if (vm_shm_ptr != NULL)
        __atomic_store_n(&vm_shm_ptr->lock, 0u, __ATOMIC_RELEASE);
}

static _Thread_local int vm_preempt_depth;
static _Thread_local sigset_t vm_preempt_saved;

void vm_lock(void)
{
    if (vm_preempt_depth == 0)
        mips_qs_block_preempt(&vm_preempt_saved);
    vm_preempt_depth++;
    (void)pthread_mutex_lock(&vm_inode_mu);
    (void)vm_inode_table();
    vm_shm_lock();
    vm_inode_fork_sync_locked(getpid());
}

void vm_unlock(void)
{
    vm_shm_unlock();
    (void)pthread_mutex_unlock(&vm_inode_mu);
    vm_preempt_depth--;
    if (vm_preempt_depth == 0)
        mips_qs_unblock_preempt(&vm_preempt_saved);
}

static void vm_inode_compact_locked(vm_inode_t *in, pid_t self)
{
    int saved = errno, i = 0, j;

    while (i < in->nmaps) {
        pid_t pid = in->maps[i].pid;
        if (pid > 0 && pid != self && kill(pid, 0) != 0 && errno == ESRCH) {
            for (j = i; j + 1 < in->nmaps; j++)
                in->maps[j] = in->maps[j + 1];
            in->nmaps--;
            continue;
        }
        i++;
    }
    errno = saved;
}

static void vm_inode_drop_ticket_locked(pid_t ticket)
{
    size_t k;

    if (ticket >= 0 || vm_inode_table_ptr == NULL)
        return;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &vm_inode_table_ptr[k];
        int i = 0, j;

        while (in->used != 0 && i < in->nmaps) {
            if (in->maps[i].pid == ticket) {
                for (j = i; j + 1 < in->nmaps; j++)
                    in->maps[j] = in->maps[j + 1];
                in->nmaps--;
                continue;
            }
            i++;
        }
    }
}

static void vm_atfork_prepare(void)
{
    pid_t self = getpid(), ticket;
    size_t k;

    vm_saved_errno = errno;
    vm_lock();
    vm_pending_ticket = 0;
    vm_fork_pipe[0] = vm_fork_pipe[1] = -1;
    if (vm_shm_ptr != NULL && vm_inode_table_ptr != NULL) {
        uint32_t raw = ++vm_shm_ptr->next_ticket;
        if (raw == 0u || raw > 0x7fffffffu)
            raw = vm_shm_ptr->next_ticket = 1u;
        ticket = -(pid_t)raw;
        for (k = 0u; k < VM_INODE_MAX; k++) {
            vm_inode_t *in = &vm_inode_table_ptr[k];
            int orig_n, i;
            if (in->used == 0)
                continue;
            vm_inode_compact_locked(in, self);
            orig_n = in->nmaps;
            for (i = 0; i < orig_n; i++) {
                if (in->maps[i].pid != self)
                    continue;
                if ((unsigned)in->nmaps < VM_INODE_MAPS) {
                    vm_inode_map_t r = in->maps[i];
                    r.pid = ticket;
                    in->maps[in->nmaps++] = r;
                    vm_pending_ticket = ticket;
                } else {
                    in->wide = 1;
                }
            }
        }
        if (vm_pending_ticket < 0 && pipe(vm_fork_pipe) != 0 &&
            vm_reserve_fds[0] >= 0) {
            (void)close(vm_reserve_fds[0]);
            (void)close(vm_reserve_fds[1]);
            vm_reserve_fds[0] = vm_reserve_fds[1] = -1;
            (void)pipe(vm_fork_pipe);
        }
        if (vm_fork_pipe[0] >= 0) {
            (void)fcntl(vm_fork_pipe[0], F_SETFD, FD_CLOEXEC);
            (void)fcntl(vm_fork_pipe[1], F_SETFD, FD_CLOEXEC);
        }
    }
    errno = 0;
}

static void vm_atfork_parent(void)
{
    int fork_err = errno;
    char c;

    if (vm_fork_pipe[0] >= 0) {
        (void)close(vm_fork_pipe[1]);
        if (fork_err == 0)
            while (read(vm_fork_pipe[0], &c, 1) < 0 && errno == EINTR) {}
        (void)close(vm_fork_pipe[0]);
        vm_fork_pipe[0] = vm_fork_pipe[1] = -1;
        vm_inode_drop_ticket_locked(vm_pending_ticket);
        vm_reserve_init();
    } else if (fork_err != 0) {
        vm_inode_drop_ticket_locked(vm_pending_ticket);
    }
    vm_pending_ticket = 0;
    vm_unlock();
    errno = (fork_err != 0) ? fork_err : vm_saved_errno;
}

static void vm_atfork_child(void)
{
    (void)pthread_mutex_init(&vm_inode_mu, NULL);
    if (vm_fork_pipe[1] >= 0) {
        (void)pthread_mutex_lock(&vm_inode_mu);
        vm_inode_fork_sync_locked(getpid());
        (void)pthread_mutex_unlock(&vm_inode_mu);
        (void)close(vm_fork_pipe[0]);
        (void)close(vm_fork_pipe[1]);
        vm_fork_pipe[0] = vm_fork_pipe[1] = -1;
        vm_reserve_init();
    } else if (vm_pending_ticket < 0) {
        vm_lock();
        vm_unlock();
    }
    errno = vm_saved_errno;
}

vm_inode_t *vm_inode_table(void)
{
    if (vm_inode_table_ptr == NULL && !vm_inode_table_tried) {
        void *p = mmap(NULL, sizeof(vm_shm_t), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        vm_inode_table_tried = 1;
        if (p != MAP_FAILED) {
            vm_shm_ptr = (vm_shm_t *)p;
            vm_inode_table_ptr = vm_shm_ptr->inodes;
            (void)pthread_atfork(vm_atfork_prepare, vm_atfork_parent,
                                 vm_atfork_child);
        }
    }
    return vm_inode_table_ptr;
}

__attribute__((constructor)) static void vm_inode_ctor(void)
{
    (void)vm_inode_table();
}

static void vm_inode_fork_sync_locked(pid_t self)
{
    size_t k;

    if (vm_pending_ticket >= 0 || vm_inode_table_ptr == NULL)
        return;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &vm_inode_table_ptr[k];
        int i;
        for (i = 0; in->used != 0 && i < in->nmaps; i++)
            if (in->maps[i].pid == vm_pending_ticket)
                in->maps[i].pid = self;
    }
    vm_pending_ticket = 0;
}

vm_inode_t *vm_inode_lookup(uint64_t dev, uint64_t ino, int create,
                                   uint64_t size)
{
    vm_inode_t *tab = vm_inode_table();
    size_t i;

    if (tab == NULL)
        return NULL;
    for (i = 0u; i < VM_INODE_MAX; i++) {
        if (tab[i].used != 0 && tab[i].dev == dev && tab[i].ino == ino)
            return &tab[i];
    }
    if (create) {
        /* Reclaim slots no mapping references anymore (R4-4): an
         * entry with zero maps carries no per-VA metadata, so its
         * stale identity/size/sequence state is safe to recycle. */
        for (i = 0u; i < VM_INODE_MAX; i++) {
            if (tab[i].used != 0 && tab[i].nmaps == 0) {
                (void)memset(&tab[i], 0, sizeof tab[i]);
                tab[i].used = 1;
                tab[i].dev = dev;
                tab[i].ino = ino;
                tab[i].size = size;
                return &tab[i];
            }
        }
        for (i = 0u; i < VM_INODE_MAX; i++) {
            if (tab[i].used == 0) {
                (void)memset(&tab[i], 0, sizeof tab[i]);
                tab[i].used = 1;
                tab[i].dev = dev;
                tab[i].ino = ino;
                tab[i].size = size;
                return &tab[i];
            }
        }
    }
    return NULL;
}

void vm_inode_note_resize_locked(vm_inode_t *in, uint64_t newsize,
                                        pid_t self)
{
    int i;

    if (in->size != newsize) {
        in->size = newsize;
        in->resize_seq++;
    }
    for (i = 0; i < in->nmaps; i++) {
        if (in->maps[i].pid == self || newsize < in->maps[i].min_size)
            in->maps[i].min_size = newsize;
    }
}

static _Thread_local int vm_inode_internal_prot;

/* Split the self-owned record straddling split_va (R4-4). Capacity
 * and the replacement descriptor are reserved BEFORE the stored
 * record is mutated; on exhaustion or dup failure the existing record
 * is preserved untouched and -1 is returned so callers can fall back
 * to conservative (wide) invalidation instead of losing metadata. */
static int vm_inode_split_at(vm_inode_t *in, pid_t self, uint64_t split_va)
{
    int i;

    vm_inode_compact_locked(in, self);
    for (i = 0; i < in->nmaps; i++) {
        vm_inode_map_t *m = &in->maps[i];
        if (m->pid != self || split_va <= m->va || split_va >= m->va + m->len)
            continue;
        if ((unsigned)in->nmaps >= VM_INODE_MAPS)
            return -1;
        {
            vm_inode_map_t r = *m;
            int nd = -1;

            r.va = split_va;
            r.len = (m->va + m->len) - split_va;
            r.file_offset = m->file_offset + (split_va - m->va);
            if (r.fd_dup >= 0) {
                nd = fcntl(r.fd_dup, F_DUPFD_CLOEXEC, 0);
                if (nd < 0)
                    return -1;
                r.fd_dup = nd;
            }
            m->len = split_va - m->va;
            in->maps[in->nmaps++] = r;
        }
        return 0;
    }
    return 0;
}

/* Translator-retained descriptors (R4-6) are never guest CLOEXEC
 * victims: mapping dups plus the reserve/fork pipes. */
int mips_vm_file_is_retained_fd(int fd)
{
    size_t k;
    int i;

    if (fd < 0) {
        return 0;
    }
    if (fd == vm_fork_pipe[0] || fd == vm_fork_pipe[1] ||
        fd == vm_reserve_fds[0] || fd == vm_reserve_fds[1]) {
        return 1;
    }
    vm_lock();
    if (vm_inode_table_ptr != NULL) {
        for (k = 0u; k < VM_INODE_MAX; k++) {
            vm_inode_t *in = &vm_inode_table_ptr[k];

            if (in->used == 0) {
                continue;
            }
            for (i = 0; i < in->nmaps; i++) {
                if (in->maps[i].fd_dup == fd) {
                    vm_unlock();
                    return 1;
                }
            }
        }
    }
    vm_unlock();
    return 0;
}

/* Shared-mapping overlap probe for the protect path (R4-7). */
int mips_vm_file_has_shared(uint64_t va, uint64_t len)
{
    uint64_t end = va + len;
    size_t k;
    int i;

    if (vm_inode_internal_prot != 0 || len == 0u || end < va) {
        return 0;
    }
    vm_lock();
    if (vm_inode_table_ptr != NULL) {
        for (k = 0u; k < VM_INODE_MAX; k++) {
            vm_inode_t *in = &vm_inode_table_ptr[k];

            if (in->used == 0) {
                continue;
            }
            for (i = 0; i < in->nmaps; i++) {
                vm_inode_map_t *m = &in->maps[i];
                uint64_t mend;

                if (m->shared == 0) {
                    continue;
                }
                mend = m->va + m->len;
                if (mend < m->va) {
                    vm_unlock();
                    return 1;
                }
                if (m->va < end && va < mend) {
                    vm_unlock();
                    return 1;
                }
            }
        }
    }
    vm_unlock();
    return 0;
}

void mips_vm_file_map_hook(mips64_ctx_t *ctx, int fd, uint64_t va,
                           uint64_t len, uint64_t file_offset,
                           uint32_t prot, int is_shared)
{
    struct stat st;
    vm_inode_t *in;
    uint64_t hmask = (uint64_t)u0f_page_size() - 1u;
    pid_t self = getpid();
    int native = 0, fd_dup;

    if (ctx == NULL || fd < 0 || len == 0u || fstat(fd, &st) != 0)
        return;
    vm_lock();
    vm_reserve_init();
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 1,
                         (uint64_t)st.st_size);
    if (in == NULL) {
        vm_unlock();
        return;
    }
    if (in->size != (uint64_t)st.st_size)
        vm_inode_note_resize_locked(in, (uint64_t)st.st_size, self);
    if (is_shared != 0 && ((ctx->guest_base + va) & hmask) == 0u &&
        (len & hmask) == 0u && (file_offset & hmask) == 0u &&
        mmap((void *)(uintptr_t)(ctx->guest_base + va), (size_t)len,
             u0f_host_prot(prot), MAP_SHARED | MAP_FIXED, fd,
             (off_t)file_offset) != MAP_FAILED)
        native = 1;
    fd_dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (native == 0 && is_shared != 0 && fd_dup >= 0)
        vm_has_shared_fallback = 1;
    vm_inode_compact_locked(in, self);
    if ((unsigned)in->nmaps < VM_INODE_MAPS) {
        vm_inode_map_t r = {
            self, fd_dup, is_shared, native, va, len, file_offset,
            in->size, in->write_seq, in->resize_seq, prot
        };
        in->maps[in->nmaps++] = r;
    } else {
        if (fd_dup >= 0)
            (void)close(fd_dup);
        in->wide = 1;
    }
    vm_unlock();
    if (native == 0) {
        mips_vm_pages_mark(va, len, (unsigned)MIPS_VM_PAGE_COW_CLEAN);
        mips_soft_tlb_invalidate_all();
    }
}

void mips_vm_file_unmap_hook(uint64_t va, uint64_t len)
{
    vm_inode_t *tab;
    pid_t self = getpid();
    uint64_t end = (va + len < va) ? ~(uint64_t)0u : va + len;
    size_t k;
    if (len == 0u || !vm_inode_table_tried || vm_inode_table_ptr == NULL)
        return;
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i = 0, j;
        if (in->used == 0)
            continue;
        vm_inode_compact_locked(in, self);
        while (i < in->nmaps) {
            vm_inode_map_t *m = &in->maps[i];
            uint64_t mlo = m->va, mhi = m->va + m->len;
            if (m->pid != self || mhi <= va || mlo >= end) {
                i++;
                continue;
            }
            if (va <= mlo && end >= mhi) {
                if (m->fd_dup >= 0)
                    (void)close(m->fd_dup);
                for (j = i; j + 1 < in->nmaps; j++)
                    in->maps[j] = in->maps[j + 1];
                in->nmaps--;
                continue;
            }
            if (va <= mlo && end < mhi) {
                m->file_offset += (end - mlo);
                m->len = mhi - end;
                m->va = end;
            } else if (va > mlo && end >= mhi) {
                m->len = va - mlo;
            } else {
                /* Middle punch: reserve the slot and the duped
                 * descriptor BEFORE truncating the stored record
                 * (R4-4). On exhaustion the record is preserved
                 * whole (conservative over-approximation) and the
                 * inode goes wide so DBT invalidation covers the
                 * hole. */
                if ((unsigned)in->nmaps < VM_INODE_MAPS) {
                    vm_inode_map_t r = *m;
                    int nd = -1;

                    r.va = end;
                    r.len = mhi - end;
                    r.file_offset = m->file_offset + (end - mlo);
                    if (r.fd_dup >= 0) {
                        nd = fcntl(r.fd_dup, F_DUPFD_CLOEXEC, 0);
                        if (nd < 0) {
                            in->wide = 1;
                            i++;
                            continue;
                        }
                        r.fd_dup = nd;
                    }
                    in->maps[in->nmaps++] = r;
                    m->len = va - mlo;
                } else {
                    in->wide = 1;
                }
            }
            i++;
        }
    }
    vm_unlock();
}

void mips_vm_file_protect_hook(uint64_t va, uint64_t len, uint32_t prot)
{
    vm_inode_t *tab;
    uint64_t hmask = (uint64_t)u0f_page_size() - 1u;
    uint64_t end = (va + len < va) ? ~(uint64_t)0u : va + len;
    pid_t self = getpid();
    size_t k;
    if (vm_inode_internal_prot != 0 || len == 0u || !vm_inode_table_tried ||
        vm_inode_table_ptr == NULL)
        return;
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i;
        if (in->used == 0)
            continue;
        /* A failed split preserves the straddled record; fall back
         * to whole-inode invalidation so no executable alias keeps
         * stale translations (R4-4). The containment update below
         * then only touches exactly covered records. */
        if ((va & hmask) == 0u && vm_inode_split_at(in, self, va) != 0)
            in->wide = 1;
        if (end != ~(uint64_t)0u && (end & hmask) == 0u &&
            vm_inode_split_at(in, self, end) != 0)
            in->wide = 1;
        for (i = 0; i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            if (m->pid == self && m->va >= va && m->va + m->len <= end)
                m->prot = prot;
        }
    }
    vm_unlock();
}

static void vm_inode_internal_protect(mips64_ctx_t *ctx, uint64_t page,
                                      uint32_t prot)
{
    vm_inode_internal_prot = 1;
    (void)mips_mem_protect(ctx, page, 4096u, prot);
    vm_inode_internal_prot = 0;
}

/* Invalidate translated code over a FILE-OFFSET interval [lo, hi)
 * (R4-1). Each mapping covers file offsets [file_offset,
 * file_offset + len); the overlap is translated into guest VA before
 * invalidating, so a write to file offset zero reaches an executable
 * alias mapped at a nonzero VA. Saturating ends keep the [lo, hi)
 * shape when either interval wraps. */
static void vm_inode_invalidate_maps(vm_inode_t *in, uint64_t lo, uint64_t hi)
{
    pid_t self = getpid();
    int i;
    if (in->wide != 0) {
        dbt_invalidate_all();
        return;
    }
    for (i = 0; i < in->nmaps; i++) {
        uint64_t flo = in->maps[i].file_offset;
        uint64_t fhi = (flo + in->maps[i].len < flo) ?
            ~(uint64_t)0u : flo + in->maps[i].len;
        uint64_t ilo = lo > flo ? lo : flo;
        uint64_t ihi = hi < fhi ? hi : fhi;

        if (in->maps[i].pid == self && ihi > ilo) {
            uint64_t gva = in->maps[i].va + (ilo - flo);

            dbt_invalidate_range(gva, ihi - ilo);
        }
    }
}

void vm_inode_apply_write_locked(mips64_ctx_t *ctx, vm_inode_t *in,
                                        int fd_hint, uint64_t off, uint64_t n)
{
    uint64_t wend = (off + n < off) ? ~(uint64_t)0u : off + n;
    uint64_t eof_page = (in->size + 4095u) & ~(uint64_t)4095u;
    pid_t self = getpid();
    int i;
    for (i = 0; i < in->nmaps; i++) {
        vm_inode_map_t *m = &in->maps[i];
        uint64_t mlo = m->va, mhi = m->va + m->len, page;
        int rfd = m->fd_dup >= 0 ? m->fd_dup : fd_hint;
        int ok = 1;
        if (m->pid != self || m->native != 0)
            continue;
        for (page = mlo & ~(uint64_t)4095U; page < mhi; page += 4096u) {
            uint64_t ps = page < mlo ? mlo : page;
            uint64_t pe = page + 4096u > mhi ? mhi : page + 4096u;
            uint64_t fbase = m->file_offset + (ps - mlo);
            uint64_t flo = fbase > off ? fbase : off;
            uint64_t fhi = fbase + (pe - ps) < wend ? fbase + (pe - ps) : wend;
            if (page + 4096u < page)
                break;
            if (ps >= pe)
                continue;
            if (fbase < eof_page && ps == page && pe == page + 4096u &&
                mips_vm_inode_page_host_prot(page) == 0)
                vm_inode_internal_protect(ctx, page, m->prot);
            if (flo < fhi &&
                (m->shared != 0 ||
                 (mips_vm_page_flags(page >> 12) &
                  (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) &&
                mips_vm_inode_refresh_span(ctx, rfd, page,
                                           ps + (flo - fbase),
                                           ps + (fhi - fbase), flo) != 0)
                ok = 0;
        }
        /* A failed refresh leaves the alias stale: keep the old
         * sequence numbers so the next reconcile retries (R4-3). */
        if (ok != 0) {
            m->seen_write_seq = in->write_seq;
            m->seen_resize_seq = in->resize_seq;
            m->min_size = in->size;
        }
    }
    vm_inode_invalidate_maps(in, off, wend);
}

void vm_inode_post_truncate_locked(mips64_ctx_t *ctx, vm_inode_t *in,
                                          uint64_t newsize)
{
    uint64_t eof_page = (newsize + 4095u) & ~(uint64_t)4095u;
    pid_t self = getpid();
    int i;
    for (i = 0; i < in->nmaps; i++) {
        vm_inode_map_t *m = &in->maps[i];
        uint64_t mlo = m->va, mhi = m->va + m->len, page;
        int ok = 1;
        if (m->pid != self || m->native != 0)
            continue;
        for (page = mlo & ~(uint64_t)4095U; page < mhi; page += 4096u) {
            uint64_t ps = page < mlo ? mlo : page;
            uint64_t pe = page + 4096u > mhi ? mhi : page + 4096u;
            uint64_t fbase = m->file_offset + (ps - mlo);
            unsigned fl = mips_vm_page_flags(page >> 12);
            if (page + 4096u < page)
                break;
            if (ps >= pe)
                continue;
            if (fbase >= newsize) {
                if (fbase >= eof_page && ps == page && pe == page + 4096u) {
                    if (mips_vm_inode_zero_span(ctx, page, 0u, 4096u) != 0)
                        ok = 0;
                    else
                        mips_vm_pages_mark(page, 4096u,
                                           (unsigned)MIPS_VM_PAGE_COW_CLEAN);
                    vm_inode_internal_protect(ctx, page, 0u);
                } else if (m->shared != 0 ||
                           (fl & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                    if (mips_vm_inode_zero_span(ctx, page, ps - page,
                                                pe - page) != 0)
                        ok = 0;
                }
            } else {
                if (ps == page && pe == page + 4096u &&
                    mips_vm_inode_page_host_prot(page) == 0)
                    vm_inode_internal_protect(ctx, page, m->prot);
                if (fbase + (pe - ps) > newsize &&
                    (m->shared != 0 ||
                     (fl & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) &&
                    mips_vm_inode_zero_span(ctx, page,
                                            ps - page + (newsize - fbase),
                                            pe - page) != 0)
                    ok = 0;
            }
        }
        /* A failed zero leaves the tail stale: keep the old resize
         * sequence so the next reconcile retries (R4-3). */
        if (ok != 0)
            m->seen_resize_seq = in->resize_seq;
    }
    vm_inode_invalidate_maps(in, 0u, ~(uint64_t)0u);
}


/* R9-5: prot restore over a pre-lock snapshot (mem_lock is never
 * taken under vm_lock here; see vm_file_int.h). */
static void vm_inode_restore_slice(mips64_ctx_t *ctx, const vm_inode_map_t *m,
                                   uint64_t slo, uint64_t shi,
                                   const mips_vm_prot_t *snap, size_t n)
{
    uint64_t hmask = (uint64_t)u0f_page_size() - 1u;
    uint64_t alo = slo & ~hmask, ahi = (shi + hmask) & ~hmask;
    uint64_t lo = m->va > alo ? m->va : alo;
    uint64_t hi = (m->va + m->len) < ahi ? (m->va + m->len) : ahi;
    if (lo < hi && m->native != 0 && m->fd_dup >= 0) {
        (void)mmap((void *)(uintptr_t)(ctx->guest_base + lo), (size_t)(hi - lo),
                   u0f_host_prot(m->prot), MAP_SHARED | MAP_FIXED, m->fd_dup,
                   (off_t)(m->file_offset + (lo - m->va)));
        (void)mips_vm_prot_apply(ctx, lo, hi, snap, n);
    }
}

void mips_vm_file_restore(mips64_ctx_t *ctx, uint64_t va1, uint64_t len1,
                          uint64_t va2, uint64_t len2)
{
    vm_inode_t *tab;
    pid_t self = getpid();
    size_t k;
    mips_vm_prot_t snap[MIPS64_MAX_REGIONS];
    size_t n = mips_vm_prot_snapshot(snap, MIPS64_MAX_REGIONS);
    if (ctx == NULL || !vm_inode_table_tried || vm_inode_table_ptr == NULL)
        return;
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i;
        for (i = 0; in->used != 0 && i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            if (m->pid == self && len1 > 0u)
                vm_inode_restore_slice(ctx, m, va1, va1 + len1, snap, n);
            if (m->pid == self && len2 > 0u)
                vm_inode_restore_slice(ctx, m, va2, va2 + len2, snap, n);
        }
    }
    vm_unlock();
}

void mips_vm_file_remap_hook(mips64_ctx_t *ctx, uint64_t old_va,
                             uint64_t old_size, uint64_t dst_va,
                             uint64_t new_size)
{
    vm_inode_t *tab;
    uint64_t kept = old_size < new_size ? old_size : new_size;
    uint64_t hmask = (uint64_t)u0f_page_size() - 1u;
    pid_t self = getpid();
    size_t k;
    mips_vm_prot_t snap[MIPS64_MAX_REGIONS];
    size_t n;
    if (ctx == NULL || !vm_inode_table_tried || vm_inode_table_ptr == NULL)
        return;
    if (dst_va != old_va)
        mips_vm_file_unmap_hook(dst_va, new_size);
    if (new_size < old_size)
        mips_vm_file_unmap_hook(old_va + new_size, old_size - new_size);
    /* R9-5: snapshot region prots before vm_lock; the in-loop apply
     * below then restores host prots without taking mem_lock, so the
     * moving-mremap (mem->vm) order is never inverted. */
    n = mips_vm_prot_snapshot(snap, MIPS64_MAX_REGIONS);
    vm_lock();
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i, touched = 0;
        if (in->used == 0)
            continue;
        /* A failed split preserves the straddled record; the move
         * loop below then skips the unseparated span and the inode
         * goes wide so invalidation stays conservative (R4-4). */
        if (vm_inode_split_at(in, self, old_va) != 0 ||
            vm_inode_split_at(in, self, old_va + kept) != 0)
            in->wide = 1;
        for (i = 0; i < in->nmaps; i++) {
            vm_inode_map_t *m = &in->maps[i];
            if (m->pid != self || m->va < old_va || m->va + m->len > old_va + kept)
                continue;
            m->va = dst_va + (m->va - old_va);
            if (new_size > old_size && m->va + m->len == dst_va + old_size) {
                m->len += (new_size - old_size);
                if (m->native == 0)
                    mips_vm_pages_mark(dst_va + old_size, new_size - old_size,
                                       (unsigned)MIPS_VM_PAGE_COW_CLEAN);
            }
            if (m->native != 0 &&
                (((ctx->guest_base + m->va) & hmask) != 0u ||
                 (m->len & hmask) != 0u || (m->file_offset & hmask) != 0u ||
                 m->fd_dup < 0 ||
                 mmap((void *)(uintptr_t)(ctx->guest_base + m->va),
                      (size_t)m->len, u0f_host_prot(m->prot),
                      MAP_SHARED | MAP_FIXED, m->fd_dup,
                      (off_t)m->file_offset) == MAP_FAILED ||
                 mips_vm_prot_apply(ctx, m->va, m->va + m->len,
                                    snap, n) != 0)) {
                m->native = 0;
                if (m->shared != 0)
                    vm_has_shared_fallback = 1;
                mips_vm_pages_mark(m->va, m->len,
                                   (unsigned)MIPS_VM_PAGE_COW_CLEAN);
            }
            touched = 1;
        }
        if (touched != 0) {
            if (new_size > old_size)
                vm_inode_apply_write_locked(ctx, in, -1, 0u, ~(uint64_t)0u);
            vm_inode_post_truncate_locked(ctx, in, in->size);
        }
    }
    vm_unlock();
}

