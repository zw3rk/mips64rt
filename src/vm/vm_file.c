/*
 * src/vm/vm_file.c — File-backed provider for the 6-step contract.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. Implements Provider F: step 1 (reserve) takes
 * an anonymous PROT_NONE reservation like Provider A and records
 * the fd in priv; the file step maps shared file pages MAP_FIXED
 * into it (W^X: EXEC rejected); protect/query/unmap/release mirror
 * the anonymous provider. Unmapped file spans return to PROT_NONE
 * anonymous pages.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "vm/vm_file.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "vm/vm_pages.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

static int u0f_host_prot(uint32_t prot)
{
    int h = 0;

    if ((prot & 1u) != 0u) {
        h |= PROT_READ;
    }
    if ((prot & 2u) != 0u) {
        h |= PROT_WRITE;
    }
    return h;
}

static long u0f_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);

    return (ps < 4096L) ? 4096L : ps;
}

static uint64_t u0f_down(uint64_t x, uint64_t ps)
{
    return x & ~(ps - 1u);
}

static uint64_t u0f_up(uint64_t x, uint64_t ps)
{
    return (x + (ps - 1u)) & ~(ps - 1u);
}

static int u0f_record(mips_vm64_t *vm, uint64_t start, uint64_t end,
                      uint32_t prot, uint32_t tag)
{
    size_t i = 0;

    while (i < vm->region_count && vm->regions[i].start < start) {
        i++;
    }
    if (i > 0 && vm->regions[i - 1].end == start &&
        vm->regions[i - 1].prot == prot && vm->regions[i - 1].tag == tag) {
        vm->regions[i - 1].end = end;
        return 0;
    }
    if (vm->region_count >= MIPS64_VM64_MAX_REGIONS) {
        return MIPS_FAULT;
    }
    memmove(&vm->regions[i + 1], &vm->regions[i],
            (vm->region_count - i) * sizeof vm->regions[0]);
    vm->regions[i].start = start;
    vm->regions[i].end = end;
    vm->regions[i].prot = prot;
    vm->regions[i].tag = tag;
    vm->region_count++;
    return 0;
}

static void u0f_forget(mips_vm64_t *vm, uint64_t start, uint64_t end)
{
    size_t i = 0;

    while (i < vm->region_count) {
        uint64_t rs = vm->regions[i].start;
        uint64_t re = vm->regions[i].end;

        if (re <= start || rs >= end) {
            i++;
            continue;
        }
        if (rs < start && re > end) {
            if (vm->region_count >= MIPS64_VM64_MAX_REGIONS) {
                return;
            }
            memmove(&vm->regions[i + 2], &vm->regions[i + 1],
                    (vm->region_count - i - 1) * sizeof vm->regions[0]);
            vm->regions[i].end = start;
            vm->regions[i + 1].start = end;
            vm->regions[i + 1].end = re;
            vm->regions[i + 1].prot = vm->regions[i].prot;
            vm->regions[i + 1].tag = vm->regions[i].tag;
            vm->region_count++;
            return;
        }
        if (rs < start) {
            vm->regions[i].end = start;
            i++;
        } else if (re > end) {
            vm->regions[i].start = end;
            i++;
        } else {
            memmove(&vm->regions[i], &vm->regions[i + 1],
                    (vm->region_count - i - 1) * sizeof vm->regions[0]);
            vm->region_count--;
        }
    }
}

static int u0f_reserve(mips_vm64_t *vm, uint64_t size)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    void *base;

    if (vm == NULL || size == 0U || (size & (ps - 1u)) != 0U) {
        return MIPS_FAULT;
    }
    base = mmap(NULL, (size_t)size, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) {
        return MIPS_FAULT;
    }
    vm->base = (uint64_t)(uintptr_t)base;
    vm->size = size;
    vm->priv = NULL;
    vm->region_count = 0U;
    return 0;
}

static int u0f_map(mips_vm64_t *vm, uint64_t va, uint64_t len,
                   uint32_t prot, uint32_t tag)
{
    (void)vm;
    (void)va;
    (void)len;
    (void)prot;
    (void)tag;
    /* File placement always goes through mips_vmfile_map (needs the
     * fd + offset); the plain map step is not meaningful here. */
    return MIPS_FAULT;
}

static int u0f_protect(mips_vm64_t *vm, uint64_t va, uint64_t len,
                       uint32_t prot)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    uint64_t start = u0f_down(va, ps);
    uint64_t end = u0f_up(va + len, ps);

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size || (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    if (mips_vm64_query(vm, start, NULL) != 0) {
        return MIPS_FAULT;
    }
    if (mprotect((void *)(uintptr_t)(vm->base + start),
                 (size_t)(end - start), u0f_host_prot(prot)) != 0) {
        return MIPS_FAULT;
    }
    u0f_forget(vm, start, end);
    return u0f_record(vm, start, end, prot, MIPS_VM_TAG_FILE);
}

static int u0f_query(const mips_vm64_t *vm, uint64_t va,
                     mips_vm_region_t *out)
{
    size_t i;

    if (vm == NULL || vm->base == 0U || va >= vm->size) {
        return MIPS_FAULT;
    }
    for (i = 0; i < vm->region_count; i++) {
        if (vm->regions[i].start <= va && va < vm->regions[i].end) {
            if (out != NULL) {
                *out = vm->regions[i];
            }
            return 0;
        }
    }
    return MIPS_FAULT;
}

static int u0f_unmap(mips_vm64_t *vm, uint64_t va, uint64_t len)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    uint64_t start = u0f_down(va, ps);
    uint64_t end = u0f_up(va + len, ps);
    void *at;

    if (vm == NULL || vm->base == 0U || len == 0U || end < start ||
        va + len < va || end > vm->size) {
        return MIPS_FAULT;
    }
    at = mmap((void *)(uintptr_t)(vm->base + start), (size_t)(end - start),
              PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (at == MAP_FAILED) {
        return MIPS_FAULT;
    }
    u0f_forget(vm, start, end);
    return 0;
}

static int u0f_release(mips_vm64_t *vm)
{
    if (vm == NULL || vm->base == 0U) {
        return MIPS_FAULT;
    }
    if (munmap((void *)(uintptr_t)vm->base, (size_t)vm->size) != 0) {
        return MIPS_FAULT;
    }
    vm->base = 0U;
    vm->size = 0U;
    vm->priv = NULL;
    vm->region_count = 0U;
    return 0;
}

const mips_provider_ops_t mips_provider_f = {
    "provider-f-file",
    u0f_reserve,
    u0f_map,
    u0f_protect,
    u0f_query,
    u0f_unmap,
    u0f_release
};

int mips_vmfile_map(mips_vm64_t *vm, int fd, uint64_t off, uint64_t va,
                    uint64_t len, uint32_t prot)
{
    uint64_t ps = (uint64_t)u0f_page_size();
    void *at;

    if (vm == NULL || vm->base == 0U || fd < 0 || len == 0U ||
        (va & (ps - 1u)) != 0U || (len & (ps - 1u)) != 0U ||
        (off & (ps - 1u)) != 0U || va + len < va || va + len > vm->size ||
        (prot & 4u) != 0u) {
        return MIPS_FAULT;
    }
    at = mmap((void *)(uintptr_t)(vm->base + va), (size_t)len,
              u0f_host_prot(prot), MAP_SHARED | MAP_FIXED, fd,
              (off_t)off);
    if (at == MAP_FAILED) {
        return MIPS_FAULT;
    }
    return u0f_record(vm, va, va + len, prot, MIPS_VM_TAG_FILE);
}

/* ---- Lane U12 family-shared inode/EOF tracking ---- */

#define VM_INODE_MAX 64u
#define VM_INODE_MAPS 8u

typedef struct {
    pid_t pid;
    int fd_dup;
    uint64_t va;
    uint64_t len;
    uint64_t file_offset;
    uint32_t prot;
    int shared;
    int native;
} vm_inode_map_t;

typedef struct {
    int used;
    uint64_t dev;
    uint64_t ino;
    uint64_t size;
    uint64_t resize_seq;
    vm_inode_map_t maps[VM_INODE_MAPS];
    int nmaps;
    int wide;
} vm_inode_t;

static vm_inode_t *vm_inode_table_ptr;
static int vm_inode_table_tried;
static int vm_has_shared_fallback;
static pthread_mutex_t vm_inode_mu = PTHREAD_MUTEX_INITIALIZER;

/* MAP_SHARED backing: fork children inherit the table and observe
 * the parent's updates (and vice versa). The mutex is usable as long
 * as no fork lands mid-mutation (already unsupported); children that
 * only exec or exit never touch it. */
static vm_inode_t *vm_inode_table(void)
{
    if (vm_inode_table_ptr == NULL && !vm_inode_table_tried) {
        void *p;

        vm_inode_table_tried = 1;
        p = mmap(NULL, sizeof(vm_inode_t) * VM_INODE_MAX,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0);
        if (p != MAP_FAILED) {
            vm_inode_table_ptr = (vm_inode_t *)p;
        }
    }
    return vm_inode_table_ptr;
}

static vm_inode_t *vm_inode_lookup(uint64_t dev, uint64_t ino, int create,
                                   uint64_t size)
{
    vm_inode_t *tab = vm_inode_table();
    size_t i;

    if (tab == NULL) {
        return NULL;
    }
    for (i = 0u; i < VM_INODE_MAX; i++) {
        if (tab[i].used != 0 && tab[i].dev == dev && tab[i].ino == ino) {
            return &tab[i];
        }
    }
    if (!create) {
        return NULL;
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
    return NULL;
}

/* Host protection covering one guest page (for the RO zeroing
 * toggle); -1 when the page is not mapped. */
static int vm_inode_page_host_prot(uint64_t page_va)
{
    size_t n = mips_mem_region_count();
    size_t i;

    for (i = 0u; i < n; i++) {
        uint64_t s = 0u;
        uint64_t e = 0u;
        uint32_t prot = 0u;

        if (mips_mem_region_at(i, &s, &e, &prot) != 0) {
            break;
        }
        if (s <= page_va && page_va < e) {
            int h = 0;

            if ((prot & (uint32_t)MIPS_PROT_READ) != 0u) {
                h |= PROT_READ;
            }
            if ((prot & (uint32_t)MIPS_PROT_WRITE) != 0u) {
                h |= PROT_WRITE;
            }
            return h;
        }
    }
    return -1;
}

/* Zero [page_va + from, page_va + to) through a temporary RW window
 * when the page is not already writable. */
static void vm_inode_zero_span(mips64_ctx_t *ctx, uint64_t page_va,
                               uint64_t from, uint64_t to)
{
    uint8_t *p;
    int hp;

    if (ctx == NULL || from >= to || to > 4096u) {
        return;
    }
    p = (uint8_t *)mips64_guest_ptr(ctx, page_va);
    if (p == NULL) {
        return;
    }
    hp = vm_inode_page_host_prot(page_va);
    if (hp < 0) {
        return;
    }
    if ((hp & PROT_WRITE) == 0) {
        if (mprotect(p, 4096u, PROT_READ | PROT_WRITE) != 0) {
            return;
        }
        (void)memset(p + from, 0, (size_t)(to - from));
        (void)mprotect(p, 4096u, hp);
        return;
    }
    (void)memset(p + from, 0, (size_t)(to - from));
}

/* Refresh one CLEAN guest span [glo, ghi) from the file at fpos
 * (zeros past EOF). DIRTY pages never reach here. */
static void vm_inode_refresh_span(mips64_ctx_t *ctx, int fd, uint64_t page_va,
                                  uint64_t glo, uint64_t ghi, uint64_t fpos)
{
    uint8_t *p;
    uint64_t from;
    uint64_t to;
    int hp;
    ssize_t got;

    if (ctx == NULL || fd < 0 || glo >= ghi) {
        return;
    }
    from = glo - (page_va & ~(uint64_t)4095U);
    to = ghi - (page_va & ~(uint64_t)4095U);
    if (to > 4096u) {
        return;
    }
    p = (uint8_t *)mips64_guest_ptr(ctx, page_va & ~(uint64_t)4095U);
    if (p == NULL) {
        return;
    }
    hp = vm_inode_page_host_prot(page_va & ~(uint64_t)4095U);
    if (hp < 0) {
        return;
    }
    if ((hp & PROT_WRITE) == 0 &&
        mprotect(p, 4096u, PROT_READ | PROT_WRITE) != 0) {
        return;
    }
    got = pread(fd, p + from, (size_t)(to - from), (off_t)fpos);
    if (got < 0) {
        got = 0;
    }
    if ((uint64_t)got < to - from) {
        (void)memset(p + from + (uint64_t)got, 0,
                     (size_t)(to - from - (uint64_t)got));
    }
    if ((hp & PROT_WRITE) == 0) {
        (void)mprotect(p, 4096u, hp);
    }
}

void mips_vm_file_map_hook(mips64_ctx_t *ctx, int fd, uint64_t va,
                           uint64_t len, uint64_t file_offset,
                           uint32_t prot, int is_shared)
{
    struct stat st;
    vm_inode_t *in;
    long hps;
    uint64_t hmask;
    int native = 0;
    int fd_dup = -1;

    if (ctx == NULL || fd < 0 || len == 0u) {
        return;
    }
    if (fstat(fd, &st) != 0) {
        return;
    }
    (void)pthread_mutex_lock(&vm_inode_mu);
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 1,
                         (uint64_t)st.st_size);
    if (in == NULL) {
        (void)pthread_mutex_unlock(&vm_inode_mu);
        return;
    }
    if (in->size != (uint64_t)st.st_size) {
        in->size = (uint64_t)st.st_size;
        in->resize_seq++;
    }
    /* MAP_SHARED goes native (writes through) whenever the host page
     * size divides the host address, length, and file offset. */
    hps = u0f_page_size();
    hmask = (uint64_t)hps - 1u;
    if (is_shared != 0 && ((ctx->guest_base + va) & hmask) == 0u &&
        (len & hmask) == 0u && (file_offset & hmask) == 0u) {
        void *at = mmap((void *)(uintptr_t)(ctx->guest_base + va),
                        (size_t)len, u0f_host_prot(prot),
                        MAP_SHARED | MAP_FIXED, fd,
                        (off_t)file_offset);

        if (at != MAP_FAILED) {
            native = 1;
        }
    }
    if (is_shared != 0 && native == 0) {
        fd_dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (fd_dup >= 0) {
            vm_has_shared_fallback = 1;
        }
    }
    if ((unsigned)in->nmaps < VM_INODE_MAPS) {
        vm_inode_map_t *m = &in->maps[in->nmaps];

        m->pid = getpid();
        m->fd_dup = fd_dup;
        m->va = va;
        m->len = len;
        m->file_offset = file_offset;
        m->prot = prot;
        m->shared = is_shared;
        m->native = native;
        in->nmaps++;
    } else {
        if (fd_dup >= 0) {
            (void)close(fd_dup);
        }
        in->wide = 1;
    }
    (void)pthread_mutex_unlock(&vm_inode_mu);
    /* Private maps and non-native shared maps start COW_CLEAN so the
     * soft-TLB write gate traps stores into dbt_mem_recover. */
    if (native == 0) {
        mips_vm_pages_mark(va, len, (unsigned)MIPS_VM_PAGE_COW_CLEAN);
    }
}

void mips_vm_file_unmap_hook(uint64_t va, uint64_t len)
{
    vm_inode_t *tab;
    pid_t self;
    uint64_t end;
    size_t k;

    if (len == 0u || !vm_inode_table_tried || vm_inode_table_ptr == NULL) {
        return;
    }
    end = va + len;
    self = getpid();
    (void)pthread_mutex_lock(&vm_inode_mu);
    tab = vm_inode_table_ptr;
    for (k = 0u; k < VM_INODE_MAX; k++) {
        vm_inode_t *in = &tab[k];
        int i = 0;

        if (in->used == 0) {
            continue;
        }
        while (i < in->nmaps) {
            vm_inode_map_t *m = &in->maps[i];
            uint64_t mlo = m->va;
            uint64_t mhi = m->va + m->len;

            if (m->pid != self || mhi <= va || mlo >= end) {
                i++;
                continue;
            }
            if (va <= mlo && end >= mhi) {
                int j;

                if (m->fd_dup >= 0) {
                    (void)close(m->fd_dup);
                }
                for (j = i; j + 1 < in->nmaps; j++) {
                    in->maps[j] = in->maps[j + 1];
                }
                in->nmaps--;
                continue;
            }
            if (va <= mlo && end < mhi) {
                m->file_offset += (end - mlo);
                m->len = mhi - end;
                m->va = end;
            } else if (va > mlo && end >= mhi) {
                m->len = va - mlo;
            }
            i++;
        }
    }
    (void)pthread_mutex_unlock(&vm_inode_mu);
}

void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va, uint64_t len)
{
    vm_inode_t *tab;
    pid_t self;
    size_t k;

    if (ctx == NULL || len == 0u || !vm_has_shared_fallback) {
        return;
    }
    self = getpid();
    (void)pthread_mutex_lock(&vm_inode_mu);
    tab = vm_inode_table();
    if (tab != NULL) {
        for (k = 0u; k < VM_INODE_MAX; k++) {
            vm_inode_t *in = &tab[k];
            int i;

            if (in->used == 0) {
                continue;
            }
            for (i = 0; i < in->nmaps; i++) {
                vm_inode_map_t *m = &in->maps[i];
                uint64_t lo;
                uint64_t hi;

                if (m->pid != self || m->shared == 0 || m->native != 0 ||
                    m->fd_dup < 0) {
                    continue;
                }
                lo = va > m->va ? va : m->va;
                hi = (va + len) < (m->va + m->len) ? (va + len) :
                                                     (m->va + m->len);
                if (lo >= hi) {
                    continue;
                }
                (void)pwrite(m->fd_dup, mips64_guest_ptr(ctx, lo),
                             (size_t)(hi - lo),
                             (off_t)(m->file_offset + (lo - m->va)));
                mips_vm_pages_mark(lo, hi - lo,
                                   (unsigned)MIPS_VM_PAGE_COW_CLEAN);
            }
        }
    }
    (void)pthread_mutex_unlock(&vm_inode_mu);
}

static void vm_inode_invalidate_maps(vm_inode_t *in, uint64_t lo,
                                       uint64_t hi)
{
    pid_t self = getpid();
    int i;

    if (in->wide != 0) {
        dbt_invalidate_all();
        return;
    }
    for (i = 0; i < in->nmaps; i++) {
        uint64_t s = in->maps[i].va;
        uint64_t e = s + in->maps[i].len;

        if (in->maps[i].pid != self || e <= lo || s >= hi) {
            continue;
        }
        dbt_invalidate_range(s, e - s);
    }
}

void mips_vm_file_post_write(mips64_ctx_t *ctx, int fd, uint64_t off,
                             uint64_t n)
{
    struct stat st;
    vm_inode_t *in;
    pid_t self;
    int i;

    if (ctx == NULL || fd < 0 || n == 0u) {
        return;
    }
    if (fstat(fd, &st) != 0) {
        return;
    }
    self = getpid();
    (void)pthread_mutex_lock(&vm_inode_mu);
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0u);
    if (in == NULL) {
        (void)pthread_mutex_unlock(&vm_inode_mu);
        return;
    }
    if (in->size != (uint64_t)st.st_size) {
        in->size = (uint64_t)st.st_size;
        in->resize_seq++;
    }
    uint64_t wend = (off + n < off) ? ~(uint64_t)0u : off + n;
    uint64_t eof_page = (in->size + 4095u) & ~(uint64_t)4095u;

    for (i = 0; i < in->nmaps; i++) {
        vm_inode_map_t *m = &in->maps[i];
        uint64_t mlo = m->va;
        uint64_t mhi = m->va + m->len;
        uint64_t page;

        if (m->pid != self || m->native != 0) {
            continue;
        }
        for (page = mlo & ~(uint64_t)4095U; page < mhi;
             page += 4096u) {
            uint64_t ps = page < mlo ? mlo : page;
            uint64_t pe = page + 4096u > mhi ? mhi : page + 4096u;
            uint64_t fbase;
            uint64_t flo;
            uint64_t fhi;
            unsigned fl;

            if (ps >= pe || page + 4096u < page) {
                if (page + 4096u < page) {
                    break;
                }
                continue;
            }
            fbase = m->file_offset + (ps - mlo);
            if (fbase < eof_page && ps == page && pe == page + 4096u &&
                vm_inode_page_host_prot(page) == 0) {
                (void)mips_mem_protect(ctx, page, 4096u, m->prot);
            }
            flo = fbase > off ? fbase : off;
            fhi = fbase + (pe - ps) < wend ? fbase + (pe - ps) : wend;
            if (flo >= fhi) {
                continue;
            }
            fl = mips_vm_page_flags(page >> 12);
            if (m->shared != 0 ||
                (fl & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                vm_inode_refresh_span(ctx, fd, page, ps + (flo - fbase),
                                      ps + (fhi - fbase), flo);
            }
        }
    }
    vm_inode_invalidate_maps(in, off, wend);
    (void)pthread_mutex_unlock(&vm_inode_mu);
}

static void vm_inode_post_truncate_locked(mips64_ctx_t *ctx, vm_inode_t *in,
                                          uint64_t newsize)
{
    uint64_t eof_page = (newsize + 4095u) & ~(uint64_t)4095u;
    pid_t self = getpid();
    int i;

    in->size = newsize;
    in->resize_seq++;
    for (i = 0; i < in->nmaps; i++) {
        vm_inode_map_t *m = &in->maps[i];
        uint64_t mlo = m->va;
        uint64_t mhi = m->va + m->len;
        uint64_t page;

        if (m->pid != self || m->native != 0) {
            continue;
        }
        for (page = mlo & ~(uint64_t)4095U; page < mhi;
             page += 4096u) {
            uint64_t ps = page < mlo ? mlo : page;
            uint64_t pe = page + 4096u > mhi ? mhi : page + 4096u;
            uint64_t fbase;
            unsigned fl;

            if (ps >= pe || page + 4096u < page) {
                if (page + 4096u < page) {
                    break;
                }
                continue;
            }
            fbase = m->file_offset + (ps - mlo);
            fl = mips_vm_page_flags(page >> 12);
            if (fbase >= newsize) {
                if (m->shared != 0 ||
                    (fl & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                    vm_inode_zero_span(ctx, page, ps - page, pe - page);
                    if (fbase >= eof_page && ps == page &&
                        pe == page + 4096u) {
                        (void)mips_mem_protect(ctx, page, 4096u, 0u);
                    }
                }
            } else {
                if (ps == page && pe == page + 4096u &&
                    vm_inode_page_host_prot(page) == 0) {
                    (void)mips_mem_protect(ctx, page, 4096u, m->prot);
                }
                if (fbase + (pe - ps) > newsize) {
                    if (m->shared != 0 ||
                        (fl & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
                        vm_inode_zero_span(ctx, page,
                                           ps - page + (newsize - fbase),
                                           pe - page);
                    }
                }
            }
        }
    }
    vm_inode_invalidate_maps(in, 0u, ~(uint64_t)0u);
}

/* Sequential-write variant: recover the range from the current
 * file position (position after the write minus the byte count).
 * Falls back to a full-inode refresh when the position is
 * unknowable. */
void mips_vm_file_post_write_seq(mips64_ctx_t *ctx, int fd, uint64_t n)
{
    off_t cur;

    if (ctx == NULL || fd < 0 || n == 0u) {
        return;
    }
    cur = lseek(fd, 0, SEEK_CUR);
    if (cur < 0 || (uint64_t)cur < n) {
        /* Unknowable position: refresh the whole inode rather than
         * risk a stale CLEAN page. */
        mips_vm_file_post_write(ctx, fd, 0u, ~(uint64_t)0u);
        return;
    }
    mips_vm_file_post_write(ctx, fd, (uint64_t)cur - n, n);
}

void mips_vm_file_post_truncate_fd(mips64_ctx_t *ctx, int fd,
                                   uint64_t newsize)
{
    struct stat st;
    vm_inode_t *in;

    if (ctx == NULL || fd < 0) {
        return;
    }
    if (fstat(fd, &st) != 0) {
        return;
    }
    (void)pthread_mutex_lock(&vm_inode_mu);
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0u);
    if (in != NULL) {
        vm_inode_post_truncate_locked(ctx, in, newsize);
    }
    (void)pthread_mutex_unlock(&vm_inode_mu);
}

void mips_vm_file_post_truncate_path(mips64_ctx_t *ctx,
                                     const char *host_path,
                                     uint64_t newsize)
{
    struct stat st;
    vm_inode_t *in;
    int fd;

    if (ctx == NULL || host_path == NULL) {
        return;
    }
    fd = open(host_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return;
    }
    (void)close(fd);
    (void)pthread_mutex_lock(&vm_inode_mu);
    in = vm_inode_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0u);
    if (in != NULL) {
        vm_inode_post_truncate_locked(ctx, in, newsize);
    }
    (void)pthread_mutex_unlock(&vm_inode_mu);
}
