/*
 * src/loader.c — Static ELF loader for mips64rt (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * See src/loader.h. Admission mirrors the E01 ground truth
 * (experiments/E01/FINDINGS.md): N64 is ELFCLASS64 with
 * (e_flags & EF_MIPS_ABI) == 0, N32 is ELFCLASS32 with
 * (e_flags & EF_MIPS_ABI2) == 0x20; both endians load with explicit
 * byte-swap so a BE guest parses on an LE host and vice versa.
 *
 * ET_EXEC images load at their linked addresses; ET_DYN (static-PIE)
 * images take a fixed load bias. PT_LOAD segments are mapped writable
 * for the fill and dropped to their final protection afterwards; the
 * host side never gains PROT_EXEC (W^X). The initial stack (argc/argv/
 * envp/auxv incl. AT_PHDR/AT_ENTRY, AT_UID/AT_EUID/AT_GID/AT_EGID,
 * AT_CLKTCK=100) is built at the per-ABI stack top with the native
 * word size (8 bytes N64, 4 bytes N32) in guest byte order.
 */

#include "loader.h"

#include "core/cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Region helpers owned by src/os/mem.c (lane L1c). */
extern int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                        uint32_t prot, const char *tag);
extern int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            uint32_t prot);

/* ELF admission (E01: N64 Flags 0x80000007, N32 Flags 0x80000025). */
#define MIPS_EM_MIPS 8U
#define MIPS_ELFCLASS32 1U
#define MIPS_ELFCLASS64 2U
#define MIPS_ELFDATA2LSB 1U
#define MIPS_ELFDATA2MSB 2U
#define MIPS_ET_EXEC 2U
#define MIPS_ET_DYN 3U
#define MIPS_PT_LOAD 1U
#define MIPS_PF_X 1U
#define MIPS_PF_W 2U
#define MIPS_PF_R 4U
#define MIPS_EF_ABI 0x0000F000U
#define MIPS_EF_ABI2 0x00000020U

/* Fixed load bias for ET_DYN (static-PIE) guests. */
#define MIPS_DYN_BIAS UINT64_C(0x400000)

/* Initial stack: 8 MiB ending at the per-ABI stack top. */
#define MIPS_STACK_SIZE (UINT64_C(8) << 20)

/* Auxiliary vector tags (Linux generic). */
#define MIPS_AT_NULL 0U
#define MIPS_AT_PHDR 3U
#define MIPS_AT_PHENT 4U
#define MIPS_AT_PHNUM 5U
#define MIPS_AT_PAGESZ 6U
#define MIPS_AT_FLAGS 8U
#define MIPS_AT_ENTRY 9U
#define MIPS_AT_UID 11U
#define MIPS_AT_EUID 12U
#define MIPS_AT_GID 13U
#define MIPS_AT_EGID 14U
#define MIPS_AT_CLKTCK 17U
#define MIPS_AT_SECURE 23U
#define MIPS_AT_RANDOM 25U
#define MIPS_AT_EXECFN 31U

/* Guest prot bits (Linux asm-generic, shared with the target). */
#define MIPS_PROT_READ 1U
#define MIPS_PROT_WRITE 2U
#define MIPS_PROT_EXEC 4U

typedef struct {
    int is64;
    int be;
    uint16_t type;
    uint32_t flags;
    uint64_t entry;
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
} ehdr_t;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
} phdr_t;

static uint16_t rd16(const uint8_t *p, int be)
{
    if (be) {
        return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
    }
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p, int be)
{
    if (be) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p, int be)
{
    if (be) {
        return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
               ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
               ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
               ((uint64_t)p[6] << 8) | (uint64_t)p[7];
    }
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Store a native stack/auxv word (4 bytes N32, 8 bytes N64) in guest
 * byte order. N32 values always fit: placements stay below 4 GiB. */
static void st_word(uint8_t *p, uint64_t v, int w32, int be)
{
    if (w32) {
        uint32_t w = (uint32_t)v;

        if (be) {
            p[0] = (uint8_t)((w >> 24) & 0xFFU);
            p[1] = (uint8_t)((w >> 16) & 0xFFU);
            p[2] = (uint8_t)((w >> 8) & 0xFFU);
            p[3] = (uint8_t)(w & 0xFFU);
        } else {
            p[0] = (uint8_t)(w & 0xFFU);
            p[1] = (uint8_t)((w >> 8) & 0xFFU);
            p[2] = (uint8_t)((w >> 16) & 0xFFU);
            p[3] = (uint8_t)((w >> 24) & 0xFFU);
        }
        return;
    }
    if (be) {
        p[0] = (uint8_t)((v >> 56) & 0xFFU);
        p[1] = (uint8_t)((v >> 48) & 0xFFU);
        p[2] = (uint8_t)((v >> 40) & 0xFFU);
        p[3] = (uint8_t)((v >> 32) & 0xFFU);
        p[4] = (uint8_t)((v >> 24) & 0xFFU);
        p[5] = (uint8_t)((v >> 16) & 0xFFU);
        p[6] = (uint8_t)((v >> 8) & 0xFFU);
        p[7] = (uint8_t)(v & 0xFFU);
    } else {
        p[0] = (uint8_t)(v & 0xFFU);
        p[1] = (uint8_t)((v >> 8) & 0xFFU);
        p[2] = (uint8_t)((v >> 16) & 0xFFU);
        p[3] = (uint8_t)((v >> 24) & 0xFFU);
        p[4] = (uint8_t)((v >> 32) & 0xFFU);
        p[5] = (uint8_t)((v >> 40) & 0xFFU);
        p[6] = (uint8_t)((v >> 48) & 0xFFU);
        p[7] = (uint8_t)((v >> 56) & 0xFFU);
    }
}

static ssize_t read_at(int fd, void *buf, size_t n, uint64_t off)
{
    size_t done = 0U;

    while (done < n) {
        ssize_t got;

        if (off + done < off) {
            return -1;
        }
        got = pread(fd, (uint8_t *)buf + done, n - done,
                    (off_t)(off + done));
        if (got < 0) {
            return -1;
        }
        if (got == 0) {
            break;
        }
        done += (size_t)got;
    }
    return (ssize_t)done;
}

static size_t str_len(const char *s)
{
    size_t n = 0U;

    while (s[n] != '\0') {
        n++;
    }
    return n;
}

/* AT_RANDOM seed: mixed host realtime clock and pid. */
static void rand16(uint8_t out[16])
{
    struct timespec ts;
    uint64_t s = 0U;
    unsigned i;

    clock_gettime(CLOCK_REALTIME, &ts);
    s = (uint64_t)ts.tv_nsec ^ ((uint64_t)getpid() << 32) ^
        (uint64_t)ts.tv_sec;
    if (s == 0U) {
        s = UINT64_C(0x9E3779B97F4A7C15);
    }
    for (i = 0; i < 16U; i++) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out[i] = (uint8_t)s;
    }
}

/* Host-only environment never reaches the guest: LD_* (a host
 * LD_PRELOAD once made a host ld.so load into the guest) and the
 * translator's own MIPS64RT_* knobs. */
static int env_hidden(const char *entry)
{
    if (entry[0] == 'L' && entry[1] == 'D' && entry[2] == '_') {
        return 1;
    }
    if (entry[0] == 'M' && entry[1] == 'I' && entry[2] == 'P' &&
        entry[3] == 'S' && entry[4] == '6' && entry[5] == '4' &&
        entry[6] == 'R' && entry[7] == 'T' && entry[8] == '_') {
        return 1;
    }
    return 0;
}

void mips_loader_init_ctx(mips64_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);
}

static int parse_ehdr(int fd, ehdr_t *eh)
{
    static const uint8_t magic[4] = { 0x7FU, 'E', 'L', 'F' };
    uint8_t head[64];
    int be;

    if (read_at(fd, head, sizeof head, 0U) != (ssize_t)sizeof head) {
        return -1;
    }
    if (memcmp(head, magic, sizeof magic) != 0 || head[6] != 1U) {
        return -1;
    }
    if (head[4] != MIPS_ELFCLASS32 && head[4] != MIPS_ELFCLASS64) {
        return -1;
    }
    if (head[5] != MIPS_ELFDATA2LSB && head[5] != MIPS_ELFDATA2MSB) {
        return -1;
    }
    be = head[5] == MIPS_ELFDATA2MSB;
    eh->is64 = head[4] == MIPS_ELFCLASS64;
    eh->be = be;
    eh->type = rd16(head + 16, be);
    if (rd16(head + 18, be) != MIPS_EM_MIPS) {
        return -1;
    }
    if (rd32(head + 20, be) != 1U) {
        return -1;
    }
    if (eh->is64) {
        eh->entry = rd64(head + 24, be);
        eh->phoff = rd64(head + 32, be);
        eh->flags = rd32(head + 48, be);
        eh->phentsize = rd16(head + 54, be);
        eh->phnum = rd16(head + 56, be);
    } else {
        eh->entry = (uint64_t)rd32(head + 24, be);
        eh->phoff = (uint64_t)rd32(head + 28, be);
        eh->flags = rd32(head + 36, be);
        eh->phentsize = rd16(head + 42, be);
        eh->phnum = rd16(head + 44, be);
    }
    if (eh->type != MIPS_ET_EXEC && eh->type != MIPS_ET_DYN) {
        return -1;
    }
    if (eh->phoff == 0U || eh->phnum == 0U) {
        return -1;
    }
    return 0;
}

/* Returns 1 for N64, 2 for N32, 0 to reject. */
static int classify(const ehdr_t *eh)
{
    if (eh->is64) {
        if ((eh->flags & MIPS_EF_ABI) == 0U) {
            return 1;
        }
        return 0;
    }
    if ((eh->flags & MIPS_EF_ABI2) == MIPS_EF_ABI2) {
        return 2;
    }
    return 0;
}

static int parse_phdr(int fd, const ehdr_t *eh, uint16_t idx, phdr_t *ph)
{
    uint8_t buf[56];
    size_t want = eh->is64 ? 56U : 32U;

    if (eh->phentsize < want) {
        return -1;
    }
    if (read_at(fd, buf, want,
                eh->phoff + (uint64_t)idx * (uint64_t)eh->phentsize) !=
        (ssize_t)want) {
        return -1;
    }
    if (eh->is64) {
        ph->type = rd32(buf, eh->be);
        ph->flags = rd32(buf + 4, eh->be);
        ph->offset = rd64(buf + 8, eh->be);
        ph->vaddr = rd64(buf + 16, eh->be);
        ph->filesz = rd64(buf + 32, eh->be);
        ph->memsz = rd64(buf + 40, eh->be);
    } else {
        ph->type = rd32(buf, eh->be);
        ph->offset = (uint64_t)rd32(buf + 4, eh->be);
        ph->vaddr = (uint64_t)rd32(buf + 8, eh->be);
        ph->filesz = (uint64_t)rd32(buf + 16, eh->be);
        ph->memsz = (uint64_t)rd32(buf + 20, eh->be);
        ph->flags = rd32(buf + 24, eh->be);
    }
    return 0;
}

static int build_stack(mips64_ctx_t *ctx, int argc, char **argv, char **envp,
                       uint64_t phdr_va, uint64_t phent, uint64_t phnum,
                       uint64_t entry, const char *path)
{
    int w32 = ctx->is_n32 != 0U ? 1 : 0;
    uint64_t ws = w32 ? 4U : 8U;
    uint64_t stack_top = ctx->is_n32 != 0U ? MIPS64_N32_STACK_TOP
                                           : MIPS64_N64_STACK_TOP;
    uint64_t stack_base = stack_top - MIPS_STACK_SIZE;
    uint64_t str_size = 0U;
    uint64_t nenv = 0U;
    uint64_t kept = 0U;
    uint64_t frame;
    uint64_t s;
    uint64_t sp;
    uint64_t argv_base;
    uint64_t env_base;
    uint64_t execfn_va;
    uint64_t rnd_va;
    uint8_t *mem;
    uint8_t rnd[16];
    int i;
    int rc;

    for (i = 0; i < argc; i++) {
        str_size += (uint64_t)str_len(argv[i]) + 1U;
    }
    while (envp[nenv] != NULL) {
        if (!env_hidden(envp[nenv])) {
            str_size += (uint64_t)str_len(envp[nenv]) + 1U;
            kept++;
        }
        nenv++;
    }
    str_size += (uint64_t)str_len(path) + 1U + 16U;
    /* 15 auxv rows (14 + AT_NULL): argc + argv[] + NULL + envp[] +
     * NULL + auxv pairs. */
    frame = ws + ws * ((uint64_t)argc + 1U) + ws * (kept + 1U) +
            ws * 2U * 15U;
    if (str_size + frame >= MIPS_STACK_SIZE) {
        errno = E2BIG;
        return -1;
    }
    rc = mips_mem_map(ctx, stack_base, MIPS_STACK_SIZE,
                      MIPS_PROT_READ | MIPS_PROT_WRITE, "stack");
    if (rc != 0) {
        errno = ENOMEM;
        return -1;
    }
    mem = (uint8_t *)mips64_guest_ptr(ctx, stack_base);
    /* Lay strings out low to high: argv[0..], kept envs, execfn,
     * random. Addresses are pure arithmetic first ... */
    s = stack_top;
    s -= 16U;
    rnd_va = s;
    s -= (uint64_t)str_len(path) + 1U;
    execfn_va = s;
    for (i = (int)nenv - 1; i >= 0; i--) {
        if (!env_hidden(envp[i])) {
            s -= (uint64_t)str_len(envp[i]) + 1U;
        }
    }
    env_base = s;
    for (i = argc - 1; i >= 0; i--) {
        s -= (uint64_t)str_len(argv[i]) + 1U;
    }
    argv_base = s;
    /* ... then the bytes follow the addresses. */
    {
        uint64_t p = argv_base;
        uint64_t q = env_base;

        for (i = 0; i < argc; i++) {
            size_t n = str_len(argv[i]) + 1U;

            memcpy(mem + (p - stack_base), argv[i], n);
            p += (uint64_t)n;
        }
        for (i = 0; envp[i] != NULL; i++) {
            if (!env_hidden(envp[i])) {
                size_t n = str_len(envp[i]) + 1U;

                memcpy(mem + (q - stack_base), envp[i], n);
                q += (uint64_t)n;
            }
        }
        memcpy(mem + (execfn_va - stack_base), path, str_len(path) + 1U);
        rand16(rnd);
        memcpy(mem + (rnd_va - stack_base), rnd, 16U);
    }
    sp = (argv_base - frame) & ~UINT64_C(15);
    {
        /* Slots are byte-addressed and word-sized (4 bytes N32, 8
         * bytes N64): every store, terminators included, goes
         * through st_word in guest byte order. */
        uint8_t *slot = mem + (sp - stack_base);
        int be = ctx->is_be != 0U;
        uint64_t off = 0U;
        uint64_t p = argv_base;
        uint64_t q = env_base;
        uint64_t auxv[30];
        unsigned naux = 0U;
        unsigned r;

        st_word(slot + off, (uint64_t)argc, w32, be);
        off += ws;
        for (i = 0; i < argc; i++) {
            st_word(slot + off, p, w32, be);
            off += ws;
            p += (uint64_t)str_len(argv[i]) + 1U;
        }
        st_word(slot + off, 0U, w32, be);
        off += ws;
        for (i = 0; envp[i] != NULL; i++) {
            if (!env_hidden(envp[i])) {
                st_word(slot + off, q, w32, be);
                off += ws;
                q += (uint64_t)str_len(envp[i]) + 1U;
            }
        }
        st_word(slot + off, 0U, w32, be);
        off += ws;
#define AUX(tag, val)                       \
    do {                                    \
        auxv[naux++] = (uint64_t)(tag);     \
        auxv[naux++] = (uint64_t)(val);     \
    } while (0)
        AUX(MIPS_AT_PHDR, phdr_va);
        AUX(MIPS_AT_PHENT, phent);
        AUX(MIPS_AT_PHNUM, phnum);
        AUX(MIPS_AT_PAGESZ, MIPS64_PAGE_SIZE);
        AUX(MIPS_AT_FLAGS, 0U);
        AUX(MIPS_AT_ENTRY, entry);
        AUX(MIPS_AT_UID, getuid());
        AUX(MIPS_AT_EUID, geteuid());
        AUX(MIPS_AT_GID, getgid());
        AUX(MIPS_AT_EGID, getegid());
        AUX(MIPS_AT_CLKTCK, 100U);
        AUX(MIPS_AT_SECURE, 0U);
        AUX(MIPS_AT_RANDOM, rnd_va);
        AUX(MIPS_AT_EXECFN, execfn_va);
        AUX(MIPS_AT_NULL, 0U);
#undef AUX
        for (r = 0U; r < naux; r++) {
            st_word(slot + off, auxv[r], w32, be);
            off += ws;
        }
        /* Guest-visible auxv copy for the /proc/self layer (Phase 5);
         * 15 rows fit the 64-entry buffer (30 used). */
        for (r = 0U; r < naux && r < 64U; r++) {
            ctx->auxv_data[r] = auxv[r];
        }
        ctx->auxv_bytes = (size_t)naux * sizeof(uint64_t);
    }
    ctx->gpr[MIPS64_REG_SP] = sp;
    ctx->stack_top = stack_top;
    ctx->stack_base = stack_base;
    return 0;
}

int mips_load_elf(mips64_ctx_t *ctx, const char *path, char **argv,
                  char **envp)
{
    ehdr_t eh;
    uint64_t bias;
    uint64_t seg_end = 0U;
    uint64_t phdr = 0U;
    uint64_t entry;
    uint16_t i;
    int kind;
    int argc = 0;
    int fd;

    if (ctx == NULL || path == NULL || argv == NULL || envp == NULL ||
        argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }
    while (argv[argc] != NULL) {
        argc++;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (parse_ehdr(fd, &eh) != 0) {
        close(fd);
        errno = ENOEXEC;
        return -1;
    }
    kind = classify(&eh);
    if (kind == 0) {
        close(fd);
        errno = ENOEXEC;
        return -1;
    }
    mips_loader_init_ctx(ctx);
    ctx->is_be = eh.be ? 1U : 0U;
    ctx->is_n32 = kind == 2 ? 1U : 0U;
    if (guest_mem_init(ctx) != 0) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    ctx->task_size = mips_task_size(ctx);
    ctx->mmap_base = ctx->is_n32 != 0U ? MIPS64_N32_MMAP_BASE
                                       : MIPS64_N64_MMAP_BASE;
    ctx->mmap_cursor = ctx->mmap_base;
    bias = eh.type == MIPS_ET_DYN ? MIPS_DYN_BIAS : 0U;
    for (i = 0; i < eh.phnum; i++) {
        phdr_t ph;
        uint64_t va;
        uint64_t page_off;
        uint64_t map_va;
        uint64_t map_len;
        uint64_t filesz;
        uint64_t memsz;
        uint32_t prot;
        uint8_t *dst;
        int rc;

        if (parse_phdr(fd, &eh, i, &ph) != 0) {
            close(fd);
            errno = ENOEXEC;
            return -1;
        }
        if (ph.type != MIPS_PT_LOAD) {
            continue;
        }
        if (ph.memsz < ph.filesz || ph.memsz == 0U) {
            close(fd);
            errno = ENOEXEC;
            return -1;
        }
        va = bias + ph.vaddr;
        /* ELF congruence (p_offset == p_vaddr mod p_align) lets a
         * toolchain pack a segment at an unaligned va; the host map
         * is page granular, so map from the page floor and fill at
         * the page offset. */
        page_off = va & (MIPS64_PAGE_SIZE - 1U);
        map_va = va - page_off;
        map_len = (ph.memsz + page_off + (MIPS64_PAGE_SIZE - 1U)) &
                  ~(MIPS64_PAGE_SIZE - 1U);
        if (map_len == 0U || map_va + map_len < map_va ||
            map_va + map_len > ctx->task_size) {
            close(fd);
            errno = ENOEXEC;
            return -1;
        }
        prot = ph.flags & 7U;
        /* Map writable for the fill; final protection is enforced
         * below once the segment body is in place. */
        rc = mips_mem_map(ctx, map_va, map_len, prot | MIPS_PROT_WRITE,
                          "elf");
        if (rc != 0) {
            close(fd);
            errno = rc == -EEXIST ? EEXIST : ENOMEM;
            return -1;
        }
        dst = (uint8_t *)mips64_guest_ptr(ctx, va);
        filesz = ph.filesz;
        if (filesz > 0U) {
            uint64_t done = 0U;

            while (done < filesz) {
                uint64_t left = filesz - done;
                size_t chunk =
                    left > (uint64_t)0x40000000 ? 0x40000000U : (size_t)left;
                ssize_t got = read_at(fd, dst + done, chunk,
                                      ph.offset + done);

                if (got != (ssize_t)chunk) {
                    close(fd);
                    errno = got < 0 ? errno : ENOEXEC;
                    return -1;
                }
                done += (uint64_t)chunk;
            }
        }
        memsz = ph.memsz;
        if (memsz > filesz) {
            memset(dst + filesz, 0, (size_t)(memsz - filesz));
        }
        if ((prot & MIPS_PROT_WRITE) == 0U) {
            rc = mips_mem_protect(ctx, map_va, map_len, prot);
            if (rc != 0) {
                close(fd);
                errno = ENOMEM;
                return -1;
            }
        }
        if (va + memsz > seg_end) {
            seg_end = va + memsz;
        }
        if (ph.offset <= eh.phoff &&
            eh.phoff - ph.offset < ph.filesz) {
            phdr = bias + ph.vaddr + (eh.phoff - ph.offset);
        }
    }
    close(fd);
    if (seg_end == 0U || phdr == 0U) {
        errno = ENOEXEC;
        return -1;
    }
    entry = bias + eh.entry;
    ctx->elf_base = bias;
    ctx->elf_entry = entry;
    ctx->brk_base = (seg_end + (MIPS64_PAGE_SIZE - 1U)) &
                    ~(MIPS64_PAGE_SIZE - 1U);
    ctx->brk_curr = ctx->brk_base;
    if (build_stack(ctx, argc, argv, envp, phdr, eh.is64 ? 56U : 32U,
                      (uint64_t)eh.phnum, entry, path) != 0) {
        return -1;
    }
    ctx->pc = entry;
    ctx->next_pc = entry + 4U;
    return 0;
}
