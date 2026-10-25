/*
 * src/os/proc.c — Guest /proc/self interception (lane L5a, Phase 5).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The dynamic loader and guest libc expect Linux /proc/self/{exe,maps,
 * cmdline,stat,auxv}; the host's own entries would leak host paths and
 * address-space layout, so open/openat of exactly those guest-absolute
 * paths (plus readlink of /proc/self/exe) is served from translator
 * state:
 *
 *   exe     -> the guest executable path passed to mips_load_elf;
 *   maps    -> guest mappings from the region table (guest VAs, guest
 *              prot flags), sorted by address, no pathnames (so no host
 *              path can ever leak);
 *   cmdline -> the guest argv (NUL-joined, as on Linux);
 *   stat    -> guest pid/comm/state line (single-threaded shape);
 *   auxv    -> the exact auxiliary vector handed to the guest (native
 *              word width: 8 bytes N64, 4 bytes N32, guest byte order).
 *
 * Each synthetic open materializes a small unlinked read-only host
 * file, so read/lseek/close on the returned fd behave like a small
 * read-only file through the ordinary host syscalls; writes fail with
 * EBADF. The loader reports each exec via mips_proc_note_exec (copies
 * the path and argv: the caller's vectors may be freed right after
 * mips_load_elf returns) and mips_proc_note_auxv.
 *
 * Only the exact /proc/self/<name> paths are intercepted
 * (/proc/self/task stays host-backed: the gate never needs it).
 * Compiled by folding this TU into src/os/syscalls.c (the Makefile is
 * frozen, so it cannot gain a TU): every helper is static and prefixed
 * with proc_ to share that TU safely. Curated C11 only.
 *
 * Lane-built acceptance guest recipe (dynamic N64 glibc; run on this
 * host with Docker; G is a scratch dir holding the guest sources
 * p5dyn.c/p5dynlib.c and the target sysroot):
 *   G=/tmp/mips-l5a; mkdir -p $G/sysroot/lib
 *   docker run --rm --platform linux/arm64 -v $G:/x debian:trixie-slim \
 *     sh -c 'apt-get update -qq >/dev/null 2>&1;
 *       apt-get install -y -qq gcc-mips64el-linux-gnuabi64 qemu-user \
 *       >/dev/null 2>&1;
 *       cp /usr/mips64el-linux-gnuabi64/lib64/ld.so.1 \
 *         /usr/mips64el-linux-gnuabi64/lib/libc.so.6 \
 *         /usr/mips64el-linux-gnuabi64/lib/libm.so.6 /x/sysroot/lib/;
 *       cd /x &&
 *       mips64el-linux-gnuabi64-gcc -shared -fPIC -o p5dynlib.so \
 *         p5dynlib.c &&
 *       mips64el-linux-gnuabi64-gcc -o p5dyn p5dyn.c \
 *         -Wl,--dynamic-linker,/x/sysroot/lib/ld.so.1 \
 *         -Wl,-rpath,/x/sysroot/lib'
 * The guest prints only deterministic bytes (dlopen/dlsym answers,
 * __thread TLS values on both sides of the library boundary,
 * auxv/maps/stat as booleans or argv-derived content, never raw
 * addresses). Compare, with identical argv so argv[0]/cmdline/exe
 * agree, in the oracle image (mips64rt-qemu:10.0.13):
 *   docker run --rm --platform linux/arm64 -v $G:/x -v $PWD/_build:/b \
 *     mips64rt-qemu:10.0.13 \
 *     sh -c 'cd /x && qemu-mips64el /x/p5dyn arg1 arg2 > golden.txt &&
 *       /b/mips64rt --interp /x/p5dyn arg1 arg2 > trans.txt &&
 *       cmp golden.txt trans.txt'
 */

#include "core/cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Guest window check + host pointer (owned by src/os/mem.c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);

/* Guest open-flag bits consulted here (MIPS UAPI asm/fcntl.h values,
 * distinct from the host's: MIPS O_DIRECTORY is 0x10000 and O_NOFOLLOW
 * is 0x20000. The RC5 watch-item: never use the host values here). */
#define PROC_O_DIRECTORY 0x10000U
#define PROC_O_NOFOLLOW 0x20000U

/* Noted guest state (copies owned here; refreshed on every exec). */
static char proc_exe[4096] = { 0 };
static char **proc_argv = NULL;
static unsigned proc_argc = 0;
static uint64_t proc_auxv[2U * 20U] = { 0 };
static size_t proc_auxc = 0;
static const mips64_ctx_t *proc_ctx = NULL;

static size_t proc_cstr_len(const char *s)
{
    size_t n = 0U;

    while (s[n] != '\0') {
        n++;
    }
    return n;
}

void mips_proc_note_exec(const char *guest_path, int argc, char **argv,
                         const mips64_ctx_t *ctx)
{
    unsigned i;
    unsigned n = 0U;
    char **vec = NULL;

    if (guest_path != NULL) {
        size_t k = 0U;

        while (guest_path[k] != '\0' && k + 1U < sizeof proc_exe) {
            proc_exe[k] = guest_path[k];
            k++;
        }
        proc_exe[k] = '\0';
    }
    if (argv != NULL && argc > 0) {
        n = (unsigned)argc > 64U ? 64U : (unsigned)argc;
        vec = (char **)malloc((size_t)(n + 1U) * sizeof *vec);
        if (vec != NULL) {
            for (i = 0U; i < n; i++) {
                size_t len =
                    argv[i] != NULL ? proc_cstr_len(argv[i]) : 0U;
                char *dst;

                if (len > 4095U) {
                    len = 4095U;
                }
                dst = (char *)malloc(len + 1U);
                if (dst == NULL) {
                    break;
                }
                if (argv[i] != NULL) {
                    memcpy(dst, argv[i], len);
                }
                dst[len] = '\0';
                vec[i] = dst;
            }
            if (i != n) {
                unsigned j;

                for (j = 0U; j < i; j++) {
                    free(vec[j]);
                }
                free(vec);
                vec = NULL;
                n = 0U;
            } else {
                vec[n] = NULL;
            }
        } else {
            n = 0U;
        }
    }
    if (proc_argv != NULL) {
        for (i = 0U; i < proc_argc; i++) {
            free(proc_argv[i]);
        }
        free(proc_argv);
    }
    proc_argv = vec;
    proc_argc = vec != NULL ? n : 0U;
    proc_ctx = ctx;
}

void mips_proc_note_auxv(const uint64_t *pairs, size_t npairs)
{
    size_t n = npairs > 20U ? 20U : npairs;

    proc_auxc = 0U;
    if (pairs == NULL) {
        return;
    }
    memcpy(proc_auxv, pairs, n * 2U * sizeof(uint64_t));
    proc_auxc = n;
}

/* Which synthetic file guest_path names (0 when not synthetic). */
static int proc_self_kind(const char *guest_path)
{
    if (strcmp(guest_path, "/proc/self/exe") == 0) {
        return 1;
    }
    if (strcmp(guest_path, "/proc/self/maps") == 0) {
        return 2;
    }
    if (strcmp(guest_path, "/proc/self/cmdline") == 0) {
        return 3;
    }
    if (strcmp(guest_path, "/proc/self/stat") == 0) {
        return 4;
    }
    if (strcmp(guest_path, "/proc/self/auxv") == 0) {
        return 5;
    }
    return 0;
}

/* write(2) loop for the materialization fd. */
static int proc_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0U;

    while (done < len) {
        ssize_t got = write(fd, p + done, len - done);

        if (got <= 0) {
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

/* One maps line per region. Guest prot bits render as Linux rwx + p
 * (every translator mapping is private); no pathname column, so no
 * host path can leak. Sorted by base by the caller. */
static int proc_maps_line(int fd, uint64_t base, uint64_t len, uint32_t prot)
{
    char line[96];
    int n = snprintf(line, sizeof line, "%llx-%llx %c%c%c%c %08llx "
                     "00:00 0\n",
                     (unsigned long long)base,
                     (unsigned long long)(base + len),
                     (prot & (uint32_t)MIPS_PROT_READ) != 0U ? 'r' : '-',
                     (prot & (uint32_t)MIPS_PROT_WRITE) != 0U ? 'w' : '-',
                     (prot & (uint32_t)MIPS_PROT_EXEC) != 0U ? 'x' : '-',
                     'p', (unsigned long long)0);

    if (n < 0 || (size_t)n >= sizeof line) {
        return -1;
    }
    return proc_write_all(fd, line, (size_t)n);
}

static int proc_emit_maps(int fd)
{
    /* Region snapshot sorted by base (insertion sort; tiny table, and
     * sorting keeps the output deterministic even if the table order
     * ever changes). */
    struct {
        uint64_t base;
        uint64_t len;
        uint32_t prot;
    } regs[128];
    unsigned n = 0U;
    unsigned i;
    unsigned j;

    if (proc_ctx == NULL) {
        return -1;
    }
    for (i = 0U; i < proc_ctx->region_count && n < 128U; i++) {
        regs[n].base = proc_ctx->regions[i].start;
        regs[n].len = proc_ctx->regions[i].end -
                      proc_ctx->regions[i].start;
        regs[n].prot = proc_ctx->regions[i].prot;
        n++;
    }
    for (i = 1U; i < n; i++) {
        uint64_t kb = regs[i].base;
        uint64_t kl = regs[i].len;
        uint32_t kp = regs[i].prot;

        j = i;
        while (j > 0U && regs[j - 1U].base > kb) {
            regs[j].base = regs[j - 1U].base;
            regs[j].len = regs[j - 1U].len;
            regs[j].prot = regs[j - 1U].prot;
            j--;
        }
        regs[j].base = kb;
        regs[j].len = kl;
        regs[j].prot = kp;
    }
    for (i = 0U; i < n; i++) {
        if (proc_maps_line(fd, regs[i].base, regs[i].len,
                           regs[i].prot) != 0) {
            return -1;
        }
    }
    return 0;
}

static int proc_emit_cmdline(int fd)
{
    unsigned i;

    for (i = 0U; i < proc_argc; i++) {
        size_t len = proc_cstr_len(proc_argv[i]);

        if (proc_write_all(fd, proc_argv[i], len + 1U) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Guest stat: pid (comm) state ... in the kernel field order through
 * starttime; the remaining counters stay zero. Only pid, comm, and
 * the single-threaded shape are guest-meaningful here. */
static int proc_emit_stat(int fd)
{
    char line[256];
    const char *exe = proc_exe[0] != '\0' ? proc_exe : "mips64rt";
    const char *comm = exe;
    const char *slash = exe;
    long pid = (long)getpid();
    long ppid = (long)getppid();
    int n;

    while (*slash != '\0') {
        if (*slash == '/') {
            comm = slash + 1;
        }
        slash++;
    }
    if (*comm == '\0') {
        comm = "mips64rt";
    }
    n = snprintf(line, sizeof line,
                 "%ld (%s) R %ld %ld %ld 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0\n",
                 pid, comm, ppid, pid, pid);
    if (n < 0 || (size_t)n >= sizeof line) {
        return -1;
    }
    return proc_write_all(fd, line, (size_t)n);
}

/* Store one auxv word in guest byte order (4 bytes N32, 8 bytes N64). */
static void proc_put_word(uint8_t *p, uint64_t v, unsigned n, int be)
{
    unsigned i;

    for (i = 0U; i < n; i++) {
        p[be != 0 ? n - 1U - i : i] = (uint8_t)(v >> (8U * i));
    }
}

static int proc_emit_auxv(int fd)
{
    unsigned ws = (proc_ctx != NULL && proc_ctx->is_n32 != 0U) ? 4U : 8U;
    int be = (proc_ctx != NULL && proc_ctx->is_be != 0U) ? 1 : 0;
    uint8_t row[8];
    size_t i;

    for (i = 0U; i < proc_auxc; i++) {
        proc_put_word(row, proc_auxv[2U * i], ws, be);
        if (proc_write_all(fd, row, (size_t)ws) != 0) {
            return -1;
        }
        proc_put_word(row, proc_auxv[2U * i + 1U], ws, be);
        if (proc_write_all(fd, row, (size_t)ws) != 0) {
            return -1;
        }
    }
    return 0;
}

/* open/openat interception: returns a readable fd for a synthetic
 * /proc/self/<name> path, -1 when guest_path is not synthetic (fall
 * through to the host), or a negative Linux errno (< -1) when it is
 * synthetic but cannot be served. flags carries the guest O_* bits. */
long mips_proc_open(const char *guest_path, uint64_t flags)
{
    char tmpl[] = "/tmp/mips64procXXXXXX";
    int kind = proc_self_kind(guest_path);
    int tmp;
    int fd;
    int rc = -1;

    if (kind == 0) {
        return -1;
    }
    if ((flags & (uint64_t)PROC_O_DIRECTORY) != 0U) {
        return -(long)ENOTDIR;
    }
    if (kind == 1 && (flags & (uint64_t)PROC_O_NOFOLLOW) != 0U) {
        return -(long)ELOOP;
    }
    tmp = mkstemp(tmpl);
    if (tmp < 0) {
        return -(long)ENOMEM;
    }
    switch (kind) {
    case 1:
        rc = proc_write_all(tmp, proc_exe, proc_cstr_len(proc_exe));
        break;
    case 2:
        rc = proc_emit_maps(tmp);
        break;
    case 3:
        rc = proc_emit_cmdline(tmp);
        break;
    case 4:
        rc = proc_emit_stat(tmp);
        break;
    case 5:
        rc = proc_emit_auxv(tmp);
        break;
    default:
        rc = -1;
        break;
    }
    close(tmp);
    if (rc != 0) {
        unlink(tmpl);
        return -(long)EIO;
    }
    /* Reopen read-only so guest writes fail with EBADF, then unlink:
     * the fd behaves like a small read-only file from here on. */
    fd = open(tmpl, O_RDONLY);
    unlink(tmpl);
    if (fd < 0) {
        return -(long)ENOMEM;
    }
    return (long)fd;
}

/* readlinkat interception for /proc/self/exe: writes at most bufsiz
 * guest-path bytes to buf_va and returns their count (no NUL
 * terminator, as on Linux), or -1 when guest_path is not synthetic
 * (the caller keeps its previous behavior). */
long mips_proc_readlink(const char *guest_path, uint64_t buf_va,
                        uint64_t bufsiz)
{
    uint8_t *dst;
    size_t len;

    if (proc_self_kind(guest_path) != 1) {
        return -1;
    }
    if (bufsiz == 0U) {
        return -(long)EINVAL;
    }
    if (proc_ctx == NULL) {
        return -(long)EFAULT;
    }
    if (!mips_mem_ok(proc_ctx, buf_va, bufsiz, (uint32_t)MIPS_PROT_WRITE)) {
        return -(long)EFAULT;
    }
    dst = (uint8_t *)mips64_guest_ptr(proc_ctx, buf_va);
    len = proc_cstr_len(proc_exe);
    if (len > (size_t)bufsiz) {
        len = (size_t)bufsiz;
    }
    memcpy(dst, proc_exe, len);
    return (long)len;
}
