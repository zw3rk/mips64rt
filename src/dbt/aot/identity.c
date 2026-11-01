/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a AOT cache identity. See `identity.h`.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "dbt/aot/identity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

int mips64_runtime_digest(const char *path, uint8_t out[MIPS64_SHA256_BYTES])
{
    mips64_sha256_t ctx;
    int fd;
    int saved;

    if (path == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    mips64_sha256_init(&ctx);
    for (;;) {
        uint8_t buf[8192];
        ssize_t got = read(fd, buf, sizeof buf);

        if (got < 0) {
            saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        if (got == 0)
            break;
        mips64_sha256_update(&ctx, buf, (size_t)got);
    }
    saved = close(fd);
    mips64_sha256_final(&ctx, out);
    if (saved != 0)
        return -1;
    return 0;
}

int mips64_runtime_digest_self(uint8_t out[MIPS64_SHA256_BYTES])
{
    char link[4096];
#if !defined(__APPLE__)
    ssize_t n;
#endif

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
#if defined(__APPLE__)
    /* macOS hosts have no `/proc/self/exe`; `_NSGetExecutablePath`
     * may return a relative or symlinked path, so canonicalize. */
    {
        char canon[4096];
        uint32_t size = (uint32_t)sizeof link;

        if (_NSGetExecutablePath(link, &size) != 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (realpath(link, canon) == NULL)
            return -1;
        return mips64_runtime_digest(canon, out);
    }
#else
    /* Linux hosts expose the runtime image via `/proc/self/exe`. */
    n = readlink("/proc/self/exe", link, sizeof link - 1u);
    if (n < 0)
        return -1;
    link[n] = '\0';
    return mips64_runtime_digest(link, out);
#endif
}

void mips64_digest_hex(const uint8_t digest[MIPS64_SHA256_BYTES],
                     char hex[MIPS64_DIGEST_HEX_BYTES])
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;

    for (i = 0; i < MIPS64_SHA256_BYTES; i++) {
        hex[i * 2u] = digits[(digest[i] >> 4u) & 0xfu];
        hex[i * 2u + 1u] = digits[digest[i] & 0xfu];
    }
    hex[MIPS64_SHA256_BYTES * 2u] = '\0';
}

int mips64_cache_leaf(const uint8_t runtime_digest[MIPS64_SHA256_BYTES],
                    char *out, size_t out_size)
{
    char hex[MIPS64_DIGEST_HEX_BYTES];
    int n;

    if (runtime_digest == NULL || out == NULL || out_size == 0) {
        errno = EINVAL;
        return -1;
    }
    mips64_digest_hex(runtime_digest, hex);
    n = snprintf(out, out_size, "%s.aot", hex);
    if (n < 0 || (size_t)n >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Minimal ELF reader: enough to confirm static-PIE shape without an
 * ELF toolchain dependency. All multi-byte fields are little-endian
 * (`ELFDATA2LSB` is required). N64 objects are `ELFCLASS64`, N32 objects
 * are `ELFCLASS32`; both carry `e_machine == EM_MIPS` (8, SPEC 1.1). */

#define MIPS64_ELF_MAGIC0 0x7fu
#define MIPS64_ELF_MAGIC1 'E'
#define MIPS64_ELF_MAGIC2 'L'
#define MIPS64_ELF_MAGIC3 'F'
#define MIPS64_ELFCLASS32 1u
#define MIPS64_ELFCLASS64 2u
#define MIPS64_ELFDATA2LSB 1u
#define MIPS64_EM_MIPS 8u
/* The cache identity also covers the translator itself, which is an
 * AArch64 static-PIE on the build host. */
#define MIPS64_EM_AARCH64 183u
#define MIPS64_ET_DYN 3u
#define MIPS64_PT_DYNAMIC 2u
#define MIPS64_DT_NULL 0u
#define MIPS64_DT_NEEDED 1u
#define MIPS64_DT_FLAGS_1 0x6ffffffbu
#define MIPS64_DF_1_PIE 0x08000000u

static uint16_t load_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

static uint32_t load_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static uint64_t load_u64le(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8u) |
           ((uint64_t)p[2] << 16u) | ((uint64_t)p[3] << 24u) |
           ((uint64_t)p[4] << 32u) | ((uint64_t)p[5] << 40u) |
           ((uint64_t)p[6] << 48u) | ((uint64_t)p[7] << 56u);
}

/* Positional `pread` loop: the check never depends on (or disturbs)
 * the descriptor offset. */
static int read_at(int fd, uint8_t *buf, size_t len, uint64_t offset)
{
    size_t done = 0;

    while (done < len) {
        ssize_t got = pread(fd, buf + done, len - done,
                            (off_t)(offset + (uint64_t)done));

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        done += (size_t)got;
    }
    return 0;
}

int mips64_elf_static_pie_check(const char *path)
{
    uint8_t ehdr[64];
    uint64_t phoff;
    uint64_t dyn_off = 0;
    uint64_t dyn_size = 0;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t i;
    uint64_t at;
    /* Class-dependent layout: N64 (`ELFCLASS64`) uses 8-byte addresses,
     * N32 (`ELFCLASS32`) uses 4-byte addresses. */
    size_t phdr_size;
    size_t dyn_size_step;
    unsigned dyn_val_off;
    int is_n32;
    int fd;
    int rc = MIPS64_ELF_NOT_STATIC_PIE;

    if (path == NULL)
        return MIPS64_ELF_IO_ERROR;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return MIPS64_ELF_IO_ERROR;
    /* Past a successful `open`, every failure (truncation, I/O, or a
     * shape mismatch) means the static-PIE shape is unconfirmed. */
    if (read_at(fd, ehdr, sizeof ehdr, 0u) != 0) {
        close(fd);
        return MIPS64_ELF_NOT_STATIC_PIE;
    }
    if (ehdr[0] != MIPS64_ELF_MAGIC0 || ehdr[1] != MIPS64_ELF_MAGIC1 ||
        ehdr[2] != MIPS64_ELF_MAGIC2 || ehdr[3] != MIPS64_ELF_MAGIC3 ||
        (ehdr[4] != MIPS64_ELFCLASS64 && ehdr[4] != MIPS64_ELFCLASS32) ||
        ehdr[5] != MIPS64_ELFDATA2LSB) {
        close(fd);
        return MIPS64_ELF_NOT_STATIC_PIE;
    }
    {
        uint16_t machine = load_u16le(ehdr + 18u);

        if (machine != MIPS64_EM_MIPS && machine != MIPS64_EM_AARCH64) {
            close(fd);
            return MIPS64_ELF_NOT_STATIC_PIE;
        }
    }
    is_n32 = ehdr[4] == MIPS64_ELFCLASS32;
    if (load_u16le(ehdr + 16u) != MIPS64_ET_DYN) {
        close(fd);
        return MIPS64_ELF_NOT_STATIC_PIE;
    }
    if (is_n32 != 0) {
        /* ELFCLASS32: `e_phoff` at 28, entries are 32 bytes
         * (`p_offset` at 4, `p_filesz` at 16); dynamic entries are
         * 8 bytes with the value at offset 4. */
        phoff = load_u32le(ehdr + 28u);
        phentsize = load_u16le(ehdr + 42u);
        phnum = load_u16le(ehdr + 44u);
        phdr_size = 32u;
        dyn_size_step = 8u;
        dyn_val_off = 4u;
    } else {
        /* ELFCLASS64: `e_phoff` at 32, entries are 56 bytes
         * (`p_offset` at 8, `p_filesz` at 32); dynamic entries are
         * 16 bytes with the value at offset 8. */
        phoff = load_u64le(ehdr + 32u);
        phentsize = load_u16le(ehdr + 54u);
        phnum = load_u16le(ehdr + 56u);
        phdr_size = 56u;
        dyn_size_step = 16u;
        dyn_val_off = 8u;
    }
    if (phentsize < phdr_size || phnum == 0 || phnum > 64u) {
        close(fd);
        return MIPS64_ELF_NOT_STATIC_PIE;
    }
    for (i = 0; i < phnum; i++) {
        uint8_t phdr[56];

        if (read_at(fd, phdr, phdr_size,
                    phoff + (uint64_t)i * (uint64_t)phentsize) != 0) {
            close(fd);
            return MIPS64_ELF_NOT_STATIC_PIE;
        }
        if (load_u32le(phdr) == MIPS64_PT_DYNAMIC) {
            dyn_off = is_n32 != 0 ? load_u32le(phdr + 4u) : load_u64le(phdr + 8u);
            dyn_size = is_n32 != 0 ? load_u32le(phdr + 16u) : load_u64le(phdr + 32u);
            break;
        }
    }
    if (dyn_off == 0 || dyn_size == 0 || dyn_size > 65536u) {
        /* No `PT_DYNAMIC`: fully static, but PIE requires the `ET_DYN`
         * shape plus the `DF_1_PIE` marker below; without dynamic tags
         * the marker cannot be present. */
        close(fd);
        return MIPS64_ELF_NOT_STATIC_PIE;
    }
    at = dyn_off;
    for (;;) {
        uint8_t entry[16];
        uint64_t tag;
        uint64_t flags;

        if (at + dyn_size_step > dyn_off + dyn_size) {
            close(fd);
            return MIPS64_ELF_NOT_STATIC_PIE;
        }
        if (read_at(fd, entry, dyn_size_step, at) != 0) {
            close(fd);
            return MIPS64_ELF_NOT_STATIC_PIE;
        }
        tag = is_n32 != 0 ? load_u32le(entry) : load_u64le(entry);
        if (tag == MIPS64_DT_NULL)
            break;
        if (tag == MIPS64_DT_NEEDED) {
            close(fd);
            return MIPS64_ELF_NOT_STATIC_PIE;
        }
        if (tag == MIPS64_DT_FLAGS_1) {
            flags = is_n32 != 0 ? load_u32le(entry + dyn_val_off) :
                                  load_u64le(entry + dyn_val_off);
            if ((flags & MIPS64_DF_1_PIE) != 0)
                rc = MIPS64_ELF_OK;
        }
        at += dyn_size_step;
    }
    close(fd);
    return rc;
}
