/*
 * src/dbt/aot/sites.c — Lane U12 versioned AOT miss-site records.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Record layout (all little-endian, appended per compiled block):
 *   u8[4] magic "M64S", u16 emitter version, u16 reserved (0),
 *   u32 row count, u64 guest pc, then count * 24-byte rows.
 * The writer opens O_WRONLY|O_APPEND per block and closes right
 * away: no fd is held across guest execution, and concurrent
 * translators only ever append whole records (each under PIPE_BUF
 * scale for sane tables, but ordering across writers is not
 * promised — the loader skips what it cannot parse). Refuses files
 * over 64 MiB and rows over DBT_MEM_SITES_MAX.
 */

#include "dbt/aot/sites.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/aot/identity.h"
#include "dbt/emit_mem.h"

#define AOT_SITES_MAGIC0 'M'
#define AOT_SITES_MAGIC1 '6'
#define AOT_SITES_MAGIC2 '4'
#define AOT_SITES_MAGIC3 'S'
#define AOT_SITES_MAX_FILE (64u * 1024u * 1024u)
#define AOT_SITES_MAX_PATH 1024u

static char aot_leaf[AOT_SITES_MAX_PATH];

void mips_aot_set_leaf(const char *path)
{
    size_t n;

    if (path == NULL) {
        aot_leaf[0] = '\0';
        return;
    }
    n = strlen(path);
    if (n >= sizeof aot_leaf) {
        aot_leaf[0] = '\0';
        return;
    }
    memcpy(aot_leaf, path, n + 1u);
}

const char *mips_aot_leaf_path(void)
{
    return aot_leaf[0] == '\0' ? NULL : aot_leaf;
}

static void put_u16le(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void put_u32le(uint8_t *out, uint32_t v)
{
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        out[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static void put_u64le(uint8_t *out, uint64_t v)
{
    unsigned i;

    for (i = 0u; i < 8u; i++) {
        out[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static uint16_t get_u16le(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t get_u32le(const uint8_t *in)
{
    uint32_t v = 0u;
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        v |= (uint32_t)in[i] << (8u * i);
    }
    return v;
}

static uint64_t get_u64le(const uint8_t *in)
{
    uint64_t v = 0u;
    unsigned i;

    for (i = 0u; i < 8u; i++) {
        v |= (uint64_t)in[i] << (8u * i);
    }
    return v;
}

void mips_aot_note_block(uint64_t guest_pc,
                         const struct dbt_mem_site *sites, size_t count)
{
    /* 20-byte header: magic[4], version u16, reserved u16,
     * count u32, guest pc u64. */
    uint8_t hdr[20];
    uint8_t rows[DBT_MEM_SITES_MAX * sizeof(dbt_mem_site_t)];
    dbt_mem_sites_t t;
    size_t need;
    int fd;
    size_t i;

    if (aot_leaf[0] == '\0' || sites == NULL || count == 0u ||
        count > DBT_MEM_SITES_MAX) {
        return;
    }
    /* Serialize through the canonical row format (single source of
     * the 24-byte layout). */
    dbt_mem_sites_init(&t);
    for (i = 0u; i < count; i++) {
        if (dbt_mem_site_bump(&t, &sites[i]) < 0) {
            return;
        }
    }
    need = dbt_mem_sites_serialize(&t, rows, sizeof rows);
    if (need == 0u) {
        return;
    }
    hdr[0] = (uint8_t)AOT_SITES_MAGIC0;
    hdr[1] = (uint8_t)AOT_SITES_MAGIC1;
    hdr[2] = (uint8_t)AOT_SITES_MAGIC2;
    hdr[3] = (uint8_t)AOT_SITES_MAGIC3;
    put_u16le(hdr + 4u, (uint16_t)MIPS64_AOT_EMITTER_VERSION);
    put_u16le(hdr + 6u, 0u);
    put_u32le(hdr + 8u, (uint32_t)count);
    put_u64le(hdr + 12u, guest_pc);
    fd = open(aot_leaf, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    if (write(fd, hdr, sizeof hdr) != (ssize_t)sizeof hdr) {
        (void)close(fd);
        return;
    }
    {
        const uint8_t *p = rows;
        size_t left = need;

        while (left != 0u) {
            ssize_t w = write(fd, p, left);

            if (w <= 0) {
                break;
            }
            p += (size_t)w;
            left -= (size_t)w;
        }
    }
    (void)close(fd);
}

int mips_aot_sites_load(const char *path, mips_aot_site_visit_t visit,
                        void *arg)
{
    uint8_t hdr[20];
    int fd;
    ssize_t r;

    if (path == NULL || visit == NULL) {
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    {
        struct stat st;

        if (fstat(fd, &st) == 0 &&
            (uint64_t)st.st_size > (uint64_t)AOT_SITES_MAX_FILE) {
            (void)close(fd);
            return -3;
        }
    }
    for (;;) {
        uint32_t count;
        uint64_t guest_pc;
        uint8_t rows[DBT_MEM_SITES_MAX * sizeof(dbt_mem_site_t)];
        dbt_mem_sites_t t;
        size_t need;
        size_t got = 0u;

        r = read(fd, hdr, sizeof hdr);
        if (r == 0) {
            break;
        }
        if (r != (ssize_t)sizeof hdr) {
            (void)close(fd);
            return -3;
        }
        if (hdr[0] != (uint8_t)AOT_SITES_MAGIC0 ||
            hdr[1] != (uint8_t)AOT_SITES_MAGIC1 ||
            hdr[2] != (uint8_t)AOT_SITES_MAGIC2 ||
            hdr[3] != (uint8_t)AOT_SITES_MAGIC3 ||
            get_u16le(hdr + 4u) != (uint16_t)MIPS64_AOT_EMITTER_VERSION ||
            get_u16le(hdr + 6u) != 0u) {
            (void)close(fd);
            return -2;
        }
        count = get_u32le(hdr + 8u);
        guest_pc = get_u64le(hdr + 12u);
        if (count == 0u || count > DBT_MEM_SITES_MAX) {
            (void)close(fd);
            return -3;
        }
        need = (size_t)count * sizeof(dbt_mem_site_t);
        while (got < need) {
            r = read(fd, rows + got, need - got);
            if (r <= 0) {
                (void)close(fd);
                return -3;
            }
            got += (size_t)r;
        }
        dbt_mem_sites_init(&t);
        if (dbt_mem_sites_deserialize(&t, rows, need) != (size_t)count) {
            (void)close(fd);
            return -3;
        }
        if (visit(guest_pc, t.sites, t.count, arg) != 0) {
            break;
        }
    }
    (void)close(fd);
    return 0;
}
