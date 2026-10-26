/*
 * tests/test_mem_sites.c — Lane U12 relative miss-site table tests.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pins the 24-byte relative dbt_mem_site_t layout (offsets,
 * serialization round-trip, validation rejects), and the 2-insn
 * miss stub shape (movz w4, #site; b with zero offset for the block
 * end to patch). Never executed: emission only.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/a64_emit.h"
#include "dbt/aot/identity.h"
#include "dbt/aot/sites.h"
#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"

static int passes;
static int fails;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            (void)printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            fails++;                                                       \
        } else {                                                           \
            passes++;                                                      \
        }                                                                  \
    } while (0)

static dbt_mem_site_t u0_site(uint16_t seq, uint16_t insn, uint16_t cont,
                              uint16_t delta)
{
    dbt_mem_site_t s;

    (void)memset(&s, 0, sizeof s);
    s.seq_start_offset = seq;
    s.host_insn_offset = insn;
    s.cont_insn_offset = cont;
    s.guest_pc_delta = delta;
    s.npc_delta = -8;
    s.insn_word = 0x8CA50010u;
    s.sp_rollback_delta = 0;
    s.npc_mode = (uint8_t)RT_NPC_SEQUENTIAL;
    s.width = 4u;
    s.flags = (uint8_t)DBT_MEM_F_STORE;
    s.val_or_dst_reg = 5u;
    s.addr_base_reg = 4u;
    s.reserved = 0u;
    return s;
}

static void test_record_layout(void)
{
    dbt_mem_site_t s = u0_site(0x10u, 0x18u, 0x1Cu, 0x20u);

    CHECK(sizeof(dbt_mem_site_t) == 24u);
    CHECK(offsetof(dbt_mem_site_t, seq_start_offset) == 0u);
    CHECK(offsetof(dbt_mem_site_t, host_insn_offset) == 2u);
    CHECK(offsetof(dbt_mem_site_t, cont_insn_offset) == 4u);
    CHECK(offsetof(dbt_mem_site_t, guest_pc_delta) == 6u);
    CHECK(offsetof(dbt_mem_site_t, npc_delta) == 8u);
    CHECK(offsetof(dbt_mem_site_t, insn_word) == 12u);
    CHECK(offsetof(dbt_mem_site_t, sp_rollback_delta) == 16u);
    CHECK(offsetof(dbt_mem_site_t, npc_mode) == 18u);
    CHECK(offsetof(dbt_mem_site_t, width) == 19u);
    CHECK(offsetof(dbt_mem_site_t, flags) == 20u);
    CHECK(offsetof(dbt_mem_site_t, val_or_dst_reg) == 21u);
    CHECK(offsetof(dbt_mem_site_t, addr_base_reg) == 22u);
    CHECK(offsetof(dbt_mem_site_t, reserved) == 23u);
    CHECK(s.flags == (uint8_t)DBT_MEM_F_STORE);
    CHECK(DBT_MEM_SITES_MAX == 256u);
}

static void test_bump_serialize_roundtrip(void)
{
    dbt_mem_sites_t t;
    dbt_mem_sites_t u;
    dbt_mem_site_t a = u0_site(0x10u, 0x18u, 0x1Cu, 0x20u);
    dbt_mem_site_t b = u0_site(0x30u, 0x38u, 0x40u, 0x44u);
    uint8_t buf[48];
    size_t n;

    dbt_mem_sites_init(&t);
    CHECK(t.count == 0u);
    CHECK(dbt_mem_site_bump(NULL, &a) < 0);
    CHECK(dbt_mem_site_bump(&t, NULL) < 0);
    CHECK(dbt_mem_site_bump(&t, &a) == 0);
    b.npc_mode = (uint8_t)RT_NPC_DYNAMIC_CTX;
    b.flags |= (uint8_t)DBT_MEM_F_IN_DELAY_SLOT;
    CHECK(dbt_mem_site_bump(&t, &b) == 1);
    CHECK(t.count == 2u);

    /* All-or-nothing sizing: short cap and NULL fail cleanly. */
    CHECK(dbt_mem_sites_serialize(NULL, buf, sizeof buf) == 0u);
    CHECK(dbt_mem_sites_serialize(&t, NULL, sizeof buf) == 0u);
    CHECK(dbt_mem_sites_serialize(&t, buf, 24u) == 0u);
    n = dbt_mem_sites_serialize(&t, buf, sizeof buf);
    CHECK(n == 48u);

    /* Row 0 is the store site: relative offsets then the payload. */
    CHECK(buf[0] == 0x10u && buf[1] == 0x00u);
    CHECK(buf[2] == 0x18u && buf[3] == 0x00u);
    CHECK(buf[4] == 0x1Cu && buf[5] == 0x00u);
    CHECK(buf[6] == 0x20u && buf[7] == 0x00u);
    CHECK(buf[18] == (uint8_t)RT_NPC_SEQUENTIAL);
    CHECK(buf[19] == 4u);
    CHECK(buf[20] == (uint8_t)DBT_MEM_F_STORE);

    /* Round trip preserves every field, including the delay bit. */
    dbt_mem_sites_init(&u);
    CHECK(dbt_mem_sites_deserialize(NULL, buf, n) == 0u);
    CHECK(dbt_mem_sites_deserialize(&u, NULL, n) == 0u);
    CHECK(dbt_mem_sites_deserialize(&u, buf, 23u) == 0u);
    CHECK(dbt_mem_sites_deserialize(&u, buf, n) == 2u);
    CHECK(u.count == 2u);
    CHECK(u.sites[0].guest_pc_delta == 0x20u);
    CHECK(u.sites[0].insn_word == 0x8CA50010u);
    CHECK(u.sites[0].width == 4u);
    CHECK(u.sites[1].npc_mode == (uint8_t)RT_NPC_DYNAMIC_CTX);
    CHECK((u.sites[1].flags & (uint8_t)DBT_MEM_F_IN_DELAY_SLOT) != 0u);
    CHECK(u.sites[1].npc_delta == -8);

    /* Reserved must be zero: nonzero rows are rejected wholesale. */
    buf[23] = 1u;
    {
        dbt_mem_sites_t v;

        dbt_mem_sites_init(&v);
        CHECK(dbt_mem_sites_deserialize(&v, buf, n) == 0u);
        CHECK(v.count == 0u);
    }
}

static void test_stub_shape(void)
{
    static a64_emit_t e;
    static uint32_t buf[16];
    size_t at;

    (void)memset(&e, 0, sizeof e);
    e.buf = buf;
    e.cap = 16u;
    at = ei_mem_miss_stub(&e, 7u);
    CHECK(at == 0u);
    CHECK(e.err == 0);
    CHECK(e.len == 2u);
    CHECK(buf[0] == UINT32_C(0x528000E4)); /* movz w4, #7 */
    CHECK(buf[1] == UINT32_C(0x14000000)); /* b (block end patches) */
    CHECK(ei_mem_miss_stub(&e, 0x10000u) == (size_t)-1);
    CHECK(ei_mem_miss_stub(NULL, 0u) == (size_t)-1);
}

static int u0_visit_count;
static uint64_t u0_visit_pc;
static size_t u0_visit_rows;

static int u0_visit(uint64_t guest_pc, const dbt_mem_site_t *sites,
                    size_t count, void *arg)
{
    (void)arg;
    u0_visit_count++;
    u0_visit_pc = guest_pc;
    u0_visit_rows = count;
    if (sites == NULL || count != 2u) {
        return 1;
    }
    if (sites[0].insn_word != 0x8CA50010u ||
        sites[1].guest_pc_delta != 0x44u) {
        return 1;
    }
    return 0;
}

static void test_aot_file_roundtrip(void)
{
    char path[] = "/tmp/mips64rt-sites-XXXXXX";
    dbt_mem_site_t rows[2];
    int fd;

    CHECK(MIPS64_AOT_EMITTER_VERSION == 2u);
    rows[0] = u0_site(0x10u, 0x18u, 0x1Cu, 0x20u);
    rows[1] = u0_site(0x30u, 0x38u, 0x40u, 0x44u);
    rows[1].npc_mode = (uint8_t)RT_NPC_DYNAMIC_CTX;

    /* No leaf: silent no-op, never fails the run. */
    mips_aot_set_leaf(NULL);
    CHECK(mips_aot_leaf_path() == NULL);
    mips_aot_note_block(0x1000u, rows, 2u);
    CHECK(mips_aot_sites_load("/nonexistent-leaf.aot", u0_visit,
                              NULL) != 0);

    fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    (void)close(fd);
    mips_aot_set_leaf(path);
    CHECK(mips_aot_leaf_path() != NULL);
    mips_aot_note_block(0x1000u, rows, 2u);
    mips_aot_note_block(0x2000u, rows, 1u);

    u0_visit_count = 0;
    u0_visit_pc = 0u;
    u0_visit_rows = 0u;
    CHECK(mips_aot_sites_load(path, u0_visit, NULL) == 0);
    CHECK(u0_visit_count == 2);
    CHECK(u0_visit_pc == 0x2000u);
    CHECK(u0_visit_rows == 1u);

    /* Version mismatch is refused, not misread. */
    {
        int wfd = open(path, O_WRONLY | O_TRUNC);

        CHECK(wfd >= 0);
        if (wfd >= 0) {
            uint8_t bad[20];

            (void)memset(bad, 0, sizeof bad);
            bad[0] = 'M';
            bad[1] = '6';
            bad[2] = '4';
            bad[3] = 'S';
            bad[4] = 1u;
            (void)write(wfd, bad, sizeof bad);
            (void)close(wfd);
        }
        CHECK(mips_aot_sites_load(path, u0_visit, NULL) == -2);
    }
    /* Truncation is refused. */
    {
        int wfd = open(path, O_WRONLY | O_TRUNC);

        CHECK(wfd >= 0);
        if (wfd >= 0) {
            (void)write(wfd, "M64S", 4u);
            (void)close(wfd);
        }
        CHECK(mips_aot_sites_load(path, u0_visit, NULL) == -3);
    }
    mips_aot_set_leaf(NULL);
    (void)unlink(path);
}

int main(void)
{
    test_record_layout();
    test_bump_serialize_roundtrip();
    test_stub_shape();
    test_aot_file_roundtrip();
    (void)printf("SITES: %d passed, %d failed\n", passes, fails);
    return (fails == 0) ? 0 : 1;
}
