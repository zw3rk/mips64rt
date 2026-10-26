/* Lane U12 miss-site table checks: 24-byte records, bump allocation,
 * little-endian serialization, and the exact 2-insn miss stub words.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-portable (same pattern as `tests/test_decode.c`): builds with
 * the host C compiler, no Docker, no guest toolchain.
 *
 * Curated C11 only: no VLA, no Annex K, no <threads.h>, no _Generic,
 * no sprintf/strcpy/strcat.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dbt/emit_mem.h"

static int failures = 0;
static int checks = 0;

static void check(const char *name, int cond)
{
    checks++;
    if (cond != 0) {
        printf("ok: %s\n", name);
    } else {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    static dbt_mem_sites_t sites;
    static uint32_t words[8];
    static uint8_t bytes[DBT_MEM_SITES_MAX * 24u];
    a64_emit_t e;
    size_t at;
    size_t n;
    int i0;
    int i1;
    int i;
    static const uint8_t want0[24] = {
        0x78u, 0x56u, 0x34u, 0x12u, 0xF0u, 0xDEu, 0xBCu, 0x9Au,
        0x00u, 0x00u, 0x00u, 0x00u, 0x2Au, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    };

    check("site is 24 bytes", sizeof(dbt_mem_site_t) == 24u);
    check("guest_pc at 0", offsetof(dbt_mem_site_t, guest_pc) == 0u);
    check("miss_kind at 8", offsetof(dbt_mem_site_t, miss_kind) == 8u);
    check("host_off at 12", offsetof(dbt_mem_site_t, host_off) == 12u);
    check("disp at 16", offsetof(dbt_mem_site_t, disp) == 16u);

    dbt_mem_sites_init(&sites);
    check("init count zero", sites.count == 0u);

    /* NULL and empty-table edges. */
    check("bump null table", dbt_mem_site_bump(NULL, 0u, 0u, 0u) == -1);
    check("serialize null table", dbt_mem_sites_serialize(NULL, bytes,
                                                          sizeof bytes) == 0u);
    check("serialize empty", dbt_mem_sites_serialize(&sites, bytes,
                                                     sizeof bytes) == 0u);
    check("stub null emitter", ei_mem_miss_stub(NULL, 0u) == (size_t)-1);

    i0 = dbt_mem_site_bump(&sites, 0x9ABCDEF012345678ull,
                           (uint32_t)DBT_MEM_SITE_LOAD, 42u);
    i1 = dbt_mem_site_bump(&sites, 0x1000u,
                           (uint32_t)DBT_MEM_SITE_STORE, 44u);
    check("bump indices", i0 == 0 && i1 == 1 && sites.count == 2u);
    check("bump fields",
          sites.sites[0].guest_pc == 0x9ABCDEF012345678ull &&
          sites.sites[0].miss_kind == (uint32_t)DBT_MEM_SITE_LOAD &&
          sites.sites[0].host_off == 42u && sites.sites[0].disp == 0u);

    /* Fill to capacity, then prove the overflow bump fails cleanly. */
    for (i = 2; i < (int)DBT_MEM_SITES_MAX; i++) {
        if (dbt_mem_site_bump(&sites, (uint64_t)i,
                              (uint32_t)DBT_MEM_SITE_ATOMIC,
                              (uint32_t)i) < 0)
            break;
    }
    check("table fills to max", sites.count == DBT_MEM_SITES_MAX);
    check("bump overflow", dbt_mem_site_bump(&sites, 0u, 0u, 0u) == -1);

    /* Serialize a fresh two-site table and byte-compare row zero. */
    dbt_mem_sites_init(&sites);
    dbt_mem_site_bump(&sites, 0x9ABCDEF012345678ull,
                      (uint32_t)DBT_MEM_SITE_LOAD, 42u);
    dbt_mem_site_bump(&sites, 0x1000u, (uint32_t)DBT_MEM_SITE_STORE, 44u);
    memset(bytes, 0xA5u, sizeof bytes);
    n = dbt_mem_sites_serialize(&sites, bytes, sizeof bytes);
    check("serialize length", n == 48u);
    check("serialize row zero", memcmp(bytes, want0, 24u) == 0);
    check("serialize row one pc",
          bytes[24] == 0x00u && bytes[25] == 0x10u && bytes[26] == 0x00u &&
          bytes[27] == 0x00u && bytes[28] == 0x00u && bytes[29] == 0x00u &&
          bytes[30] == 0x00u && bytes[31] == 0x00u);
    check("serialize row one kind/off",
          bytes[32] == 0x01u && bytes[33] == 0x00u && bytes[34] == 0x00u &&
          bytes[35] == 0x00u && bytes[36] == 0x2Cu && bytes[37] == 0x00u &&
          bytes[38] == 0x00u && bytes[39] == 0x00u);
    check("serialize short cap",
          dbt_mem_sites_serialize(&sites, bytes, 47u) == 0u);

    /* The 2-insn stub: `movz w0, #7` then `brk #0xDB`, nothing else. */
    memset(words, 0, sizeof words);
    e.buf = words;
    e.cap = 8u;
    e.len = 0u;
    e.err = 0;
    at = ei_mem_miss_stub(&e, 7u);
    check("stub slot", at == 0u && e.err == 0 && e.len == 2u);
    check("stub movz", words[0] == 0x528000E0u);
    check("stub brk", words[1] == 0xD4201B60u);
    check("stub rejects 17-bit site",
          ei_mem_miss_stub(&e, 0x10000u) == (size_t)-1);

    printf("mem_sites: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
