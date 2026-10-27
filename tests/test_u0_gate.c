/*
 * tests/test_u0_gate.c — Lane U12 write-gate + Provider A gate test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the Rev4 write gate end to end with the real
 * interpreter (no stubs for interp_step): COW_CLEAN closes the
 * write tag, the miss path promotes and the store lands; HAS_CODE
 * closes the tag, the SMC path retires the translation and the
 * store lands; the inode tracker records maps, zeroes discarded
 * tails on shrink, and refreshes CLEAN pages on file growth.
 *
 * Host-portable (same pattern as the U0 gates): builds with the
 * host C compiler, no Docker, no guest toolchain.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/emit_mem.h"
#include "interp/decode.h"
#include "os/backend.h"
#include "os/quiesce.h"
#include "vm/vm_file.h"
#include "vm/vm_pages.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0;
static int passes = 0;

#define CHECK(cond) do { \
        if (cond) { \
            passes++; \
        } else { \
            (void)printf("FAIL line %u: %s\n", (unsigned)__LINE__, #cond); \
            fails++; \
        } \
    } while (0)

/* ---- stubs: trap/hostfault/syscall are not exercised natively ---- */

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    (void)signo;
    (void)addr;
}

void mips_hostfault_install(const void *pool, size_t len)
{
    (void)pool;
    (void)len;
}

int mips_hostfault_run(mips64_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    (void)ctx;
    (void)code;
    if (reasonp != NULL) {
        *reasonp = (uint32_t)MIPS64_EXIT_UNDEF;
    }
    return 0;
}

void mips_hostfault_disarm(void)
{
}

int64_t mips_syscall(mips64_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

#define GATE_PAGE UINT64_C(0x10000)
#define GATE_CODE (GATE_PAGE + UINT64_C(0x000))
#define GATE_DATA (GATE_PAGE + UINT64_C(0x800))

static void setup_gate_ctx(mips64_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof *ctx);
    ctx->is_n32 = 0U;
    ctx->is_be = 0U;
    mips_backend_state_reset(ctx);
    if (guest_mem_init(ctx) != 0) {
        (void)printf("FAIL: guest_mem_init\n");
        fails++;
        return;
    }
    if (mips_mem_map(ctx, GATE_PAGE, UINT64_C(0x1000),
                     (uint32_t)(1u | 2u | 4u), "gate-page") != 0) {
        (void)printf("FAIL: mips_mem_map errno=%d\n", errno);
        fails++;
    }
}

static dbt_mem_site_t gate_site(uint64_t pc, uint32_t word, unsigned width,
                                unsigned flags, unsigned rt, unsigned rs)
{
    dbt_mem_site_t s;

    (void)memset(&s, 0, sizeof s);
    s.seq_start_offset = 0u;
    s.host_insn_offset = 6u;
    s.cont_insn_offset = 7u;
    s.guest_pc_delta = (uint16_t)(pc - GATE_PAGE);
    s.insn_word = word;
    s.width = (uint8_t)width;
    s.flags = (uint8_t)flags;
    s.val_or_dst_reg = (uint8_t)rt;
    s.addr_base_reg = (uint8_t)rs;
    return s;
}

int main(void)
{
    static mips64_ctx_t ctx;
    mips_soft_tlb_entry_t *tlb;
    dbt_mem_site_t site;
    char tmpl[] = "/tmp/mips64rt-gate-XXXXXX";
    int fd;
    uint8_t probe[16];
    uint64_t v = 0u;

    setup_gate_ctx(&ctx);
    tlb = (mips_soft_tlb_entry_t *)mips_soft_tlb_base(&ctx);
    CHECK(tlb != NULL);

    /* Plant SW r6, 0(r5) at GATE_CODE and point r5 at GATE_DATA. */
    CHECK(guest_st32(&ctx, GATE_CODE,
                     (uint64_t)(((0x2Bu << 26) | (5u << 21) |
                                 (6u << 16)) & 0xFFFFFFFFu)) == 0);
    ctx.gpr[5] = GATE_DATA;
    ctx.gpr[6] = UINT64_C(0xA5A5A5A5);

    /* COW_CLEAN closes the write tag but keeps reads. */
    mips_vm_pages_mark(GATE_PAGE, UINT64_C(0x1000),
                       (unsigned)MIPS_VM_PAGE_COW_CLEAN);
    mips_soft_tlb_fill(&ctx, GATE_DATA);
    CHECK(tlb[((GATE_DATA >> 12) & MIPS64_SOFT_TLB_INDEX_MASK)].read_tag ==
          (GATE_DATA & ~(uint64_t)0xFFFu));
    CHECK(tlb[((GATE_DATA >> 12) & MIPS64_SOFT_TLB_INDEX_MASK)].write_tag ==
          UINT64_MAX);

    /* The miss path promotes: the store lands, the mark clears, and
     * a refill reopens the gate. */
    site = gate_site(GATE_CODE,
                     (uint32_t)((0x2Bu << 26) | (5u << 21) | (6u << 16)),
                     4u, (unsigned)DBT_MEM_F_STORE, 6u, 5u);
    ctx.pc = GATE_CODE;
    ctx.exit_reason = MIPS64_EXIT_NONE;
    CHECK(dbt_mem_recover(&ctx, &site, GATE_PAGE, GATE_CODE) == 0);
    CHECK((mips_vm_page_flags(GATE_DATA >> 12) &
           (unsigned)MIPS_VM_PAGE_COW_CLEAN) == 0u);
    CHECK(guest_ld32(&ctx, GATE_DATA, &v) == 0 &&
          v == (uint64_t)ctx.gpr[6]);
    mips_soft_tlb_fill(&ctx, GATE_DATA);
    CHECK(tlb[((GATE_DATA >> 12) & MIPS64_SOFT_TLB_INDEX_MASK)].write_tag ==
          (GATE_DATA & ~(uint64_t)0xFFFu));

    /* HAS_CODE closes the tag; the SMC path retires the code first
     * and the store still lands. */
    mips_vm_pages_mark(GATE_PAGE, UINT64_C(0x1000),
                       (unsigned)MIPS_VM_PAGE_HAS_CODE);
    mips_soft_tlb_fill(&ctx, GATE_DATA);
    CHECK(tlb[((GATE_DATA >> 12) & MIPS64_SOFT_TLB_INDEX_MASK)].write_tag ==
          UINT64_MAX);
    ctx.gpr[6] = UINT64_C(0x5A5A5A5A);
    ctx.exit_reason = MIPS64_EXIT_NONE;
    CHECK(dbt_mem_recover(&ctx, &site, GATE_PAGE, GATE_CODE) == 0);
    CHECK(guest_ld32(&ctx, GATE_DATA, &v) == 0 &&
          v == UINT64_C(0x5A5A5A5A));
    CHECK((mips_vm_page_flags(GATE_DATA >> 12) &
           (unsigned)MIPS_VM_PAGE_HAS_CODE) == 0u);

    /* Inode tracking: map a private file, shrink it, grow it. */
    fd = mkstemp(tmpl);
    CHECK(fd >= 0);
    if (fd < 0) {
        goto done;
    }
    (void)memset(probe, 0xAB, sizeof probe);
    CHECK(write(fd, probe, sizeof probe) == (ssize_t)sizeof probe);
    mips_vm_file_map_hook(&ctx, fd, GATE_DATA, UINT64_C(0x1000), 0u,
                          (uint32_t)(1u | 2u), 0);
    CHECK((mips_vm_page_flags(GATE_DATA >> 12) &
           (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u);
    CHECK(ftruncate(fd, 4) == 0);
    mips_vm_file_post_truncate_fd(&ctx, fd, 4u);
    /* Wholly removed CLEAN pages read back as zeros. */
    CHECK(guest_ld32(&ctx, GATE_DATA + 8u, &v) == 0 && v == 0u);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(write(fd, probe, sizeof probe) == (ssize_t)sizeof probe);
    mips_vm_file_post_write(&ctx, fd, 0u, sizeof probe);
    /* Refreshed CLEAN pages show the file again (bytes past the
     * 16-byte EOF stay zero). */
    {
        size_t k;

        for (k = 0u; k < 8u; k++) {
            CHECK(guest_ld8(&ctx, GATE_DATA + 8u + k, &v) == 0 &&
                  v == 0xABu);
            CHECK(guest_ld8(&ctx, GATE_DATA + 16u + k, &v) == 0 &&
                  v == 0u);
        }
    }
    /* Wholly removed page past eof_page revokes access (SIGBUS/MIPS_FAULT)
     * and restores access on file growth; non-native MAP_SHARED writes
     * through to the underlying file; read-only MREMAP_FIXED copies
     * without faulting. */
    {
        extern int64_t mips_mem_remap(mips64_ctx_t *c, uint64_t old_va,
                                      uint64_t old_len, uint64_t new_len,
                                      uint64_t flags, uint64_t new_va);
        uint64_t fpage = UINT64_C(0x20000);
        uint64_t spage = UINT64_C(0x2C000);
        uint64_t rpage = UINT64_C(0x24000);
        uint64_t dpage = UINT64_C(0x28000);
        uint8_t rbuf[4];

        CHECK(mips_mem_map(&ctx, fpage, UINT64_C(0x1000),
                           (uint32_t)(1u | 2u), "fpage") == 0);
        mips_vm_file_map_hook(&ctx, fd, fpage, UINT64_C(0x1000), 0u,
                              (uint32_t)(1u | 2u), 0);
        CHECK(guest_st8(&ctx, fpage, 0x77u) == 0);
        CHECK(ftruncate(fd, 0) == 0);
        mips_vm_file_post_truncate_fd(&ctx, fd, 0u);
        CHECK(guest_ld8(&ctx, fpage, &v) == MIPS_FAULT);
        CHECK(lseek(fd, 0, SEEK_SET) == 0);
        CHECK(write(fd, probe, sizeof probe) == (ssize_t)sizeof probe);
        mips_vm_file_post_write(&ctx, fd, 0u, sizeof probe);
        CHECK(guest_ld8(&ctx, fpage, &v) == 0 && v == 0xABu);

        /* Interior unmap split: unmapping middle page of 3-page file map
         * keeps outer pages tracked and leaves middle page untouched. */
        CHECK(ftruncate(fd, 12288) == 0);
        CHECK(mips_mem_map(&ctx, UINT64_C(0x30000), UINT64_C(0x3000),
                           (uint32_t)(1u | 2u), "tri") == 0);
        mips_vm_file_map_hook(&ctx, fd, UINT64_C(0x30000), UINT64_C(0x3000),
                              0u, (uint32_t)(1u | 2u), 0);
        mips_vm_file_unmap_hook(UINT64_C(0x31000), UINT64_C(0x1000));
        (void)memset(mips64_guest_ptr(&ctx, UINT64_C(0x31000)), 0xEE, 16u);
        mips_vm_file_post_write(&ctx, fd, 0u, 12288u);
        CHECK(guest_ld8(&ctx, UINT64_C(0x31000), &v) == 0 && v == 0xEEu);
        CHECK(guest_ld8(&ctx, UINT64_C(0x30000), &v) == 0 && v == 0xABu);

        CHECK(ftruncate(fd, 8192) == 0);
        CHECK(mips_mem_map(&ctx, spage, UINT64_C(0x1000),
                           (uint32_t)(1u | 2u), "spage") == 0);
        mips_vm_file_map_hook(&ctx, fd, spage, UINT64_C(0x1000),
                              UINT64_C(0x1000), (uint32_t)(1u | 2u), 1);
        CHECK(guest_st32(&ctx, spage, UINT64_C(0x11223344)) == 0);
        CHECK(pread(fd, rbuf, 4u, (off_t)0x1000) == 4 &&
              rbuf[0] == 0x44u && rbuf[1] == 0x33u &&
              rbuf[2] == 0x22u && rbuf[3] == 0x11u);

        CHECK(mips_mem_map(&ctx, rpage, UINT64_C(0x1000),
                           (uint32_t)(1u | 2u), "rpage") == 0);
        CHECK(guest_st32(&ctx, rpage, UINT64_C(0xCAFEBABE)) == 0);
        CHECK(mips_mem_protect(&ctx, rpage, UINT64_C(0x1000), 1u) == 0);
        CHECK(mips_mem_remap(&ctx, rpage, UINT64_C(0x1000),
                             UINT64_C(0x1000), 3u, dpage) ==
              (int64_t)dpage);
        CHECK(guest_ld32(&ctx, dpage, &v) == 0 &&
              v == UINT64_C(0xCAFEBABE));
        CHECK(guest_st32(&ctx, dpage, 0u) == MIPS_FAULT);
    }
    (void)close(fd);
    (void)unlink(tmpl);

done:
    (void)printf("GATE: %d passed, %d failed\n", passes, fails);
    return fails == 0 ? 0 : 1;
}
