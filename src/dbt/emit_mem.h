/*
 * src/dbt/emit_mem.h — Lane U12: serialized DBT memory miss-site table.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each emitted memory word that can miss owns one 24-byte relative
 * `dbt_mem_site_t` record (offsets are byte offsets from the block RX
 * base, so rows are position-independent and serialize directly into
 * AOT block payloads). The table is bump-allocated per block and
 * drained by the dispatcher into the block-cache entry
 * (`ei_mem_take_sites`), which the miss path, the host-fault signal
 * rewind, and the AOT writer all consult.
 *
 * The miss stub itself is exactly two A64 words (`movz w4, #site`
 * then `b .L_block_tlb_miss` to the single shared per-block miss
 * epilogue, which exits with MIPS64_EXIT_TRAP and the site index in
 * `exit_info`). Only w4 is written by the stub, so `x18` never
 * appears.
 */

#ifndef MIPS64RT_DBT_EMIT_MEM_H
#define MIPS64RT_DBT_EMIT_MEM_H

#include <stddef.h>
#include <stdint.h>

#include "dbt/emit_int.h"

/* NPC select mode for resuming after a delay-slot fault: sequential
 * fallthrough, a static branch-target delta, or the dynamic target
 * (JR/JALR) recovered from the branch register at fault time. */
typedef enum {
    RT_NPC_SEQUENTIAL = 0, /* guest_npc = slot_pc + 4                */
    RT_NPC_STATIC_TARGET = 1, /* guest_npc = branch_pc + npc_delta    */
    RT_NPC_DYNAMIC_CTX = 2 /* guest_npc = branch rs value at fault */
} rt_npc_mode_t;

/* Site flags. */
#define DBT_MEM_F_STORE 0x01u        /* store (else load) */
#define DBT_MEM_F_SIGNED 0x02u       /* sign-extending load */
#define DBT_MEM_F_BE 0x04u           /* big-endian byte swap on the path */
#define DBT_MEM_F_IN_DELAY_SLOT 0x08u /* word is a branch delay slot */
#define DBT_MEM_F_SPAN 0x10u         /* multi-byte merge span (LWL et al) */
#define DBT_MEM_F_ATOMIC 0x20u       /* LL/SC reservation word */

/* One miss site: exactly 24 bytes, all relative. */
typedef struct dbt_mem_site {
    uint16_t seq_start_offset;  /* .L_tlb_seq_start_k (ubfx) for rewind */
    uint16_t host_insn_offset;  /* .L_tlb_mem_insn_k (ldr/str) */
    uint16_t cont_insn_offset;  /* .L_tlb_cont_k (first word past mem) */
    uint16_t guest_pc_delta;    /* faulting word pc minus block pc */
    int32_t npc_delta;          /* static target minus branch pc */
    uint32_t insn_word;         /* raw guest instruction word */
    int16_t sp_rollback_delta;  /* pre-store base adjustment to undo */
    uint8_t npc_mode;           /* rt_npc_mode_t */
    uint8_t width;              /* 1, 2, 4, or 8 */
    uint8_t flags;              /* DBT_MEM_F_* */
    uint8_t val_or_dst_reg;     /* architectural store-val / load-dst reg */
    uint8_t addr_base_reg;      /* architectural base register (rs) */
    uint8_t reserved;           /* zero */
} dbt_mem_site_t;

_Static_assert(sizeof(dbt_mem_site_t) == 24u,
               "dbt_mem_site_t must serialize as 24 bytes");
_Static_assert(offsetof(dbt_mem_site_t, seq_start_offset) == 0u,
               "seq_start offset");
_Static_assert(offsetof(dbt_mem_site_t, host_insn_offset) == 2u,
               "host_insn offset");
_Static_assert(offsetof(dbt_mem_site_t, cont_insn_offset) == 4u,
               "cont offset");
_Static_assert(offsetof(dbt_mem_site_t, guest_pc_delta) == 6u,
               "guest_pc_delta offset");
_Static_assert(offsetof(dbt_mem_site_t, npc_delta) == 8u,
               "npc_delta offset");
_Static_assert(offsetof(dbt_mem_site_t, insn_word) == 12u,
               "insn_word offset");
_Static_assert(offsetof(dbt_mem_site_t, sp_rollback_delta) == 16u,
               "sp_rollback offset");
_Static_assert(offsetof(dbt_mem_site_t, npc_mode) == 18u,
               "npc_mode offset");
_Static_assert(offsetof(dbt_mem_site_t, width) == 19u, "width offset");
_Static_assert(offsetof(dbt_mem_site_t, flags) == 20u, "flags offset");
_Static_assert(offsetof(dbt_mem_site_t, val_or_dst_reg) == 21u,
               "val_or_dst offset");
_Static_assert(offsetof(dbt_mem_site_t, addr_base_reg) == 22u,
               "addr_base offset");
_Static_assert(offsetof(dbt_mem_site_t, reserved) == 23u,
               "reserved offset");

/* Per-block bump table (64 insns max per block, so 256 is ample). */
#define DBT_MEM_SITES_MAX 256u

typedef struct {
    dbt_mem_site_t sites[DBT_MEM_SITES_MAX];
    size_t count;
} dbt_mem_sites_t;

void dbt_mem_sites_init(dbt_mem_sites_t *t);

/* Record one site by copy; returns the site index, or -1 when `t` or
 * `s` is NULL or the table is full (the emitter then falls back to
 * the plain fault epilogue for that word). */
int dbt_mem_site_bump(dbt_mem_sites_t *t, const dbt_mem_site_t *s);

/* Serialize the table as flat little-endian 24-byte records. Returns
 * `count * 24` on success, 0 when `t` is NULL, when `out` is NULL with
 * a non-empty table, or when `cap` is too small (all-or-nothing). */
size_t dbt_mem_sites_serialize(const dbt_mem_sites_t *t, uint8_t *out,
                               size_t cap);

/* Inverse of serialize: appends whole rows (all-or-nothing, 0 rows
 * consume 0 bytes). Returns the rows appended, or 0 when `t`/`in`
 * is NULL, `len` is not a multiple of 24, or the table would
 * overflow. */
size_t dbt_mem_sites_deserialize(dbt_mem_sites_t *t, const uint8_t *in,
                                 size_t len);

/* Branch context for the next delay-slot word (called by ei_branch
 * in emit_int.c around the slot emission; cleared after). Gives the
 * slot site its static/dynamic NPC resolution without replay. */
void ei_mem_branch_note(uint64_t branch_pc, unsigned npc_mode,
                        int32_t npc_delta);
void ei_mem_branch_clear(void);

/* Emit the 2-insn miss stub for `site` (`site` must fit 16 bits):
 * `movz w4, #site` then `b` with a zero (unpatched) offset; the block
 * end patches the branch to the shared miss epilogue. Returns the
 * word index of the stub, or `(size_t)-1` on error. */
size_t ei_mem_miss_stub(a64_emit_t *e, unsigned site);

#endif /* MIPS64RT_DBT_EMIT_MEM_H */
