/*
 * src/dbt/emit_int.h — Lane-L2c-private shared declarations (Phase 2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal to the integer emitter split (emit_int.c, emit_enc.c,
 * emit_alu.c, emit_mem.c). Not a frozen header: no other lane includes
 * it. The only cross-lane surface remains a64_emit_t + a64e_u32 plus
 * the card-text register map below (x19 = ctx, x20 = guest window
 * base, x21..x24 scratch, x18 never touched).
 */

#ifndef MIPS64RT_DBT_EMIT_INT_H
#define MIPS64RT_DBT_EMIT_INT_H

#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

#ifdef __has_include
#if __has_include("dbt/a64_emit.h")
#include "dbt/a64_emit.h"
#define MIPS64RT_HAVE_A64_EMIT_H 1
#endif
#if __has_include("dbt/dbt.h")
#include "dbt/dbt.h"
#define MIPS64RT_HAVE_DBT_H 1
#endif
#endif

#ifndef MIPS64RT_HAVE_A64_EMIT_H
/* Frozen cross-lane shape (must match src/dbt/a64_emit.h). Owned by L2b.
 * The trailing GPR cache pins guest `r` in host `x(9 + (r & 7))`; the
 * Wave P13 FPR cache pins guest `fpr` in callee-saved `d(8 + (f & 7))`. */
typedef struct {
    uint32_t *buf;
    size_t cap;
    size_t len;
    int err;
    uint8_t gpr_cache_valid;
    uint8_t gpr_cache_reg[8];
    uint8_t fpr_valid;
    uint8_t fpr_is_d;
    uint8_t fpr_slot_reg[8];
} a64_emit_t;

/* Bounds-checked append; sets e->err on overflow. Owned by L2b. */
void a64e_u32(a64_emit_t *e, uint32_t w);
#endif

/* Scratch register map (card text; x18 never appears here). */
#define EI_CTX 19u
#define EI_BASE 20u
#define EI_A 21u
#define EI_B 22u
#define EI_C 23u
#define EI_T 24u
/* Indirect-branch target spill: the trampoline preserves x25 across
 * the block and no word emitter uses it, so JR/JALR park the target
 * here while the delay slot runs (delay emission owns x21..x24). */
#define EI_S 25u
#define EI_XZR 31u
/* Rev4 probe scratch: x4 carries the addend out of the ldp and is
 * dead after the masked compare (entry reuse); x0 is never encoded
 * anywhere in the memory emitters; x18 is rejected by the encoders. */
#define EI_H 4u

/* AArch64 condition codes. */
#define EI_EQ 0u
#define EI_NE 1u
#define EI_HS 2u
#define EI_LO 3u
#define EI_MI 4u
#define EI_PL 5u
#define EI_VS 6u
#define EI_GE 10u
#define EI_LT 11u
#define EI_GT 12u
#define EI_LE 13u

/* Guest field offsets for unsigned-offset LDR/STR. */
#define EI_OFF_GPR(r) ((uint32_t)(r) * 8u)
#define EI_OFF_TASK ((uint32_t)offsetof(mips64_ctx_t, task_size))
/* Intra-word scratch slot (padding, never semantically read). */
#define EI_OFF_SCRATCH ((uint32_t)offsetof(mips64_ctx_t, pad150))

_Static_assert(MIPS64_CTX_PC_OFFSET == 0x100u, "pc offset");
_Static_assert(MIPS64_CTX_HI_OFFSET == 0x110u, "hi offset");
_Static_assert(MIPS64_CTX_ULR_OFFSET == 0x120u, "ulr offset");
_Static_assert(MIPS64_CTX_EXIT_REASON_OFFSET == 0x148u, "exit offset");
_Static_assert((EI_OFF_TASK & 7u) == 0u, "task_size aligned");
_Static_assert(EI_OFF_TASK < 32768u, "task_size reachable");
_Static_assert((EI_OFF_SCRATCH & 7u) == 0u, "scratch aligned");
_Static_assert(EI_OFF_SCRATCH < 32768u, "scratch reachable");

/* ---- emit_enc.c: raw word encoders (all words assembler-verified) ---- */
void ei_movz(a64_emit_t *e, unsigned rd, uint32_t imm, unsigned hw);
void ei_movk(a64_emit_t *e, unsigned rd, uint32_t imm, unsigned hw);
void ei_mov64(a64_emit_t *e, unsigned rd, uint64_t v);
void ei_mov32(a64_emit_t *e, unsigned rd, uint32_t v);
void ei_mov(a64_emit_t *e, unsigned rd, unsigned rm);
void ei_add(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_sub(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_adds(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_subs(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_and(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_orr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_eor(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_bic_w(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm);
void ei_tst(a64_emit_t *e, unsigned rn, unsigned rm);
void ei_mvn(a64_emit_t *e, unsigned rd, unsigned rm);
void ei_lslv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_lsrv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_asrv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_rorv(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_mul(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm);
void ei_mulwide(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                unsigned rm);
void ei_maddl(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
              unsigned rm, unsigned ra);
void ei_div(a64_emit_t *e, uint32_t base, int is_w, unsigned rd, unsigned rn,
            unsigned rm);
void ei_msub(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm,
             unsigned ra);
void ei_clz(a64_emit_t *e, int is_w, unsigned rd, unsigned rn);
void ei_add_lsl(a64_emit_t *e, unsigned rd, unsigned rn, unsigned rm,
                unsigned amount);
void ei_ldp(a64_emit_t *e, unsigned rt1, unsigned rt2, unsigned rn,
            int32_t off);
void ei_bic_imm(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t mask);
/* Register-offset access kinds for ei_mem_rx. */
enum {
    EI_RX_U8 = 0,
    EI_RX_U16 = 1,
    EI_RX_U32 = 2,
    EI_RX_U64 = 3,
    EI_RX_S8 = 4,
    EI_RX_S16 = 5,
    EI_RX_S32 = 6
};
void ei_mem_rx(a64_emit_t *e, unsigned kind, int is_load, unsigned rt,
               unsigned rn, unsigned rm);
void ei_rev(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn);
void ei_sxt(a64_emit_t *e, unsigned imms, unsigned rd, unsigned rn);
void ei_bfm(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
            unsigned immr, unsigned imms);
void ei_lsl(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned sa);
void ei_lsr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned sa);
void ei_asr(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned sa);
void ei_cmp(a64_emit_t *e, int is_w, unsigned rn, unsigned rm);
void ei_cset(a64_emit_t *e, unsigned rd, unsigned cc);
void ei_csel(a64_emit_t *e, int is_w, unsigned rd, unsigned rn, unsigned rm,
             unsigned cc);
size_t ei_fwd(a64_emit_t *e, uint32_t w);
size_t ei_cbz(a64_emit_t *e, int is_w, int is_nz, unsigned rt);
size_t ei_tbz(a64_emit_t *e, int is_nz, unsigned rt, unsigned bit);
size_t ei_bcc(a64_emit_t *e, unsigned cc);
void ei_patch_at(a64_emit_t *e, size_t slot, size_t tgt, int bit14);
void ei_patch(a64_emit_t *e, size_t slot, int bit14);
void ei_cbnz_back(a64_emit_t *e, int is_w, unsigned rt, size_t top);
void ei_ldr(a64_emit_t *e, int is_w, unsigned rt, unsigned rn, uint32_t off);
void ei_str(a64_emit_t *e, int is_w, unsigned rt, unsigned rn, uint32_t off);
void ei_ldrb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_strb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_ldrh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_strh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_ldrsb(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_ldrsh(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_ldrsw(a64_emit_t *e, unsigned rt, unsigned rn, uint32_t off);
void ei_ldxr(a64_emit_t *e, int is_w, unsigned rt, unsigned rn);
void ei_stxr(a64_emit_t *e, int is_w, unsigned ws, unsigned data,
             unsigned addr);
void ei_ret(a64_emit_t *e);

/* ---- emit_int.c: guest access, exits, dispatch, driver ---- */
void ei_gld(a64_emit_t *e, unsigned tmp, unsigned r);
void ei_gst(a64_emit_t *e, unsigned tmp, unsigned r);
void ei_set_pc(a64_emit_t *e, uint64_t pc);
void ei_exit_tail(a64_emit_t *e, uint64_t next_pc, uint32_t reason);
void ei_exit_at(a64_emit_t *e, uint64_t pc, uint32_t reason);
void ei_exit_fault_pc(a64_emit_t *e, uint64_t pc);
void ei_exit_fault_reg(a64_emit_t *e, uint64_t pc, unsigned areg);
void ei_exit_syscall(a64_emit_t *e, uint64_t pc);
void ei_exit_undef(a64_emit_t *e, uint64_t pc);
void ei_bfault(a64_emit_t *e, uint64_t pc, size_t slot);
void ei_sub_imm(a64_emit_t *e, unsigned rd, unsigned rn, uint32_t imm);
size_t ei_b(a64_emit_t *e);
void ei_patch26(a64_emit_t *e, size_t slot, size_t tgt);

/* ---- emit_alu.c: register-pure integer words ---- */
int ei_special(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);
int ei_special2(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);
int ei_special3(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);
int ei_imm(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);
int ei_regimm_trap(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);
int ei_cop(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot);

/* ---- emit_mem.c: loads, stores, unaligned words, LL/SC ---- */
/* U0 7-instruction soft-TLB probe (entry EI_A = guest VA, x20 = TLB
 * base; hit falls through with x4 = entry pointer, miss slot
 * returned for the shared fault epilogue). Preserves x0, never x18. */
size_t ei_tlb_probe(a64_emit_t *e, uint32_t mask, int is_store);
int ei_mem_aligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
                   int slot);
int ei_unaligned(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int is_load,
                 int is_d, int be, int mode, int dir, unsigned cval,
                 int slot);
int ei_atomic(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
              int slot);
/* Wave P probe sharing with src/dbt/emit_fpmem.c: address materialize
 * (A = rs + simm), site open/close around one memory word, and the
 * mark that rewinds signal preemption past register-only setup. */
void ei_mem_addr(a64_emit_t *e, const mips_dec_t *d);
size_t ei_probe_open(a64_emit_t *e, uint64_t pc, const mips_dec_t *d,
                     unsigned width, unsigned flags, unsigned val_reg,
                     int is_store, int slot);
void ei_probe_mark_insn(a64_emit_t *e);
void ei_probe_close(a64_emit_t *e);
/* Wave P FPR loads/stores (src/dbt/emit_fpmem.c): LWC1/SWC1/LDC1/SDC1
 * through the same probe + miss-site path as integer memory. */
int ei_fp_mem(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
              int slot);
int ei_fp_mem_idx(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int be,
                  int slot);
/* Wave P13 8-slot write-through scalar FPR cache in d8..d15
 * (src/dbt/emit_fpmem.c): lane spill/fill routed through the cache,
 * integer-side read/write/invalidate for lane-bit producers. */
void ef_fill(a64_emit_t *e, int is_d, unsigned fp, unsigned fs);
void ef_spill(a64_emit_t *e, int is_d, unsigned fp, unsigned fd);
void ef_fpr_invalidate(a64_emit_t *e, unsigned fs);
int ef_cache_read_d(a64_emit_t *e, unsigned fs, unsigned xd);
int ef_cache_read_s(a64_emit_t *e, unsigned fs, unsigned wd);
void ef_cache_write_d(a64_emit_t *e, unsigned fs, unsigned xn);
/* Lane U12 block-site framing: every memory word records one relative
 * site (see dbt/emit_mem.h) between begin and end; end emits the
 * per-site 2-insn stubs plus the single shared miss epilogue (which
 * exits with MIPS64_EXIT_TRAP and the site index in exit_info) and
 * patches every recorded miss slot. The take accessor drains the
 * table for the block cache (NULL/0 when the block was declined). */
void ei_mem_block_begin(uint64_t block_pc);
void ei_mem_block_end(a64_emit_t *e);
/* Forward-declared: the full record lives in dbt/emit_mem.h (which
 * includes this header for a64_emit_t, so including it back here
 * would cycle). */
struct dbt_mem_site;
void ei_mem_take_sites(const struct dbt_mem_site **sites, size_t *count);

#endif /* MIPS64RT_DBT_EMIT_INT_H */
