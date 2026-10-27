/*
 * src/dbt/mem_recover.c — Lane U12 DBT memory-miss recovery.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns the fill-and-retry core (prefill, fill_retry, fault-EA
 * decode) plus the site-based miss path shared by the TRAP stubs
 * and the host-guard FAULT captures:
 *
 *  - delay-slot faults resume at the slot with the saved branch
 *    target applied afterwards (no branch replay);
 *  - misaligned integer accesses route through FIXADE emulation
 *    when enabled (interp_step over the faulting word, sharing the
 *    interp's alignment handling) and deliver SIGBUS when disabled;
 *  - full-span validation runs before any retry, so a cross-page
 *    span that reaches an unmapped page faults genuinely instead of
 *    refilling forever;
 *  - host program counters rewind to sequence starts (signal
 *    preemption) and resolve to guest pcs (host-guard fault
 *    reporting) through the retained per-block site tables.
 */

#include <string.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/emit_mem.h"
#include "interp/decode.h"
#include "os/backend.h"
#include "os/signal_core.h"
#include "vm/vm_pages.h"

__attribute__((weak)) void mips_vm_file_reconcile(mips64_ctx_t *ctx)
{
    (void)ctx;
}

/* Retry/step contract: 0 means the word ran again (retry
 * scheduled: the caller clears the exit and continues), 1 means a
 * fault or exit was delivered with its trace lines already printed
 * (the caller returns), 2 means a fault was delivered but the
 * faulting word line is still owed (the caller prints it from
 * ctx->pc, mirroring the dispatcher's explicit fault-line print). */

/* Decode one memory word into its access shape: effective address,
 * covered span [base, base+len), required prot, and whether the word
 * merges a cross-page span (LWL family, LL/SC excluded: exclusives
 * are single-address). Returns 0 on success, MIPS_FAULT when the word
 * is not a memory access the miss path handles. */
static int dbt_mem_span(mips64_ctx_t *ctx, const mips_dec_t *d,
                        uint64_t *ea, uint64_t *base, uint64_t *len,
                        uint32_t *need)
{
    int is_load;
    unsigned size = 0u;

    if (ctx == NULL || d == NULL || ea == NULL || base == NULL ||
        len == NULL || need == NULL) {
        return MIPS_FAULT;
    }
    switch (d->op) {
    case 0x20u: /* LB */
    case 0x24u: /* LBU */
    case 0x28u: /* SB */
        size = 1u;
        break;
    case 0x21u: /* LH */
    case 0x25u: /* LHU */
    case 0x29u: /* SH */
        size = 2u;
        break;
    case 0x22u: /* LWL */
    case 0x26u: /* LWR */
    case 0x2Au: /* SWL */
    case 0x2Eu: /* SWR */
        size = 4u;
        break;
    case 0x23u: /* LW */
    case 0x27u: /* LWU */
    case 0x2Bu: /* SW */
    case 0x30u: /* LL */
    case 0x38u: /* SC */
        size = 4u;
        break;
    case 0x1Au: /* LDL */
    case 0x1Bu: /* LDR */
    case 0x2Cu: /* SDL */
    case 0x2Du: /* SDR */
        size = 8u;
        break;
    case 0x37u: /* LD */
    case 0x3Fu: /* SD */
    case 0x34u: /* LLD */
    case 0x3Cu: /* SCD */
        size = 8u;
        break;
    default:
        return MIPS_FAULT;
    }
    is_load =
        (d->op == 0x28u || d->op == 0x29u || d->op == 0x2Bu ||
         d->op == 0x2Au || d->op == 0x2Eu || d->op == 0x2Cu ||
         d->op == 0x2Du || d->op == 0x38u || d->op == 0x3Cu ||
         d->op == 0x3Fu) ? 0 : 1;
    *ea = ctx->gpr[d->rs] + (uint64_t)(int64_t)d->simm;
    if (d->op == 0x22u || d->op == 0x26u || d->op == 0x2Au ||
        d->op == 0x2Eu || d->op == 0x1Au || d->op == 0x1Bu ||
        d->op == 0x2Cu || d->op == 0x2Du) {
        *base = *ea & ~(uint64_t)(size - 1u);
    } else {
        *base = *ea;
    }
    *len = size;
    *need = is_load != 0 ? (uint32_t)MIPS_PROT_READ :
                           (uint32_t)MIPS_PROT_WRITE;
    return 0;
}

/* Integer misaligned loads/stores (the FIXADE class: plain LB..SD,
 * never the merge-span family or LL/SC, which trap unconditionally).
 * Sets *width when misaligned. */
static int dbt_mem_is_fixade_word(const mips_dec_t *d, uint64_t ea,
                                  unsigned *width)
{
    unsigned w = 0u;

    switch (d->op) {
    case 0x21u: /* LH */
    case 0x25u: /* LHU */
    case 0x29u: /* SH */
        w = 2u;
        break;
    case 0x23u: /* LW */
    case 0x27u: /* LWU */
    case 0x2Bu: /* SW */
        w = 4u;
        break;
    case 0x37u: /* LD */
    case 0x3Fu: /* SD */
        w = 8u;
        break;
    default:
        return 0;
    }
    if (width != NULL) {
        *width = w;
    }
    return (ea & (uint64_t)(w - 1u)) != 0u;
}

/* Resolve the post-slot target for a delay-slot fault without
 * replaying the branch: static branches re-evaluate their (intact)
 * condition, unconditional jumps use the recorded delta, and
 * JR/JALR read the branch register (fault-before-commit keeps it
 * intact). Returns 0 with *target set, MIPS_FAULT when the branch
 * word cannot be fetched or decoded. */
static int dbt_resolve_delay_target(mips64_ctx_t *ctx, uint64_t branch_pc,
                                    const dbt_mem_site_t *site,
                                    uint64_t *target)
{
    uint32_t bw;
    mips_dec_t b;
    uint64_t rs_v;
    int taken;

    if (ctx == NULL || site == NULL || target == NULL) {
        return MIPS_FAULT;
    }
    if (mips_fetch(ctx, branch_pc, &bw) != 0) {
        return MIPS_FAULT;
    }
    mips_decode(bw, &b);
    if (!mips_has_delay_slot(&b)) {
        /* The "branch" is not one: fall through past the slot. */
        *target = branch_pc + 8u;
        return 0;
    }
    if (site->npc_mode == (uint8_t)RT_NPC_DYNAMIC_CTX ||
        b.op == 0x00u) {
        /* JR/JALR (SPECIAL 0x08/0x09): the register holds it. */
        if (b.op != 0x00u) {
            *target = branch_pc + 8u;
            return 0;
        }
        *target = ctx->gpr[b.rs];
        return 0;
    }
    switch (b.op) {
    case 0x02u: /* J */
    case 0x03u: /* JAL */
        *target = branch_pc + (uint64_t)site->npc_delta;
        return 0;
    case 0x04u: /* BEQ */
    case 0x14u: /* BEQL */
        taken = ctx->gpr[b.rs] == ctx->gpr[b.rt];
        break;
    case 0x05u: /* BNE */
    case 0x15u: /* BNEL */
        taken = ctx->gpr[b.rs] != ctx->gpr[b.rt];
        break;
    case 0x06u: /* BLEZ */
    case 0x16u: /* BLEZL */
        taken = (int64_t)ctx->gpr[b.rs] <= 0;
        break;
    case 0x07u: /* BGTZ */
    case 0x17u: /* BGTZL */
        taken = (int64_t)ctx->gpr[b.rs] > 0;
        break;
    case 0x11u: /* COP1 BC1F/BC1T/BC1FL/BC1TL */
        if (b.rs == 0x08u) {
            unsigned cc = ((unsigned)b.rt >> 2u) & 7u;
            unsigned tf = (unsigned)b.rt & 1u;
            uint32_t mask = (cc == 0u) ? 0x00800000u : (1u << (24u + cc));

            taken = (((ctx->fcsr & mask) != 0u) == (tf != 0u));
        } else {
            taken = 0;
        }
        break;
    case 0x01u: /* REGIMM */
        rs_v = ctx->gpr[b.rs];
        switch (b.rt) {
        case 0x00u: /* BLTZ */
        case 0x02u: /* BLTZL */
        case 0x10u: /* BLTZAL */
        case 0x12u: /* BLTZALL */
            taken = (int64_t)rs_v < 0;
            break;
        case 0x01u: /* BGEZ */
        case 0x03u: /* BGEZL */
        case 0x11u: /* BGEZAL */
        case 0x13u: /* BGEZALL */
            taken = (int64_t)rs_v >= 0;
            break;
        default:
            taken = 0;
            break;
        }
        break;
    default:
        taken = 0;
        break;
    }
    *target = taken != 0 ? branch_pc + (uint64_t)site->npc_delta :
                           branch_pc + 8u;
    return 0;
}

/* Fill-and-retry core shared by the demand path and the unit test:
 * decode at pc, validate the full span, fill cold pages, and report
 * 1 when the caller should run the word again (0: genuine fault). */
int dbt_u0_fill_retry(mips64_ctx_t *ctx, uint64_t pc)
{
    mips_dec_t d;
    uint32_t w;
    uint64_t ea;
    uint64_t base;
    uint64_t len;
    uint32_t need;
    uint64_t p0;
    uint64_t p1;
    mips_soft_tlb_entry_t *tlb;

    if (ctx == NULL) {
        return 0;
    }
    if (mips_fetch(ctx, pc, &w) != 0) {
        return 0;
    }
    mips_decode(w, &d);
    if (dbt_mem_span(ctx, &d, &ea, &base, &len, &need) != 0) {
        return 0;
    }
    if (mips_mem_ok(ctx, base, len, need) == 0) {
        return 0;
    }
    tlb = (mips_soft_tlb_entry_t *)mips_soft_tlb_base(ctx);
    if (tlb == NULL) {
        return 0;
    }
    p0 = base >> 12;
    p1 = (base + len - 1u) >> 12;
    /* The liveness guard consults the direction's tag (read_tag for
     * loads, write_tag for stores), so a store whose page the gate
     * now closes refills instead of spinning on a stale hit. */
    {
        uint64_t t0 = tlb[p0 & MIPS64_SOFT_TLB_INDEX_MASK].read_tag;
        uint64_t t1 = tlb[p1 & MIPS64_SOFT_TLB_INDEX_MASK].read_tag;
        int is_store = need == (uint32_t)MIPS_PROT_WRITE;

        if (is_store) {
            t0 = tlb[p0 & MIPS64_SOFT_TLB_INDEX_MASK].write_tag;
            t1 = tlb[p1 & MIPS64_SOFT_TLB_INDEX_MASK].write_tag;
        }
        if (t0 == (p0 << 12) && (p1 == p0 || t1 == (p1 << 12)))
            return 0;
    }
    mips_soft_tlb_fill(ctx, base);
    if (p1 != p0) {
        mips_soft_tlb_fill(ctx, base + len - 1u);
    }
    return 1;
}

/* Prefill one fill per 4 KiB page in [start, end): empty slots only
 * (the UINT64_MAX sentinel or an already-correct read_tag), mapped
 * pages only (a fill over PROT_NONE would stamp a readable tag over
 * the hole). */
void dbt_u0_prefill(mips64_ctx_t *ctx, uint64_t start, uint64_t end)
{
    uint64_t va;

    if (ctx == NULL || end <= start) {
        return;
    }
    {
        mips_soft_tlb_entry_t *tlb =
            (mips_soft_tlb_entry_t *)mips_soft_tlb_base(ctx);

        if (tlb == NULL) {
            return;
        }
        va = start & ~(uint64_t)4095U;
        while (va < end) {
            uint64_t vpn = va >> 12;
            mips_soft_tlb_entry_t *e =
                &tlb[vpn & MIPS64_SOFT_TLB_INDEX_MASK];

            if ((e->read_tag == UINT64_MAX ||
                 e->read_tag == (vpn << 12)) &&
                mips_mem_ok(ctx, va, 4096U,
                            (uint32_t)MIPS_PROT_READ)) {
                mips_soft_tlb_fill(ctx, va);
            }
            if (va + 4096U < va) {
                break;
            }
            va += 4096U;
        }
    }
}

/* Fault-EA helper for the dispatcher: decode at pc and return the
 * effective address (0 when the word is not a memory access). */
uint64_t dbt_fault_ea(mips64_ctx_t *ctx, uint64_t pc)
{
    mips_dec_t d;
    uint32_t w;
    uint64_t ea;
    uint64_t base;
    uint64_t len;
    uint32_t need;

    if (ctx == NULL) {
        return 0U;
    }
    if (mips_fetch(ctx, pc, &w) != 0) {
        return 0U;
    }
    mips_decode(w, &d);
    if (dbt_mem_span(ctx, &d, &ea, &base, &len, &need) != 0) {
        return 0U;
    }
    (void)base;
    (void)len;
    (void)need;
    return ea;
}

/* The shared miss path. site is the retained record for fault_pc
 * (NULL for host-guard captures whose word predates sites, in which
 * case the word decodes at fault_pc and delay recovery is skipped).
 * block_pc anchors relative deltas. The natively executed prefix
 * [block_pc, run_pc) prints here (the step prints the word itself),
 * so the I-stream matches the interpreter exactly in every case. */
int dbt_mem_recover(mips64_ctx_t *ctx, const dbt_mem_site_t *site,
                    uint64_t block_pc, uint64_t fault_pc)
{
    mips_dec_t d;
    uint64_t ea;
    uint64_t base;
    uint64_t len;
    uint32_t need;
    unsigned width = 0u;
    uint64_t slot_pc;
    uint64_t branch_pc;
    uint64_t target = 0u;
    uint32_t bw = 0u;
    int rc;

    if (ctx == NULL) {
        return 1;
    }
    mips_vm_file_reconcile(ctx);
    if (site != NULL) {
        mips_decode(site->insn_word, &d);
        slot_pc = block_pc + (uint64_t)site->guest_pc_delta;
    } else {
        uint32_t w;

        slot_pc = fault_pc;
        if (mips_fetch(ctx, fault_pc, &w) != 0) {
            ctx->pc = fault_pc;
            mips_fault(ctx, fault_pc);
            return 2;
        }
        mips_decode(w, &d);
    }
    if (dbt_mem_span(ctx, &d, &ea, &base, &len, &need) != 0) {
        ctx->pc = slot_pc;
        dbt_trace_fault_prefix(ctx, block_pc, slot_pc);
        mips_fault(ctx, slot_pc);
        return 2;
    }
    /* FIXADE class first: when disabled, a misaligned integer access
     * delivers SIGBUS before any fill; when enabled, it falls through
     * to span validation, write-gate promotion, and delay-slot target
     * restoration before executing via interp_step. */
    if (dbt_mem_is_fixade_word(&d, ea, &width) != 0 &&
        mips_fixade_enabled(ctx) == 0) {
        ctx->pc = slot_pc;
        dbt_trace_fault_prefix(ctx, block_pc, slot_pc);
        mips_bus_fault(ctx, ea);
        return 2;
    }
    /* Full-span validation before any retry: a span reaching an
     * unmapped (or wrong-prot) page faults genuinely instead of
     * refilling forever. */
    if (mips_mem_ok(ctx, base, len, need) == 0) {
        ctx->pc = slot_pc;
        dbt_trace_fault_prefix(ctx, block_pc, slot_pc);
        mips_fault(ctx, base);
        return 2;
    }
    mips_soft_tlb_fill(ctx, base);
    if (((base + len - 1u) >> 12) != (base >> 12)) {
        mips_soft_tlb_fill(ctx, base + len - 1u);
    }
    if (need == (uint32_t)MIPS_PROT_WRITE &&
        d.op != 0x38u && d.op != 0x3Cu) {
        /* Write-gate remedies (plain stores only; the interp
         * validates SC exclusives itself). The fill above may still
         * leave write_tag closed: COW_CLEAN promotes, HAS_CODE
         * retires the translation first (SMC), and a same-page LL
         * reservation clears (any store does). Refill afterwards;
         * if the gate is still closed the page state changed under
         * us and the fault is genuine. */
        uint64_t p0 = base >> 12;
        uint64_t p1 = (base + len - 1u) >> 12;
        unsigned f0 = mips_vm_page_flags(p0);
        unsigned f1 = (p1 == p0) ? 0u : mips_vm_page_flags(p1);
        unsigned both = f0 | f1;
        int fixed = 0;

        if ((both & (unsigned)MIPS_VM_PAGE_COW_CLEAN) != 0u) {
            mips_vm_pages_clear(base, len,
                                (unsigned)MIPS_VM_PAGE_COW_CLEAN);
            fixed = 1;
        }
        if ((both & (unsigned)MIPS_VM_PAGE_HAS_CODE) != 0u) {
            dbt_invalidate_range(base, len);
            fixed = 1;
        }
        if (ctx->llbit != 0u &&
            ((ctx->lladdr >> 12) == p0 || (ctx->lladdr >> 12) == p1)) {
            mips64_ctx_clear_ll(ctx);
            fixed = 1;
        }
        if (fixed != 0) {
            mips_soft_tlb_fill(ctx, base);
            if (p1 != p0) {
                mips_soft_tlb_fill(ctx, base + len - 1u);
            }
        }
    }
    if (site != NULL &&
        (site->flags & (uint8_t)DBT_MEM_F_IN_DELAY_SLOT) != 0u) {
        /* Delay slot: print the prefix plus the branch word (both
         * ran natively), run only the slot via the interp, then
         * apply the saved branch target (no branch replay). */
        branch_pc = slot_pc - 4u;
        if (dbt_resolve_delay_target(ctx, branch_pc, site,
                                     &target) != 0) {
            ctx->pc = slot_pc;
            dbt_trace_fault_prefix(ctx, block_pc, slot_pc);
            mips_fault(ctx, slot_pc);
            return 2;
        }
        ctx->pc = branch_pc;
        ctx->next_pc = slot_pc;
        dbt_trace_fault_prefix(ctx, block_pc, branch_pc);
        if (mips_fetch(ctx, branch_pc, &bw) == 0) {
            mips64_dbt_trace(ctx, branch_pc, bw);
        }
        ctx->pc = slot_pc;
        ctx->next_pc = slot_pc + 4u;
        ctx->in_delay_slot = 1U;
        mips_delay_target_set(ctx, target);
        rc = interp_step(ctx);
        if (rc != 0) {
            return 1;
        }
        {
            uint64_t applied = 0U;

            (void)mips_npc_resume_step(ctx, &applied);
        }
        return 0;
    }
    /* Only the faulting access runs again, against the freshly
     * filled entry. */
    ctx->pc = slot_pc;
    ctx->next_pc = slot_pc + 4u;
    dbt_trace_fault_prefix(ctx, block_pc, slot_pc);
    rc = interp_step(ctx);
    return rc == 0 ? 0 : 1;
}

/* Block visitor state for host-pc resolution. */
typedef struct {
    uint64_t host_pc;
    uint64_t guest_pc;
    uint64_t seq_start;
    int found;
    int want_rewind;
} dbt_pc_lookup_t;

/* Match one block against the lookup: rpc is the RX-relative offset.
 * Rewind matches [seq_start, host_insn) (side-effect-free prefix);
 * guest resolution matches [seq_start, cont) (precise fault pc for
 * any captured offset inside the word). */
static int dbt_pc_visit(const dbt_mem_site_t *sites, size_t count,
                        uint64_t rx_base, size_t rx_len, uint64_t guest_pc,
                        void *arg)
{
    dbt_pc_lookup_t *lk = (dbt_pc_lookup_t *)arg;
    size_t i;

    if (lk == NULL || lk->found != 0 || sites == NULL) {
        return 0;
    }
    if (lk->host_pc < rx_base || lk->host_pc >= rx_base + rx_len) {
        return 0;
    }
    {
        uint64_t rpc = lk->host_pc - rx_base;

        if (rpc > (uint64_t)0xFFFFu) {
            return 0;
        }
        for (i = 0u; i < count; i++) {
            uint64_t seq = (uint64_t)sites[i].seq_start_offset;
            uint64_t insn = (uint64_t)sites[i].host_insn_offset;
            uint64_t cont = (uint64_t)sites[i].cont_insn_offset;

            if (lk->want_rewind != 0) {
                if (rpc >= seq && rpc <= insn) {
                    lk->seq_start = rx_base + seq;
                    lk->found = 1;
                    return 1;
                }
            } else if (rpc >= seq && rpc < cont) {
                lk->guest_pc = guest_pc +
                    (uint64_t)sites[i].guest_pc_delta;
                lk->found = 1;
                return 1;
            }
        }
    }
    return 0;
}

/* Resolve a host pc captured inside RX to the faulting guest pc (for
 * the host-guard fault path). Returns 1 with *guest_pc set, else 0. */
int dbt_host_pc_to_guest(uint64_t host_pc, uint64_t *guest_pc)
{
    dbt_pc_lookup_t lk;

    (void)memset(&lk, 0, sizeof lk);
    lk.host_pc = host_pc;
    lk.want_rewind = 0;
    dbt_visit_blocks(dbt_pc_visit, &lk);
    if (lk.found == 0 || guest_pc == NULL) {
        return 0;
    }
    *guest_pc = lk.guest_pc;
    return 1;
}

/* Rewind a host pc interrupted inside a sequence prefix to the
 * sequence start (for reserved-signal preemption). Returns 1 with
 * *seq_out set, else 0. */
int dbt_rewind_pc(uint64_t host_pc, uint64_t *seq_out)
{
    dbt_pc_lookup_t lk;

    (void)memset(&lk, 0, sizeof lk);
    lk.host_pc = host_pc;
    lk.want_rewind = 1;
    dbt_visit_blocks(dbt_pc_visit, &lk);
    if (lk.found == 0 || seq_out == NULL) {
        return 0;
    }
    *seq_out = lk.seq_start;
    return 1;
}
