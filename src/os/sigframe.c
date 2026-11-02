/*
 * src/os/sigframe.c — Guest rt_sigframe delivery, restoration, and
 * synchronous trap mapping (lane L4a, Phase 4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Defines the frozen cpu.h seams mips_raise_guest, mips_rt_sigreturn,
 * and mips_trap. Frame layouts come from frozen
 * src/os/sigframe_mips64rt.h: N64 808 bytes (24-byte prefix, 128-byte
 * siginfo, 656-byte ucontext), N32 792 bytes (same prefix/siginfo,
 * 640-byte ucontext); the 600-byte sigcontext has no sc_cause field.
 * Semantics mirror ../rvrt/src/linux/signal.c + signal_frame.c with
 * MIPS renumbering (SIGSEGV=11, SIGILL=4, SIGFPE=8, SIGTRAP=5,
 * SIGBUS=10 on MIPS asm/signal.h).
 *
 * Delivery register convention (MIPS o32/n32/n64 shared): $a0 = signo,
 * $a1 = siginfo pointer (frame+24), $a2 = ucontext pointer
 * (frame+152); $ra points at the frozen per-ABI trampoline page, which
 * holds a two-instruction rt_sigreturn stub mapped lazily here. N32
 * guest pointers are truncated to 32 bits (frozen N32 pointer rule);
 * sc_regs stay 64-bit slots on both ABIs.
 *
 * mips_raise_guest returns 0 when the frame was built and pc was
 * redirected, 1 when the signal stays queued (blocked, ignored, or
 * defaulted) or the frame was invalid. mips_trap records every trap
 * into the bounded pend_queue and delivers immediately only when a
 * handler is installed and the signal is unblocked; otherwise the
 * entry stays pending for the interp/DBT loop check (the coordinator
 * wires the fatal-default path at RC4 integration).
 */

#include "core/cpu.h"

#include "os/sigframe_mips64rt.h"
#include "os/syscall_nr.h"
#include "os/signal_core.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

/* Shared helpers owned by src/os/syscalls.c (lane L2a) and guest
 * memory helpers owned by src/os/mem.c (lane L1c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int mips_mem_map(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                        uint32_t prot, const char *tag);
extern int mips_mem_unmap(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
extern int mips_mem_protect(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            uint32_t prot);
extern int guest_st32(mips64_ctx_t *ctx, uint64_t va, uint64_t val);
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
/* Lane-internal table reset owned by src/os/sigact.c (lane L4a). */
extern void mips_l4a_action_reset(mips64_ctx_t *ctx, int signo);

/* MIPS SA_* bits (asm/signal.h), matching src/os/sigact.c. */
#define L4B_SA_ONSTACK   UINT64_C(0x08000000)
#define L4B_SA_NODEFER   UINT64_C(0x40000000)
#define L4B_SA_RESETHAND UINT64_C(0x80000000)

/* sigaltstack report bits (asm/signal.h). */
#define L4B_SS_ONSTACK UINT32_C(1)
#define L4B_SS_DISABLE UINT32_C(2)

/* Synchronous trap signals (MIPS asm/signal.h numbers). */
#define L4B_SIGILL  4
#define L4B_SIGTRAP 5
#define L4B_SIGFPE  8
#define L4B_SIGBUS  10
#define L4B_SIGSEGV 11

#define L4B_UNBLOCKABLE \
    ((UINT64_C(1) << (9 - 1)) | (UINT64_C(1) << (23 - 1)))

/* SI_KERNEL: code for translator-synthesized and bad-frame signals. */
#define L4B_SI_KERNEL 128

/* sigcontext field offsets inside the frame (frozen header). */
#define L4B_SC_REGS   0U
#define L4B_SC_FPREGS 256U
#define L4B_SC_MDHI   512U
#define L4B_SC_MDLO   544U
#define L4B_SC_PC     576U
#define L4B_SC_FCSR   584U
#define L4B_SC_MATH   588U
#define L4B_SC_DSP    592U

static int l4b_signo_valid(int signo)
{
    return signo >= 1 && signo <= MIPS64RT_NSIG;
}

static unsigned l4b_word(int signo)
{
    return (unsigned)(signo - 1) / 64U;
}

static uint64_t l4b_bit(int signo)
{
    return UINT64_C(1) << ((unsigned)(signo - 1) % 64U);
}

static int l4b_is_blocked(const mips64_ctx_t *ctx, int signo)
{
    return (ctx->sig_blocked[l4b_word(signo)] & l4b_bit(signo)) != 0U;
}

static uint64_t l4b_va(const mips64_ctx_t *ctx, uint64_t va)
{
    if (ctx->is_n32 != 0U) {
        return va & UINT64_C(0xffffffff);
    }
    return va;
}

static uint64_t l4b_frame_size(const mips64_ctx_t *ctx)
{
    return ctx->is_n32 != 0U ?
           (uint64_t)sizeof(mips64_n32_rt_sigframe_t) :
           (uint64_t)sizeof(mips64_n64_rt_sigframe_t);
}

/* Remove the oldest entry for signo, reporting its code/addr when
 * present. Returns 1 when an entry was consumed. */
static int l4b_pend_consume(mips64_ctx_t *ctx, int signo, int32_t *codep,
                            int32_t *errp, uint64_t *addrp)
{
    uint32_t i;

    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t slot = (ctx->pend_head + i) % 16U;

        if ((int)ctx->pend_queue[slot].signo == signo) {
            uint32_t j;

            if (codep != NULL) {
                *codep = ctx->pend_queue[slot].code;
            }
            if (errp != NULL) {
                *errp = ctx->pend_queue[slot].errnum;
            }
            if (addrp != NULL) {
                *addrp = ctx->pend_queue[slot].addr;
            }
            for (j = i; j + 1U < ctx->pend_count; j++) {
                uint32_t dst = (ctx->pend_head + j) % 16U;
                uint32_t src = (ctx->pend_head + j + 1U) % 16U;

                ctx->pend_queue[dst] = ctx->pend_queue[src];
            }
            ctx->pend_count--;
            return 1;
        }
    }
    return 0;
}

/* Lazily map the frozen per-ABI trampoline page and publish the
 * two-instruction rt_sigreturn stub (li $v0, nr; syscall) with
 * endian-correct stores. The host side never gains PROT_EXEC (W^X);
 * the stub is written through a temporary writable window. */
static int l4b_ensure_trampoline(mips64_ctx_t *ctx)
{
    int n32 = ctx->is_n32 != 0U;
    uint64_t tramp = (!n32 && ctx->task_size != 0U &&
                      ctx->task_size < MIPS64_N64_TASK_SIZE)
        ? (ctx->task_size - UINT64_C(0x20000))
        : mips64_signal_trampoline_addr(n32);
    uint64_t page = tramp & MIPS64_PAGE_MASK;
    uint64_t nr = (uint64_t)(n32 ? MIPS64_NR32_rt_sigreturn
                                 : MIPS64_NR_rt_sigreturn);
    uint32_t li;
    int rc;

    /* The N64 trampoline page sits inside the initial stack mapping
     * (stack top 0xffffff0000, 8 MiB down): require EXEC, not just
     * READ, or the early return leaves an unmapped stub whose fetch
     * faults on handler return. The unmap splits the stack and punches
     * a one-page guard hole; the map below installs the RX stub. */
    if (mips_mem_ok(ctx, tramp, 8U, (uint32_t)(MIPS_PROT_READ |
                                               MIPS_PROT_EXEC))) {
        return 0;
    }
    (void)mips_mem_unmap(ctx, page, MIPS64_PAGE_SIZE);
    rc = mips_mem_map(ctx, page, MIPS64_PAGE_SIZE,
                      (uint32_t)(MIPS_PROT_READ | MIPS_PROT_EXEC),
                      "sigtramp");
    if (rc != 0) {
        return -ENOMEM;
    }
    rc = mips_mem_protect(ctx, page, MIPS64_PAGE_SIZE,
                          (uint32_t)(MIPS_PROT_READ | MIPS_PROT_WRITE |
                                     MIPS_PROT_EXEC));
    if (rc != 0) {
        return rc;
    }
    /* addiu $v0, $zero, nr (nr < 2^16 on both ABIs). */
    li = (uint32_t)(UINT32_C(0x24020000) | (nr & UINT32_C(0xffff)));
    if (guest_st32(ctx, tramp, (uint64_t)li) != 0 ||
        guest_st32(ctx, tramp + 4U, (uint64_t)MIPS64_SYSCALL_INSN) !=
            0) {
        return -EFAULT;
    }
    rc = mips_mem_protect(ctx, page, MIPS64_PAGE_SIZE,
                          (uint32_t)(MIPS_PROT_READ | MIPS_PROT_EXEC));
    if (rc != 0) {
        return rc;
    }
    return 0;
}

/* Force-deliver SIGSEGV after an invalid frame, mirroring the
 * reference force_bad_frame: the faulted signal goes back to SIG_DFL,
 * SIGSEGV is unblocked and queued with SI_KERNEL. */
static void l4b_force_bad_frame(mips64_ctx_t *ctx, uint64_t frame)
{
    mips_l4a_action_reset(ctx, L4B_SIGSEGV);
    ctx->sig_blocked[l4b_word(L4B_SIGSEGV)] &=
        ~l4b_bit(L4B_SIGSEGV);
    (void)mips64_sigpend_enqueue(ctx, (uint32_t)L4B_SIGSEGV, L4B_SI_KERNEL, 0,
                                 frame);
}

/* Build the rt_sigframe for signo on the guest (or alt) stack and
 * redirect execution to the handler. Returns 0 on delivery, 1 when
 * the signal stays queued. Consumes one matching pend_queue entry
 * for the siginfo code/addr, synthesising SI_USER-style content when
 * none is queued. */
int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr)
{
    mips64_sigaction_t act;
    int32_t code = 0;
    int32_t errnum = 0;
    uint64_t addr = fault_addr;
    int n32;
    int be;
    uint64_t size;
    uint64_t sp;
    uint64_t frame;
    uint8_t *f;
    uint64_t sc_pc;
    uint32_t i;

    if (ctx == NULL || !l4b_signo_valid(signo)) {
        return 1;
    }
    act = ctx->sigactions[signo];
    if (act.handler < 2U) {
        return 1;
    }
    if (l4b_is_blocked(ctx, signo)) {
        return 1;
    }
    n32 = ctx->is_n32 != 0U;
    be = ctx->is_be != 0U;
    size = l4b_frame_size(ctx);
    if (!l4b_pend_consume(ctx, signo, &code, &errnum, &addr)) {
        code = 0;
        errnum = 0;
        addr = fault_addr;
    }
    sp = l4b_va(ctx, ctx->gpr[MIPS64_REG_SP]);
    if ((act.flags & L4B_SA_ONSTACK) != 0U && ctx->sigalt_size != 0U) {
        int on_stack = sp > ctx->sigalt_sp &&
                       sp - ctx->sigalt_sp <= ctx->sigalt_size;

        if (!on_stack) {
            sp = ctx->sigalt_sp + ctx->sigalt_size;
        }
    }
    if (sp < size) {
        l4b_force_bad_frame(ctx, sp);
        return 1;
    }
    frame = (sp - size) & ~UINT64_C(15);
    if (n32 && frame > UINT64_C(0xffffffff)) {
        l4b_force_bad_frame(ctx, frame);
        return 1;
    }
    if (!mips_mem_ok(ctx, frame, size, (uint32_t)MIPS_PROT_WRITE)) {
        if (signo == L4B_SIGSEGV) {
            return 1;
        }
        l4b_force_bad_frame(ctx, frame);
        return 1;
    }
    if (l4b_ensure_trampoline(ctx) != 0) {
        if (signo == L4B_SIGSEGV) {
            return 1;
        }
        l4b_force_bad_frame(ctx, frame);
        return 1;
    }
    f = guest_range(ctx, frame, size, 1);
    if (f == NULL) {
        if (signo == L4B_SIGSEGV) {
            return 1;
        }
        l4b_force_bad_frame(ctx, frame);
        return 1;
    }
    memset(f, 0, (size_t)size);
    /* siginfo: signo@0 code@4 errno@8, then addr at +16 (8 bytes
     * N64) or +12 (4 bytes N32: 4-byte pointers need no pad). */
    putn(f + 24, (uint64_t)(uint32_t)signo, 4, be);
    putn(f + 28, (uint64_t)(uint32_t)code, 4, be);
    putn(f + 32, (uint64_t)(uint32_t)errnum, 4, be);
    if (n32) {
        putn(f + 36, addr & UINT64_C(0xffffffff), 4, be);
    } else {
        putn(f + 40, addr, 8, be);
    }
    /* ucontext flags/link zeroed; altstack report mirrors current. */
    {
        uint64_t uc = frame + 152U;
        uint8_t *u = f + 152U;
        int on_stack = ctx->sigalt_size != 0U &&
                       sp > ctx->sigalt_sp &&
                       sp - ctx->sigalt_sp <= ctx->sigalt_size;
        uint32_t rep = ctx->sigalt_size == 0U ? L4B_SS_DISABLE :
                       (on_stack ? L4B_SS_ONSTACK : 0U);

        (void)uc;
        if (n32) {
            putn(u + 8, ctx->sigalt_sp & UINT64_C(0xffffffff), 4,
                 be);
            putn(u + 12, ctx->sigalt_size & UINT64_C(0xffffffff), 4,
                 be);
            putn(u + 16, rep, 4, be);
            putn(u + 20, 0U, 4, be);
        } else {
            putn(u + 16, ctx->sigalt_sp, 8, be);
            putn(u + 24, ctx->sigalt_size, 8, be);
            putn(u + 32, rep, 4, be);
            putn(u + 36, 0U, 4, be);
        }
    }
    /* Delay-slot faults record the branch pc (interp parks ctx->pc at
     * the slot with in_delay_slot set, SPEC 2.2). */
    sc_pc = ctx->pc;
    if (ctx->in_delay_slot != 0U) {
        sc_pc -= 4U;
    }
    {
        uint8_t *m = f + (n32 ? 176U : 192U);

        for (i = 0U; i < 32U; i++) {
            putn(m + L4B_SC_REGS + 8U * i, ctx->gpr[i], 8, be);
        }
        for (i = 0U; i < 32U; i++) {
            putn(m + L4B_SC_FPREGS + 8U * i, ctx->fpr[i], 8, be);
        }
        putn(m + L4B_SC_MDHI, ctx->hi, 8, be);
        putn(m + L4B_SC_MDLO, ctx->lo, 8, be);
        putn(m + L4B_SC_PC, sc_pc, 8, be);
        putn(m + L4B_SC_FCSR, (uint64_t)ctx->fcsr, 4, be);
        putn(m + L4B_SC_MATH, 1U, 4, be);
        putn(m + L4B_SC_DSP, 0U, 4, be);
    }
    /* Saved mask: the pre-delivery blocked set. */
    {
        uint8_t *s = f + (n32 ? 776U : 792U);

        if (n32) {
            putn(s, ctx->sig_blocked[0] & UINT64_C(0xffffffff), 4,
                 be);
            putn(s + 4,
                 (ctx->sig_blocked[0] >> 32) & UINT64_C(0xffffffff),
                 4, be);
            putn(s + 8, ctx->sig_blocked[1] & UINT64_C(0xffffffff),
                 4, be);
            putn(s + 12,
                 (ctx->sig_blocked[1] >> 32) & UINT64_C(0xffffffff),
                 4, be);
        } else {
            putn(s, ctx->sig_blocked[0], 8, be);
            putn(s + 8, ctx->sig_blocked[1], 8, be);
        }
    }
    /* One-shot actions revert to SIG_DFL on delivery. */
    if ((act.flags & L4B_SA_RESETHAND) != 0U) {
        mips_l4a_action_reset(ctx, signo);
    }
    /* Block the action mask plus the handled signal itself, unless
     * SA_NODEFER; SIGKILL/SIGSTOP stay unblockable. */
    ctx->sig_blocked[0] |= act.mask[0];
    ctx->sig_blocked[1] |= act.mask[1];
    if ((act.flags & L4B_SA_NODEFER) == 0U) {
        ctx->sig_blocked[l4b_word(signo)] |= l4b_bit(signo);
    }
    ctx->sig_blocked[0] &= ~L4B_UNBLOCKABLE;
    ctx->sig_blocked[1] &= ~L4B_UNBLOCKABLE;
    /* Every delivery invalidates the LL/SC reservation. */
    mips64_ctx_clear_ll(ctx);
    ctx->gpr[MIPS64_REG_SP] = frame;
    ctx->gpr[MIPS64_REG_A0] = (uint64_t)(uint32_t)signo;
    ctx->gpr[MIPS64_REG_A1] = l4b_va(ctx, frame + 24U);
    ctx->gpr[MIPS64_REG_A2] = l4b_va(ctx, frame + 152U);
    ctx->gpr[MIPS64_REG_RA] = (!n32 && ctx->task_size != 0U &&
                               ctx->task_size < MIPS64_N64_TASK_SIZE)
        ? (ctx->task_size - UINT64_C(0x20000))
        : mips64_signal_trampoline_addr(n32);
    /* PIC handlers recompute gp from $25 (mips32rt precedent): the
     * kernel enters the handler with $25 = handler address. */
    ctx->gpr[MIPS64_REG_T9] = act.handler;
    ctx->pc = l4b_va(ctx, act.handler);
    ctx->next_pc = ctx->pc + 4U;
    ctx->in_delay_slot = 0U;
    return 0;
}

/* rt_sigreturn: restore registers, FP state, hi/lo, pc, fcsr, and the
 * blocked mask from the frame at the current sp. A bogus (unreadable)
 * frame queues SIGSEGV and reports -ENOSYS. */
int64_t mips_rt_sigreturn(mips64_ctx_t *ctx)
{
    int n32;
    int be;
    uint64_t size;
    uint64_t frame;
    const uint8_t *f;
    const uint8_t *m;
    const uint8_t *s;
    uint32_t i;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    n32 = ctx->is_n32 != 0U;
    be = ctx->is_be != 0U;
    size = l4b_frame_size(ctx);
    frame = l4b_va(ctx, ctx->gpr[MIPS64_REG_SP]);
    if (!mips_mem_ok(ctx, frame, size, (uint32_t)MIPS_PROT_READ)) {
        l4b_force_bad_frame(ctx, frame);
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    f = guest_range(ctx, frame, size, 0);
    if (f == NULL) {
        l4b_force_bad_frame(ctx, frame);
        return l2a_ret(ctx, -(int64_t)ENOSYS);
    }
    m = f + (n32 ? 176U : 192U);
    s = f + (n32 ? 776U : 792U);
    if (n32) {
        ctx->sig_blocked[0] = getn(s, 4, be) |
                              (getn(s + 4, 4, be) << 32);
        ctx->sig_blocked[1] = getn(s + 8, 4, be) |
                              (getn(s + 12, 4, be) << 32);
    } else {
        ctx->sig_blocked[0] = getn(s, 8, be);
        ctx->sig_blocked[1] = getn(s + 8, 8, be);
    }
    ctx->sig_blocked[0] &= ~L4B_UNBLOCKABLE;
    ctx->sig_blocked[1] &= ~L4B_UNBLOCKABLE;
    for (i = 1U; i < 32U; i++) {
        ctx->gpr[i] = getn(m + L4B_SC_REGS + 8U * i, 8, be);
    }
    ctx->gpr[0] = 0U;
    for (i = 0U; i < 32U; i++) {
        ctx->fpr[i] = getn(m + L4B_SC_FPREGS + 8U * i, 8, be);
    }
    ctx->hi = getn(m + L4B_SC_MDHI, 8, be);
    ctx->lo = getn(m + L4B_SC_MDLO, 8, be);
    ctx->pc = getn(m + L4B_SC_PC, 8, be);
    ctx->next_pc = ctx->pc + 4U;
    ctx->in_delay_slot = 0U;
    ctx->fcsr = (uint32_t)getn(m + L4B_SC_FCSR, 4, be);
    /* The frame carries no altstack validity token: apply the saved
     * stack only when it accepts cleanly, like the reference. */
    {
        uint64_t ssp;
        uint64_t ssize;
        uint32_t sflags;
        const uint8_t *u = f + 152U;
        uint64_t cur_sp = ctx->gpr[MIPS64_REG_SP];
        int on_stack = ctx->sigalt_size != 0U &&
                       cur_sp > ctx->sigalt_sp &&
                       cur_sp - ctx->sigalt_sp <= ctx->sigalt_size;

        if (n32) {
            ssp = getn(u + 8, 4, be);
            ssize = getn(u + 12, 4, be);
            sflags = (uint32_t)getn(u + 16, 4, be);
        } else {
            ssp = getn(u + 16, 8, be);
            ssize = getn(u + 24, 8, be);
            sflags = (uint32_t)getn(u + 32, 4, be);
        }
        if (!on_stack) {
            uint32_t mode = sflags & ~(uint32_t)0x80000000;

            if (mode == L4B_SS_DISABLE) {
                ctx->sigalt_sp = 0U;
                ctx->sigalt_size = 0U;
                ctx->sigalt_flags = sflags;
            } else if ((mode == 0U || mode == L4B_SS_ONSTACK) &&
                       ssize >= 2048U) {
                ctx->sigalt_sp = n32 ? ssp & UINT64_C(0xffffffff) :
                                       ssp;
                ctx->sigalt_size = ssize;
                ctx->sigalt_flags = sflags;
            }
        }
    }
    mips64_ctx_clear_ll(ctx);
    /* Register state is authoritative; the raw return carries the
     * restored $v0 for dispatchers that inspect it. */
    return (int64_t)ctx->gpr[MIPS64_REG_V0];
}

/* Synchronous trap entry for fault sites. The coordinator maps: guest
 * fetch/mem fault -> SIGSEGV, undefined word -> SIGILL, FP V cause ->
 * SIGFPE, BREAK -> SIGTRAP, misaligned address -> SIGBUS. Default
 * si_code is 1 (MAPERR/ILLOPC/FPE/BRKPT/ADRALN family); other signals
 * get SI_KERNEL. */
void mips_trap_code(mips64_ctx_t *ctx, int signo, int32_t code, uint64_t addr)
{
    if (ctx == NULL || !l4b_signo_valid(signo)) {
        return;
    }
    if (code == 0) {
        if (signo == L4B_SIGSEGV) {
            /* Linux si_code: an address inside a recorded mapping is a
             * protection fault (SEGV_ACCERR); outside any mapping it is
             * unmapped (SEGV_MAPERR). PROT_NONE pages stay mapped, so
             * they report ACCERR like the kernel. */
            code = mips_mem_ok(ctx, addr, 1U, 0U) ? 2 : 1;
        } else if (signo == L4B_SIGILL || signo == L4B_SIGFPE ||
                   signo == L4B_SIGTRAP || signo == L4B_SIGBUS) {
            code = 1;
        } else {
            code = L4B_SI_KERNEL;
        }
    }
    (void)mips64_sigpend_enqueue(ctx, (uint32_t)signo, code, 0, addr);
    if (ctx->sigactions[signo].handler >= 2U &&
        !l4b_is_blocked(ctx, signo)) {
        (void)mips_raise_guest(ctx, signo, addr);
    }
}

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    mips_trap_code(ctx, signo, 0, addr);
}
