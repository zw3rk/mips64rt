/*
 * src/os/sigact.c — Guest signal actions, masks, altstack, and the
 * signal-related syscall seam (lane L4a, Phase 4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Defines the frozen cpu.h signal seams mips_sc_rt_sigaction,
 * mips_l4a_rt_sigprocmask, mips_sc_sigaltstack, mips_signal_has_handler,
 * and mips64_signals_reset_for_exec, plus the dispatch seam
 * mips_sc_sig_syscall for rt_sigpending / rt_sigtimedwait+suspend /
 * rt_sigqueueinfo / kill / tkill / tgkill (N64+N32 numbers from frozen
 * src/os/syscall_nr.h). Frame construction, restoration, and trap
 * delivery live in src/os/sigframe.c (lane L4a).
 *
 * Calling convention: the (ctx, sp) seams read their syscall arguments
 * from the guest registers ($a0..$a3, already decoded by the engines
 * into ctx->gpr); sp carries the guest stack pointer at the trap, used
 * only where stack-relative state matters (sigaltstack old-stack
 * report). All seams record the N64/N32 $a3 convention ($a3=0/$v0 on
 * success, $a3=1/$v0=+errno on error) through l2a_ret and return the
 * raw host-style value (negative errno on error) for the dispatcher.
 *
 * Semantics mirror ../rvrt/src/linux/signal.c with MIPS renumbering:
 * signal numbers follow MIPS asm/signal.h (SIGKILL=9, SIGSTOP=23,
 * SIGCHLD=18, SIGWINCH=20, SIGURG=21, SIGUSR1=16, SIGUSR2=17); the mask
 * ops are MIPS_SIG_BLOCK=1 / UNBLOCK=2 / SETMASK=3 (not asm-generic
 * 0/1/2); the kernel sigset is 16 bytes on N64 and N32 alike
 * (sigsetsize != 16 is -EINVAL, verified live in experiments/E03).
 * SIGKILL/SIGSTOP bits are unblockable and uncatchable: they are
 * stripped from every stored mask and rejected in rt_sigaction.
 * N32 guest VAs and pointers are truncated to 32 bits on use (frozen
 * N32 pointer rule); sc_regs stay 64-bit slots on both ABIs.
 */

#include "core/cpu.h"

#include "os/sigframe_mips64rt.h"
#include "os/signal_core.h"
#include "os/syscall_nr.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Shared helpers owned by src/os/syscalls.c (lane L2a) and guest
 * memory helpers owned by src/os/mem.c (lane L1c). */
extern int mips_mem_ok(const mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                       uint32_t need);
extern int64_t l2a_ret(mips64_ctx_t *ctx, int64_t raw);
extern void putn(uint8_t *p, uint64_t v, unsigned n, int be);
extern uint64_t getn(const uint8_t *p, unsigned n, int be);
extern uint8_t *guest_range(mips64_ctx_t *ctx, uint64_t va, uint64_t len,
                            int write);
extern int64_t mips_sc_copyout(mips64_ctx_t *ctx, uint64_t va,
                               const void *src, uint64_t len);
extern int mips_thread_kill(mips64_ctx_t *caller, long tid, int signo,
                            int32_t code);

/* MIPS SA_* bits (asm/signal.h). SA_KNOWN is the storable subset,
 * matching the reference implementation. */
#define L4A_SA_NOCLDSTOP  UINT64_C(0x00000001)
#define L4A_SA_NOCLDWAIT  UINT64_C(0x00000002)
#define L4A_SA_SIGINFO    UINT64_C(0x00000004)
#define L4A_SA_ONSTACK    UINT64_C(0x08000000)
#define L4A_SA_RESTART    UINT64_C(0x10000000)
#define L4A_SA_NODEFER    UINT64_C(0x40000000)
#define L4A_SA_RESETHAND  UINT64_C(0x80000000)
#define L4A_SA_KNOWN      UINT64_C(0xd8000807)

/* sigaltstack report bits (asm/signal.h). */
#define L4A_SS_ONSTACK    UINT32_C(1)
#define L4A_SS_DISABLE    UINT32_C(2)
#define L4A_SS_AUTODISARM UINT32_C(0x80000000)
#define L4A_MINSIGSTKSZ   UINT64_C(2048)

/* MIPS signal numbers (asm/signal.h): KILL/STOP are never caught;
 * CHLD/WINCH/URG are default-ignore like the reference. */
#define L4A_SIGKILL 9
#define L4A_SIGSTOP 23
#define L4A_SIGCHLD 18

/* MIPS mask ops (asm/signal.h: 1/2/3, unlike asm-generic 0/1/2). */
#define L4A_SIG_BLOCK   UINT64_C(1)
#define L4A_SIG_UNBLOCK UINT64_C(2)
#define L4A_SIG_SETMASK UINT64_C(3)

/* Bits that can never be blocked, caught, or stored. */
#define L4A_UNBLOCKABLE \
    ((UINT64_C(1) << (L4A_SIGKILL - 1)) | (UINT64_C(1) << (L4A_SIGSTOP - 1)))

/* SI_USER: code for kill()/tkill()/tgkill-raised signals. */
#define L4A_SI_USER 0

static int l4a_signo_valid(int signo)
{
    return signo >= 1 && signo <= MIPS64RT_NSIG;
}

static unsigned l4a_word(int signo)
{
    return (unsigned)(signo - 1) / 64U;
}

static uint64_t l4a_bit(int signo)
{
    return UINT64_C(1) << ((unsigned)(signo - 1) % 64U);
}

static int l4a_is_blocked(const mips64_ctx_t *ctx, int signo)
{
    return (ctx->sig_blocked[l4a_word(signo)] & l4a_bit(signo)) != 0U;
}

/* N32 VAs are 32-bit; silently truncate (frozen N32 pointer rule). */
static uint64_t l4a_va(const mips64_ctx_t *ctx, uint64_t va)
{
    if (ctx->is_n32 != 0U) {
        return va & UINT64_C(0xffffffff);
    }
    return va;
}

/* Most recently active context, for the ctx-less
 * mips_signal_has_handler seam. Exact for the single-context RC4 gate;
 * threads (lane L4b) share process-wide actions, so any live context
 * reports the same table. */
static const mips64_ctx_t *l4a_active;

static void l4a_mark_active(mips64_ctx_t *ctx)
{
    l4a_active = ctx;
}

/* Pending ring purge helper (enqueue lives in src/os/signal_core.c). */
static void l4a_pend_purge(mips64_ctx_t *ctx, int signo)
{
    uint32_t kept = 0U;
    uint32_t i;
    mips64_sigpend_t tmp[16];

    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t slot = (ctx->pend_head + i) % 16U;

        if ((int)ctx->pend_queue[slot].signo != signo) {
            tmp[kept] = ctx->pend_queue[slot];
            kept++;
        }
    }
    for (i = 0U; i < kept; i++) {
        ctx->pend_queue[i] = tmp[i];
    }
    ctx->pend_head = 0U;
    ctx->pend_count = kept;
}

/* Process-wide handler-bit mirror backing mips_signal_has_handler.
 * Updated on every table mutation in this file and on one-shot resets
 * in sigframe.c (via mips_l4a_action_reset below). */
static uint64_t l4a_handler_words[2];

/* Lane-internal: reset one action to SIG_DFL and refresh the mirror.
 * Used by the sigframe.c one-shot (SA_RESETHAND) and bad-frame paths. */
void mips_l4a_action_reset(mips64_ctx_t *ctx, int signo)
{
    if (ctx == NULL || !l4a_signo_valid(signo)) {
        return;
    }
    ctx->sigactions[signo].handler = 0U;
    ctx->sigactions[signo].flags = 0U;
    ctx->sigactions[signo].mask[0] = 0U;
    ctx->sigactions[signo].mask[1] = 0U;
    ctx->sigactions[signo].restorer = 0U;
    l4a_handler_words[l4a_word(signo)] &= ~l4a_bit(signo);
    l4a_mark_active(ctx);
}

static int l4a_default_ignore(int signo)
{
    return signo == L4A_SIGCHLD || signo == 20 || signo == 21;
}

static int l4a_is_ignored(const mips64_ctx_t *ctx, int signo)
{
    uint64_t handler = ctx->sigactions[signo].handler;

    return handler == 1U || (handler == 0U && l4a_default_ignore(signo));
}

/* rt_sigaction: (signum=a0, act=a1, oldact=a2, sigsetsize=a3). Kernel
 * layouts from frozen sigframe_mips64rt.h: N64 32 bytes
 * (flags@0, handler@8, mask@16), N32 24 bytes (flags@0, handler@4,
 * mask@8, no restorer slot). */
int64_t mips_sc_rt_sigaction(mips64_ctx_t *ctx, uint64_t sp)
{
    uint64_t signo;
    uint64_t act_va;
    uint64_t old_va;
    uint64_t setsize;
    int n32;
    int be;
    mips64_sigaction_t old;

    (void)sp;
    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    l4a_mark_active(ctx);
    signo = ctx->gpr[MIPS64_REG_A0];
    act_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A1]);
    old_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A2]);
    setsize = ctx->gpr[MIPS64_REG_A3];
    if (setsize != MIPS64RT_SIGSETSIZE) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (signo < 1U || signo > (uint64_t)MIPS64RT_NSIG) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    n32 = ctx->is_n32 != 0U;
    be = ctx->is_be != 0U;
    old = ctx->sigactions[signo];
    if (act_va != 0U) {
        uint8_t *p;
        uint64_t flags;
        uint64_t handler;
        uint64_t mask0;
        uint64_t mask1;
        uint64_t restorer;

        if (signo == (uint64_t)L4A_SIGKILL ||
            signo == (uint64_t)L4A_SIGSTOP) {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
        p = guest_range(ctx, act_va, n32 ? 24U : 32U, 0);
        if (p == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        /* The kernel layouts carry no restorer slot on either ABI, so
         * the recorded restorer is preserved across sigaction calls. */
        restorer = ctx->sigactions[signo].restorer;
        if (n32) {
            flags = getn(p, 4, be);
            handler = getn(p + 4, 4, be);
            mask0 = getn(p + 8, 4, be) |
                    (getn(p + 12, 4, be) << 32);
            mask1 = getn(p + 16, 4, be) |
                    (getn(p + 20, 4, be) << 32);
        } else {
            flags = getn(p, 4, be);
            handler = getn(p + 8, 8, be);
            mask0 = getn(p + 16, 8, be);
            mask1 = getn(p + 24, 8, be);
        }
        ctx->sigactions[signo].handler = handler;
        ctx->sigactions[signo].flags = flags & L4A_SA_KNOWN;
        ctx->sigactions[signo].mask[0] = mask0 & ~L4A_UNBLOCKABLE;
        ctx->sigactions[signo].mask[1] = mask1 & ~L4A_UNBLOCKABLE;
        ctx->sigactions[signo].restorer = restorer;
        if (handler >= 2U) {
            l4a_handler_words[l4a_word((int)signo)] |=
                l4a_bit((int)signo);
        } else {
            l4a_handler_words[l4a_word((int)signo)] &=
                ~l4a_bit((int)signo);
            if (l4a_is_ignored(ctx, (int)signo)) {
                l4a_pend_purge(ctx, (int)signo);
            }
        }
    }
    if (old_va != 0U) {
        uint8_t img[32];

        if (n32) {
            putn(img, old.flags & UINT64_C(0xffffffff), 4, be);
            putn(img + 4, old.handler & UINT64_C(0xffffffff), 4, be);
            putn(img + 8, old.mask[0] & UINT64_C(0xffffffff), 4, be);
            putn(img + 12, (old.mask[0] >> 32) & UINT64_C(0xffffffff),
                 4, be);
            putn(img + 16, old.mask[1] & UINT64_C(0xffffffff), 4, be);
            putn(img + 20, (old.mask[1] >> 32) & UINT64_C(0xffffffff),
                 4, be);
        } else {
            putn(img, old.flags & UINT64_C(0xffffffff), 4, be);
            putn(img + 4, 0U, 4, be);
            putn(img + 8, old.handler, 8, be);
            putn(img + 16, old.mask[0], 8, be);
            putn(img + 24, old.mask[1], 8, be);
        }
        /* Stage in host memory, commit under sc_lock (R3-1). */
        if (mips_sc_copyout(ctx, old_va, img, n32 ? 24U : 32U) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

/* rt_sigprocmask: (how=a0, set=a1, oldset=a2, sigsetsize=a3). The mask
 * lives in the frozen ctx tail (replaces the lane-L2a recorded static
 * once the coordinator rewires dispatch to this seam). */
int64_t mips_l4a_rt_sigprocmask(mips64_ctx_t *ctx, uint64_t sp)
{
    uint64_t how;
    uint64_t set_va;
    uint64_t old_va;
    uint64_t setsize;
    int n32;
    int be;
    uint64_t cur0;
    uint64_t cur1;

    (void)sp;
    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    l4a_mark_active(ctx);
    how = ctx->gpr[MIPS64_REG_A0];
    set_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A1]);
    old_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A2]);
    setsize = ctx->gpr[MIPS64_REG_A3];
    if (setsize != MIPS64RT_SIGSETSIZE) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    n32 = ctx->is_n32 != 0U;
    be = ctx->is_be != 0U;
    cur0 = ctx->sig_blocked[0];
    cur1 = ctx->sig_blocked[1];
    if (set_va != 0U) {
        const uint8_t *p = guest_range(ctx, set_va, 16U, 0);
        uint64_t nw0;
        uint64_t nw1;

        if (p == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        if (n32) {
            nw0 = (getn(p, 4, be) | (getn(p + 4, 4, be) << 32)) &
                ~L4A_UNBLOCKABLE;
            nw1 = (getn(p + 8, 4, be) | (getn(p + 12, 4, be) << 32)) &
                ~L4A_UNBLOCKABLE;
        } else {
            nw0 = getn(p, 8, be) & ~L4A_UNBLOCKABLE;
            nw1 = getn(p + 8, 8, be) & ~L4A_UNBLOCKABLE;
        }
        if (how == L4A_SIG_BLOCK) {
            ctx->sig_blocked[0] |= nw0;
            ctx->sig_blocked[1] |= nw1;
        } else if (how == L4A_SIG_UNBLOCK) {
            ctx->sig_blocked[0] &= ~nw0;
            ctx->sig_blocked[1] &= ~nw1;
        } else if (how == L4A_SIG_SETMASK) {
            ctx->sig_blocked[0] = nw0;
            ctx->sig_blocked[1] = nw1;
        } else {
            return l2a_ret(ctx, -(int64_t)EINVAL);
        }
    }
    if (old_va != 0U) {
        uint8_t img[16];

        if (n32) {
            putn(img, (uint32_t)cur0, 4, be);
            putn(img + 4, (uint32_t)(cur0 >> 32), 4, be);
            putn(img + 8, (uint32_t)cur1, 4, be);
            putn(img + 12, (uint32_t)(cur1 >> 32), 4, be);
        } else {
            putn(img, cur0, 8, be);
            putn(img + 8, cur1, 8, be);
        }
        /* Stage in host memory, commit under sc_lock (R3-1). */
        if (mips_sc_copyout(ctx, old_va, img, sizeof img) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

/* sigaltstack: (ss=a0, oss=a1). Layouts from frozen
 * sigframe_mips64rt.h: N64 24 bytes (sp@0, size@8, flags@16),
 * N32 12 bytes (sp@0, size@4, flags@8). The sp parameter feeds the
 * on-stack report, mirroring the reference reported_stack. */
int64_t mips_sc_sigaltstack(mips64_ctx_t *ctx, uint64_t sp)
{
    uint64_t ss_va;
    uint64_t oss_va;
    int n32;
    int be;
    int on_stack;
    uint32_t reported;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    l4a_mark_active(ctx);
    ss_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A0]);
    oss_va = l4a_va(ctx, ctx->gpr[MIPS64_REG_A1]);
    n32 = ctx->is_n32 != 0U;
    be = ctx->is_be != 0U;
    on_stack = ctx->sigalt_size != 0U && sp > ctx->sigalt_sp &&
               sp - ctx->sigalt_sp <= ctx->sigalt_size;
    reported = (ctx->sigalt_flags & L4A_SS_AUTODISARM) |
               (ctx->sigalt_size == 0U ? L4A_SS_DISABLE :
                (on_stack ? L4A_SS_ONSTACK : 0U));
    {
        uint64_t old_sp = ctx->sigalt_sp;
        uint64_t old_size = ctx->sigalt_size;
        uint32_t old_flags = reported;
        if (ss_va != 0U) {
            const uint8_t *p = guest_range(ctx, ss_va, n32 ? 12U : 24U, 0);
            uint64_t nsp;
            uint64_t nsize;
            uint32_t nflags;
            uint32_t mode;

            if (p == NULL) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
            if (n32) {
                nsp = getn(p, 4, be);
                nsize = getn(p + 4, 4, be);
                nflags = (uint32_t)getn(p + 8, 4, be);
            } else {
                nsp = getn(p, 8, be);
                nsize = getn(p + 8, 8, be);
                nflags = (uint32_t)getn(p + 16, 4, be);
            }
            if (on_stack) {
                return l2a_ret(ctx, -(int64_t)EPERM);
            }
            mode = nflags & ~L4A_SS_AUTODISARM;
            if (mode != 0U && mode != L4A_SS_ONSTACK &&
                mode != L4A_SS_DISABLE) {
                return l2a_ret(ctx, -(int64_t)EINVAL);
            }
            if (mode == L4A_SS_DISABLE) {
                ctx->sigalt_sp = 0U;
                ctx->sigalt_size = 0U;
                ctx->sigalt_flags = nflags;
            } else {
                if (nsize < L4A_MINSIGSTKSZ) {
                    return l2a_ret(ctx, -(int64_t)ENOMEM);
                }
                ctx->sigalt_sp = nsp;
                ctx->sigalt_size = nsize;
                ctx->sigalt_flags = nflags;
            }
        }
        if (oss_va != 0U) {
            uint8_t img[24];

            if (n32) {
                putn(img, old_sp & UINT64_C(0xffffffff), 4, be);
                putn(img + 4, old_size & UINT64_C(0xffffffff), 4, be);
                putn(img + 8, old_flags, 4, be);
            } else {
                putn(img, old_sp, 8, be);
                putn(img + 8, old_size, 8, be);
                putn(img + 16, old_flags, 4, be);
                putn(img + 20, 0U, 4, be);
            }
            /* Stage in host memory, commit under sc_lock (R3-1). */
            if (mips_sc_copyout(ctx, oss_va, img, n32 ? 12U : 24U) != 0) {
                return l2a_ret(ctx, -(int64_t)EFAULT);
            }
        }
        return l2a_ret(ctx, 0);
    }
}

/* Whether signo currently has a guest handler installed (consults the
 * most recently active context, refreshed by every seam in this file
 * and by delivery in sigframe.c). */
int mips_signal_has_handler(int signo)
{
    if (!l4a_signo_valid(signo) || l4a_active == NULL) {
        return 0;
    }
    return (l4a_handler_words[l4a_word(signo)] & l4a_bit(signo)) != 0U;
}

/* execve reset (M64-R10-2): caught actions to SIG_DFL, SIG_IGN (1) and
 * sig_blocked preserved per signal(7), queues/altstack cleared. */
void mips64_signals_reset_for_exec(mips64_ctx_t *ctx)
{
    size_t i;

    if (ctx == NULL) {
        return;
    }
    for (i = 0U; i < 129U; i++) {
        if (ctx->sigactions[i].handler != 1U) {
            ctx->sigactions[i].handler = 0U;
        }
        ctx->sigactions[i].flags = 0U;
        ctx->sigactions[i].mask[0] = 0U;
        ctx->sigactions[i].mask[1] = 0U;
        ctx->sigactions[i].restorer = 0U;
    }
    ctx->pend_head = 0U;
    ctx->pend_count = 0U;
    ctx->sigalt_sp = 0U;
    ctx->sigalt_size = 0U;
    ctx->sigalt_flags = 0U;
    ctx->clear_child_tid = 0U;
    l4a_handler_words[0] = 0U;
    l4a_handler_words[1] = 0U;
    l4a_mark_active(ctx);
}

/* Queue one standard signal for later delivery at the interp/DBT loop
 * check. Mirrors the reference admission rule: a signal that is
 * neither blocked nor handled-to-be-delivered, and whose disposition
 * is ignore, is dropped without queueing. */
int mips_sig_enqueue(mips64_ctx_t *ctx, int signo, int32_t code,
                     uint64_t addr)
{
    uint64_t handler;

    if (ctx == NULL || !l4a_signo_valid(signo)) {
        return -(int)EINVAL;
    }
    handler = ctx->sigactions[signo].handler;
    if (!l4a_is_blocked(ctx, signo) && l4a_is_ignored(ctx, signo)) {
        return 0;
    }
    if (handler == 1U) {
        return 0;
    }
    (void)mips64_sigpend_enqueue(ctx, (uint32_t)signo, code, 0, addr);
    return 0;
}

static int l4a_raise_self(mips64_ctx_t *ctx, int signo, int32_t code,
                          uint64_t addr)
{
    return mips_sig_enqueue(ctx, signo, code, addr);
}

/* rt_sigpending: (set=a0, sigsetsize=a1). Reports the queued-but-
 * blocked subset, mirroring the reference byte-count rule against the
 * 16-byte kernel set. */
static int64_t l4a_pending(mips64_ctx_t *ctx, uint64_t set_va,
                           uint64_t setsize)
{
    uint64_t bits[2] = { 0U, 0U };
    uint32_t i;
    int n32;
    int be;

    if (setsize > MIPS64RT_SIGSETSIZE) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (setsize != 0U) {
        uint64_t w0;
        uint64_t w1;
        uint8_t img[16];

        for (i = 0U; i < ctx->pend_count; i++) {
            uint32_t slot = (ctx->pend_head + i) % 16U;
            int s = (int)ctx->pend_queue[slot].signo;

            if (l4a_signo_valid(s)) {
                bits[l4a_word(s)] |= l4a_bit(s);
            }
        }
        w0 = bits[0] & ctx->sig_blocked[0];
        w1 = bits[1] & ctx->sig_blocked[1];
        if (set_va == 0U) {
            return l2a_ret(ctx, 0);
        }
        n32 = ctx->is_n32 != 0U;
        be = ctx->is_be != 0U;
        if (n32) {
            putn(img, (uint32_t)w0, 4, be);
            putn(img + 4, (uint32_t)(w0 >> 32), 4, be);
            putn(img + 8, (uint32_t)w1, 4, be);
            putn(img + 12, (uint32_t)(w1 >> 32), 4, be);
        } else {
            putn(img, w0, 8, be);
            putn(img + 8, w1, 8, be);
        }
        /* Stage in host memory, commit under sc_lock (R3-1). */
        if (mips_sc_copyout(ctx, l4a_va(ctx, set_va), img,
                            setsize) != 0) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
    }
    return l2a_ret(ctx, 0);
}

/* rt_sigsuspend / rt_sigtimedwait (shared N64 5126 / N32 6126 number;
 * the frozen header carries no separate rt_sigsuspend number, so both
 * spellings are served here: with a 16-byte sigsetsize in a3 the call
 * is sigtimedwait(set=a0, info=a1, timeout=a2, sigsetsize=a3), else
 * sigsuspend(mask=a0, sigsetsize=a1)). Installs the wait mask and
 * reports -EINTR like the reference; delivery then proceeds at the
 * loop check and sigreturn restores the frame mask. */
static int64_t l4a_suspend(mips64_ctx_t *ctx, uint64_t a0, uint64_t a1,
                           uint64_t a2, uint64_t a3)
{
    uint64_t mask_va;
    uint64_t setsize;
    const uint8_t *p;
    int n32;
    int be;

    (void)a2;
    if (a3 == MIPS64RT_SIGSETSIZE) {
        mask_va = a0;
        setsize = a3;
        /* sigtimedwait info/timeout are accepted but not waited on:
         * single-threaded delivery happens at the loop check. */
        (void)a1;
    } else if (a1 == MIPS64RT_SIGSETSIZE) {
        mask_va = a0;
        setsize = a1;
    } else if (a1 == 0U && a3 == 0U) {
        mask_va = a0;
        setsize = 0U;
    } else {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (setsize != 0U && setsize != MIPS64RT_SIGSETSIZE) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (setsize != 0U) {
        p = guest_range(ctx, l4a_va(ctx, mask_va), 16U, 0);
        if (p == NULL) {
            return l2a_ret(ctx, -(int64_t)EFAULT);
        }
        n32 = ctx->is_n32 != 0U;
        be = ctx->is_be != 0U;
        if (n32) {
            ctx->sig_blocked[0] =
                (getn(p, 4, be) | (getn(p + 4, 4, be) << 32)) &
                ~L4A_UNBLOCKABLE;
            ctx->sig_blocked[1] =
                (getn(p + 8, 4, be) | (getn(p + 12, 4, be) << 32)) &
                ~L4A_UNBLOCKABLE;
        } else {
            ctx->sig_blocked[0] = getn(p, 8, be) & ~L4A_UNBLOCKABLE;
            ctx->sig_blocked[1] = getn(p + 8, 8, be) & ~L4A_UNBLOCKABLE;
        }
    }
    return l2a_ret(ctx, -(int64_t)EINTR);
}

/* rt_sigqueueinfo: (pid=a0, signo=a1, info=a2). Self-only; the
 * 128-byte guest siginfo contributes si_code/si_errno/si_addr. */
static int64_t l4a_queueinfo(mips64_ctx_t *ctx, uint64_t pid,
                             uint64_t signo, uint64_t info_va)
{
    const uint8_t *p;
    int32_t code;
    int32_t errnum;
    uint64_t addr;
    int be;

    if (pid != 0U && pid != (uint64_t)getpid()) {
        return l2a_ret(ctx, -(int64_t)EOPNOTSUPP);
    }
    if (signo == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (signo > (uint64_t)MIPS64RT_NSIG) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    be = ctx->is_be != 0U;
    p = guest_range(ctx, l4a_va(ctx, info_va), 128U, 0);
    if (p == NULL) {
        return l2a_ret(ctx, -(int64_t)EFAULT);
    }
    code = (int32_t)getn(p + 4, 4, be);
    errnum = (int32_t)getn(p + 8, 4, be);
    addr = ctx->is_n32 != 0U ? getn(p + 16, 4, be) :
                               getn(p + 16, 8, be);
    if (!l4a_is_blocked(ctx, (int)signo) &&
        l4a_is_ignored(ctx, (int)signo)) {
        return l2a_ret(ctx, 0);
    }
    if (ctx->sigactions[signo].handler == 1U) {
        return l2a_ret(ctx, 0);
    }
    (void)mips64_sigpend_enqueue(ctx, (uint32_t)signo, code, errnum, addr);
    return l2a_ret(ctx, 0);
}

static int64_t l4a_kill(mips64_ctx_t *ctx, uint64_t pid, uint64_t signo)
{
    if (pid != 0U && pid != (uint64_t)getpid()) {
        return l2a_ret(ctx, -(int64_t)EOPNOTSUPP);
    }
    if (signo == 0U) {
        return l2a_ret(ctx, 0);
    }
    if (signo > (uint64_t)MIPS64RT_NSIG) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    return l2a_ret(ctx,
                   (int64_t)l4a_raise_self(ctx, (int)signo, L4A_SI_USER,
                                           0U));
}

static int64_t l4a_tkill(mips64_ctx_t *ctx, uint64_t tid, uint64_t signo,
                         int group, uint64_t tgid)
{
    int32_t stid = (int32_t)(uint32_t)tid;
    int32_t stgid = (int32_t)(uint32_t)tgid;

    if (stid <= 0) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (group && stgid <= 0) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (signo > (uint64_t)MIPS64RT_NSIG) {
        return l2a_ret(ctx, -(int64_t)EINVAL);
    }
    if (group && (pid_t)stgid != getpid()) {
        return l2a_ret(ctx, -(int64_t)ESRCH);
    }
    return l2a_ret(ctx,
                   (int64_t)mips_thread_kill(ctx, (long)stid, (int)signo,
                                             L4A_SI_USER));
}

/* Dispatch seam for the signal syscalls not covered by the frozen
 * single-purpose seams. Unknown numbers report -ENOSYS. */
int64_t mips_sc_sig_syscall(mips64_ctx_t *ctx, uint64_t nr, uint64_t a0,
                            uint64_t a1, uint64_t a2, uint64_t a3)
{
    int n32;

    if (ctx == NULL) {
        return -(int64_t)EFAULT;
    }
    l4a_mark_active(ctx);
    n32 = ctx->is_n32 != 0U;
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigpending
                             : MIPS64_NR_rt_sigpending)) {
        return l4a_pending(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigtimedwait
                             : MIPS64_NR_rt_sigtimedwait)) {
        return l4a_suspend(ctx, a0, a1, a2, a3);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_rt_sigqueueinfo
                             : MIPS64_NR_rt_sigqueueinfo)) {
        return l4a_queueinfo(ctx, a0, a1, a2);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_kill : MIPS64_NR_kill)) {
        return l4a_kill(ctx, a0, a1);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_tkill : MIPS64_NR_tkill)) {
        return l4a_tkill(ctx, a0, a1, 0, 0U);
    }
    if (nr == (uint64_t)(n32 ? MIPS64_NR32_tgkill : MIPS64_NR_tgkill)) {
        return l4a_tkill(ctx, a1, a2, 1, a0);
    }
    return l2a_ret(ctx, -(int64_t)ENOSYS);
}
