/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE

#include "os/signal_core.h"
#include "os/syscall_nr.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

uint64_t mips64_signal_trampoline_addr(int is_n32)
{
    return is_n32 != 0 ? MIPS64_N32_SIGTRAMP : MIPS64_N64_SIGTRAMP;
}

void mips64_ctx_clear_ll(mips64_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    ctx->llbit = 0;
    ctx->lladdr = 0;
    ctx->llval = 0;
}

int mips64_sigpend_enqueue(mips64_ctx_t *ctx, uint32_t signo, int32_t code,
                           int32_t errnum, uint64_t addr)
{
    uint32_t slot;

    if (ctx == NULL || ctx->pend_count >= 16U) {
        return 0;
    }
    slot = (ctx->pend_head + ctx->pend_count) % 16U;
    ctx->pend_queue[slot].signo = signo;
    ctx->pend_queue[slot].code = code;
    ctx->pend_queue[slot].errnum = errnum;
    ctx->pend_queue[slot].addr = addr;
    ctx->pend_count++;
    return 0;
}

/* Deferred sigmask restore (Linux restore_saved_sigmask): pselect6 and
 * ppoll install their temporary mask in ctx->sig_blocked and park the
 * caller's mask here, so a signal delivered on the way out of the
 * syscall runs under the temporary mask while its frame records the
 * caller's mask for rt_sigreturn. Per host thread, like ctx. */
static _Thread_local uint64_t sc_saved_mask[2];
static _Thread_local int sc_saved_valid;

void mips64_sig_defer_restore(const uint64_t old[2])
{
    sc_saved_mask[0] = old[0];
    sc_saved_mask[1] = old[1];
    sc_saved_valid = 1;
}

int mips64_sig_take_saved(uint64_t out[2])
{
    if (sc_saved_valid == 0) {
        return 0;
    }
    out[0] = sc_saved_mask[0];
    out[1] = sc_saved_mask[1];
    sc_saved_valid = 0;
    return 1;
}

void mips64_sig_restore_saved(mips64_ctx_t *ctx)
{
    uint64_t old[2];

    if (ctx != NULL && mips64_sig_take_saved(old)) {
        ctx->sig_blocked[0] = old[0];
        ctx->sig_blocked[1] = old[1];
    }
}

/* Host SIGCHLD bridge. Guest children are host children, so their
 * exits raise host SIGCHLD; once the guest installs a MIPS SIGCHLD (18)
 * handler, a host handler records the event so the dispatcher can
 * queue the guest signal. The host handler runs with SA_SIGINFO plus
 * SA_NOCLDSTOP exactly when the guest SIGCHLD action carries
 * MIPS64_SA_NOCLDSTOP, and never with SA_RESTART: a host SA_RESTART
 * would transparently re-enter blocked read()/wait4() without
 * returning EINTR, so mips64_host_eintr_retry would never run and the
 * guest SIGCHLD handler would stay queued until the call finished for
 * some other reason (deadlocking self-pipe loops that install SIGCHLD
 * with SA_RESTART). Guests observe EINTR on blocking calls whenever a
 * handler is delivered, while mips64_host_eintr_retry still re-enters
 * transparently when SIGCHLD is blocked in the guest sigmask (and
 * pselect/ppoll/select/poll are never restarted by the kernel
 * regardless of SA_RESTART). Callers that see EINTR consult
 * mips64_host_eintr_retry: the host call is re-entered only when the
 * EINTR was spurious (no unblocked deliverable guest signal pending);
 * otherwise EINTR surfaces so the dispatcher runs the handler at
 * once. All cross-thread state is _Atomic: the async-signal handler
 * only stores the flag, and exactly one polling thread consumes each
 * child exit via atomic_exchange. */
static atomic_int sc_host_sigchld;
static atomic_int sc_host_sigchld_armed;
/* Guest SIGCHLD action flags at the last arm (MIPS64_SA_* bits): the
 * waitid report set and the SA_NOCLDSTOP install follow the guest,
 * re-installed whenever the SA_NOCLDSTOP bit changes. The guest
 * SA_RESTART bit is recorded but never installed on the host. */
static _Atomic uint64_t sc_chld_guest_flags;

/* Last reaped-but-not-consumed child state (si_pid/si_uid/si_status/
 * si_code from waitid WNOWAIT, which reports without reaping).
 * Standard signals coalesce, so one slot is enough; it is consumed
 * by the sigframe builder when it emits the SIGCHLD siginfo. Written
 * by the single thread that won the flag exchange, read by the frame
 * builder; _Atomic so a concurrent capture never tears. */
static atomic_uint sc_chld_pid;
static atomic_uint sc_chld_uid;
static atomic_int sc_chld_status;
static atomic_int sc_chld_code;
static atomic_int sc_chld_valid;

/* Forward: host->MIPS signal renumbering (defined below with the
 * poll fallback that shares it). */
static int sc_host_to_mips_sig(int signo);

static void sc_host_sigchld_action(int signo, siginfo_t *info, void *uc)
{
    int saved_errno;

    (void)signo;
    (void)uc;
    if (info == NULL || info->si_pid <= 0) {
        atomic_store(&sc_host_sigchld, 1);
        return;
    }
    /* SA_SIGINFO hands us the exact triggering child: capture its
     * siginfo directly so a later waitid(WNOWAIT) in the poller cannot
     * report an older un-reaped stopped child instead. Only _Atomic
     * stores (async-signal-safe); errno is preserved. Fields land
     * before sc_chld_valid, which the poller loads with acquire. */
    saved_errno = errno;
    {
        int32_t code;
        int32_t status = (int32_t)info->si_status;

        switch (info->si_code) {
        case CLD_EXITED:
        case CLD_KILLED:
        case CLD_DUMPED:
        case CLD_TRAPPED:
        case CLD_STOPPED:
        case CLD_CONTINUED:
            code = (int32_t)info->si_code;
            break;
        default:
            code = MIPS64_CLD_EXITED;
            break;
        }
        /* si_status carries a host signal number for every code but
         * CLD_EXITED (same translation as the waitid fallback below). */
        if (code != (int32_t)CLD_EXITED) {
            status = (int32_t)sc_host_to_mips_sig((int)status);
        }
        atomic_store_explicit(&sc_chld_pid, (unsigned int)info->si_pid,
                              memory_order_relaxed);
        atomic_store_explicit(&sc_chld_uid, (unsigned int)info->si_uid,
                              memory_order_relaxed);
        atomic_store_explicit(&sc_chld_status, status,
                              memory_order_relaxed);
        atomic_store_explicit(&sc_chld_code, code, memory_order_relaxed);
        atomic_store_explicit(&sc_chld_valid, 1, memory_order_release);
    }
    atomic_store(&sc_host_sigchld, 1);
    errno = saved_errno;
}

void mips64_host_sigchld_arm(uint64_t guest_flags)
{
    struct sigaction sa;
    uint64_t prev = atomic_load(&sc_chld_guest_flags);

    /* Re-install whenever the guest SA_NOCLDSTOP bit changed (or the
     * bridge is not armed yet): the host disposition mirrors the
     * guest action for stop/continue delivery only. SA_RESTART is
     * never installed on the host (see the bridge comment above), so
     * the guest SA_RESTART bit alone never re-installs. */
    if (atomic_load(&sc_host_sigchld_armed) != 0 &&
        ((prev ^ guest_flags) & MIPS64_SA_NOCLDSTOP) == 0U) {
        atomic_store(&sc_chld_guest_flags, guest_flags);
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sc_host_sigchld_action;
    sa.sa_flags = (int)(SA_SIGINFO |
                        (((guest_flags & MIPS64_SA_NOCLDSTOP) != 0U) ?
                             SA_NOCLDSTOP : 0));
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == 0) {
        atomic_store(&sc_chld_guest_flags, guest_flags);
        atomic_store(&sc_host_sigchld_armed, 1);
    }
}

int mips64_host_sigchld_armed(void)
{
    return atomic_load(&sc_host_sigchld_armed) != 0;
}

/* Disarm the host SIGCHLD handler (guest reset SIGCHLD to SIG_DFL or
 * SIG_IGN, or exec reset the table): the host disposition returns to
 * SIG_DFL so a child exit no longer interrupts host waits, and any
 * recorded event is dropped so pselect6/ppoll never see a spurious
 * EINTR with no deliverable guest signal behind it. */
void mips64_host_sigchld_disarm(void)
{
    struct sigaction sa;

    if (atomic_load(&sc_host_sigchld_armed) == 0) {
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    (void)sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGCHLD, &sa, NULL);
    atomic_store(&sc_host_sigchld_armed, 0);
    atomic_store(&sc_host_sigchld, 0);
    atomic_store(&sc_chld_valid, 0);
    atomic_store(&sc_chld_guest_flags, 0U);
}

/* Fork-child hook: the child inherits the recorded flag and the armed
 * handler, but the pre-fork child exit (if any) belongs to the
 * parent's wait set, so the flag and any cached child state are
 * dropped to avoid a phantom guest SIGCHLD in the child. */
void mips64_host_sigchld_fork_child(void)
{
    atomic_store(&sc_host_sigchld, 0);
    atomic_store(&sc_chld_valid, 0);
}

/* Consume the cached child state for the SIGCHLD siginfo frame.
 * Returns 0 when no waitid state was captured (ECHILD race). */
int mips64_sigchld_info(uint32_t *pid, uint32_t *uid, int32_t *status,
                        int32_t *code)
{
    /* Single atomic consume: exactly one siginfo frame takes the
     * cached child state (a load+store pair could hand it out twice
     * when two threads race here). */
    if (atomic_exchange_explicit(&sc_chld_valid, 0,
                                 memory_order_acq_rel) == 0) {
        return 0;
    }
    if (pid != NULL) {
        *pid = atomic_load(&sc_chld_pid);
    }
    if (uid != NULL) {
        *uid = atomic_load(&sc_chld_uid);
    }
    if (status != NULL) {
        *status = atomic_load(&sc_chld_status);
    }
    if (code != NULL) {
        *code = atomic_load(&sc_chld_code);
    }
    return 1;
}

/* Turn a recorded host SIGCHLD into one queued guest SIGCHLD (standard
 * signals coalesce: none is added while one is already queued). The
 * flag is consumed only while the guest still handles SIGCHLD, and
 * only into a context where SIGCHLD is NOT blocked: a process-directed
 * signal stays pending at process level until a thread with SIGCHLD
 * unblocked polls it. atomic_exchange consumes the flag exactly once,
 * so only one thread enqueues per child exit. When a SIGCHLD is
 * already queued the cached capture is left intact (it belongs to the
 * queued entry's future frame). The queued entry carries the siginfo
 * the SA_SIGINFO handler captured for the exact triggering child,
 * falling back to waitid(P_ALL, WEXITED | WNOHANG | WNOWAIT plus
 * WSTOPPED | WCONTINUED only when the guest SIGCHLD action lacks
 * SA_NOCLDSTOP), which reports the state change without reaping the
 * child (the guest wait4/waitid reaps later). Under SA_NOCLDSTOP the
 * stop/continue reports are omitted so a stopped child is never
 * reported ahead of an exited child. */
/* Thread-registry wake helper (strong in src/os/threads.c): forward
 * a recorded SIGCHLD to an eligible peer guest thread with SIGCHLD
 * unblocked. Weak no-op fallback for single-threaded and unit-test
 * links without the thread registry (same pattern as the weak quiesce
 * hooks in src/os/mem_table.c); the strong registry def wins in the
 * full binary. */
__attribute__((weak)) void mips_threads_wake_sigchld_peer(
    const mips64_ctx_t *ctx)
{
    (void)ctx;
}

/* Host (asm-generic, AArch64) to MIPS (asm/signal.h) signal numbers.
 * Signals 1-6, 8-9, 11 and 13-15 coincide; the rest are renumbered on
 * MIPS (SIGBUS 7->10, SIGUSR1 10->16, SIGUSR2 12->17, SIGCHLD 17->18,
 * SIGCONT 18->25, SIGSTOP 19->23, SIGTSTP 20->24, SIGTTIN 21->26,
 * SIGTTOU 22->27, SIGURG 23->21, SIGXCPU 24->30, SIGXFSZ 25->31,
 * SIGVTALRM 26->28, SIGPROF 27->29, SIGWINCH 28->20, SIGIO 29->22,
 * SIGPWR 30->19, SIGSYS 31->12; STKFLT 16 has no MIPS counterpart and
 * takes the unused SIGEMT 7 slot, matching qemu-user). Realtime
 * signals (>= 32) and out-of-range values pass through unchanged. */
static int sc_host_to_mips_sig(int signo)
{
    static const int map[32] = {
        0, 1, 2, 3, 4, 5, 6, 10, 8, 9, 16, 11, 17, 13, 14, 15,
        7, 18, 25, 23, 24, 26, 27, 21, 30, 31, 28, 29, 20, 22, 19, 12
    };

    if (signo >= 0 && signo < 32) {
        return map[signo];
    }
    return signo;
}

void mips64_host_sigchld_poll(mips64_ctx_t *ctx)
{
    uint64_t bit = UINT64_C(1) << ((unsigned)(MIPS64_SIGCHLD - 1) % 64U);
    unsigned word = ((unsigned)MIPS64_SIGCHLD - 1U) / 64U;
    uint32_t i;
    siginfo_t si;
    int32_t code;
    int wflags = WEXITED | WNOHANG | WNOWAIT;

    if (ctx == NULL ||
        ctx->sigactions[MIPS64_SIGCHLD].handler < 2U) {
        return;
    }
    if ((ctx->sig_blocked[word] & bit) != 0U) {
        /* A recorded child exit is not ours: leave the flag set and
         * wake an eligible peer with SIGCHLD unblocked (parked in
         * ppoll/pselect6/read) so it polls immediately instead of
         * stalling to its timeout. */
        if (atomic_load(&sc_host_sigchld) != 0) {
            mips_threads_wake_sigchld_peer(ctx);
        }
        return;
    }
    if (atomic_exchange(&sc_host_sigchld, 0) == 0) {
        return;
    }
    for (i = 0U; i < ctx->pend_count; i++) {
        if (ctx->pend_queue[(ctx->pend_head + i) % 16U].signo ==
            (uint32_t)MIPS64_SIGCHLD) {
            return;
        }
    }
    /* Prefer the siginfo the SA_SIGINFO handler captured (the exact
     * triggering child); only fall back to waitid(WNOWAIT) when the
     * handler left nothing, so the fallback cannot report an older
     * un-reaped stopped child instead. */
    if (atomic_load_explicit(&sc_chld_valid, memory_order_acquire) != 0) {
        (void)mips64_sigpend_enqueue(ctx, (uint32_t)MIPS64_SIGCHLD,
                                     atomic_load(&sc_chld_code),
                                     0, 0U);
        return;
    }
    (void)memset(&si, 0, sizeof si);
    if ((atomic_load(&sc_chld_guest_flags) & MIPS64_SA_NOCLDSTOP) == 0U) {
        wflags |= WSTOPPED | WCONTINUED;
    }
    if (waitid(P_ALL, 0, &si, wflags) == 0 && si.si_pid != 0) {
        int32_t status = (int32_t)si.si_status;

        atomic_store(&sc_chld_pid, (unsigned int)si.si_pid);
        atomic_store(&sc_chld_uid, (unsigned int)si.si_uid);
        switch (si.si_code) {
        case CLD_EXITED:
        case CLD_KILLED:
        case CLD_DUMPED:
        case CLD_TRAPPED:
        case CLD_STOPPED:
        case CLD_CONTINUED:
            code = (int32_t)si.si_code;
            break;
        default:
            code = MIPS64_CLD_EXITED;
            break;
        }
        /* si_status carries a host signal number for every code but
         * CLD_EXITED (which carries the exit status): translate it to
         * the MIPS number the guest siginfo frame reports (SIGUSR1
         * 10->16, SIGCHLD 17->18, SIGSTOP 19->23, SIGTSTP 20->24,
         * SIGBUS 7->10, ...). */
        if (code != (int32_t)CLD_EXITED) {
            status = (int32_t)sc_host_to_mips_sig((int)status);
        }
        atomic_store(&sc_chld_status, status);
        atomic_store(&sc_chld_code, code);
        atomic_store(&sc_chld_valid, 1);
    }
    (void)mips64_sigpend_enqueue(ctx, (uint32_t)MIPS64_SIGCHLD,
                                 atomic_load(&sc_chld_valid) != 0 ?
                                 atomic_load(&sc_chld_code) :
                                 MIPS64_CLD_EXITED,
                                 0, 0U);
}

/* MIPS signals whose SIG_DFL disposition ignores the signal (like
 * the sigact.c lane: SIGCHLD 18, SIGWINCH 20, SIGURG 21, SIGCONT 25).
 * Every other unblocked SIG_DFL signal terminates or stops the guest. */
static int sc_default_ignore(int signo)
{
    return signo == MIPS64_SIGCHLD || signo == 20 || signo == 21 ||
        signo == 25;
}

/* Post-EINTR verdict for a blocking host call (read/nanosleep/wait4
 * and the poll/select family): 1 means re-enter the host call, 0
 * means surface EINTR so the dispatcher delivers the signal. The
 * recorded SIGCHLD is polled first. A host EINTR is retried only when
 * it was spurious, i.e. no unblocked deliverable signal is pending:
 * neither a queued guest handler (even one carrying SA_RESTART, which
 * must still run before any restart) nor a fatal/stop SIG_DFL signal.
 * Surfacing EINTR runs the handler immediately, which also keeps the
 * self-pipe idiom (SA_RESTART handler writing a byte the blocked
 * poll/read waits for) from deadlocking. */
int mips64_host_eintr_retry(mips64_ctx_t *ctx)
{
    uint32_t i;

    if (ctx == NULL) {
        return 0;
    }
    mips64_host_sigchld_poll(ctx);
    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t slot = (ctx->pend_head + i) % 16U;
        uint32_t s = ctx->pend_queue[slot].signo;
        unsigned word;
        uint64_t bit;
        uint64_t handler;

        /* sigactions[] has 129 slots (index 1..128 valid): out-of-range
         * queue entries (padding/corruption) never index the table. */
        if (s < 1U || s > 128U) {
            continue;
        }
        if (s == 9U || s == 23U) {
            return 0; /* KILL/STOP are unblockable and fatal/stop. */
        }
        word = (s - 1U) / 64U;
        bit = UINT64_C(1) << ((s - 1U) % 64U);
        if ((ctx->sig_blocked[word] & bit) != 0U) {
            continue;
        }
        handler = ctx->sigactions[s].handler;
        if (handler >= 2U) {
            return 0;
        }
        if (handler == 0U && !sc_default_ignore((int)s)) {
            return 0; /* Unblocked fatal/stop SIG_DFL. */
        }
    }
    return 1;
}

/* Whether a queued signal with a guest handler is unblocked under
 * mask (the wakeup test of a sigmask-taking wait). */
int mips64_sig_deliverable(const mips64_ctx_t *ctx, const uint64_t mask[2])
{
    uint32_t i;

    if (ctx == NULL) {
        return 0;
    }
    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t s = ctx->pend_queue[(ctx->pend_head + i) % 16U].signo;

        /* Same 1..128 bound as above: sigactions[] index stays in range. */
        if (s >= 1U && s <= 128U && ctx->sigactions[s].handler >= 2U &&
            (mask[(s - 1U) / 64U] &
             (UINT64_C(1) << ((s - 1U) % 64U))) == 0U) {
            return 1;
        }
    }
    return 0;
}

/* Delivery seams owned by lane L4a (src/os/sigact.c, src/os/sigframe.c).
 * Weak no-op fallbacks for TU lists without the lane (u0 gates link
 * this TU alone): no handler, never delivered. The strong lane
 * definitions win in the full binary; the unit gate overrides them
 * with recording stubs (same pattern as mips_threads_wake_sigchld_peer
 * above). */
__attribute__((weak)) int mips_signal_has_handler(int signo)
{
    (void)signo;
    return 0;
}

__attribute__((weak)) int mips_raise_guest(mips64_ctx_t *ctx, int signo,
                                           uint64_t fault_addr)
{
    (void)ctx;
    (void)signo;
    (void)fault_addr;
    return 1;
}

/* Guest SA_RESTART (MIPS arch/mips/kernel/signal.c): 1 when nr names
 * a restartable guest syscall, 0 for the waits the kernel never
 * restarts (poll/ppoll/select/pselect6, epoll_wait/epoll_pwait/
 * epoll_pwait2, pause, rt_sigsuspend, nanosleep/clock_nanosleep and
 * their N32 time64 companions, futex incl. its N32 time64 number,
 * rt_sigtimedwait). Every other guest syscall that can surface -EINTR
 * (read/write/vec/pread/pwrite, wait4/waitid, ioctl, ...) restarts
 * after rt_sigreturn when the delivered handler carries
 * MIPS64_SA_RESTART. The futex 0 here is the conservative no-arg
 * answer; the deliver_pending sweep below still restarts an untimed
 * FUTEX_WAIT under SA_RESTART (the only futex wait Linux restarts). */
int mips64_syscall_restartable(uint64_t nr, int is_n32)
{
    uint64_t base = (uint64_t)(is_n32 ? 6000 : 5000);

    /* poll(7) and _newselect(22) share the Linux base on both ABIs. */
    if (nr == base + 7U || nr == base + 22U) {
        return 0;
    }
    /* pause(33, -ERESTARTNOHAND) and rt_sigsuspend(128,
     * -ERESTARTNOHAND) are never restarted after a handler runs, even
     * with SA_RESTART (Linux arch/mips/kernel/signal.c). Index 127 is
     * rt_sigqueueinfo (see syscall_nr.h): it never blocks, so "never
     * restarted" holds for it too; listing it keeps the whole suspend
     * neighborhood non-restartable. pause/rt_sigsuspend carry no
     * syscall_nr.h define, so base + index (as above) names them. */
    if (nr == base + 33U || nr == base + 127U || nr == base + 128U) {
        return 0;
    }
    /* epoll_wait / epoll_pwait (defines in syscall_nr.h) and
     * epoll_pwait2 (index 441, no header define yet): Linux ep_poll
     * returns plain -EINTR, never restarted by SA_RESTART. */
    if (nr == (uint64_t)(is_n32 ? MIPS64_NR32_epoll_wait
                                : MIPS64_NR_epoll_wait) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_epoll_pwait
                                : MIPS64_NR_epoll_pwait) ||
        nr == base + 441U) {
        return 0;
    }
    if (nr == (uint64_t)(is_n32 ? MIPS64_NR32_nanosleep
                                : MIPS64_NR_nanosleep) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_clock_nanosleep
                                : MIPS64_NR_clock_nanosleep) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_pselect6
                                : MIPS64_NR_pselect6) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_ppoll : MIPS64_NR_ppoll) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_futex : MIPS64_NR_futex) ||
        nr == (uint64_t)(is_n32 ? MIPS64_NR32_rt_sigtimedwait
                                : MIPS64_NR_rt_sigtimedwait)) {
        return 0;
    }
    /* N32-only time64 companions (no N64 collision). */
    if (nr == (uint64_t)MIPS64_NR32_clock_nanosleep_time64 ||
        nr == (uint64_t)MIPS64_NR32_futex_time64) {
        return 0;
    }
    return 1;
}

/* Restart verdict for the deliver_pending sweep: the conservative
 * mips64_syscall_restartable answer, plus the untimed-FUTEX_WAIT
 * exception. The futex number alone cannot decide (op and timeout
 * live in the entry regs), so the no-arg query keeps futex
 * non-restartable while this sweep restarts an untimed FUTEX_WAIT
 * under SA_RESTART: entry $a1 is the futex op (untouched by dispatch)
 * and orig_a3 is the timeout pointer (low 32 bits on N32), matching
 * Linux kernel/futex/waitwake.c (-ERESTARTSYS when !to, EINTR via
 * -ERESTART_RESTARTBLOCK when timed or FUTEX_WAIT_BITSET). */
static int sc_restartable(mips64_ctx_t *ctx, uint64_t orig_v0,
                          uint64_t orig_a3)
{
    int n32 = ctx->is_n32 != 0U;

    if (orig_v0 == (uint64_t)MIPS64_NR_futex ||
        orig_v0 == (uint64_t)MIPS64_NR32_futex ||
        orig_v0 == (uint64_t)MIPS64_NR32_futex_time64) {
        uint32_t op = (uint32_t)ctx->gpr[MIPS64_REG_A1];
        int no_timeout = n32 ? (uint32_t)orig_a3 == 0U : orig_a3 == 0U;

        if (((op & 0x7fU) == 0U) && no_timeout) {
            return 1;
        }
        return 0;
    }
    return mips64_syscall_restartable(orig_v0, n32);
}

/* Syscall-exit pending-signal sweep (both engines observe the
 * redirected pc via their pc-moved checks). The interrupted syscall
 * already completed, so pc advances past it before the frame is built
 * (sc_pc resumes after the syscall) — except for a guest SA_RESTART
 * restart: when the raw result is -EINTR on a restartable syscall and
 * the delivered handler carries MIPS64_SA_RESTART, the entry regs
 * ($v0 = syscall number, $a3 = fourth arg, clobbered by the -EINTR
 * writeback) are restored and pc stays on the syscall, so the frame's
 * sigcontext re-executes it after rt_sigreturn, like Linux. */
void mips64_sc_deliver_pending(mips64_ctx_t *ctx, uint64_t orig_v0,
                               uint64_t orig_a3, int64_t raw_rc)
{
    uint32_t i;

    if (ctx == NULL || ctx->pend_count == 0U) {
        return;
    }
    for (i = 0U; i < ctx->pend_count; i++) {
        uint32_t slot = (ctx->pend_head + i) % 16U;
        int signo = (int)ctx->pend_queue[slot].signo;
        unsigned w;
        uint64_t bit;
        uint64_t ev0;
        uint64_t ea3;

        if (signo < 1 || signo > 128) {
            continue;
        }
        if (mips_signal_has_handler(signo) == 0) {
            continue;
        }
        w = (unsigned)(signo - 1) / 64U;
        bit = (uint64_t)1U << ((unsigned)(signo - 1) % 64U);
        if ((ctx->sig_blocked[w] & bit) != 0U) {
            continue;
        }
        if (raw_rc == -(int64_t)EINTR &&
            sc_restartable(ctx, orig_v0, orig_a3) &&
            (ctx->sigactions[signo].flags & MIPS64_SA_RESTART) != 0U) {
            ev0 = ctx->gpr[MIPS64_REG_V0];
            ea3 = ctx->gpr[MIPS64_REG_A3];
            ctx->gpr[MIPS64_REG_V0] = orig_v0;
            ctx->gpr[MIPS64_REG_A3] = orig_a3;
            if (mips_raise_guest(ctx, signo,
                                 ctx->pend_queue[slot].addr) == 0) {
                return;
            }
            /* Frame refused: report -EINTR after the syscall. */
            ctx->gpr[MIPS64_REG_V0] = ev0;
            ctx->gpr[MIPS64_REG_A3] = ea3;
            ctx->pc += 4U;
            ctx->next_pc = ctx->pc + 4U;
            break;
        }
        ctx->pc += 4U; /* syscall done; resume after it on sigreturn */
        ctx->next_pc = ctx->pc + 4U;
        if (mips_raise_guest(ctx, signo,
                             ctx->pend_queue[slot].addr) == 0) {
            return;
        }
        break;
    }
}
