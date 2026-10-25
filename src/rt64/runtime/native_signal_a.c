/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_signal_parts.h"
#if defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <ucontext.h>
extern unsigned char mips64_native_safe_syscall_begin[];
extern unsigned char mips64_native_safe_syscall_after_svc[];
extern unsigned char mips64_native_safe_syscall_abort[];
#endif

 _Thread_local _Atomic(mips64_native_signals_t *) mips64_native_signal_native_signals;
 _Thread_local mips64_native_signal_fork_freeze_t *mips64_native_signal_native_fork_freeze;
 _Thread_local mips64_native_signal_process_t *mips64_native_signal_child_reset_process;
 _Thread_local volatile sig_atomic_t mips64_native_signal_child_reset_seen;
/* sigaction is process-wide; this one owner prevents competing installations.
 * mips64_native_signal_capture loads mips64_native_signal_process_owner. It also writes the slot, the wake latch,
 * and on aarch64 the safe-syscall PC. */
 _Atomic(mips64_native_signal_process_t *) mips64_native_signal_process_owner;

 bool mips64_native_signal_local_process(const mips64_native_signal_process_t *process)
{
    return process != NULL && atomic_load(&mips64_native_signal_process_owner) == process &&
           process->local_pid == getpid();
}

 bool mips64_native_signal_local_worker(const mips64_native_signals_t *signals)
{
    return signals != NULL && atomic_load(&mips64_native_signal_native_signals) == signals &&
           mips64_native_signal_local_process(signals->process) &&
           pthread_equal(signals->owner, pthread_self()) != 0;
}

 int mips64_native_signal_lock_registration(mips64_native_signal_process_t *process)
{
    /* Only the seal owner can observe its token without acquiring this lock.
     * Other threads wait normally until parent thaw; no shared token pointer
     * is dereferenced outside registration_lock. */
    if (mips64_native_signal_native_fork_freeze != NULL && mips64_native_signal_native_fork_freeze->process == process)
        return EBUSY;
    return pthread_mutex_lock(&process->registration_lock);
}

 int mips64_native_signal_carrier_at(const mips64_native_signal_process_t *process,
                      unsigned int index)
{
    if (index == 0) return SIGUSR1;
    if (index == 1) return SIGUSR2;
    if (index == 2 && process->stop_signal != 0) return process->stop_signal;
    return SIGCHLD;
}

 bool mips64_native_signal_child_default(mips64_native_child_policy_t policy)
{
    return policy == MIPS64_NATIVE_CHILD_DEFAULT ||
           policy == MIPS64_NATIVE_CHILD_DEFAULT_NOCLDWAIT;
}

 bool mips64_native_signal_child_uncaptured(const mips64_native_signal_process_t *process,
                             mips64_native_child_policy_t policy)
{
    return mips64_native_signal_child_default(policy) ||
           (process->exec_resume && policy == MIPS64_NATIVE_CHILD_IGNORED);
}

 void mips64_native_signal_child_reset_marker(int signal, siginfo_t *info, void *context)
{
    (void)context;
    if (signal != SIGCHLD || info == NULL || mips64_native_signal_child_reset_process == NULL ||
        info->si_pid != mips64_native_signal_child_reset_process->local_pid ||
#if defined(__linux__)
        info->si_code != SI_TKILL ||
#endif
        mips64_native_signal_child_reset_seen != 0)
        _exit(125);
    mips64_native_signal_child_reset_seen = 1;
}

static int take_pending_pipe(void)
{
    sigset_t only_pipe;
    sigemptyset(&only_pipe);
    sigaddset(&only_pipe, SIGPIPE);
#if defined(__linux__)
    const struct timespec zero = {0, 0};
    int result = sigtimedwait(&only_pipe, NULL, &zero);
    if (result == SIGPIPE)
        return 1;
    if (result < 0 && errno == EAGAIN)
        return 0;
#else
    /* Native Darwin units have no sigtimedwait. The production Linux path
     * above uses an atomic zero-time dequeue on the blocked owner thread. */
    sigset_t pending;
    if (sigpending(&pending) != 0)
        return -1;
    if (sigismember(&pending, SIGPIPE) == 0)
        return 0;
    int result = 0;
    int error = sigwait(&only_pipe, &result);
    if (error != 0) {
        errno = error;
        return -1;
    }
    if (result == SIGPIPE)
        return 1;
#endif
    if (result >= 0)
        errno = EIO;
    return -1;
}

static bool pipe_owner(mips64_native_signals_t *signals)
{
    return mips64_native_signal_local_worker(signals) && mips64_native_signal_native_fork_freeze == NULL && !signals->open &&
           !signals->teardown_only && !signals->process->teardown_only;
}

bool mips64_native_signals_pipe_begin(mips64_native_signals_t *signals,
                                   bool *previously_blocked)
{
    if (!pipe_owner(signals) || signals->pipe_active || previously_blocked == NULL) {
        errno = EINVAL;
        return false;
    }
    sigset_t only_pipe, old;
    sigemptyset(&only_pipe);
    sigaddset(&only_pipe, SIGPIPE);
    int error = pthread_sigmask(SIG_BLOCK, &only_pipe, &old);
    if (error != 0) {
        errno = error;
        return false;
    }
    *previously_blocked = sigismember(&old, SIGPIPE) == 1;
    signals->pipe_active = true;
    return true;
}

int mips64_native_signals_take_pipe(mips64_native_signals_t *signals)
{
    if (!pipe_owner(signals)) {
        errno = EINVAL;
        return -1;
    }
    sigset_t current;
    int error = pthread_sigmask(SIG_BLOCK, NULL, &current);
    if (error != 0 || sigismember(&current, SIGPIPE) != 1) {
        errno = error != 0 ? error : EINVAL;
        return -1;
    }
    return take_pending_pipe();
}

bool mips64_native_signals_pipe_end(mips64_native_signals_t *signals,
                                 bool previously_blocked)
{
    if (!pipe_owner(signals) || !signals->pipe_active) {
        errno = EINVAL;
        return false;
    }
    if (previously_blocked) {
        signals->pipe_active = false;
        return true;
    }
    sigset_t only_pipe;
    sigemptyset(&only_pipe);
    sigaddset(&only_pipe, SIGPIPE);
    int error = pthread_sigmask(SIG_UNBLOCK, &only_pipe, NULL);
    if (error != 0) {
        errno = error;
        return false;
    }
    signals->pipe_active = false;
    return true;
}

 bool mips64_native_signal_restore_worker_stack(const mips64_native_signals_t *signals)
{
    stack_t original = signals->original_stack;
#if defined(__APPLE__)
    /* Darwin validates ss_size even for SS_DISABLE, while a newly created
     * pthread reports disabled storage with size zero. Reuse the still-live
     * installed buffer for that disabling call; free it only afterward. */
    if ((original.ss_flags & SS_DISABLE) != 0 && original.ss_size == 0) {
        original.ss_sp = signals->stack;
        original.ss_size = signals->stack_size;
    }
#endif
    return sigaltstack(&original, NULL) == 0;
}

 void mips64_native_signal_capture(int signal, siginfo_t *info, void *context)
{
    int saved_errno = errno;
    mips64_native_signals_t *signals = atomic_load_explicit(&mips64_native_signal_native_signals,
                                                       memory_order_acquire);
    if (signals == NULL || info == NULL || !mips64_native_signal_local_process(signals->process))
        _exit(125);
    bool internal_carrier = signal == signals->process->stop_signal &&
                            signals->process->stop_signal != 0;
    bool child_carrier = signal == SIGCHLD;
    if (internal_carrier) {
        atomic_store_explicit(&signals->kick_pending, 0, memory_order_release);
        atomic_store_explicit(&signals->wake, 1, memory_order_release);
    } else if (((signal != SIGUSR1 && signal != SIGUSR2) && !child_carrier) ||
               info->si_pid <= 0) {
        _exit(125);
    }
    /* This first component accepts kill/tkill origins. Queued payloads and
     * other native classes need their own full siginfo codec. */
    int32_t code = info->si_code;
    uint64_t child_generation = child_carrier ?
        atomic_load_explicit(&signals->process->child_generation,
                             memory_order_acquire) : 0;
    if (!internal_carrier) {
#if defined(__APPLE__)
    if (code == SI_USER) code = 0;
#endif
    if (child_carrier ?
        (code != CLD_EXITED && code != CLD_KILLED && code != CLD_DUMPED) :
        (code != 0 && code != -6))
        _exit(125);
    unsigned int index = child_carrier ? 4U :
                         (signal == SIGUSR1 ? 0U : 1U) +
                         (code == -6 ? 2U : 0U);
    mips64_native_signal_slot_t *slot = &signals->slots[index];
    unsigned int empty = 0;
    if (atomic_compare_exchange_strong_explicit(&slot->state, &empty, 1,
                                                memory_order_relaxed,
                                                memory_order_relaxed)) {
        slot->event = (mips64_native_signal_event_t){
            .signal = child_carrier ? 17U : (signal == SIGUSR1 ? 10U : 12U),
            .code = code, .pid = (int32_t)info->si_pid,
            .uid = (uint32_t)info->si_uid,
            .status = child_carrier ? (int32_t)info->si_status : 0
        };
        slot->child_generation = child_generation;
        atomic_store_explicit(&slot->state, 2, memory_order_release);
    }
    atomic_store_explicit(&signals->wake, 1, memory_order_release);
    }
#if defined(__linux__) && defined(__aarch64__)
    bool stopping = internal_carrier &&
        atomic_load_explicit(&signals->stop, memory_order_acquire) != 0;
    ucontext_t *frame = context;
    if (frame == NULL)
        _exit(125);
    uintptr_t pc = (uintptr_t)frame->uc_mcontext.pc;
    if (pc >= (uintptr_t)mips64_native_safe_syscall_begin &&
        pc < (uintptr_t)mips64_native_safe_syscall_after_svc) {
        if (!stopping)
            atomic_store_explicit(&signals->syscall_origin, 1, memory_order_release);
        frame->uc_mcontext.pc = (uintptr_t)mips64_native_safe_syscall_abort;
    } else if (pc == (uintptr_t)mips64_native_safe_syscall_after_svc &&
               frame->uc_mcontext.regs[0] == UINT64_C(0) - 4) {
        if (!stopping)
            atomic_store_explicit(&signals->syscall_origin, 1, memory_order_release);
    }
#else
    (void)context;
#endif
    errno = saved_errno;
}

bool mips64_native_signals_block(mips64_native_signals_t *signals)
{
    if (!mips64_native_signal_local_worker(signals)) {
        errno = EINVAL;
        return false;
    }
    sigset_t to_block = signals->process->carriers;
    if (mips64_native_signal_child_uncaptured(signals->process,
            atomic_load_explicit(&signals->process->child_policy,
                                 memory_order_acquire)) &&
        !signals->child_guest_blocked)
        sigdelset(&to_block, SIGCHLD);
    int error = pthread_sigmask(SIG_BLOCK, &to_block, NULL);
    if (error != 0) {
        errno = error;
        return false;
    }
    error = mips64_native_signal_lock_registration(signals->process);
    if (error != 0) {
        errno = error;
        return false;
    }
    signals->open = false;
    if (pthread_mutex_unlock(&signals->process->registration_lock) != 0)
        _exit(125);
    return true;
}

bool mips64_native_signals_enter(mips64_native_signals_t *signals)
{
    if (!mips64_native_signal_local_worker(signals) ||
        signals->teardown_only || signals->process->teardown_only ||
        signals->process->actions_installed != signals->process->carrier_count ||
        !signals->stack_installed) {
        errno = EINVAL;
        return false;
    }
    int error = mips64_native_signal_lock_registration(signals->process);
    if (error != 0) {
        errno = error;
        return false;
    }
    /* Seal and open publication share the lock. No new mips64_native_signal_capture can start
     * between a successful all-closed check and native fork. The handler
     * itself never takes this lock, even if delivery occurs in sigmask. */
    signals->open = true;
    sigset_t to_unblock = signals->process->carriers;
    if (mips64_native_signal_child_uncaptured(signals->process,
            atomic_load_explicit(&signals->process->child_policy,
                                 memory_order_acquire)) &&
        signals->child_guest_blocked)
        sigdelset(&to_unblock, SIGCHLD);
    error = pthread_sigmask(SIG_UNBLOCK, &to_unblock, NULL);
    if (error != 0) {
        signals->open = false;
        if (pthread_mutex_unlock(&signals->process->registration_lock) != 0)
            _exit(125);
        errno = error;
        return false;
    }
    if (pthread_mutex_unlock(&signals->process->registration_lock) != 0)
        _exit(125);
    return true;
}

bool mips64_native_signals_take(mips64_native_signals_t *signals,
                             mips64_native_signal_event_t *event)
{
    if (!mips64_native_signal_local_worker(signals) || event == NULL || signals->open ||
        signals->teardown_only || signals->process->teardown_only ||
        signals->process->actions_installed != signals->process->carrier_count) {
        errno = EINVAL;
        return false;
    }
    sigset_t current;
    int error = pthread_sigmask(SIG_BLOCK, NULL, &current);
    if (error != 0 || sigismember(&current, SIGUSR1) != 1 ||
        sigismember(&current, SIGUSR2) != 1 ||
        (!mips64_native_signal_child_uncaptured(signals->process,
             atomic_load_explicit(&signals->process->child_policy,
                                  memory_order_acquire)) &&
         sigismember(&current, SIGCHLD) != 1) ||
        (signals->process->stop_signal != 0 &&
         sigismember(&current, signals->process->stop_signal) != 1)) {
        errno = error != 0 ? error : EINVAL;
        return false;
    }
    bool found = false;
    bool remaining = false;
    for (unsigned int i = 0; i < 5; ++i) {
        /* Preserve independent directed/shared pending instances, with the
         * directed queue inspected first, as in guest dequeue_signal. */
        mips64_native_signal_slot_t *slot = &signals->slots[i == 4 ? 4 : (i + 2) % 4];
        unsigned int state = atomic_load_explicit(&slot->state, memory_order_acquire);
        if (state != 0 && state != 2) {
            errno = EIO; /* No handler can be filling on this blocked thread. */
            return false;
        }
        if (state != 2)
            continue;
        if (slot == &signals->slots[4] &&
            slot->child_generation != atomic_load_explicit(
                &signals->process->child_generation, memory_order_acquire)) {
            atomic_store_explicit(&slot->state, 0, memory_order_release);
            continue;
        }
        if (!found) {
            *event = slot->event;
            atomic_store_explicit(&slot->state, 0, memory_order_release);
            found = true;
        } else {
            remaining = true;
        }
    }
    (void)atomic_exchange_explicit(&signals->wake, remaining ? 1U : 0U,
                                   memory_order_acq_rel);
    /* A concurrent request_stop publishes stop before wake. Never erase that
     * persistent notification while clearing a guest-signal mailbox slot. */
    if (atomic_load_explicit(&signals->stop, memory_order_acquire) != 0)
        atomic_store_explicit(&signals->wake, 1, memory_order_release);
    errno = 0; /* Distinguish an empty mailbox from misuse. */
    return found;
}

_Atomic unsigned int *mips64_native_signals_wake(mips64_native_signals_t *signals)
{
    if (!mips64_native_signal_local_worker(signals) ||
        signals->teardown_only || signals->process->teardown_only) {
        errno = EINVAL;
        return NULL;
    }
    return &signals->wake;
}

_Atomic unsigned int *mips64_native_signals_syscall_origin(mips64_native_signals_t *signals)
{
    if (!mips64_native_signal_local_worker(signals) ||
        signals->teardown_only || signals->process->teardown_only) {
        errno = EINVAL;
        return NULL;
    }
    return &signals->syscall_origin;
}

uint64_t mips64_native_signals_initial_mask(const mips64_native_signals_t *signals)
{
    return !mips64_native_signal_local_worker(signals) ?
           0 : signals->process->initial_mask;
}

uint64_t mips64_native_signals_initial_ignored(const mips64_native_signals_t *signals)
{
    return !mips64_native_signal_local_worker(signals) ?
           0 : signals->process->initial_ignored;
}

/* The creator owns global sigactions. A failed restore leaves this owner and
 * its cancellation-disabled state intact for a destroy-only retry. */
 bool mips64_native_signal_process_destroy_internal(mips64_native_signal_process_t *process,
                                     bool restore_cancellation)
{
    if (!mips64_native_signal_local_process(process) ||
        !pthread_equal(process->creator, pthread_self())) {
        errno = EINVAL;
        return false;
    }
    if (atomic_load_explicit(&process->attached_workers, memory_order_acquire) != 0) {
        errno = EBUSY;
        return false;
    }
    process->teardown_only = true;
    if (process->mask_saved) {
        sigset_t to_block = process->carriers;
        if (process->exec_resume)
            sigdelset(&to_block, SIGCHLD);
        int error = pthread_sigmask(SIG_BLOCK, &to_block, NULL);
        if (error != 0) {
            errno = error;
            return false;
        }
        /* A child may have been reaped before its blocked native carrier was
         * delivered. Do not release that stale notification to the creator's
         * restored disposition after the translator's guest owner is gone. */
        if (!process->exec_resume) {
            sigset_t child_only;
            sigemptyset(&child_only);
            sigaddset(&child_only, SIGCHLD);
            for (;;) {
#if defined(__linux__)
                const struct timespec no_wait = {0};
                int caught = sigtimedwait(&child_only, NULL, &no_wait);
#else
                sigset_t pending;
                if (sigpending(&pending) != 0)
                return false;
                if (sigismember(&pending, SIGCHLD) != 1)
                    break;
                int caught = 0;
                int wait_error = sigwait(&child_only, &caught);
                if (wait_error != 0) {
                    errno = wait_error;
                    return false;
                }
#endif
                if (caught == SIGCHLD)
                    continue;
                if (caught < 0 && errno == EINTR)
                    continue;
                if (caught < 0 && errno == EAGAIN)
                    break;
                return false;
            }
        }
    }
    while (process->actions_installed != 0) {
        unsigned int index = process->actions_installed - 1;
        if (!(process->exec_resume && mips64_native_signal_carrier_at(process, index) == SIGCHLD &&
              !process->child_action_changed) &&
            sigaction(mips64_native_signal_carrier_at(process, index),
                      &process->original_actions[index], NULL) != 0)
            return false;
        process->actions_installed = index;
    }
    if (process->mask_saved) {
        int error = pthread_sigmask(SIG_SETMASK, &process->original_mask, NULL);
        if (error != 0) {
            errno = error;
            return false; /* Retry with owner and cancellation state retained. */
        }
        process->mask_saved = false;
    }
    int old_cancel_state = process->creator_cancel_state;
    atomic_store_explicit(&mips64_native_signal_process_owner, NULL, memory_order_release);
    if (pthread_mutex_destroy(&process->registration_lock) != 0)
        _exit(125);
    free(process);
    if (restore_cancellation &&
        pthread_setcancelstate(old_cancel_state, NULL) != 0)
        _exit(125);
    return true;
}

bool mips64_native_signal_process_destroy(mips64_native_signal_process_t *process)
{
    return mips64_native_signal_process_destroy_internal(process, true);
}

int mips64_native_signal_fork_freeze_begin(mips64_native_signal_process_t *process,
                                      mips64_native_signals_t *survivor,
                                      mips64_native_signal_fork_freeze_t **out)
{
    if (out == NULL || *out != NULL || !mips64_native_signal_local_worker(survivor) ||
        survivor->process != process || survivor->open || survivor->pipe_active ||
        survivor->detached || survivor->teardown_only || process->teardown_only ||
        process->actions_installed != process->carrier_count) {
        errno = EINVAL;
        return -1;
    }
    sigset_t mask;
    int error = pthread_sigmask(SIG_BLOCK, NULL, &mask);
    if (error != 0) {
        errno = error;
        return -1;
    }
    for (unsigned int i = 0; i < process->carrier_count; ++i)
        if (!(mips64_native_signal_carrier_at(process, i) == SIGCHLD &&
              mips64_native_signal_child_uncaptured(process,
                  atomic_load_explicit(&process->child_policy,
                                       memory_order_acquire)) &&
              !survivor->child_guest_blocked) &&
            sigismember(&mask, mips64_native_signal_carrier_at(process, i)) != 1) {
            errno = EINVAL;
            return -1;
        }
    error = mips64_native_signal_lock_registration(process);
    if (error != 0) {
        errno = error;
        return -1;
    }
    int failure = 0;
    bool busy = false, found = false;
    uint32_t count = 0;
    for (mips64_native_signals_t *worker = process->workers; worker != NULL;
         worker = worker->registration_next) {
        if (count == UINT32_MAX || worker->process != process ||
            worker->detached || worker->teardown_only || !worker->stack_installed) {
            failure = EINVAL;
            break;
        }
        ++count;
        found = found || worker == survivor;
        busy = busy || worker->open;
        for (unsigned int i = 0; i < 5; ++i)
            busy = busy || atomic_load_explicit(&worker->slots[i].state,
                                                memory_order_acquire) == 1;
    }
    if (!found || count != atomic_load_explicit(&process->attached_workers,
                                                 memory_order_acquire))
        failure = EINVAL;
    if (process->stopped)
        failure = ECANCELED;
    if (process->freeze_generation == UINT64_MAX)
        failure = EOVERFLOW;
    if (failure != 0 || busy) {
        if (pthread_mutex_unlock(&process->registration_lock) != 0)
            _exit(125);
        errno = failure != 0 ? failure : EBUSY;
        return failure != 0 ? -1 : 0;
    }
    mips64_native_signal_fork_freeze_t *freeze = calloc(1, sizeof(*freeze));
    if (freeze == NULL) {
        int saved = errno;
        if (pthread_mutex_unlock(&process->registration_lock) != 0)
            _exit(125);
        errno = saved;
        return -1;
    }
    freeze->process = process;
    freeze->survivor = survivor;
    freeze->parent_pid = getpid();
    freeze->owner = pthread_self();
    freeze->generation = ++process->freeze_generation;
    process->freeze = freeze;
    mips64_native_signal_native_fork_freeze = freeze;
    *out = freeze;
    return 1; /* Keep registration_lock held through fork or parent abort. */
}

bool mips64_native_signal_fork_freeze_end(mips64_native_signal_fork_freeze_t **owned)
{
    if (owned == NULL || *owned == NULL || mips64_native_signal_native_fork_freeze != *owned) {
        errno = EINVAL;
        return false;
    }
    mips64_native_signal_fork_freeze_t *freeze = *owned;
    if (freeze->parent_pid != getpid() || !mips64_native_signal_local_process(freeze->process) ||
        !pthread_equal(freeze->owner, pthread_self()) ||
        freeze->process->freeze != freeze ||
        freeze->generation != freeze->process->freeze_generation) {
        errno = EINVAL;
        return false;
    }
    mips64_native_signal_process_t *process = freeze->process;
    process->freeze = NULL;
    mips64_native_signal_native_fork_freeze = NULL;
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    *owned = NULL;
    free(freeze);
    return true;
}

static bool captured_scan(const mips64_native_signal_fork_freeze_t *seal,
                          mips64_native_signal_captured_t *records,
                          size_t *out_count)
{
    if (seal == NULL || out_count == NULL || mips64_native_signal_native_fork_freeze != seal ||
        seal->parent_pid != getpid() || !mips64_native_signal_local_process(seal->process) ||
        !pthread_equal(seal->owner, pthread_self()) ||
        seal->process->freeze != seal ||
        seal->generation != seal->process->freeze_generation ||
        seal->survivor == NULL || !mips64_native_signal_local_worker(seal->survivor) ||
        seal->survivor->open || seal->survivor->pipe_active) {
        errno = EINVAL;
        return false;
    }
    mips64_native_signal_process_t *process = seal->process;
    uint32_t attached = atomic_load_explicit(&process->attached_workers,
                                              memory_order_acquire);
    uint64_t child_generation = atomic_load_explicit(
        &process->child_generation, memory_order_acquire);
    size_t visited = 0, selected = 0;
    bool survivor_found = false;
    for (mips64_native_signals_t *worker = process->workers; worker != NULL;
         worker = worker->registration_next) {
        if (visited == attached || worker->process != process ||
            worker->detached || worker->teardown_only || worker->open) {
            errno = EINVAL;
            return false;
        }
        ++visited;
        survivor_found = survivor_found || worker == seal->survivor;
        for (unsigned int i = 0; i < 5; ++i) {
            mips64_native_signal_slot_t *slot = &worker->slots[i];
            unsigned int state = atomic_load_explicit(&slot->state,
                                                        memory_order_acquire);
            if (state != 0 && state != 2) {
                errno = EBUSY;
                return false;
            }
            if (state != 2 || ((i == 2 || i == 3) && worker != seal->survivor) ||
                (i == 4 && slot->child_generation != child_generation))
                continue;
            if (selected == SIZE_MAX) {
                errno = EOVERFLOW;
                return false;
            }
            if (records != NULL)
                records[selected] = (mips64_native_signal_captured_t){
                    .event = slot->event,
                    .process_directed = i < 2 || i == 4
                };
            ++selected;
        }
    }
    if (!survivor_found || visited != attached) {
        errno = EINVAL;
        return false;
    }
    *out_count = selected;
    return true;
}

bool mips64_native_signal_fork_captured_count(
    const mips64_native_signal_fork_freeze_t *seal, size_t *out_count)
{
    return captured_scan(seal, NULL, out_count);
}

bool mips64_native_signal_fork_captured_export(
    const mips64_native_signal_fork_freeze_t *seal,
    mips64_native_signal_captured_t *records, size_t capacity,
    size_t *out_count)
{
    size_t required = 0;
    if (!captured_scan(seal, NULL, &required))
        return false;
    if (out_count == NULL || capacity < required ||
        (required != 0 && records == NULL)) {
        errno = capacity < required ? ENOSPC : EINVAL;
        return false;
    }
    /* The held registration seal and blocked mips64_native_signal_capture windows make this
     * second scan stable. Only now may caller memory be written. */
    size_t written = 0;
    if (!captured_scan(seal, records, &written))
        _exit(125);
    if (written != required)
        _exit(125);
    *out_count = written;
    return true;
}
