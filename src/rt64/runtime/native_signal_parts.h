/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_NATIVE_SIGNAL_PARTS_H
#define MIPS64RT_NATIVE_SIGNAL_PARTS_H

#define _GNU_SOURCE
#include "runtime/native_signal.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

typedef struct {
    _Atomic unsigned int state; /* 0 empty, 1 filling, 2 published */
    mips64_native_signal_event_t event;
    uint64_t child_generation;
} mips64_native_signal_slot_t;

struct mips64_native_signal_process {
    sigset_t carriers;
    sigset_t original_mask;
    struct sigaction original_actions[4];
    unsigned int actions_installed;
    unsigned int carrier_count;
    int stop_signal;
    _Atomic mips64_native_child_policy_t child_policy;
    _Atomic uint64_t child_generation;
    pthread_mutex_t registration_lock;
    pid_t local_pid;
    mips64_native_signal_fork_freeze_t *freeze; /* Protected by registration_lock. */
    uint64_t freeze_generation;
    mips64_native_signals_t *workers;
    bool stopped; /* Protected by registration_lock; closes attach/stop race. */
    pthread_t creator;
    int creator_cancel_state;
    bool exec_resume;
    bool resume_guest_child_blocked;
    bool child_action_changed;
    bool mask_saved;
    bool teardown_only;
    _Atomic unsigned int attached_workers;
    uint64_t initial_mask;
    uint64_t initial_ignored;
};

struct mips64_native_signal_fork_freeze {
    mips64_native_signal_process_t *process;
    mips64_native_signals_t *survivor;
    pid_t parent_pid;
    pthread_t owner;
    uint64_t generation;
};

struct mips64_native_signals {
    mips64_native_signal_process_t *process;
    mips64_native_signals_t *registration_next;
    pthread_t owner;
    uint32_t guest_tid; /* Immutable after binding; protected by registration_lock. */
    int prior_cancel_state;
    sigset_t original_mask;
    bool creator_thread;
    bool pipe_active;
    bool child_guest_blocked;
    bool compatibility_owner;
    bool detached;
    bool teardown_only;
    stack_t original_stack;
    void *stack;
    size_t stack_size;
    bool stack_installed;
    bool open;
    mips64_native_signal_slot_t slots[5]; /* Four user lanes plus SIGCHLD. */
    _Atomic unsigned int wake;
    _Atomic unsigned int kick_pending; /* One private RT instance at most. */
    _Atomic unsigned int stop;
    _Atomic unsigned int syscall_origin;
};
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "native signal slots must be lock-free");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "native signal TLS must be lock-free");
_Static_assert(sizeof(unsigned int) == 4, "safe SVC latch geometry");
/* Cross-part prototypes (Phase 0 mechanical split). */

 bool mips64_native_signal_local_process(const mips64_native_signal_process_t *process);

 bool mips64_native_signal_local_worker(const mips64_native_signals_t *signals);

 int mips64_native_signal_lock_registration(mips64_native_signal_process_t *process);

 int mips64_native_signal_carrier_at(const mips64_native_signal_process_t *process,
                      unsigned int index);

 bool mips64_native_signal_child_default(mips64_native_child_policy_t policy);

 bool mips64_native_signal_child_uncaptured(const mips64_native_signal_process_t *process,
                             mips64_native_child_policy_t policy);

 void mips64_native_signal_child_reset_marker(int signal, siginfo_t *info, void *context);

 int take_pending_pipe(void);

 bool pipe_owner(mips64_native_signals_t *signals);

bool mips64_native_signals_pipe_begin(mips64_native_signals_t *signals,
                                   bool *previously_blocked);

int mips64_native_signals_take_pipe(mips64_native_signals_t *signals);

bool mips64_native_signals_pipe_end(mips64_native_signals_t *signals,
                                 bool previously_blocked);

 bool mips64_native_signal_restore_worker_stack(const mips64_native_signals_t *signals);

 void mips64_native_signal_capture(int signal, siginfo_t *info, void *context);

bool mips64_native_signals_block(mips64_native_signals_t *signals);

bool mips64_native_signals_enter(mips64_native_signals_t *signals);

bool mips64_native_signals_take(mips64_native_signals_t *signals,
                             mips64_native_signal_event_t *event);

_Atomic unsigned int *mips64_native_signals_wake(mips64_native_signals_t *signals);

_Atomic unsigned int *mips64_native_signals_syscall_origin(mips64_native_signals_t *signals);

uint64_t mips64_native_signals_initial_mask(const mips64_native_signals_t *signals);

uint64_t mips64_native_signals_initial_ignored(const mips64_native_signals_t *signals);

/* The creator owns global sigactions. A failed restore leaves this owner and
 * its cancellation-disabled state intact for a destroy-only retry. */
 bool mips64_native_signal_process_destroy_internal(mips64_native_signal_process_t *process,
                                     bool restore_cancellation);

bool mips64_native_signal_process_destroy(mips64_native_signal_process_t *process);

int mips64_native_signal_fork_freeze_begin(mips64_native_signal_process_t *process,
                                      mips64_native_signals_t *survivor,
                                      mips64_native_signal_fork_freeze_t **out);

bool mips64_native_signal_fork_freeze_end(mips64_native_signal_fork_freeze_t **owned);

 bool captured_scan(const mips64_native_signal_fork_freeze_t *seal,
                          mips64_native_signal_captured_t *records,
                          size_t *out_count);

bool mips64_native_signal_fork_captured_count(
    const mips64_native_signal_fork_freeze_t *seal, size_t *out_count);

bool mips64_native_signal_fork_captured_export(
    const mips64_native_signal_fork_freeze_t *seal,
    mips64_native_signal_captured_t *records, size_t capacity,
    size_t *out_count);

bool mips64_native_signal_fork_child_rebase(mips64_native_signal_process_t **owned,
                                        mips64_native_signals_t **surviving,
                                        mips64_native_signal_fork_freeze_t **sealed,
                                        uint32_t new_guest_tid);

 mips64_native_signal_process_t *process_create(bool exec_resume,
                                                  mips64_native_child_policy_t policy,
                                                  bool guest_child_blocked);

mips64_native_signal_process_t *mips64_native_signal_process_create(void);

mips64_native_signal_process_t *mips64_native_signal_process_create_exec(
    mips64_native_child_policy_t policy, bool guest_child_blocked);

bool mips64_native_signal_process_set_child_policy(
    mips64_native_signal_process_t *process, mips64_native_child_policy_t policy,
    bool discard_pending);

bool mips64_native_signal_process_reset_child_policy(
    mips64_native_signal_process_t *process, mips64_native_child_policy_t policy);

mips64_native_child_policy_t mips64_native_signal_process_child_policy(
    const mips64_native_signal_process_t *process);

bool mips64_native_signal_pending_child(mips64_native_signal_process_t *process);

bool mips64_native_signal_transition_block_child(mips64_native_signal_process_t *process);

bool mips64_native_signal_reconcile_child_mask(mips64_native_signal_process_t *process,
                                            bool guest_blocked);

mips64_native_signals_t *mips64_native_signal_worker_attach(mips64_native_signal_process_t *process);

bool mips64_native_signal_worker_bind_tid(mips64_native_signals_t *signals,
                                       uint32_t guest_tid);

bool mips64_native_signal_process_request_wake(mips64_native_signal_process_t *process,
                                            uint32_t guest_tid);

 bool mips64_native_signal_worker_detach_internal(mips64_native_signals_t *signals, bool free_worker);

bool mips64_native_signal_process_request_stop(mips64_native_signal_process_t *process);

bool mips64_native_signals_stop_requested(const mips64_native_signals_t *signals);

bool mips64_native_signal_worker_detach(mips64_native_signals_t *signals);

mips64_native_signals_t *mips64_native_signals_create(void);

bool mips64_native_signals_destroy(mips64_native_signals_t *signals);
/* Cross-part externs (Phase 0 mechanical split). */
extern #if defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <ucontext.h>
extern unsigned char mips64_native_safe_syscall_begin[];
extern  _Thread_local _Atomic(mips64_native_signals_t *) mips64_native_signal_native_signals;
extern  _Thread_local mips64_native_signal_fork_freeze_t *mips64_native_signal_native_fork_freeze;
extern  _Thread_local mips64_native_signal_process_t *mips64_native_signal_child_reset_process;
extern  _Thread_local volatile sig_atomic_t mips64_native_signal_child_reset_seen;
extern /* sigaction is process-wide; this one owner prevents competing installations.
 * mips64_native_signal_capture loads mips64_native_signal_process_owner. It also writes the slot, the wake latch,
 * and on aarch64 the safe-syscall PC. */
 _Atomic(mips64_native_signal_process_t *) mips64_native_signal_process_owner;
#endif /* MIPS64RT_NATIVE_SIGNAL_PARTS_H */
