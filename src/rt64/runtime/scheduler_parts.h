/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_SCHEDULER_PARTS_H
#define MIPS64RT_SCHEDULER_PARTS_H

#include "runtime/scheduler.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum {
    MIPS64_TICKET_RUNNABLE,
    MIPS64_TICKET_SELECTED,
    MIPS64_TICKET_RUNNING,
    MIPS64_TICKET_BLOCKED,
    MIPS64_TICKET_SUSPENDED,
    MIPS64_TICKET_OWNER_WAIT,
    MIPS64_TICKET_DEAD
} ticket_phase_t;

struct mips64_sched_ticket {
    mips64_scheduler_t *scheduler;
    mips64_sched_ticket_t *all_next;
    mips64_sched_ticket_t *queue_next;
    pthread_t owner;
    ticket_phase_t phase;
    uint32_t remaining;
    unsigned int sequence_length;
    bool attached;
    bool queued;
    bool io_inflight;
    bool io_suspended;
    mips64_sched_native_hook_fn native_hook;
    void *native_hook_context;
    uint64_t native_hook_ack;
    uint64_t native_hook_requested;
};

struct mips64_scheduler {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    mips64_sched_ticket_t *all;
    mips64_sched_ticket_t *queue_head;
    mips64_sched_ticket_t *queue_tail;
    mips64_sched_ticket_t *suspended_head;
    mips64_sched_ticket_t *suspended_tail;
    mips64_sched_ticket_t *turn;
    mips64_sched_ticket_t *quiesce_owner;
    _Atomic bool quiescing;
    size_t io_flights;
    size_t native_hook_pending;
    uint64_t native_hook_epoch;
    unsigned int native_hook_phase;
    uint32_t quantum;
    bool terminal;
    pid_t creator_pid;
};
/* Cross-part prototypes (Phase 0 mechanical split). */

 int mips64_scheduler_lock_scheduler(mips64_scheduler_t *scheduler);

 int mips64_scheduler_unlock_scheduler(mips64_scheduler_t *scheduler);

 void mips64_scheduler_notify_all(mips64_scheduler_t *scheduler);

 bool mips64_scheduler_owned(const mips64_sched_ticket_t *ticket);

 bool mips64_scheduler_current(const mips64_sched_ticket_t *ticket);

 void queue_push(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

 void suspended_push(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

 void mips64_scheduler_suspended_remove(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

 void mips64_scheduler_queue_remove(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

 void mips64_scheduler_select_next(mips64_scheduler_t *scheduler);

int mips64_scheduler_create(mips64_scheduler_t **out, mips64_sched_ticket_t **initial,
                        uint32_t quantum);

int mips64_scheduler_add(mips64_sched_ticket_t *current_ticket, mips64_sched_ticket_t **child);

int mips64_scheduler_attach(mips64_sched_ticket_t *ticket);

int mips64_scheduler_wait_turn(mips64_sched_ticket_t *ticket);

int mips64_scheduler_budget(mips64_sched_ticket_t *ticket, uint32_t *budget,
                        bool *interpreter_only);

int mips64_scheduler_account(mips64_sched_ticket_t *ticket, uint32_t retired,
                         mips64_sched_sequence_t sequence,
                         mips64_sched_decision_t *decision);

 int release_turn(mips64_sched_ticket_t *ticket, bool park);

int mips64_scheduler_yield(mips64_sched_ticket_t *ticket);

int mips64_scheduler_park(mips64_sched_ticket_t *ticket);

int mips64_scheduler_wake(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

int mips64_scheduler_io_begin(mips64_sched_ticket_t *ticket);

int mips64_scheduler_io_end(mips64_sched_ticket_t *ticket);

int mips64_scheduler_io_suspend(mips64_sched_ticket_t *ticket);

int mips64_scheduler_io_resume(mips64_sched_ticket_t *ticket);

int mips64_scheduler_quiesce_begin(mips64_sched_ticket_t *owner);

bool mips64_scheduler_quiesce_pending(const mips64_sched_ticket_t *ticket);

int mips64_scheduler_quiesce_ready(mips64_sched_ticket_t *owner);

int mips64_scheduler_quiesce_wait(mips64_sched_ticket_t *owner);

int mips64_scheduler_quiesce_checkpoint(mips64_sched_ticket_t *ticket);

int mips64_scheduler_native_hook_bind(mips64_sched_ticket_t *ticket,
                                  mips64_sched_native_hook_fn hook, void *context);

int mips64_scheduler_parked_native_hook(mips64_sched_ticket_t *ticket);

int mips64_scheduler_quiesce_hook_begin(mips64_sched_ticket_t *owner,
                                     unsigned int phase);

int mips64_scheduler_quiesce_hook_wait(mips64_sched_ticket_t *owner);

#ifdef MIPS64_RUNTIME_TEST_EXEC_SUSPENDED_IO
int mips64_scheduler_test_suspended_io(mips64_sched_ticket_t *owner, uint32_t *count);

int mips64_scheduler_quiesce_abort(mips64_sched_ticket_t *owner);

int mips64_scheduler_retire(mips64_sched_ticket_t *ticket);

int mips64_scheduler_discard(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket);

int mips64_scheduler_terminate(mips64_scheduler_t *scheduler);

int mips64_scheduler_ticket_destroy(mips64_sched_ticket_t **owned_ticket);

int mips64_scheduler_destroy(mips64_scheduler_t **owned_scheduler);

int mips64_scheduler_fork_child_abandon(mips64_scheduler_t **owned_scheduler);
#endif /* MIPS64RT_SCHEDULER_PARTS_H */
