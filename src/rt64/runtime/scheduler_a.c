/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "scheduler_parts.h"

 int mips64_scheduler_lock_scheduler(mips64_scheduler_t *scheduler)
{
    int result = pthread_mutex_lock(&scheduler->lock);
    if (result != 0)
        errno = result;
    return result == 0 ? 0 : -1;
}

 int mips64_scheduler_unlock_scheduler(mips64_scheduler_t *scheduler)
{
    int result = pthread_mutex_unlock(&scheduler->lock);
    if (result != 0)
        _exit(125); /* Ownership is uncertain after a failed unlock. */
    return 0;
}

 void mips64_scheduler_notify_all(mips64_scheduler_t *scheduler)
{
    if (pthread_cond_broadcast(&scheduler->changed) != 0)
        _exit(125); /* Never silently lose a selected worker's wake. */
}

 bool mips64_scheduler_owned(const mips64_sched_ticket_t *ticket)
{
    return ticket->attached && pthread_equal(ticket->owner, pthread_self()) != 0;
}

 bool mips64_scheduler_current(const mips64_sched_ticket_t *ticket)
{
    return ticket->scheduler->turn == ticket &&
           ticket->phase == MIPS64_TICKET_RUNNING;
}

static void queue_push(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    ticket->phase = MIPS64_TICKET_RUNNABLE;
    ticket->queue_next = NULL;
    ticket->queued = true;
    if (scheduler->queue_tail == NULL)
        scheduler->queue_head = ticket;
    else
        scheduler->queue_tail->queue_next = ticket;
    scheduler->queue_tail = ticket;
}

static void suspended_push(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    ticket->phase = MIPS64_TICKET_SUSPENDED;
    ticket->queue_next = NULL;
    ticket->queued = true;
    if (scheduler->suspended_tail == NULL)
        scheduler->suspended_head = ticket;
    else
        scheduler->suspended_tail->queue_next = ticket;
    scheduler->suspended_tail = ticket;
}

 void mips64_scheduler_suspended_remove(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    mips64_sched_ticket_t **position = &scheduler->suspended_head;
    while (*position != NULL && *position != ticket)
        position = &(*position)->queue_next;
    if (*position == NULL)
        return;
    *position = ticket->queue_next;
    if (scheduler->suspended_tail == ticket) {
        scheduler->suspended_tail = NULL;
        for (mips64_sched_ticket_t *entry = scheduler->suspended_head;
             entry != NULL; entry = entry->queue_next)
            scheduler->suspended_tail = entry;
    }
    ticket->queue_next = NULL;
    ticket->queued = false;
}

 void mips64_scheduler_queue_remove(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    mips64_sched_ticket_t **position = &scheduler->queue_head;
    while (*position != NULL && *position != ticket)
        position = &(*position)->queue_next;
    if (*position == NULL)
        return;
    *position = ticket->queue_next;
    if (scheduler->queue_tail == ticket) {
        scheduler->queue_tail = NULL;
        for (mips64_sched_ticket_t *entry = scheduler->queue_head;
             entry != NULL; entry = entry->queue_next)
            scheduler->queue_tail = entry;
    }
    ticket->queue_next = NULL;
    ticket->queued = false;
}

 void mips64_scheduler_select_next(mips64_scheduler_t *scheduler)
{
    mips64_sched_ticket_t *next = scheduler->queue_head;
    if (next == NULL && scheduler->quiesce_owner != NULL &&
        scheduler->io_flights == 0 && scheduler->native_hook_pending == 0 &&
        scheduler->quiesce_owner->phase == MIPS64_TICKET_OWNER_WAIT) {
        scheduler->turn = scheduler->quiesce_owner;
        scheduler->turn->phase = MIPS64_TICKET_SELECTED;
        scheduler->turn->remaining = scheduler->quantum;
        scheduler->turn->sequence_length = 0;
        mips64_scheduler_notify_all(scheduler);
        return;
    }
    scheduler->turn = next;
    if (next == NULL)
        return;
    mips64_scheduler_queue_remove(scheduler, next);
    next->phase = MIPS64_TICKET_SELECTED;
    next->remaining = scheduler->quantum;
    next->sequence_length = 0;
    mips64_scheduler_notify_all(scheduler);
}

int mips64_scheduler_create(mips64_scheduler_t **out, mips64_sched_ticket_t **initial,
                        uint32_t quantum)
{
    if (out != NULL)
        *out = NULL;
    if (initial != NULL)
        *initial = NULL;
    if (out == NULL || initial == NULL || quantum == 0) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = calloc(1, sizeof(*scheduler));
    mips64_sched_ticket_t *ticket = calloc(1, sizeof(*ticket));
    if (scheduler == NULL || ticket == NULL) {
        free(ticket);
        free(scheduler);
        return -1;
    }
    int result = pthread_mutex_init(&scheduler->lock, NULL);
    if (result != 0) {
        free(ticket);
        free(scheduler);
        errno = result;
        return -1;
    }
    result = pthread_cond_init(&scheduler->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&scheduler->lock);
        free(ticket);
        free(scheduler);
        errno = result;
        return -1;
    }
    scheduler->quantum = quantum;
    scheduler->creator_pid = getpid();
    atomic_init(&scheduler->quiescing, false);
    scheduler->turn = ticket;
    scheduler->all = ticket;
    ticket->scheduler = scheduler;
    ticket->owner = pthread_self();
    ticket->attached = true;
    ticket->phase = MIPS64_TICKET_RUNNING;
    ticket->remaining = quantum;
    *out = scheduler;
    *initial = ticket;
    return 0;
}

int mips64_scheduler_add(mips64_sched_ticket_t *current_ticket, mips64_sched_ticket_t **child)
{
    if (child != NULL)
        *child = NULL;
    if (current_ticket == NULL || child == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_sched_ticket_t *new_ticket = calloc(1, sizeof(*new_ticket));
    if (new_ticket == NULL)
        return -1;
    mips64_scheduler_t *scheduler = current_ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0) {
        free(new_ticket);
        return -1;
    }
    if (scheduler->terminal || scheduler->quiesce_owner != NULL ||
        !mips64_scheduler_owned(current_ticket) || !mips64_scheduler_current(current_ticket)) {
        int saved = scheduler->terminal ? EIDRM :
                    scheduler->quiesce_owner != NULL ? EBUSY : EPERM;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        free(new_ticket);
        errno = saved;
        return -1;
    }
    new_ticket->scheduler = scheduler;
    new_ticket->all_next = scheduler->all;
    scheduler->all = new_ticket;
    queue_push(scheduler, new_ticket);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    *child = new_ticket;
    return 0;
}

int mips64_scheduler_attach(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    bool duplicate = false;
    for (mips64_sched_ticket_t *entry = scheduler->all;
         entry != NULL; entry = entry->all_next)
        if (entry->attached && entry->phase != MIPS64_TICKET_DEAD &&
            pthread_equal(entry->owner, pthread_self()) != 0)
            duplicate = true;
    if (scheduler->terminal || scheduler->quiesce_owner != NULL || ticket->attached ||
        ticket->phase == MIPS64_TICKET_DEAD || duplicate) {
        int saved = scheduler->terminal ? EIDRM : EBUSY;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = saved;
        return -1;
    }
    ticket->owner = pthread_self();
    ticket->attached = true;
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_wait_turn(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket)) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    while (!scheduler->terminal &&
           (scheduler->turn != ticket ||
            (scheduler->quiesce_owner != NULL &&
             ticket->native_hook_requested == scheduler->native_hook_epoch &&
             ticket->native_hook_ack != ticket->native_hook_requested)) &&
           ticket->phase != MIPS64_TICKET_DEAD) {
        if (scheduler->quiesce_owner != NULL &&
            ticket->native_hook_requested == scheduler->native_hook_epoch &&
            ticket->native_hook_ack != ticket->native_hook_requested) {
            mips64_sched_native_hook_fn hook = ticket->native_hook;
            void *context = ticket->native_hook_context;
            uint64_t epoch = scheduler->native_hook_epoch;
            unsigned int phase = scheduler->native_hook_phase;
            if (hook == NULL || mips64_scheduler_unlock_scheduler(scheduler) != 0)
                _exit(125);
            int saved_errno = errno;
            if (!hook(context, phase))
                _exit(125);
            if (mips64_scheduler_lock_scheduler(scheduler) != 0)
                _exit(125);
            if (ticket->native_hook_ack != epoch &&
                scheduler->native_hook_epoch == epoch) {
                ticket->native_hook_ack = epoch;
                if (scheduler->native_hook_pending == 0)
                    _exit(125);
                --scheduler->native_hook_pending;
                if (scheduler->native_hook_pending == 0 &&
                    scheduler->turn == NULL)
                    mips64_scheduler_select_next(scheduler);
                mips64_scheduler_notify_all(scheduler);
            }
            errno = saved_errno;
            continue;
        }
        int result = pthread_cond_wait(&scheduler->changed, &scheduler->lock);
        if (result != 0) {
            (void)mips64_scheduler_unlock_scheduler(scheduler);
            errno = result;
            return -1;
        }
    }
    if (scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 0;
    }
    if (ticket->phase == MIPS64_TICKET_DEAD) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EIDRM;
        return -1;
    }
    if (ticket->phase != MIPS64_TICKET_SELECTED &&
        ticket->phase != MIPS64_TICKET_RUNNING) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EIO;
        return -1;
    }
    ticket->phase = MIPS64_TICKET_RUNNING;
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 1;
}

int mips64_scheduler_budget(mips64_sched_ticket_t *ticket, uint32_t *budget,
                        bool *interpreter_only)
{
    if (ticket == NULL || budget == NULL || interpreter_only == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket)) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    *interpreter_only = ticket->sequence_length != 0;
    *budget = scheduler->terminal ? 0 :
              *interpreter_only ? 1 : ticket->remaining;
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 0;
}

int mips64_scheduler_account(mips64_sched_ticket_t *ticket, uint32_t retired,
                         mips64_sched_sequence_t sequence,
                         mips64_sched_decision_t *decision)
{
    if (ticket == NULL || decision == NULL ||
        (retired == 0 && sequence != MIPS64_SCHED_SEQ_BREAK) ||
        sequence < MIPS64_SCHED_SEQ_NONE || sequence > MIPS64_SCHED_SEQ_BREAK) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket)) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->terminal) {
        *decision = MIPS64_SCHED_TERMINAL;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 0;
    }
    bool active = ticket->sequence_length != 0;
    if ((retired > 1 && (sequence != MIPS64_SCHED_SEQ_NONE || active)) ||
        (ticket->remaining != 0 && retired > ticket->remaining) ||
        (ticket->remaining == 0 && !active) ||
        (sequence == MIPS64_SCHED_SEQ_CONSTRAINED && !active)) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EINVAL;
        return -1;
    }
    if (ticket->remaining != 0)
        ticket->remaining -= retired;
    if (sequence == MIPS64_SCHED_SEQ_LR_START) {
        /* A second LR cannot reset an already extended window. */
        ticket->sequence_length = active && ticket->remaining == 0 ? 0 : 1;
    } else if (sequence == MIPS64_SCHED_SEQ_CONSTRAINED) {
        ++ticket->sequence_length;
    } else if (sequence == MIPS64_SCHED_SEQ_SC_END ||
               sequence == MIPS64_SCHED_SEQ_BREAK || sequence == MIPS64_SCHED_SEQ_NONE) {
        ticket->sequence_length = 0;
    }
    if (ticket->sequence_length >= 16)
        ticket->sequence_length = 0;
    *decision = ticket->remaining != 0 ||
                (ticket->sequence_length != 0 && ticket->sequence_length < 16) ?
                MIPS64_SCHED_CONTINUE : MIPS64_SCHED_YIELD;
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 0;
}

static int release_turn(mips64_sched_ticket_t *ticket, bool park)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || scheduler->terminal) {
        int saved = scheduler->terminal ? EIDRM : EPERM;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = saved;
        return -1;
    }
    scheduler->turn = NULL;
    ticket->remaining = 0;
    ticket->sequence_length = 0;
    if (park)
        ticket->phase = MIPS64_TICKET_BLOCKED;
    else if (scheduler->quiesce_owner != NULL &&
             scheduler->quiesce_owner != ticket && !ticket->io_inflight)
        suspended_push(scheduler, ticket);
    else
        queue_push(scheduler, ticket);
    mips64_scheduler_select_next(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_yield(mips64_sched_ticket_t *ticket)
{
    return release_turn(ticket, false);
}

int mips64_scheduler_park(mips64_sched_ticket_t *ticket)
{
    return release_turn(ticket, true);
}

int mips64_scheduler_wake(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    if (scheduler == NULL || ticket == NULL || ticket->scheduler != scheduler) {
        errno = EINVAL;
        return -1;
    }
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (scheduler->terminal || ticket->phase == MIPS64_TICKET_DEAD) {
        int saved = scheduler->terminal ? EIDRM : EINVAL;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = saved;
        return -1;
    }
    if (ticket->phase != MIPS64_TICKET_BLOCKED) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 0;
    }
    if (scheduler->quiesce_owner != NULL && !ticket->io_inflight)
        suspended_push(scheduler, ticket);
    else
        queue_push(scheduler, ticket);
    if (scheduler->turn == NULL)
        mips64_scheduler_select_next(scheduler);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 1;
}

int mips64_scheduler_io_begin(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || ticket->io_inflight ||
        scheduler->quiesce_owner != NULL || scheduler->terminal) {
        int saved = scheduler->terminal ? EIDRM :
                    scheduler->quiesce_owner != NULL ? EBUSY : EPERM;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = saved;
        return -1;
    }
    ticket->io_inflight = true;
    ++scheduler->io_flights;
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_io_end(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || !ticket->io_inflight ||
        ticket->io_suspended ||
        scheduler->io_flights == 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    ticket->io_inflight = false;
    --scheduler->io_flights;
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_io_suspend(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || !ticket->io_inflight ||
        ticket->io_suspended || scheduler->io_flights == 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->quiesce_owner == NULL ||
        scheduler->quiesce_owner == ticket) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 0;
    }
    ticket->io_suspended = true;
    --scheduler->io_flights;
    scheduler->turn = NULL;
    suspended_push(scheduler, ticket);
    mips64_scheduler_select_next(scheduler);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 1;
}

int mips64_scheduler_io_resume(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || !ticket->io_inflight ||
        !ticket->io_suspended || scheduler->quiesce_owner != NULL ||
        scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    ticket->io_suspended = false;
    ++scheduler->io_flights;
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_quiesce_begin(mips64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) || owner->io_inflight ||
        scheduler->quiesce_owner != NULL || scheduler->terminal) {
        int saved = scheduler->terminal ? EIDRM : EBUSY;
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = saved;
        return -1;
    }
    scheduler->quiesce_owner = owner;
    /* An I/O worker may already have completed its native syscall and be
     * queued to reacquire the family guard. It must remain admissible until
     * the guest result and copyout have been committed. */
    for (mips64_sched_ticket_t *ticket = scheduler->queue_head; ticket != NULL;) {
        mips64_sched_ticket_t *next = ticket->queue_next;
        if (!ticket->io_inflight || ticket->io_suspended) {
            mips64_scheduler_queue_remove(scheduler, ticket);
            suspended_push(scheduler, ticket);
        }
        ticket = next;
    }
    atomic_store_explicit(&scheduler->quiescing, true, memory_order_release);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

bool mips64_scheduler_quiesce_pending(const mips64_sched_ticket_t *ticket)
{
    return ticket != NULL &&
           atomic_load_explicit(&ticket->scheduler->quiescing,
                                memory_order_acquire);
}

int mips64_scheduler_quiesce_ready(mips64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    int ready = scheduler->io_flights == 0 ? 1 : 0;
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return ready;
}

int mips64_scheduler_quiesce_wait(mips64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->io_flights == 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 1;
    }
    owner->phase = MIPS64_TICKET_OWNER_WAIT;
    scheduler->turn = NULL;
    mips64_scheduler_select_next(scheduler);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 0; /* Release guard, wait_turn, then reacquire it. */
}

int mips64_scheduler_quiesce_checkpoint(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || !mips64_scheduler_current(ticket) || ticket->io_inflight ||
        scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->quiesce_owner == NULL ||
        scheduler->quiesce_owner == ticket) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 0;
    }
    scheduler->turn = NULL;
    suspended_push(scheduler, ticket);
    mips64_scheduler_select_next(scheduler);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 1; /* Caller leaves guard, then waits for abort/termination. */
}

int mips64_scheduler_native_hook_bind(mips64_sched_ticket_t *ticket,
                                  mips64_sched_native_hook_fn hook, void *context)
{
    if (ticket == NULL || hook == NULL || context == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (scheduler->terminal || scheduler->quiesce_owner != NULL ||
        ticket->phase == MIPS64_TICKET_DEAD || ticket->native_hook != NULL ||
        (ticket->attached && !mips64_scheduler_owned(ticket))) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    ticket->native_hook = hook;
    ticket->native_hook_context = context;
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_parked_native_hook(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(ticket) || ticket->phase != MIPS64_TICKET_BLOCKED ||
        scheduler->turn == ticket) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->terminal) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 1;
    }
    if (scheduler->quiesce_owner != NULL &&
        ticket->native_hook_requested == scheduler->native_hook_epoch &&
        ticket->native_hook_ack != ticket->native_hook_requested) {
        mips64_sched_native_hook_fn hook = ticket->native_hook;
        void *context = ticket->native_hook_context;
        uint64_t epoch = scheduler->native_hook_epoch;
        unsigned int phase = scheduler->native_hook_phase;
        if (hook == NULL || mips64_scheduler_unlock_scheduler(scheduler) != 0)
            _exit(125);
        int saved_errno = errno;
        if (!hook(context, phase) || mips64_scheduler_lock_scheduler(scheduler) != 0)
            _exit(125);
        if (ticket->native_hook_ack != epoch &&
            scheduler->native_hook_epoch == epoch) {
            ticket->native_hook_ack = epoch;
            if (scheduler->native_hook_pending == 0)
                _exit(125);
            --scheduler->native_hook_pending;
            if (scheduler->native_hook_pending == 0 &&
                scheduler->turn == NULL)
                mips64_scheduler_select_next(scheduler);
            mips64_scheduler_notify_all(scheduler);
        }
        errno = saved_errno;
    }
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_quiesce_hook_begin(mips64_sched_ticket_t *owner,
                                     unsigned int phase)
{
    if (owner == NULL || phase == 0) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->io_flights != 0 || scheduler->native_hook_pending != 0 ||
        scheduler->native_hook_epoch == UINT64_MAX) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    size_t pending = 0;
    for (mips64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next) {
        if (ticket == owner || !ticket->attached ||
            ticket->phase == MIPS64_TICKET_DEAD)
            continue;
        if (ticket->native_hook == NULL) {
            (void)mips64_scheduler_unlock_scheduler(scheduler);
            errno = EINVAL;
            return -1;
        }
        ++pending;
    }
    ++scheduler->native_hook_epoch;
    scheduler->native_hook_phase = phase;
    scheduler->native_hook_pending = pending;
    for (mips64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next)
        if (ticket != owner && ticket->attached &&
            ticket->phase != MIPS64_TICKET_DEAD)
            ticket->native_hook_requested = scheduler->native_hook_epoch;
    mips64_scheduler_notify_all(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_quiesce_hook_wait(mips64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->io_flights != 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->native_hook_pending == 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        return 1;
    }
    owner->phase = MIPS64_TICKET_OWNER_WAIT;
    scheduler->turn = NULL;
    mips64_scheduler_select_next(scheduler);
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    return 0;
}

#ifdef MIPS64_RUNTIME_TEST_EXEC_SUSPENDED_IO
int mips64_scheduler_test_suspended_io(mips64_sched_ticket_t *owner, uint32_t *count)
{
    if (owner == NULL || count == NULL) {
        errno = EINVAL;
        return -1;
    }
    *count = 0;
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->creator_pid != getpid() ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->io_flights != 0 || scheduler->native_hook_pending != 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    for (mips64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next) {
        if (ticket == owner || !ticket->io_inflight)
            continue;
        if (!ticket->io_suspended || ticket->phase != MIPS64_TICKET_SUSPENDED ||
            *count == UINT32_MAX) {
            (void)mips64_scheduler_unlock_scheduler(scheduler);
            errno = EIO;
            return -1;
        }
        ++*count;
    }
    return mips64_scheduler_unlock_scheduler(scheduler);
}
#endif

int mips64_scheduler_quiesce_abort(mips64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = owner->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!mips64_scheduler_owned(owner) || !mips64_scheduler_current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->native_hook_pending != 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    scheduler->quiesce_owner = NULL;
    while (scheduler->suspended_head != NULL) {
        mips64_sched_ticket_t *ticket = scheduler->suspended_head;
        mips64_scheduler_suspended_remove(scheduler, ticket);
        queue_push(scheduler, ticket);
    }
    atomic_store_explicit(&scheduler->quiescing, false, memory_order_release);
    mips64_scheduler_notify_all(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}
