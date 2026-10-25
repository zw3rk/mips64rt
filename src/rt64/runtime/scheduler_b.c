/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "scheduler_parts.h"

int mips64_scheduler_retire(mips64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
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
    ticket->phase = MIPS64_TICKET_DEAD;
    scheduler->turn = NULL;
    mips64_scheduler_select_next(scheduler);
    mips64_scheduler_notify_all(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_discard(mips64_scheduler_t *scheduler, mips64_sched_ticket_t *ticket)
{
    if (scheduler == NULL || ticket == NULL || ticket->scheduler != scheduler) {
        errno = EINVAL;
        return -1;
    }
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (ticket->phase == MIPS64_TICKET_RUNNING ||
        ticket->phase == MIPS64_TICKET_DEAD) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    if (ticket->queued) {
        if (ticket->phase == MIPS64_TICKET_SUSPENDED)
            mips64_scheduler_suspended_remove(scheduler, ticket);
        else
            mips64_scheduler_queue_remove(scheduler, ticket);
    }
    if (ticket == scheduler->turn) {
        scheduler->turn = NULL;
        mips64_scheduler_select_next(scheduler);
    }
    ticket->phase = MIPS64_TICKET_DEAD;
    mips64_scheduler_notify_all(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_terminate(mips64_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    scheduler->terminal = true;
    mips64_scheduler_notify_all(scheduler);
    return mips64_scheduler_unlock_scheduler(scheduler);
}

int mips64_scheduler_ticket_destroy(mips64_sched_ticket_t **owned_ticket)
{
    if (owned_ticket == NULL || *owned_ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_sched_ticket_t *ticket = *owned_ticket;
    mips64_scheduler_t *scheduler = ticket->scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (!scheduler->terminal &&
        (ticket->phase != MIPS64_TICKET_DEAD || ticket == scheduler->turn ||
         ticket->queued)) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    /* After group termination the caller has joined every worker. Tickets
     * can still be selected or queued, but none can execute or wait again. */
    if (ticket->queued) {
        if (ticket->phase == MIPS64_TICKET_SUSPENDED)
            mips64_scheduler_suspended_remove(scheduler, ticket);
        else
            mips64_scheduler_queue_remove(scheduler, ticket);
    }
    if (scheduler->turn == ticket)
        scheduler->turn = NULL;
    if (scheduler->quiesce_owner == ticket)
        scheduler->quiesce_owner = NULL;
    if (ticket->io_inflight && !ticket->io_suspended) {
        if (scheduler->io_flights == 0)
            _exit(125);
        --scheduler->io_flights;
    }
    mips64_sched_ticket_t **position = &scheduler->all;
    while (*position != NULL && *position != ticket)
        position = &(*position)->all_next;
    if (*position != ticket) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EINVAL;
        return -1;
    }
    *position = ticket->all_next;
    (void)mips64_scheduler_unlock_scheduler(scheduler);
    free(ticket);
    *owned_ticket = NULL;
    return 0;
}

int mips64_scheduler_destroy(mips64_scheduler_t **owned_scheduler)
{
    if (owned_scheduler == NULL || *owned_scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = *owned_scheduler;
    if (mips64_scheduler_lock_scheduler(scheduler) != 0)
        return -1;
    if (scheduler->all != NULL || scheduler->turn != NULL ||
        scheduler->queue_head != NULL || scheduler->suspended_head != NULL ||
        scheduler->quiesce_owner != NULL || scheduler->io_flights != 0) {
        (void)mips64_scheduler_unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    if (mips64_scheduler_unlock_scheduler(scheduler) != 0)
        return -1;
    int result = pthread_cond_destroy(&scheduler->changed);
    if (result == 0)
        result = pthread_mutex_destroy(&scheduler->lock);
    if (result != 0) {
        errno = result;
        return -1;
    }
    free(scheduler);
    *owned_scheduler = NULL;
    return 0;
}

int mips64_scheduler_fork_child_abandon(mips64_scheduler_t **owned_scheduler)
{
    if (owned_scheduler == NULL || *owned_scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_scheduler_t *scheduler = *owned_scheduler;
    /* Never inspect a copied mutex. The parent still owns its original
     * tickets and callback frames; this process only disposes their copies
     * after the native seal and all copied I/O/futex capabilities are gone. */
    if (scheduler->creator_pid == getpid() ||
        scheduler->all == NULL || scheduler->quiesce_owner == NULL ||
        scheduler->turn != scheduler->quiesce_owner || scheduler->terminal ||
        scheduler->quiesce_owner->phase != MIPS64_TICKET_RUNNING ||
        scheduler->io_flights != 0 || scheduler->native_hook_pending != 0 ||
        !atomic_load_explicit(&scheduler->quiescing, memory_order_relaxed)) {
        errno = EPERM;
        return -1;
    }
    bool owner_found = false;
    for (mips64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next) {
        bool is_owner = ticket == scheduler->quiesce_owner;
        if (ticket->scheduler != scheduler ||
            (is_owner ? ticket->io_inflight || ticket->io_suspended :
             (ticket->phase != MIPS64_TICKET_SUSPENDED &&
              ticket->phase != MIPS64_TICKET_BLOCKED &&
              ticket->phase != MIPS64_TICKET_DEAD)) ||
            (ticket->io_inflight && (!ticket->io_suspended ||
                                     ticket->phase != MIPS64_TICKET_SUSPENDED)) ||
            (!ticket->io_inflight && ticket->io_suspended)) {
            errno = EPERM;
            return -1;
        }
        owner_found = owner_found || is_owner;
    }
    if (!owner_found) {
        errno = EPERM;
        return -1;
    }
    mips64_sched_ticket_t *ticket = scheduler->all;
    while (ticket != NULL) {
        mips64_sched_ticket_t *next = ticket->all_next;
        free(ticket);
        ticket = next;
    }
    free(scheduler);
    *owned_scheduler = NULL;
    return 0;
}
