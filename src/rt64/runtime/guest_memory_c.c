/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_parts.h"

static int worker_attach(mips64_guest_memory_t *session, uint64_t task_id,
                         bool canonical, mips64_guest_memory_worker_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (session == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                         &previous_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    /* Allocation and publication share the lifecycle seal. A fork cannot
     * copy a worker allocated but not yet linked into the session. */
    if (mips64_family_zero_backing(session->family)) {
        mips64_guest_memory_lifecycle_unlock(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = EOPNOTSUPP;
        return -1;
    }
    mips64_guest_memory_worker_t *worker = NULL;
    if (session->phase != MIPS64_GUEST_MEMORY_READY ||
        session->extra_workers == SIZE_MAX || session->fork_frozen ||
        session->retirement != NULL) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    if ((!canonical && (session->canonical_space != NULL ||
                        session->source_restricted)) ||
        (canonical && (session->canonical_space == NULL ||
                       session->mm_view == NULL || task_id == 0 ||
                       task_id <= session->last_task_id))) {
        mips64_guest_memory_lifecycle_unlock(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = canonical ? EINVAL : EOPNOTSUPP;
        return -1;
    }
    worker = calloc(1, sizeof(*worker));
    if (worker == NULL) {
        int saved = errno;
        mips64_guest_memory_lifecycle_unlock(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    worker->session = session;
    worker->owner = pthread_self();
    worker->previous_cancel_state = previous_cancel_state;
    worker->task_id = task_id;
    /* One thread owns exactly one guard. A second handle could deadlock on
     * the process-local family mutex and restore cancellation out of order. */
    bool duplicate_owner =
        pthread_equal(session->initial.owner, worker->owner) != 0;
    for (mips64_guest_memory_worker_t *present = session->workers;
         present != NULL && !duplicate_owner; present = present->next)
        duplicate_owner = pthread_equal(present->owner, worker->owner) != 0;
    if (duplicate_owner) {
        free(worker);
        mips64_guest_memory_lifecycle_unlock(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = EBUSY;
        return -1;
    }
    worker->next = session->workers;
    session->workers = worker;
    ++session->extra_workers;
    if (canonical)
        session->last_task_id = task_id;
    mips64_guest_memory_lifecycle_unlock(session);
    *out = worker;
    return 0;
}

int mips64_guest_memory_worker_attach(mips64_guest_memory_t *session,
                                   mips64_guest_memory_worker_t **out)
{
    return worker_attach(session, 0, false, out);
}

int mips64_guest_memory_worker_attach_task(mips64_guest_memory_t *session,
                                       uint64_t task_id,
                                       mips64_guest_memory_worker_t **out)
{
    if (out == NULL || *out != NULL) {
        errno = out == NULL ? EINVAL : EBUSY;
        return -1;
    }
    return worker_attach(session, task_id, true, out);
}

static bool held_canonical_caller(const mips64_guest_memory_worker_t *caller)
{
    mips64_guest_memory_t *session = caller->session;
    return session->phase == MIPS64_GUEST_MEMORY_READY &&
           session->canonical_space != NULL && session->mm_view != NULL &&
           session->held_worker == caller && caller->phase == MIPS64_WORKER_HELD &&
           caller->admitted && !caller->cleanup_only && session->bound &&
           mips64_family_guard_matches(&caller->guard, session->family);
}

static int member_order(mips64_family_mm_member_t left,
                        mips64_family_mm_member_t right)
{
    if (left.owner_incarnation != right.owner_incarnation)
        return left.owner_incarnation < right.owner_incarnation ? -1 : 1;
    if (left.task_id == right.task_id)
        return 0;
    return left.task_id < right.task_id ? -1 : 1;
}

static bool session_has_worker(const mips64_guest_memory_t *session,
                               const mips64_guest_memory_worker_t *target)
{
    if (target == &session->initial)
        return true;
    for (const mips64_guest_memory_worker_t *worker = session->workers;
         worker != NULL; worker = worker->next)
        if (worker == target)
            return true;
    return false;
}

static bool state_has_member(const mips64_family_mm_state_t *state,
                             mips64_family_mm_member_t member)
{
    for (size_t i = 0; i < state->member_count; ++i)
        if (member_order(state->members[i], member) == 0)
            return true;
    return false;
}

int mips64_guest_memory_worker_admit(mips64_guest_memory_worker_t *caller,
                                  mips64_guest_memory_worker_t *child)
{
    if (caller == NULL || child == NULL || caller->session == NULL ||
        child->session != caller->session ||
        !mips64_guest_memory_local_session(caller->session) || !mips64_guest_memory_owned_by_current(caller)) {
        errno = EINVAL; return -1;
    }
    mips64_guest_memory_t *session = caller->session;
    mips64_guest_memory_lifecycle_lock(session);
    if (!held_canonical_caller(caller) || session->retirement != NULL ||
        session->fork_frozen || child->initial || child->phase != MIPS64_WORKER_IDLE ||
        child->admitted || child->retiring || child->retired ||
        child->task_id == 0 || !session_has_worker(session, child)) {
        mips64_guest_memory_lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    mips64_family_mm_state_t state = {0};
    mips64_family_mm_t mm = mips64_mm_view_identity(session->mm_view);
    if (mips64_family_mm_read(&caller->guard, mm, &state) != 0) {
        int saved = errno;
        if (saved != ENOMEM) {
            session->phase = MIPS64_GUEST_MEMORY_FATAL;
            mips64_guest_memory_lifecycle_signal(session);
        }
        mips64_guest_memory_lifecycle_unlock(session); errno = saved; return -1;
    }
    if (state.member_count >= MIPS64_FAMILY_MM_MAX_RECORDS) {
        mips64_family_mm_state_destroy(&state);
        mips64_guest_memory_lifecycle_unlock(session); errno = ENOMEM; return -1;
    }
    mips64_family_mm_member_t caller_member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = caller->task_id};
    if (!state_has_member(&state, caller_member)) {
        mips64_family_mm_state_destroy(&state);
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
        mips64_guest_memory_lifecycle_unlock(session); errno = EIO; return -1;
    }
    mips64_family_mm_member_t member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = child->task_id};
    size_t at = 0;
    while (at < state.member_count &&
           member_order(state.members[at], member) < 0)
        ++at;
    if (at < state.member_count && member_order(state.members[at], member) == 0) {
        mips64_family_mm_state_destroy(&state);
        mips64_guest_memory_lifecycle_unlock(session); errno = EEXIST; return -1;
    }
    mips64_family_mm_member_t *larger = realloc(state.members,
        (state.member_count + 1u) * sizeof(*larger));
    if (larger == NULL) {
        int saved = errno;
        mips64_family_mm_state_destroy(&state);
        mips64_guest_memory_lifecycle_unlock(session); errno = saved; return -1;
    }
    state.members = larger;
    memmove(&state.members[at + 1], &state.members[at],
            (state.member_count - at) * sizeof(*larger));
    state.members[at] = member;
    ++state.member_count;
    int result = mips64_family_mm_commit(&caller->guard, mm, &state);
    int saved = errno;
    mips64_family_mm_state_destroy(&state);
    if (result == 0)
        child->admitted = true;
    else if (saved != ENOMEM) {
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
    }
    mips64_guest_memory_lifecycle_unlock(session);
    errno = saved;
    return result;
}

int mips64_guest_memory_worker_retire_prepare(mips64_guest_memory_worker_t *caller,
                                          mips64_guest_memory_worker_t *target,
                                          mips64_guest_memory_retirement_t **out)
{
    if (out != NULL && *out != NULL) {
        errno = EBUSY; return -1;
    }
    if (caller == NULL || target == NULL || out == NULL ||
        caller->session == NULL || target->session != caller->session ||
        !mips64_guest_memory_local_session(caller->session) || !mips64_guest_memory_owned_by_current(caller)) {
        errno = EINVAL; return -1;
    }
    mips64_guest_memory_t *session = caller->session;
    mips64_guest_memory_lifecycle_lock(session);
    if (!held_canonical_caller(caller) || session->retirement != NULL ||
        session->fork_frozen || !target->admitted || target->retiring ||
        target->retired || !session_has_worker(session, target) ||
        (target != caller && target->phase != MIPS64_WORKER_IDLE)) {
        mips64_guest_memory_lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    mips64_guest_memory_retirement_t *ticket = calloc(1, sizeof(*ticket));
    if (ticket == NULL) {
        int saved = errno;
        mips64_guest_memory_lifecycle_unlock(session); errno = saved; return -1;
    }
    ticket->session = session;
    ticket->caller = caller;
    ticket->target = target;
    ticket->mm = mips64_mm_view_identity(session->mm_view);
    if (mips64_family_mm_read(&caller->guard, ticket->mm, &ticket->state) != 0) {
        int saved = errno;
        free(ticket); mips64_guest_memory_lifecycle_unlock(session); errno = saved; return -1;
    }
    mips64_family_mm_member_t caller_member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = caller->task_id};
    if (!state_has_member(&ticket->state, caller_member)) {
        mips64_family_mm_state_destroy(&ticket->state);
        free(ticket);
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
        mips64_guest_memory_lifecycle_unlock(session); errno = EIO; return -1;
    }
    mips64_family_mm_member_t member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = target->task_id};
    size_t at = 0;
    while (at < ticket->state.member_count &&
           member_order(ticket->state.members[at], member) < 0)
        ++at;
    if (at == ticket->state.member_count ||
        member_order(ticket->state.members[at], member) != 0) {
        mips64_family_mm_state_destroy(&ticket->state);
        free(ticket); mips64_guest_memory_lifecycle_unlock(session); errno = EIO; return -1;
    }
    if (at + 1u < ticket->state.member_count)
        memmove(&ticket->state.members[at], &ticket->state.members[at + 1],
                (ticket->state.member_count - at - 1u) *
                sizeof(*ticket->state.members));
    --ticket->state.member_count;
    target->retiring = true;
    session->retirement = ticket;
    mips64_guest_memory_lifecycle_unlock(session);
    *out = ticket;
    return 0;
}

int mips64_guest_memory_worker_retire_commit(mips64_guest_memory_retirement_t **owned)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL; return -1;
    }
    mips64_guest_memory_retirement_t *ticket = *owned;
    mips64_guest_memory_t *session = ticket->session;
    if (!mips64_guest_memory_local_session(session) || !mips64_guest_memory_owned_by_current(ticket->caller)) {
        errno = EPERM; return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    if (session->retirement != ticket || !ticket->target->retiring ||
        !held_canonical_caller(ticket->caller)) {
        mips64_guest_memory_lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    /* This is a metadata-only plan. Clear-TID and wait cleanup may change
     * payload bytes/epochs, but no MM-root transaction may intervene. The
     * revision check in commit rejects a stale plan. A failure after those
     * effects is fatal, never a guest-visible retry. */
    int result = mips64_family_mm_commit(&ticket->caller->guard, ticket->mm,
                                      &ticket->state);
    int saved = errno;
    if (result == 0) {
        ticket->target->admitted = false;
        ticket->target->retired = true;
        ticket->target->retiring = false;
        session->retirement = NULL;
    } else {
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
    }
    mips64_guest_memory_lifecycle_unlock(session);
    if (result == 0) {
        mips64_family_mm_state_destroy(&ticket->state);
        free(ticket);
        *owned = NULL;
    }
    errno = saved;
    return result;
}

static int worker_enter(mips64_guest_memory_worker_t *worker, bool cleanup)
{
    if (worker == NULL || worker->session == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *session = worker->session;
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_guest_memory_owned_by_current(worker)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    if (session->phase != MIPS64_GUEST_MEMORY_READY ||
        worker->phase != MIPS64_WORKER_IDLE || session->retirement != NULL ||
        (cleanup && (worker != &session->initial ||
                     session->canonical_space == NULL || !worker->retired)) ||
        (!cleanup && session->canonical_space != NULL &&
         (!worker->admitted || worker->retired || worker->retiring))) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    worker->phase = MIPS64_WORKER_WAITING;
    mips64_guest_memory_lifecycle_unlock(session);
    /* Never hold the lifecycle lock while waiting for the family token. */
    if (mips64_family_enter(session->family, &worker->guard) != 0) {
        mips64_guest_memory_poison(session);
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    while (session->transitioning && session->phase == MIPS64_GUEST_MEMORY_READY) {
        if (pthread_cond_wait(&session->changed, &session->lock) != 0)
            _exit(125);
    }
    if (session->phase != MIPS64_GUEST_MEMORY_READY ||
        session->held_worker != NULL || session->bound ||
        mips64_family_backing_bind(session->backing, &worker->guard) != 0) {
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
        mips64_guest_memory_lifecycle_unlock(session);
        errno = EIO;
        return -1;
    }
    session->bound = true;
    if (!cleanup && session->mm_view != NULL &&
        mips64_mm_view_refresh(session->mm_view, &worker->guard) != 0) {
        int saved = errno;
        if (saved != ENOMEM) {
            session->phase = MIPS64_GUEST_MEMORY_FATAL;
            mips64_guest_memory_lifecycle_signal(session); mips64_guest_memory_lifecycle_unlock(session);
            errno = saved; return -1;
        }
        /* Never publish HELD with stale mappings. Serialize guard release with
         * the existing leave transition; retry and teardown remain possible. */
        mips64_family_backing_unbind(session->backing);
        session->bound = false; session->transitioning = true;
        mips64_guest_memory_lifecycle_unlock(session);
        int left = mips64_family_leave_with_cleanup(&worker->guard,
                                                  mips64_path_drain_quarantine, session->resolver);
        int leave_error = errno;
        mips64_guest_memory_lifecycle_lock(session);
        worker->phase = MIPS64_WORKER_IDLE;
        session->transitioning = false;
        if (left != 0)
            session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session); mips64_guest_memory_lifecycle_unlock(session);
        errno = left == 0 ? saved : leave_error;
        return -1;
    }
    if (!cleanup && session->mm_view != NULL &&
        !mips64_mm_view_has_member(session->mm_view, &worker->guard,
                               worker->task_id)) {
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
        mips64_guest_memory_lifecycle_signal(session);
        mips64_guest_memory_lifecycle_unlock(session);
        errno = EIO;
        return -1;
    }
    session->held_worker = worker;
    worker->phase = MIPS64_WORKER_HELD;
    worker->cleanup_only = cleanup;
    mips64_guest_memory_lifecycle_unlock(session);
    return 0;
}

int mips64_guest_memory_worker_enter(mips64_guest_memory_worker_t *worker)
{
    return worker_enter(worker, false);
}

int mips64_guest_memory_worker_enter_cleanup(mips64_guest_memory_worker_t *initial)
{
    return worker_enter(initial, true);
}

bool mips64_guest_memory_worker_cleanup_guard(mips64_guest_memory_worker_t *initial,
                                           mips64_family_guard_t **guard)
{
    if (initial == NULL || guard == NULL || initial->session == NULL ||
        !mips64_guest_memory_local_session(initial->session) || !mips64_guest_memory_owned_by_current(initial))
        return false;
    mips64_guest_memory_t *session = initial->session;
    mips64_guest_memory_lifecycle_lock(session);
    bool valid = initial == &session->initial && initial->retired &&
        initial->cleanup_only && session->phase == MIPS64_GUEST_MEMORY_READY &&
        session->held_worker == initial && initial->phase == MIPS64_WORKER_HELD &&
        session->bound && session->retirement == NULL &&
        mips64_family_guard_matches(&initial->guard, session->family);
    mips64_guest_memory_lifecycle_unlock(session);
    if (valid)
        *guard = &initial->guard;
    return valid;
}

int mips64_guest_memory_worker_leave(mips64_guest_memory_worker_t *worker)
{
    if (worker == NULL || worker->session == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *session = worker->session;
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_guest_memory_owned_by_current(worker)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    if (session->phase != MIPS64_GUEST_MEMORY_READY ||
        session->held_worker != worker || worker->phase != MIPS64_WORKER_HELD ||
        !session->bound || session->retirement != NULL) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    mips64_family_backing_unbind(session->backing);
    session->bound = false;
    session->held_worker = NULL;
    worker->phase = MIPS64_WORKER_IDLE;
    worker->cleanup_only = false;
    session->transitioning = true;
    mips64_guest_memory_lifecycle_unlock(session);
#ifdef MIPS64_GUEST_MEMORY_TEST_TRANSITION
    if (session->test_transition_hook != NULL)
        session->test_transition_hook(session->test_transition_context);
#endif
    int result = mips64_family_leave_with_cleanup(&worker->guard,
                                                mips64_path_drain_quarantine,
                                                session->resolver);
    int saved = errno;
    mips64_guest_memory_lifecycle_lock(session);
    if (result != 0)
        session->phase = MIPS64_GUEST_MEMORY_FATAL;
    session->transitioning = false;
    mips64_guest_memory_lifecycle_signal(session);
    mips64_guest_memory_lifecycle_unlock(session);
    if (result != 0) {
        errno = saved;
        return -1;
    }
    return 0;
}

int mips64_guest_memory_worker_detach(mips64_guest_memory_worker_t **owned)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_worker_t *worker = *owned;
    if (worker->initial) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *session = worker->session;
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_guest_memory_owned_by_current(worker)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    if (session->phase != MIPS64_GUEST_MEMORY_READY ||
        worker->phase != MIPS64_WORKER_IDLE || worker->admitted ||
        worker->retiring || session->retirement != NULL) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    mips64_guest_memory_worker_t **position = &session->workers;
    while (*position != NULL && *position != worker)
        position = &(*position)->next;
    if (*position != worker || session->extra_workers == 0)
        _exit(125);
    *position = worker->next;
    --session->extra_workers;
    int previous_cancel_state = worker->previous_cancel_state;
    free(worker);
    *owned = NULL;
    mips64_guest_memory_lifecycle_unlock(session);
    mips64_guest_memory_restore_cancellation(previous_cancel_state);
    return 0;
}

int mips64_guest_memory_round_trip(mips64_guest_memory_t *session)
{
    if (session == NULL || !mips64_guest_memory_active(session)) {
        errno = EINVAL;
        return -1;
    }
    if (mips64_guest_memory_worker_leave(&session->initial) != 0)
        return -1;
    return mips64_guest_memory_worker_enter(&session->initial);
}

int mips64_guest_memory_stop(mips64_guest_memory_t *session)
{
    if (session == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_guest_memory_owned_by_current(&session->initial)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    bool idle_canonical = session->phase == MIPS64_GUEST_MEMORY_READY &&
        session->canonical_space != NULL && session->initial.phase == MIPS64_WORKER_IDLE &&
        session->held_worker == NULL && !session->bound;
    if ((session->phase != MIPS64_GUEST_MEMORY_READY &&
         session->phase != MIPS64_GUEST_MEMORY_STARTING) ||
        session->extra_workers != 0 || session->transitioning ||
        session->retirement != NULL ||
        (session->phase == MIPS64_GUEST_MEMORY_READY && !idle_canonical &&
         (session->held_worker != &session->initial ||
          session->initial.phase != MIPS64_WORKER_HELD))) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    session->phase = MIPS64_GUEST_MEMORY_STOPPING;
    mips64_guest_memory_lifecycle_unlock(session);
    if (idle_canonical) {
        /* Teardown-only reacquisition cannot admit guest memory, copyout or
         * dispatch. In particular it must not require a successful refresh. */
        if (mips64_family_enter(session->family, &session->initial.guard) != 0 ||
            mips64_family_backing_bind(session->backing, &session->initial.guard) != 0) {
            mips64_guest_memory_poison(session); return -1;
        }
        session->bound = true;
    }
    if (session->canonical_space != NULL) {
        mips64_mm_view_destroy(&session->mm_view);
        /* A native canonical child owns these structs through owned_image;
         * startup/exec canonical sessions borrow stable caller storage. */
        if (session->owned_image == NULL) {
            mips64_linux_memory_destroy(session->canonical_memory);
            mips64_space_destroy(session->canonical_space);
        }
        session->canonical_space = NULL; session->canonical_memory = NULL;
    }
    if (session->bound) {
        mips64_family_backing_unbind(session->backing);
        session->bound = false;
    }
    if (session->owned_image != NULL) {
        mips64_process_memory_discard(&session->owned_image);
        session->backing = NULL;
    } else if (session->backing != NULL) {
        if (mips64_family_backing_destroy(session->backing) != 0) {
            mips64_guest_memory_poison(session);
            return -1;
        }
        session->backing = NULL;
    }
    if (session->observing) {
        if (mips64_family_unobserve_inodes(&session->initial.guard) != 0) {
            mips64_guest_memory_poison(session);
            return -1;
        }
        session->observing = false;
    }
    if (session->initial.guard.held &&
        (session->resolver != NULL ?
         mips64_family_leave_with_cleanup(&session->initial.guard,
                                      mips64_path_drain_quarantine,
                                      session->resolver) :
         mips64_family_leave(&session->initial.guard)) != 0) {
        mips64_guest_memory_poison(session);
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    session->initial.phase = MIPS64_WORKER_IDLE;
    session->held_worker = NULL;
    session->phase = MIPS64_GUEST_MEMORY_STOPPED;
    mips64_guest_memory_lifecycle_unlock(session);
    return 0;
}

static int guest_memory_finish(mips64_guest_memory_t **owned, bool restore_prior,
                               int *prior_state)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *session = *owned;
    if (!mips64_guest_memory_local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_guest_memory_owned_by_current(&session->initial)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_lifecycle_lock(session);
    if (session->phase != MIPS64_GUEST_MEMORY_STOPPED ||
        session->extra_workers != 0) {
        int saved = session->phase == MIPS64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    mips64_guest_memory_lifecycle_unlock(session);
    if (session->resolver != NULL && session->resolver->initialized) {
        errno = EBUSY;
        return -1;
    }
    if (session->family != NULL) {
        if ((session->owns_family_cleanup &&
             mips64_family_cleanup(session->family) != 0) ||
            mips64_family_destroy(session->family) != 0) {
            mips64_guest_memory_poison(session);
            return -1;
        }
    }
    int previous_cancel_state = session->initial.previous_cancel_state;
    if (pthread_cond_destroy(&session->changed) != 0 ||
        pthread_mutex_destroy(&session->lock) != 0)
        _exit(125);
    free(session);
    *owned = NULL;
    if (prior_state != NULL)
        *prior_state = previous_cancel_state;
    if (restore_prior)
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
    return 0;
}

int mips64_guest_memory_finish(mips64_guest_memory_t **owned)
{
    return guest_memory_finish(owned, true, NULL);
}

int mips64_guest_memory_finish_keep_cancellation_disabled(mips64_guest_memory_t **owned,
                                                       int *prior_state)
{
    if (prior_state == NULL) {
        errno = EINVAL;
        return -1;
    }
    int current;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &current);
    if (result != 0) {
        errno = result;
        return -1;
    }
    if (current != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(current, NULL);
        errno = EPERM;
        return -1;
    }
    return guest_memory_finish(owned, false, prior_state);
}

int mips64_guest_memory_register_service_cleanup(mips64_guest_memory_t *session)
{
    if (!mips64_guest_memory_local_session(session) || !session->family_creator ||
        !session->source_restricted || session->canonical_space == NULL ||
        session->phase != MIPS64_GUEST_MEMORY_READY || session->extra_workers != 0 ||
        session->held_worker != &session->initial ||
        !session->initial.guard.held ||
        session->cleanup_registration_attempted) {
        errno = EINVAL;
        return -1;
    }
    session->cleanup_registration_attempted = true;
    bool may_have_delegated = false;
    int result = mips64_family_register_service_cleanup(&session->initial.guard,
                                                     &may_have_delegated);
    if (may_have_delegated)
        session->owns_family_cleanup = false;
    if (result == 0 && may_have_delegated)
        session->cleanup_delegated = true;
    return result;
}

bool mips64_guest_memory_service_cleanup_delegated(const mips64_guest_memory_t *session)
{
    return mips64_guest_memory_local_session(session) && session->source_restricted &&
           session->cleanup_delegated;
}

int mips64_guest_memory_departure_begin(mips64_guest_memory_t *session,
                                   mips64_file_caps_departure_t *out)
{
    if (!mips64_guest_memory_local_session(session) || out == NULL ||
        !session->source_restricted || !session->cleanup_delegated ||
        session->phase != MIPS64_GUEST_MEMORY_READY ||
        session->held_worker != &session->initial ||
        session->extra_workers != 0 || session->retirement != NULL ||
        !mips64_guest_memory_owned_by_current(&session->initial) ||
        !session->initial.guard.held) {
        errno = EINVAL;
        return -1;
    }
    const mips64_file_caps_client_t *sources =
        mips64_family_sources(&session->initial.guard);
    if (sources == NULL)
        return -1;
    return mips64_file_caps_departure_begin(sources, out);
}

const char *mips64_guest_memory_private_directory(const mips64_guest_memory_t *session)
{
    return session == NULL ? NULL : mips64_family_private_directory(session->family);
}
