/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_parts.h"

/* Only the sealing thread observes this pointer. It prevents accidental
 * recursive entry into its held lifecycle mutex, including after native fork. */
 _Thread_local mips64_guest_memory_t *mips64_guest_memory_local_frozen_session;

 bool mips64_guest_memory_local_session(const mips64_guest_memory_t *session)
{
    return session != NULL && session->owner_pid == getpid();
}

/* A pthread synchronization failure makes ownership uncertain. The family
 * control descriptor must not be closed through ordinary cleanup in that case. */
 void mips64_guest_memory_lifecycle_lock(mips64_guest_memory_t *session)
{
    if (mips64_guest_memory_local_frozen_session == session)
        _exit(125);
    if (pthread_mutex_lock(&session->lock) != 0)
        _exit(125);
}

 void mips64_guest_memory_lifecycle_unlock(mips64_guest_memory_t *session)
{
    if (pthread_mutex_unlock(&session->lock) != 0)
        _exit(125);
}

#ifdef MIPS64_GUEST_MEMORY_TEST_TRANSITION
void mips64_guest_memory_test_set_transition_hook(mips64_guest_memory_t *session,
                                              void (*hook)(void *), void *context)
{
    if (!mips64_guest_memory_local_session(session))
        _exit(125);
    mips64_guest_memory_lifecycle_lock(session);
    if (session->transitioning)
        _exit(125);
    session->test_transition_hook = hook;
    session->test_transition_context = context;
    mips64_guest_memory_lifecycle_unlock(session);
}
#endif

 void mips64_guest_memory_lifecycle_signal(mips64_guest_memory_t *session)
{
    if (pthread_cond_broadcast(&session->changed) != 0)
        _exit(125);
}

 bool mips64_guest_memory_owned_by_current(const mips64_guest_memory_worker_t *worker)
{
    return worker != NULL && pthread_equal(worker->owner, pthread_self()) != 0;
}

 void mips64_guest_memory_restore_cancellation(int previous_state)
{
    if (pthread_setcancelstate(previous_state, NULL) != 0)
        _exit(125);
}

 int mips64_guest_memory_observe_inode(void *context, const struct stat *status)
{
    mips64_path_resolver_t *resolver = context;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mips64_path_protect_identity(resolver, status->st_dev, status->st_ino);
}

 void mips64_guest_memory_poison(mips64_guest_memory_t *session)
{
    mips64_guest_memory_lifecycle_lock(session);
    session->phase = MIPS64_GUEST_MEMORY_FATAL;
    session->transitioning = false;
    mips64_guest_memory_lifecycle_signal(session);
    mips64_guest_memory_lifecycle_unlock(session);
}

static int allocate_session(mips64_guest_memory_t **out, mips64_path_resolver_t *resolver)
{
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                         &previous_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    mips64_guest_memory_t *session = calloc(1, sizeof(*session));
    if (session == NULL) {
        int saved = errno;
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    result = pthread_mutex_init(&session->lock, NULL);
    if (result != 0) {
        free(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = result;
        return -1;
    }
    result = pthread_cond_init(&session->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&session->lock);
        free(session);
        mips64_guest_memory_restore_cancellation(previous_cancel_state);
        errno = result;
        return -1;
    }
    session->resolver = resolver;
    session->owner_pid = getpid();
    session->phase = MIPS64_GUEST_MEMORY_STARTING;
    session->initial.session = session;
    session->initial.owner = pthread_self();
    session->initial.initial = true;
    session->initial.previous_cancel_state = previous_cancel_state;
    *out = session;
    return 0;
}

static int adopt_space(mips64_guest_memory_t *session, mips64_space_t *space,
                        uint32_t slots_per_object)
{
    session->initial.phase = MIPS64_WORKER_HELD;
    session->held_worker = &session->initial;
    if (mips64_family_mm_id(&session->initial.guard, &session->mm_id) != 0)
        return -1;
    if (mips64_family_observe_inodes(&session->initial.guard,
                                 mips64_guest_memory_observe_inode, session->resolver) != 0)
        return -1;
    session->observing = true;
    if (mips64_family_backing_create(&session->backing, session->family,
                                 slots_per_object) != 0 ||
        mips64_family_backing_bind(session->backing, &session->initial.guard) != 0)
        return -1;
    session->bound = true;
    if (!mips64_family_backing_adopt(session->backing, space)) {
        errno = space->fault_reason == MIPS64_FAULT_RESOURCE ? ENOMEM : EIO;
        return -1;
    }
    return 0;
}

static bool valid_start(mips64_guest_memory_t **out, mips64_space_t *space,
                         mips64_path_resolver_t *resolver, uint32_t slots_per_object)
{
    return out != NULL && space != NULL && resolver != NULL &&
           resolver->initialized && slots_per_object != 0 &&
           slots_per_object <= MIPS64_FAMILY_OBJECT_MAX_SLOTS;
}

static int start_session(mips64_guest_memory_t **out, mips64_space_t *space,
                           mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                           mips64_linux_memory_t *canonical_memory, uint64_t task_id,
                           mips64_file_caps_client_t *sources,
                           mips64_file_identity_policy_t identity_policy,
                           mips64_family_storage_authority_t authority)
{
    if (out != NULL)
        *out = NULL;
    if (!valid_start(out, space, resolver, slots_per_object)) {
        errno = EINVAL;
        return -1;
    }
    if (canonical_memory != NULL) {
        if (canonical_memory->space != space || task_id == 0 ||
            canonical_memory->count > MIPS64_FAMILY_MM_MAX_RECORDS ||
            (canonical_memory->count != 0 && canonical_memory->vmas == NULL)) {
            errno = EINVAL; return -1;
        }
        for (size_t i = 0; i < canonical_memory->count; ++i) {
            if (canonical_memory->vmas[i].kind == MIPS64_VMA_FILE_PRIVATE ||
                canonical_memory->vmas[i].kind == MIPS64_VMA_ANONYMOUS_SHARED) {
                errno = EOPNOTSUPP; return -1;
            }
        }
    }
    if (allocate_session(out, resolver) != 0)
        return -1;
    mips64_guest_memory_t *session = *out;
    session->canonical_space = canonical_memory == NULL ? NULL : space;
    session->canonical_memory = canonical_memory;
    session->owns_family_cleanup = true;
    session->family_creator = true;
    session->source_restricted = sources != NULL;
    int created = sources == NULL ?
        mips64_family_create_with_authority(&session->family, authority) :
        mips64_family_create_with_sources_authority(&session->family, sources,
                                                authority);
    if (created != 0)
        return -1;
    if (mips64_family_enter(session->family, &session->initial.guard) != 0) {
        /* Enter can fail after an attempted file-lock rollback. */
        mips64_guest_memory_poison(session);
        return -1;
    }
    if (adopt_space(session, space, slots_per_object) != 0)
        return -1;
    if (canonical_memory != NULL) {
        if (mips64_mm_view_seed(&session->mm_view, session->backing,
                             &session->initial.guard, space, canonical_memory, task_id) != 0)
            return -1;
        session->mm_id = mips64_mm_view_identity(session->mm_view).mm_id;
        if (sources != NULL && mips64_mm_view_bind_family_sources(session->mm_view,
                &session->initial.guard, identity_policy) != 0)
            return -1;
        session->initial.task_id = task_id;
        session->initial.admitted = true;
        session->last_task_id = task_id;
    }
    session->phase = MIPS64_GUEST_MEMORY_READY;
    return 0;
}

int mips64_guest_memory_start(mips64_guest_memory_t **out, mips64_space_t *space,
                          mips64_path_resolver_t *resolver, uint32_t slots_per_object)
{
    return start_session(out, space, resolver, slots_per_object, NULL, 0, NULL,
                         MIPS64_FILE_IDENTITY_AUTO, MIPS64_FAMILY_AUTHORITY_AUTO);
}

int mips64_guest_memory_start_authority(mips64_guest_memory_t **out, mips64_space_t *space,
                          mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                          mips64_family_storage_authority_t authority)
{
    return start_session(out, space, resolver, slots_per_object, NULL, 0, NULL,
                         MIPS64_FILE_IDENTITY_AUTO, authority);
}

int mips64_guest_memory_start_canonical(mips64_guest_memory_t **out, mips64_space_t *space,
                                    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id)
{
    if (out == NULL || *out != NULL) { errno = EINVAL; return -1; }
    if (memory == NULL) {
        errno = EINVAL; return -1;
    }
    return start_session(out, space, resolver, slots_per_object, memory, initial_task_id,
                         NULL, MIPS64_FILE_IDENTITY_AUTO, MIPS64_FAMILY_AUTHORITY_AUTO);
}

static int start_owned_sources(mips64_guest_memory_t **out,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               mips64_linux_memory_t *memory, uint64_t initial_task_id,
                               mips64_file_caps_client_t *owned_sources,
                               mips64_file_identity_policy_t identity_policy,
                               mips64_family_storage_authority_t authority)
{
    if (owned_sources == NULL) { errno = EINVAL; return -1; }
    /* Ownership crosses allocator, native-cap validation and family creation.
     * Keep cancellation disabled until a returned session owns cleanup, or all
     * supplied caps are closed. A partial session retains the original caller
     * state, not the nested DISABLE state observed by allocate_session. */
    int previous;
    int error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    if (error != 0) {
        mips64_file_caps_client_close(owned_sources);
        errno = error;
        return -1;
    }
    mips64_file_caps_client_t supplied = *owned_sources;
    *owned_sources = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    mips64_file_caps_client_t sources = MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    mips64_guest_memory_t *created_session = NULL;
    int result = -1;
    if (out == NULL || *out != NULL || (memory == NULL && initial_task_id != 0) ||
        !mips64_file_identity_policy_valid(identity_policy) ||
        (authority != MIPS64_FAMILY_AUTHORITY_AUTO &&
         authority != MIPS64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1) ||
        !valid_start(out, space, resolver, slots_per_object)) {
        mips64_file_caps_client_close(&supplied);
        errno = EINVAL;
        goto done;
    }
    if (mips64_file_caps_client_adopt(&sources, supplied.request_fd,
                                  supplied.lifetime_fd) != 0)
        goto done;
    result = start_session(&created_session, space, resolver, slots_per_object, memory,
                           initial_task_id, &sources, identity_policy, authority);
done: {
        int saved = errno;
        mips64_file_caps_client_close(&sources);
        if (created_session != NULL) {
            created_session->initial.previous_cancel_state = previous;
            *out = created_session;
        } else
            mips64_guest_memory_restore_cancellation(previous);
        errno = saved;
        return result;
    }
}

int mips64_guest_memory_start_canonical_sources(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id,
                                    mips64_file_caps_client_t *owned_sources,
                                    mips64_file_identity_policy_t identity_policy)
{
    if (memory == NULL || initial_task_id == 0) {
        if (owned_sources != NULL) mips64_file_caps_client_close(owned_sources);
        errno = EINVAL;
        return -1;
    }
    return start_owned_sources(out, space, resolver, slots_per_object,
                               memory, initial_task_id, owned_sources,
                               identity_policy, MIPS64_FAMILY_AUTHORITY_AUTO);
}

int mips64_guest_memory_start_canonical_sources_authority(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_linux_memory_t *memory, uint64_t initial_task_id,
                                    mips64_file_caps_client_t *owned_sources,
                                    mips64_file_identity_policy_t identity_policy,
                                    mips64_family_storage_authority_t authority)
{
    if (memory == NULL || initial_task_id == 0) {
        if (owned_sources != NULL) mips64_file_caps_client_close(owned_sources);
        errno = EINVAL;
        return -1;
    }
    return start_owned_sources(out, space, resolver, slots_per_object,
                               memory, initial_task_id, owned_sources,
                               identity_policy, authority);
}

int mips64_guest_memory_start_borrowed_sources(mips64_guest_memory_t **out,
                                    mips64_space_t *space, mips64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    mips64_file_caps_client_t *owned_sources)
{
    return start_owned_sources(out, space, resolver, slots_per_object,
                               NULL, 0, owned_sources, MIPS64_FILE_IDENTITY_AUTO,
                               MIPS64_FAMILY_AUTHORITY_AUTO);
}

static int replay_exec_exit(mips64_family_guard_t *guard,
                            const mips64_family_exec_state_t *state,
                            mips64_family_mm_t old_mm,
                            const mips64_exec_tid_clear_t *intents, size_t count)
{
    /* Same-PID exec keeps its owner lease, so death sweeping cannot retire
     * the vanished sibling tasks. Do this before any clear-TID selects a
     * foreign waiter; a returning native exec never reaches this path. */
    mips64_family_wait_table_t table = {0};
    if (mips64_family_wait_table_read(guard, &table) != 0)
        return -1;
    size_t kept = 0;
    for (size_t i = 0; i < table.count; ++i) {
        mips64_family_wait_row_t row = table.rows[i];
        if (row.owner_incarnation == state->incarnation) {
            if (old_mm.mm_id == 0 || row.mm_id != old_mm.mm_id) {
                mips64_family_wait_table_destroy(&table);
                errno = EINVAL;
                return -1;
            }
        } else
            table.rows[kept++] = row;
    }
    bool changed = kept != table.count;
    table.count = kept;
    int retired = changed ? mips64_family_wait_table_commit(guard, &table, NULL, 0) : 0;
    mips64_family_wait_table_destroy(&table);
    if (retired != 0)
        return -1;
    return mips64_exec_tid_replay_old_mm(guard, old_mm, intents, count);
}

static int exec_receive_clear_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    bool valid = out != NULL && *out == NULL && state != NULL &&
                 (count == 0 || intents != NULL);
    if (!valid || allocate_session(out, NULL) != 0) {
        int saved = valid ? errno : EINVAL;
        mips64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, sources);
        errno = saved;
        return -1;
    }
    mips64_guest_memory_t *session = *out;
    session->owns_family_cleanup = state->creator;
    session->family_creator = state->creator;
    session->source_restricted = sources.request_fd >= 3;
    int result = sources.request_fd == -1 && sources.lifetime_fd == -1 ?
        mips64_family_exec_receive(&session->family, &session->initial.guard,
                                owned_control_fd, owned_directory_fd, owned_pins, state) :
        mips64_family_exec_receive_sources(&session->family, &session->initial.guard,
                                owned_control_fd, owned_directory_fd, owned_pins, sources, state);
    if (result != 0)
        return -1;
    return replay_exec_exit(&session->initial.guard, state, old_mm, intents, count);
}

int mips64_guest_memory_exec_receive_clear_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
        owned_pins, (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER,
        state, (mips64_family_mm_t){.mm_id = old_mm_id}, intents, count);
}

int mips64_guest_memory_exec_outside_guard(mips64_guest_memory_t *session,
                                      int (*operation)(void *), void *opaque)
{
    if (!mips64_guest_memory_local_session(session) || !mips64_guest_memory_owned_by_current(&session->initial) ||
        operation == NULL || session->phase != MIPS64_GUEST_MEMORY_STARTING ||
        session->terminal_only || !session->initial.guard.held ||
        session->backing != NULL || session->resolver != NULL ||
        session->mm_view != NULL || session->held_worker != NULL) {
        errno = EINVAL;
        return -1;
    }
    /* allocate_session kept cancellation disabled. The callback cannot
     * abandon the family between native unlock and exact reentry. */
    if (mips64_family_leave(&session->initial.guard) != 0) {
        mips64_guest_memory_poison(session);
        return -1;
    }
    int result = operation(opaque);
    int operation_error = errno;
    if (mips64_family_enter(session->family, &session->initial.guard) != 0) {
        mips64_guest_memory_poison(session);
        errno = EIO;
        return -1;
    }
    errno = operation_error;
    return result;
}

int mips64_guest_memory_exec_receive_sources_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    if (owned_sources.request_fd < 3 || owned_sources.lifetime_fd < 3) {
        mips64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
        owned_pins, owned_sources, state,
        (mips64_family_mm_t){.mm_id = old_mm_id}, intents, count);
}

static int retire_old_canonical_mm(mips64_family_guard_t *guard,
                                   const mips64_family_exec_state_t *state,
                                   mips64_family_mm_t old_mm, uint64_t old_task_id)
{
    if (guard->incarnation != state->incarnation) {
        errno = EIO;
        return -1;
    }
    /* The exec lease excludes another local publisher across native exec.
     * Clear-TID replay precedes retiring this incarnation's tasks. A separate
     * CLONE_VM process retains its rows, mappings and all payload keys. */
    return mips64_mm_retire_exec_owner(guard, old_mm, old_task_id);
}

int mips64_guest_memory_exec_receive_sources_canonical_mm(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    if (old_mm.mm_id == 0 || old_mm.root_object == 0 || old_task_id == 0) {
        mips64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    if (owned_sources.request_fd < 3 || owned_sources.lifetime_fd < 3) {
        mips64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    if (exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state, old_mm, intents, count) != 0)
        return -1;
    return retire_old_canonical_mm(&(*out)->initial.guard, state, old_mm, old_task_id);
}

static int require_idle_file_cursor(mips64_family_guard_t *guard)
{
    mips64_family_file_cursor_t cursor = {0};
    if (mips64_family_file_index_cursor_read(guard, &cursor) != 0)
        return -1;
    if (cursor.phase != MIPS64_FILE_IDLE) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

static int receive_clean_source_exec(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    bool valid = out != NULL && *out == NULL && state != NULL &&
                 old_mm.mm_id != 0 && old_mm.root_object != 0 &&
                 old_task_id != 0 && (count == 0 || intents != NULL) &&
                 owned_sources.request_fd >= 3 && owned_sources.lifetime_fd >= 3;
    if (!valid || allocate_session(out, NULL) != 0) {
        int saved = valid ? errno : EINVAL;
        mips64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = saved;
        return -1;
    }
    mips64_guest_memory_t *session = *out;
    session->family_creator = state->creator;
    session->source_restricted = true;
    session->terminal_only = true;
    if (mips64_family_exec_receive_sources_terminal(&session->family,
            &session->initial.guard, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state) != 0)
        return -1;
    /* The prior exec preparation drained the file cursor before exporting
     * caps. A nonidle cursor here cannot be recovered against a dead peer,
     * and no exit effect may precede this proof. */
    if (require_idle_file_cursor(&session->initial.guard) != 0 ||
        replay_exec_exit(&session->initial.guard, state, old_mm,
                         intents, count) != 0 ||
        retire_old_canonical_mm(&session->initial.guard, state,
                                old_mm, old_task_id) != 0)
        return -1;
    /* An incomplete receive or nonidle cursor must not attempt ordinary
     * creator cleanup, which could recover against a dead source service. */
    session->terminal_replay_complete = true;
    return 0;
}

static int exec_receive_sources_canonical_mm_classified(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count,
                               bool cleanup_delegated)
{
    if (receive_clean_source_exec(out, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state, old_mm, old_task_id,
            intents, count) != 0)
        return -1;
    mips64_guest_memory_t *session = *out;
    const mips64_file_caps_client_t *sources = mips64_family_sources(&session->initial.guard);
    if (sources == NULL)
        return -1;
    if (mips64_file_caps_client_live(sources)) {
        session->terminal_only = false;
        session->owns_family_cleanup = state->creator &&
                                        !cleanup_delegated;
        session->cleanup_delegated = cleanup_delegated;
        return 0;
    }
    /* The peer can die before or during receive. Its exit effects are now
     * durable. Return only cleanup ownership; the caller must fail-stop. */
    return 1;
}

int mips64_guest_memory_exec_receive_sources_canonical_mm_classified(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_sources_canonical_mm_classified(out,
        owned_control_fd, owned_directory_fd, owned_pins, owned_sources,
        state, old_mm, old_task_id, intents, count, false);
}

#ifdef MIPS64_RUNTIME_TEST_ATTRIBUTED_FILE
int mips64_guest_memory_exec_receive_sources_canonical_mm_classified_delegated(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_sources_canonical_mm_classified(out,
        owned_control_fd, owned_directory_fd, owned_pins, owned_sources,
        state, old_mm, old_task_id, intents, count, true);
}
#endif

int mips64_guest_memory_exec_replay_dead_sources(
                               mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               mips64_file_caps_client_t owned_sources,
                               const mips64_family_exec_state_t *state,
                               mips64_family_mm_t old_mm, uint64_t old_task_id,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    return receive_clean_source_exec(out, owned_control_fd,
        owned_directory_fd, owned_pins, owned_sources, state,
        old_mm, old_task_id, intents, count);
}

int mips64_guest_memory_terminal_cleanup(mips64_guest_memory_t *session,
                                     bool proven_sole_family_owner)
{
    if (!mips64_guest_memory_local_session(session) || !mips64_guest_memory_owned_by_current(&session->initial) ||
        !session->terminal_only || !session->terminal_replay_complete ||
        session->phase != MIPS64_GUEST_MEMORY_STARTING ||
        !session->initial.guard.held || !proven_sole_family_owner) {
        errno = EPERM;
        return -1;
    }
    if (require_idle_file_cursor(&session->initial.guard) != 0)
        return -1;
    return mips64_family_cleanup_held_terminal(&session->initial.guard, true);
}

int mips64_guest_memory_exec_receive_clear(mips64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    return mips64_guest_memory_exec_receive_clear_mm(out, owned_control_fd,
        owned_directory_fd, owned_pins, state, 0, intents, count);
}

int mips64_guest_memory_exec_adopt(mips64_guest_memory_t *session,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object)
{
    if (!mips64_guest_memory_local_session(session) || !mips64_guest_memory_owned_by_current(&session->initial) ||
        session->phase != MIPS64_GUEST_MEMORY_STARTING ||
        session->terminal_only ||
        session->resolver != NULL || session->backing != NULL ||
        session->canonical_space != NULL ||
        !session->initial.guard.held ||
        !valid_start(&session, space, resolver, slots_per_object)) {
        errno = EINVAL;
        return -1;
    }
    session->resolver = resolver;
    int result = adopt_space(session, space, slots_per_object);
    if (result == 0)
        session->phase = MIPS64_GUEST_MEMORY_READY;
    return result;
}

int mips64_guest_memory_exec_adopt_canonical(mips64_guest_memory_t *session,
                               mips64_space_t *space, mips64_linux_memory_t *memory,
                               mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object, uint64_t initial_task_id,
                               mips64_file_identity_policy_t identity_policy)
{
    if (!mips64_guest_memory_local_session(session) || !mips64_guest_memory_owned_by_current(&session->initial) ||
        session->phase != MIPS64_GUEST_MEMORY_STARTING ||
        session->terminal_only ||
        session->resolver != NULL || session->backing != NULL ||
        session->canonical_space != NULL || !session->initial.guard.held ||
        !valid_start(&session, space, resolver, slots_per_object) ||
        memory == NULL || memory->space != space || initial_task_id == 0 ||
        memory->count > MIPS64_FAMILY_MM_MAX_RECORDS ||
        (memory->count != 0 && memory->vmas == NULL) ||
        !mips64_file_identity_policy_valid(identity_policy)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < memory->count; ++i) {
        if (memory->vmas[i].kind == MIPS64_VMA_FILE_PRIVATE ||
            memory->vmas[i].kind == MIPS64_VMA_ANONYMOUS_SHARED) {
            errno = EOPNOTSUPP;
            return -1;
        }
    }
    /* No fallible step precedes the ownership transfer. In particular,
     * teardown must not leave a partially installed backing in caller-owned
     * space after seed or source binding fails. */
    session->canonical_space = space;
    session->canonical_memory = memory;
    session->resolver = resolver;
    if (adopt_space(session, space, slots_per_object) != 0)
        return -1;
    if (mips64_mm_view_seed(&session->mm_view, session->backing,
                        &session->initial.guard, space, memory,
                        initial_task_id) != 0)
        return -1;
    if (session->source_restricted &&
        mips64_mm_view_bind_family_sources(session->mm_view,
                                       &session->initial.guard,
                                       identity_policy) != 0)
        return -1;
    session->mm_id = mips64_mm_view_identity(session->mm_view).mm_id;
    session->initial.task_id = initial_task_id;
    session->initial.admitted = true;
    session->last_task_id = initial_task_id;
    session->phase = MIPS64_GUEST_MEMORY_READY;
    return 0;
}

bool mips64_guest_memory_owns_image(const mips64_guest_memory_t *session,
                                const mips64_space_t *space,
                                const mips64_linux_memory_t *memory)
{
    return mips64_guest_memory_local_session(session) && session->canonical_space == space &&
           session->canonical_memory == memory && space != NULL && memory != NULL;
}

bool mips64_guest_memory_family_creator(const mips64_guest_memory_t *session)
{
    return mips64_guest_memory_local_session(session) && session->family_creator;
}

bool mips64_guest_memory_zero_backing(const mips64_guest_memory_t *session)
{
    return mips64_guest_memory_local_session(session) &&
           mips64_family_zero_backing(session->family);
}

int mips64_guest_memory_exec_start_with_clear(mips64_guest_memory_t **out,
                               mips64_space_t *space, mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state,
                               const mips64_exec_tid_clear_t *intents, size_t count)
{
    if (out != NULL)
        *out = NULL;
    if (!valid_start(out, space, resolver, slots_per_object)) {
        mips64_family_close_capabilities(owned_control_fd, owned_directory_fd,
                                       owned_pins);
        errno = EINVAL;
        return -1;
    }
    if (mips64_guest_memory_exec_receive_clear(out, owned_control_fd,
            owned_directory_fd, owned_pins, state, intents, count) != 0)
        return -1;
    return mips64_guest_memory_exec_adopt(*out, space, resolver, slots_per_object);
}

int mips64_guest_memory_exec_start(mips64_guest_memory_t **out, mips64_space_t *space,
                               mips64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               mips64_inode_pins_t owned_pins,
                               const mips64_family_exec_state_t *state)
{
    return mips64_guest_memory_exec_start_with_clear(out, space, resolver,
        slots_per_object, owned_control_fd, owned_directory_fd, owned_pins, state, NULL, 0);
}

int mips64_guest_memory_prepare_child(mips64_guest_memory_t *parent,
                                  const mips64_linux_memory_t *vmas,
                                  mips64_process_memory_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (parent == NULL || vmas == NULL || out == NULL ||
        parent->owner_pid != getpid() || parent->fork_frozen ||
        !mips64_guest_memory_active(parent)) {
        errno = EINVAL;
        return -1;
    }
    if (parent->canonical_space != NULL || parent->source_restricted) {
        errno = EOPNOTSUPP; return -1;
    }
    return mips64_process_memory_prepare(out, vmas, parent->backing,
                                      parent->family, &parent->initial.guard);
}
