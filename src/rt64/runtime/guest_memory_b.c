/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_parts.h"

static int freeze_begin(mips64_guest_memory_worker_t *caller,
                        mips64_guest_memory_fork_freeze_t **out, bool exec_only)
{
    /* A rejected nested begin must not erase the only owned thaw token. */
    if (mips64_guest_memory_local_frozen_session != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (out != NULL)
        *out = NULL;
    if (caller == NULL || out == NULL || !mips64_guest_memory_local_session(caller->session) ||
        !mips64_guest_memory_owned_by_current(caller)) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *session = caller->session;
    mips64_guest_memory_lifecycle_lock(session);
    if (mips64_family_zero_backing(session->family)) {
        mips64_guest_memory_lifecycle_unlock(session);
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Canonical fork uses a separate immutable MM image and child bootstrap.
     * Only source-backed sessions have that child path. The legacy
     * prepare/transfer path still rejects every canonical session. */
    if (!exec_only && session->canonical_space != NULL &&
        !session->source_restricted) {
        mips64_guest_memory_lifecycle_unlock(session);
        errno = EOPNOTSUPP;
        return -1;
    }
    if (session->retirement != NULL) {
        mips64_guest_memory_lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    if (session->canonical_space != NULL &&
        (!caller->admitted || caller->retired || caller->retiring ||
         caller->cleanup_only)) {
        mips64_guest_memory_lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    bool idle_others = caller == &session->initial ||
                       session->initial.phase == MIPS64_WORKER_IDLE;
    bool found = caller == &session->initial;
    size_t counted = 0;
    for (mips64_guest_memory_worker_t *worker = session->workers;
         worker != NULL; worker = worker->next) {
        ++counted;
        if (worker == caller)
            found = true;
        else if (worker->phase != MIPS64_WORKER_IDLE)
            idle_others = false;
        if (exec_only && session->canonical_space != NULL &&
            (!worker->admitted || worker->retired || worker->retiring))
            idle_others = false;
    }
    bool ready = session->phase == MIPS64_GUEST_MEMORY_READY &&
                 !session->fork_frozen && !session->transitioning &&
                 session->bound && session->held_worker == caller &&
                 caller->phase == MIPS64_WORKER_HELD && found && idle_others &&
                 counted == session->extra_workers &&
                 mips64_family_guard_matches(&caller->guard, session->family);
    if (!ready) {
        mips64_guest_memory_lifecycle_unlock(session);
        errno = EBUSY;
        return -1;
    }
    mips64_guest_memory_fork_freeze_t *freeze = calloc(1, sizeof(*freeze));
    if (freeze == NULL) {
        int saved = errno;
        mips64_guest_memory_lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    session->fork_frozen = true;
    freeze->session = session;
    freeze->caller = caller;
    freeze->parent_pid = session->owner_pid;
    freeze->previous_cancel_state = caller->previous_cancel_state;
    freeze->exec_only = exec_only;
    mips64_guest_memory_local_frozen_session = session;
    *out = freeze;
    /* The mutex remains held until parent end or child-only consumption. */
    return 0;
}

int mips64_guest_memory_fork_freeze_begin(mips64_guest_memory_worker_t *caller,
                                      mips64_guest_memory_fork_freeze_t **out)
{
    return freeze_begin(caller, out, false);
}

int mips64_guest_memory_exec_freeze_begin(mips64_guest_memory_worker_t *caller,
                                      mips64_guest_memory_fork_freeze_t **out)
{
    return freeze_begin(caller, out, true);
}

int mips64_guest_memory_fork_freeze_end(mips64_guest_memory_fork_freeze_t **owned)
{
    if (owned == NULL || *owned == NULL ||
        (*owned)->parent_pid != getpid() ||
        !mips64_guest_memory_local_session((*owned)->session) ||
        mips64_guest_memory_local_frozen_session != (*owned)->session ||
        !mips64_guest_memory_owned_by_current((*owned)->caller)) {
        errno = EPERM;
        return -1;
    }
    mips64_guest_memory_fork_freeze_t *freeze = *owned;
    if (freeze->exec != NULL && mips64_family_exec_destroy(&freeze->exec) != 0)
        return -1;
    mips64_mm_fork_image_destroy(&freeze->canonical_child);
    mips64_mm_join_image_destroy(&freeze->canonical_join);
    freeze->session->fork_frozen = false;
    mips64_guest_memory_local_frozen_session = NULL;
    mips64_guest_memory_lifecycle_unlock(freeze->session);
    free(freeze->canonical_tasks);
    free(freeze);
    *owned = NULL;
    return 0;
}

int mips64_guest_memory_exec_prepare(mips64_guest_memory_fork_freeze_t *freeze,
                                 mips64_family_exec_t **out)
{
    if (freeze == NULL || out == NULL || *out != NULL ||
        freeze->parent_pid != getpid() || !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) || freeze->exec != NULL ||
        !freeze->session->fork_frozen ||
        (freeze->session->canonical_space != NULL && !freeze->canonical_checked) ||
        freeze->session->held_worker != freeze->caller) {
        errno = EINVAL;
        return -1;
    }
    int result = mips64_family_sources(&freeze->caller->guard) != NULL ?
        mips64_family_exec_prepare_sources(&freeze->caller->guard, &freeze->exec) :
        mips64_family_exec_prepare(&freeze->caller->guard, &freeze->exec);
    if (result != 0)
        return -1;
    *out = freeze->exec;
    return 0;
}

static int compare_task_id(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
    return a == b ? 0 : (a < b ? -1 : 1);
}

int mips64_guest_memory_exec_canonical_identity(mips64_guest_memory_fork_freeze_t *freeze,
                                 mips64_family_mm_t *out_mm, uint64_t *out_task_id)
{
    if (freeze == NULL || out_mm == NULL || out_task_id == NULL ||
        freeze->parent_pid != getpid() || !freeze->exec_only ||
        !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) ||
        !freeze->session->fork_frozen ||
        freeze->session->held_worker != freeze->caller) {
        errno = EINVAL;
        return -1;
    }
    *out_mm = (mips64_family_mm_t){0};
    *out_task_id = 0;
    if (freeze->session->mm_view == NULL)
        return 0;
    if (freeze->canonical_checked) {
        *out_mm = freeze->canonical_mm;
        *out_task_id = freeze->canonical_caller_task;
        return 0;
    }
    mips64_guest_memory_t *session = freeze->session;
    if (session->extra_workers >= 4096) {
        errno = E2BIG;
        return -1;
    }
    uint64_t *tasks = calloc(session->extra_workers + 1u, sizeof(*tasks));
    if (tasks == NULL)
        return -1;
    size_t local_count = 0;
    if (session->initial.admitted && !session->initial.retired &&
        !session->initial.retiring)
        tasks[local_count++] = session->initial.task_id;
    for (mips64_guest_memory_worker_t *worker = session->workers;
         worker != NULL; worker = worker->next) {
        /* An unadmitted/retired local handle is still owned by another native
         * thread. Resolve it before the native exec transition. */
        if (!worker->admitted || worker->retired || worker->retiring ||
            worker->task_id == 0) {
            free(tasks);
            errno = EBUSY;
            return -1;
        }
        tasks[local_count++] = worker->task_id;
    }
    qsort(tasks, local_count, sizeof(*tasks), compare_task_id);
    mips64_family_mm_t mm = mips64_mm_view_identity(freeze->session->mm_view);
    mips64_family_mm_state_t state = {0};
    if (mips64_family_mm_read(&freeze->caller->guard, mm, &state) != 0) {
        free(tasks);
        return -1;
    }
    bool exact = local_count != 0;
    bool caller_found = false;
    for (size_t i = 0; i < local_count; ++i) {
        if (i != 0 && tasks[i - 1u] == tasks[i])
            exact = false;
        if (tasks[i] == freeze->caller->task_id)
            caller_found = true;
    }
    size_t same_owner = 0;
    bool shared_owners = false;
    for (size_t i = 0; i < state.member_count; ++i) {
        if (state.members[i].owner_incarnation != freeze->caller->guard.incarnation) {
            bool alive = false;
            if (mips64_family_owner_alive(&freeze->caller->guard,
                    state.members[i].owner_incarnation, &alive) != 0) {
                /* The lifecycle mutex is already held by this exec seal.
                 * An unverifiable lease is infrastructure-fatal, not a guest
                 * errno or permission to execute with uncertain MM users. */
                session->phase = MIPS64_GUEST_MEMORY_FATAL;
                mips64_family_mm_state_destroy(&state);
                free(tasks);
                errno = EIO;
                return -1;
            }
            shared_owners = shared_owners || alive;
            continue;
        }
        if (same_owner >= local_count || state.members[i].task_id != tasks[same_owner])
            exact = false;
        ++same_owner;
    }
    exact = exact && same_owner == local_count;
    if (!exact || !caller_found) {
        mips64_family_mm_state_destroy(&state);
        free(tasks);
        errno = EINVAL;
        return -1;
    }
    freeze->canonical_mm = mm;
    freeze->canonical_caller_task = freeze->caller->task_id;
    freeze->canonical_tasks = tasks;
    freeze->canonical_task_count = local_count;
    freeze->canonical_shared_owners = shared_owners;
    freeze->canonical_checked = true;
    *out_mm = mm;
    *out_task_id = freeze->canonical_caller_task;
    mips64_family_mm_state_destroy(&state);
    return 0;
}

int mips64_guest_memory_exec_canonical_members(mips64_guest_memory_fork_freeze_t *freeze,
                                 const uint64_t **out_tasks, size_t *out_count)
{
    if (freeze == NULL || out_tasks == NULL || out_count == NULL ||
        freeze->parent_pid != getpid() || !freeze->exec_only ||
        !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) ||
        !freeze->session->fork_frozen || !freeze->canonical_checked ||
        freeze->session->held_worker != freeze->caller) {
        errno = EINVAL;
        return -1;
    }
    *out_tasks = freeze->canonical_tasks;
    *out_count = freeze->canonical_task_count;
    return 0;
}

int mips64_guest_memory_exec_shared_owners(mips64_guest_memory_fork_freeze_t *freeze,
                                      bool *out)
{
    const uint64_t *tasks = NULL;
    size_t count = 0;
    if (out == NULL) { errno = EINVAL; return -1; }
    if (mips64_guest_memory_exec_canonical_members(freeze, &tasks, &count) != 0)
        return -1;
    *out = freeze->canonical_shared_owners;
    return 0;
}

int mips64_guest_memory_exec_capture_clear_tids(mips64_guest_memory_fork_freeze_t *freeze,
                                  const mips64_linux_memory_t *memory,
                                  const uint64_t *addresses, size_t count,
                                  mips64_exec_tid_clear_t **out, size_t *out_count)
{
    if (freeze == NULL || memory == NULL || out == NULL || out_count == NULL ||
        freeze->parent_pid != getpid() || !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) || !freeze->session->fork_frozen ||
        (freeze->session->canonical_space != NULL && !freeze->canonical_checked) ||
        freeze->session->held_worker != freeze->caller ||
        memory->space == NULL ||
        memory->space->page_factory.context != freeze->session->backing) {
        errno = EINVAL;
        return -1;
    }
    if (freeze->canonical_shared_owners)
        return mips64_exec_tid_capture_same_mm(&freeze->caller->guard,
            memory->space, memory, freeze->session->backing, addresses,
            count, out, out_count);
    return mips64_exec_tid_capture(&freeze->caller->guard, memory->space, memory,
        freeze->session->backing, addresses, count, out, out_count);
}

int mips64_guest_memory_exec_capture_clear_tids_tagged(
                                  mips64_guest_memory_fork_freeze_t *freeze,
                                  const mips64_linux_memory_t *memory,
                                  const mips64_exec_tid_request_t *requests,
                                  size_t count,
                                  mips64_exec_tid_clear_t **out, size_t *out_count)
{
    if (freeze == NULL || memory == NULL || out == NULL || out_count == NULL ||
        freeze->parent_pid != getpid() || !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) || !freeze->session->fork_frozen ||
        (freeze->session->canonical_space != NULL && !freeze->canonical_checked) ||
        freeze->session->held_worker != freeze->caller ||
        memory->space == NULL ||
        memory->space->page_factory.context != freeze->session->backing) {
        errno = EINVAL;
        return -1;
    }
    return mips64_exec_tid_capture_tagged(&freeze->caller->guard,
        memory->space, memory, freeze->session->backing, requests, count,
        freeze->canonical_shared_owners, out, out_count);
}

int mips64_guest_memory_prepare_child_frozen(mips64_guest_memory_fork_freeze_t *freeze,
                                         const mips64_linux_memory_t *vmas,
                                         mips64_process_memory_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (freeze == NULL || vmas == NULL || out == NULL || freeze->exec != NULL ||
        freeze->parent_pid != getpid() ||
        !mips64_guest_memory_local_session(freeze->session) ||
        !mips64_guest_memory_owned_by_current(freeze->caller) ||
        !freeze->session->fork_frozen ||
        freeze->session->held_worker != freeze->caller ||
        vmas->space == NULL ||
        vmas->space->managed.context != freeze->session->backing) {
        errno = EINVAL;
        return -1;
    }
    if (freeze->exec_only || freeze->session->canonical_space != NULL ||
        freeze->session->source_restricted) {
        errno = EOPNOTSUPP; return -1;
    }
    return mips64_process_memory_prepare(out, vmas, freeze->session->backing,
                                      freeze->session->family,
                                      &freeze->caller->guard);
}

static int prepare_child_canonical_frozen(
    mips64_guest_memory_fork_freeze_t *freeze, bool shared)
{
    if (freeze == NULL || freeze->parent_pid != getpid() ||
        freeze->exec_only || freeze->exec != NULL ||
        freeze->canonical_child != NULL || freeze->canonical_join != NULL ||
        !mips64_guest_memory_local_session(freeze->session) ||
        mips64_guest_memory_local_frozen_session != freeze->session ||
        !mips64_guest_memory_owned_by_current(freeze->caller) ||
        !freeze->session->fork_frozen ||
        freeze->session->held_worker != freeze->caller ||
        freeze->session->mm_view == NULL ||
        freeze->session->canonical_space == NULL ||
        !freeze->session->source_restricted ||
        !freeze->caller->admitted || freeze->caller->retired ||
        freeze->caller->retiring) {
        errno = EINVAL;
        return -1;
    }
    return shared ? mips64_mm_join_prepare(freeze->session->mm_view,
        &freeze->caller->guard, &freeze->canonical_join) :
        mips64_mm_fork_prepare(freeze->session->mm_view,
        &freeze->caller->guard, &freeze->canonical_child);
}

int mips64_guest_memory_prepare_child_canonical_frozen(
    mips64_guest_memory_fork_freeze_t *freeze)
{
    return prepare_child_canonical_frozen(freeze, false);
}

int mips64_guest_memory_prepare_child_shared_frozen(
    mips64_guest_memory_fork_freeze_t *freeze)
{
    return prepare_child_canonical_frozen(freeze, true);
}

static int fork_child_start(mips64_guest_memory_fork_freeze_t **frozen,
                            mips64_guest_memory_t **copied_parent,
                            mips64_linux_memory_t *copied_vmas,
                            mips64_space_t *copied_space,
                            mips64_file_registry_t *copied_files,
                            mips64_process_memory_t **prepared,
                            mips64_path_resolver_t *resolver,
                            uint32_t slots_per_object,
                            mips64_guest_memory_t **out)
{
    if (copied_parent == out || (frozen != NULL &&
        (frozen == (void *)copied_parent || frozen == (void *)out))) {
        errno = EINVAL;
        return -1;
    }
    if (out != NULL)
        *out = NULL;
    if (copied_parent == NULL || *copied_parent == NULL ||
        copied_vmas == NULL || copied_space == NULL || copied_files == NULL ||
        copied_vmas->space != copied_space ||
        copied_files->space != copied_space ||
        prepared == NULL || *prepared == NULL || out == NULL ||
        resolver == NULL || !resolver->initialized || slots_per_object == 0 ||
        slots_per_object > MIPS64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *copied = *copied_parent;
    if (copied->canonical_space != NULL || copied->source_restricted) {
        errno = EOPNOTSUPP; return -1;
    }
    mips64_guest_memory_fork_freeze_t *freeze = frozen == NULL ? NULL : *frozen;
    bool sealed = freeze != NULL && !freeze->exec_only &&
                  freeze->exec == NULL && freeze->session == copied &&
                  freeze->parent_pid == copied->owner_pid &&
                  freeze->parent_pid != getpid() && copied->fork_frozen &&
                  freeze->caller == copied->held_worker &&
                  mips64_guest_memory_local_frozen_session == copied;
    if (copied->owner_pid == getpid() || copied->phase != MIPS64_GUEST_MEMORY_READY ||
        (frozen == NULL ? copied->extra_workers != 0 ||
                          copied->fork_frozen : !sealed) ||
        copied->transitioning || !copied->bound ||
        copied->backing == NULL ||
        copied_space->page_factory.context != copied->backing ||
        copied_space->managed.context != copied->backing ||
        (copied->owned_image != NULL &&
         (mips64_process_memory_space(copied->owned_image) != copied_space ||
          mips64_process_memory_vmas(copied->owned_image) != copied_vmas ||
          mips64_process_memory_files(copied->owned_image) != copied_files ||
          mips64_process_memory_backing(copied->owned_image) != copied->backing))) {
        errno = EPERM;
        return -1;
    }
    /* The copied registry can be embedded in owned_image and freed below.
     * Preserve this value before any copied view/source ownership is dropped. */
    mips64_file_identity_policy_t identity_policy = copied_files->identity_policy;
    mips64_guest_memory_t *child = calloc(1, sizeof(*child));
    if (child == NULL)
        return -1;
    int result = pthread_mutex_init(&child->lock, NULL);
    if (result != 0) {
        free(child);
        errno = result;
        return -1;
    }
    result = pthread_cond_init(&child->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&child->lock);
        free(child);
        errno = result;
        return -1;
    }
    child->owner_pid = getpid();
    child->resolver = resolver;
    child->phase = MIPS64_GUEST_MEMORY_STARTING;
    child->initial.session = child;
    child->initial.owner = pthread_self();
    child->initial.initial = true;
    child->initial.previous_cancel_state =
        sealed ? freeze->previous_cancel_state :
                 copied->initial.previous_cancel_state;
    child->owned_image = *prepared;
    *prepared = NULL;
    *out = child;

    /* These releases use no copied family guard or pthread synchronization.
     * An attached child owns its image/backing as one unit; the original
     * creator instead borrows its image views and owns backing separately. */
    if (copied->owned_image != NULL) {
        mips64_process_memory_discard(&copied->owned_image);
    } else {
        mips64_linux_memory_destroy(copied_vmas);
        mips64_space_destroy(copied_space);
        mips64_file_registry_destroy(copied_files);
        mips64_family_backing_unbind(copied->backing);
        if (mips64_family_backing_destroy(copied->backing) != 0)
            _exit(125);
    }
    copied->backing = NULL;
    /* Every other worker was idle at the seal. The caller's copied HELD
     * guard and all idle guards are abandoned without release or pthread
     * destruction; the fresh child session enters with a new guard. */
    mips64_guest_memory_worker_t *worker = copied->workers;
    while (worker != NULL) {
        mips64_guest_memory_worker_t *next = worker->next;
        free(worker);
        worker = next;
    }
    copied->workers = NULL;
    if (sealed) {
        mips64_guest_memory_local_frozen_session = NULL;
        free(freeze);
        *frozen = NULL;
    }
    if (mips64_family_fork_child_transfer(&copied->family, &child->family) != 0)
        _exit(125);
    /* Nothing in copied may run a pthread destructor or cancellation restore.
     * The copied family object was freed by transfer. */
    free(copied);
    *copied_parent = NULL;
    if (mips64_family_enter(child->family, &child->initial.guard) != 0) {
        mips64_guest_memory_poison(child);
        return -1;
    }
    child->initial.phase = MIPS64_WORKER_HELD;
    child->held_worker = &child->initial;
    if (mips64_family_mm_id(&child->initial.guard, &child->mm_id) != 0)
        return -1;
    if (mips64_family_observe_inodes(&child->initial.guard,
                                 mips64_guest_memory_observe_inode, resolver) != 0)
        return -1;
    child->observing = true;
    if (mips64_process_memory_set_file_identity_policy(child->owned_image,
                                                    identity_policy) != 0)
        return -1;
    if (mips64_process_memory_commit(child->owned_image, child->family,
                                 &child->initial.guard, slots_per_object) != 0)
        return -1;
    child->backing = mips64_process_memory_backing(child->owned_image);
    if (mips64_process_memory_bind(child->owned_image,
                               &child->initial.guard) != 0)
        return -1;
    child->bound = true;
    child->phase = MIPS64_GUEST_MEMORY_READY;
    return 0;
}

int mips64_guest_memory_fork_child_start(mips64_guest_memory_t **copied_parent,
                                     mips64_linux_memory_t *copied_vmas,
                                     mips64_space_t *copied_space,
                                     mips64_file_registry_t *copied_files,
                                     mips64_process_memory_t **prepared,
                                     mips64_path_resolver_t *resolver,
                                     uint32_t slots_per_object,
                                     mips64_guest_memory_t **out)
{
    return fork_child_start(NULL, copied_parent, copied_vmas, copied_space,
                            copied_files, prepared, resolver,
                            slots_per_object, out);
}

int mips64_guest_memory_fork_child_start_frozen(
    mips64_guest_memory_fork_freeze_t **freeze,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_process_memory_t **prepared, mips64_path_resolver_t *resolver,
    uint32_t slots_per_object, mips64_guest_memory_t **out)
{
    if (freeze == NULL || *freeze == NULL) {
        errno = EINVAL;
        return -1;
    }
    return fork_child_start(freeze, copied_parent, copied_vmas, copied_space,
                            copied_files, prepared, resolver,
                            slots_per_object, out);
}

static int fork_child_start_canonical_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out, bool shared)
{
    if (copied_parent == out || (frozen != NULL &&
        (frozen == (void *)copied_parent || frozen == (void *)out))) {
        errno = EINVAL;
        return -1;
    }
    if (frozen == NULL || *frozen == NULL || copied_parent == NULL ||
        *copied_parent == NULL || copied_vmas == NULL || copied_space == NULL ||
        copied_files == NULL || copied_vmas->space != copied_space ||
        copied_files->space != copied_space || resolver == NULL ||
        !resolver->initialized || out == NULL || *out != NULL || child_task_id == 0 ||
        slots_per_object == 0 || slots_per_object > MIPS64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EINVAL;
        return -1;
    }
    mips64_guest_memory_t *copied = *copied_parent;
    mips64_guest_memory_fork_freeze_t *freeze = *frozen;
    if (copied->owner_pid == getpid() ||
        copied->phase != MIPS64_GUEST_MEMORY_READY ||
        copied->canonical_space != copied_space ||
        copied->canonical_memory != copied_vmas ||
        copied->mm_view == NULL || !copied->source_restricted ||
        copied->transitioning || !copied->bound || !copied->fork_frozen ||
        freeze->exec_only || freeze->exec != NULL ||
        (shared ? freeze->canonical_join == NULL || freeze->canonical_child != NULL :
                  freeze->canonical_child == NULL || freeze->canonical_join != NULL) ||
        freeze->session != copied || freeze->parent_pid != copied->owner_pid ||
        freeze->caller != copied->held_worker ||
        mips64_guest_memory_local_frozen_session != copied ||
        copied_space->page_factory.context != copied->backing ||
        copied_space->managed.context != copied->backing ||
        (copied->owned_image != NULL &&
         (mips64_process_memory_space(copied->owned_image) != copied_space ||
          mips64_process_memory_vmas(copied->owned_image) != copied_vmas ||
          mips64_process_memory_files(copied->owned_image) != copied_files ||
          mips64_process_memory_backing(copied->owned_image) != copied->backing))) {
        errno = EPERM;
        return -1;
    }
    /* Borrow only immutable scalar configuration before retiring copied local
     * owners. No copied mutex, guard, source view or payload enters the child. */
    uint64_t limit = copied_space->limit;
    mips64_file_identity_policy_t identity_policy = copied_files->identity_policy;
    mips64_guest_memory_t *child = calloc(1, sizeof(*child));
    if (child == NULL)
        return -1;
    int result = pthread_mutex_init(&child->lock, NULL);
    if (result != 0) {
        free(child); errno = result; return -1;
    }
    result = pthread_cond_init(&child->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&child->lock);
        free(child); errno = result; return -1;
    }
    child->owner_pid = getpid();
    child->resolver = resolver;
    child->phase = MIPS64_GUEST_MEMORY_STARTING;
    child->source_restricted = true;
    child->cleanup_delegated = copied->cleanup_delegated;
    child->initial.session = child;
    child->initial.owner = pthread_self();
    child->initial.initial = true;
    child->initial.previous_cancel_state = freeze->previous_cancel_state;
    *out = child;

    mips64_mm_view_destroy(&copied->mm_view);
    if (copied->owned_image != NULL) {
        mips64_process_memory_discard(&copied->owned_image);
    } else {
        mips64_linux_memory_destroy(copied_vmas);
        mips64_space_destroy(copied_space);
        mips64_file_registry_destroy(copied_files);
        mips64_family_backing_unbind(copied->backing);
        if (mips64_family_backing_destroy(copied->backing) != 0)
            _exit(125);
    }
    copied->backing = NULL;
    mips64_guest_memory_worker_t *worker = copied->workers;
    while (worker != NULL) {
        mips64_guest_memory_worker_t *next = worker->next;
        free(worker);
        worker = next;
    }
    copied->workers = NULL;
    if (mips64_family_fork_child_transfer(&copied->family, &child->family) != 0)
        _exit(125);
    free(copied);
    *copied_parent = NULL;
    mips64_guest_memory_local_frozen_session = NULL;
    if (mips64_family_enter(child->family, &child->initial.guard) != 0)
        _exit(125);
    child->initial.phase = MIPS64_WORKER_HELD;
    child->held_worker = &child->initial;
    if (mips64_family_observe_inodes(&child->initial.guard,
                                 mips64_guest_memory_observe_inode, resolver) != 0)
        _exit(125);
    child->observing = true;
    if (mips64_process_memory_create_canonical_empty(&child->owned_image,
            child->family, &child->initial.guard, limit,
            slots_per_object, identity_policy) != 0)
        _exit(125);
    child->backing = mips64_process_memory_backing(child->owned_image);
    child->bound = true;
    child->canonical_space = mips64_process_memory_space(child->owned_image);
    child->canonical_memory = mips64_process_memory_vmas(child->owned_image);
    int adopted = shared ?
        mips64_mm_join_child_adopt(&freeze->canonical_join, &child->initial.guard,
            child->backing, child->canonical_space, child->canonical_memory,
            identity_policy, child_task_id, &child->mm_view) :
        mips64_mm_fork_child_adopt(&freeze->canonical_child, &child->initial.guard,
            child->backing, child->canonical_space, child->canonical_memory,
            identity_policy, child_task_id, &child->mm_view);
    if (adopted != 0)
        _exit(125); /* A member commit may have taken effect. Never retry. */
    free(freeze);
    *frozen = NULL;
    child->mm_id = mips64_mm_view_identity(child->mm_view).mm_id;
    child->initial.task_id = child_task_id;
    child->initial.admitted = true;
    child->last_task_id = child_task_id;
    child->phase = MIPS64_GUEST_MEMORY_READY;
    return 0;
}

int mips64_guest_memory_fork_child_start_canonical_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out)
{
    return fork_child_start_canonical_frozen(frozen, copied_parent, copied_vmas,
        copied_space, copied_files, resolver, slots_per_object, child_task_id,
        out, false);
}

int mips64_guest_memory_fork_child_start_shared_frozen(
    mips64_guest_memory_fork_freeze_t **frozen,
    mips64_guest_memory_t **copied_parent, mips64_linux_memory_t *copied_vmas,
    mips64_space_t *copied_space, mips64_file_registry_t *copied_files,
    mips64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, mips64_guest_memory_t **out)
{
    return fork_child_start_canonical_frozen(frozen, copied_parent, copied_vmas,
        copied_space, copied_files, resolver, slots_per_object, child_task_id,
        out, true);
}

mips64_space_t *mips64_guest_memory_child_space(mips64_guest_memory_t *session)
{
    return session == NULL ? NULL : mips64_process_memory_space(session->owned_image);
}

mips64_linux_memory_t *mips64_guest_memory_child_vmas(mips64_guest_memory_t *session)
{
    return session == NULL ? NULL : mips64_process_memory_vmas(session->owned_image);
}

mips64_file_registry_t *mips64_guest_memory_child_files(mips64_guest_memory_t *session)
{
    return session == NULL ? NULL : mips64_process_memory_files(session->owned_image);
}

mips64_guest_memory_worker_t *mips64_guest_memory_initial_worker(mips64_guest_memory_t *session)
{
    return session == NULL ? NULL : &session->initial;
}

bool mips64_guest_memory_worker_active(const mips64_guest_memory_worker_t *worker)
{
    if (worker == NULL || !mips64_guest_memory_local_session(worker->session) ||
        !mips64_guest_memory_owned_by_current(worker))
        return false;
    mips64_guest_memory_t *session = worker->session;
    mips64_guest_memory_lifecycle_lock(session);
    bool active = session->phase == MIPS64_GUEST_MEMORY_READY &&
                  session->held_worker == worker && session->bound &&
                  worker->phase == MIPS64_WORKER_HELD &&
                  (session->canonical_space == NULL ||
                   (worker->admitted && !worker->retired &&
                    !worker->cleanup_only)) &&
                  mips64_family_guard_matches(&worker->guard, session->family);
    mips64_guest_memory_lifecycle_unlock(session);
    return active;
}

bool mips64_guest_memory_active(const mips64_guest_memory_t *session)
{
    return session != NULL &&
           mips64_guest_memory_worker_active(&session->initial);
}

bool mips64_guest_memory_worker_resources(mips64_guest_memory_worker_t *worker,
    mips64_family_guard_t **guard, mips64_family_backing_t **backing, uint64_t *mm_id)
{
    if (guard == NULL || backing == NULL || mm_id == NULL ||
        !mips64_guest_memory_worker_active(worker))
        return false;
    *guard = &worker->guard;
    *backing = worker->session->backing;
    *mm_id = worker->session->mm_id;
    return *mm_id != 0;
}

mips64_mm_view_t *mips64_guest_memory_worker_mm(mips64_guest_memory_worker_t *worker)
{
    return mips64_guest_memory_worker_active(worker) ? worker->session->mm_view : NULL;
}
