/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_parts.h"

static int exec_receive(mips64_family_t **out, mips64_family_guard_t *guard,
                         int owned_control_fd, int owned_dir_fd,
                         mips64_inode_pins_t owned_pins, mips64_file_caps_client_t sources,
                         const mips64_family_exec_state_t *state, bool terminal_sources)
{
    if (out == NULL || *out != NULL || guard == NULL || guard->held || state == NULL ||
        state->owner_pid != (uint64_t)getpid() || state->incarnation == 0 ||
        state->incarnation >= state->next_incarnation ||
        !mips64_family_distinct_source_fds(owned_control_fd, owned_dir_fd, owned_pins, sources) ||
        !mips64_family_exec_identity_matches(owned_control_fd, owned_dir_fd, &state->identity)) {
        mips64_family_close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, sources);
        errno = EINVAL;
        return -1;
    }
    size_t length = strnlen(state->directory, sizeof(state->directory));
    struct stat path_status;
    if (length == sizeof(state->directory) ||
        (!state->creator && length != 0) ||
        (state->creator && (state->directory[0] != '/' ||
         fstatat(AT_FDCWD, state->directory, &path_status, AT_SYMLINK_NOFOLLOW) != 0 ||
         !S_ISDIR(path_status.st_mode) ||
         path_status.st_dev != state->identity.directory_device ||
         path_status.st_ino != state->identity.directory_inode))) {
        mips64_family_close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, sources);
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = NULL;
    if (mips64_family_initialize_family(&family, owned_control_fd, owned_dir_fd, owned_pins,
                           sources, state->creator,
                           state->creator ? state->directory : NULL,
                           terminal_sources, MIPS64_FAMILY_AUTHORITY_AUTO) != 0)
        return -1;
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state);
    if (result != 0) {
        (void)mips64_family_destroy(family);
        errno = result;
        return -1;
    }
    result = pthread_mutex_lock(&family->local_mutex);
    if (result != 0) {
        (void)mips64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = result;
        return -1;
    }
    /* A conflicting owner means continuity was lost. Never block here and
     * silently reacquire ownership after another process has run. */
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    result = fcntl(family->control_fd, F_SETLK, &lock);
    int saved = errno;
    mips64_family_control_t *control = family->control;
    atomic_thread_fence(memory_order_acquire);
    if (result == 0 && (control->active != 1 || control->retired != 0 ||
        control->active_incarnation != state->incarnation ||
        control->recovery_epoch != state->recovery_epoch ||
        control->next_incarnation != state->next_incarnation ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != MIPS64_LOG_EMPTY)) {
        result = -1;
        saved = EIO;
    }
    /* The exact inherited descriptor retains this same-PID lease through
     * exec. Reassert its range without releasing any existing record lock. */
    if (result == 0 && mips64_family_acquire_owner_lease(family, state->incarnation) != 0) {
        result = -1;
        saved = errno;
    }
    if (result != 0) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)mips64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    family->incarnation = state->incarnation;
    family->active_guard = guard;
    *guard = (mips64_family_guard_t){.family = family, .incarnation = state->incarnation,
                                .owner_thread = pthread_self(),
                                .previous_cancel_state = previous_cancel_state, .held = true};
    if (control->source_mode != 0 && !terminal_sources &&
        mips64_family_recover_file_state(guard) != 0) {
        saved = errno;
        family->active_guard = NULL;
        memset(guard, 0, sizeof(*guard));
        if (mips64_family_unlock_family_file(family) != 0)
            saved = EIO;
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)mips64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    *out = family;
    return 0;
}

int mips64_family_exec_receive(mips64_family_t **out, mips64_family_guard_t *guard,
                            int owned_control_fd, int owned_dir_fd,
                            mips64_inode_pins_t owned_pins,
                            const mips64_family_exec_state_t *state)
{
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                          (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER,
                          state, false);
}

int mips64_family_exec_receive_sources(mips64_family_t **out, mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state)
{
    if (!mips64_family_source_caps_present(owned_sources)) {
        mips64_family_close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                          owned_sources, state, false);
}

int mips64_family_exec_receive_sources_terminal(mips64_family_t **out,
                                    mips64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    mips64_inode_pins_t owned_pins,
                                    mips64_file_caps_client_t owned_sources,
                                    const mips64_family_exec_state_t *state)
{
    if (!mips64_family_source_caps_present(owned_sources)) {
        mips64_family_close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                        owned_sources, state, true);
}

int mips64_family_fork_child_transfer(mips64_family_t **inherited,
                                   mips64_family_t **attached)
{
    if (inherited == NULL || attached == NULL || inherited == attached) {
        errno = EINVAL;
        return -1;
    }
    *attached = NULL;
    mips64_family_t *copied = *inherited;
    if (copied != NULL && copied->local_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    if (copied == NULL || !copied->initialized ||
        copied->destroying || copied->cleaned || copied->poisoned ||
        copied->control == NULL || copied->control_fd < 3 ||
        copied->dir_fd < 3 || copied->control_fd == copied->dir_fd) {
        errno = EINVAL;
        return -1;
    }
    if (copied->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (atomic_load_explicit(&copied->live_views, memory_order_relaxed) != 0) {
        errno = EBUSY;
        return -1;
    }
    /* The mapped control is shared, but this unmap only drops this child's
     * inherited VA. Never clear control.active: the parent still owns its
     * POSIX record lock and will leave using its own guard and mutex. */
    if (munmap(copied->control, sizeof(mips64_family_control_t)) != 0)
        return -1;
    int control_fd = copied->control_fd;
    int dir_fd = copied->dir_fd;
    mips64_inode_pins_t pins = copied->pins;
    mips64_file_caps_client_t sources = copied->sources;
#ifdef MIPS64_FAMILY_TESTING
    bool inject_failure = copied->test_fail_child_transfer_attach;
#endif
    copied->control = NULL;
    copied->control_fd = -1;
    copied->dir_fd = -1;
    copied->pins = (mips64_inode_pins_t)MIPS64_INODE_PINS_INITIALIZER;
    copied->sources = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    copied->active_guard = NULL;
    copied->inode_observer = NULL;
    copied->inode_observer_context = NULL;
    /* The copied local mutex may be locked by a vanished native worker.
     * Neither lock, unlock nor destroy it in the child. */
    free(copied);
    *inherited = NULL;
#ifdef MIPS64_FAMILY_TESTING
    if (inject_failure) {
        (void)close(control_fd);
        control_fd = -1;
    }
#endif
    return mips64_family_initialize_family(attached, control_fd, dir_fd, pins, sources,
                             false, NULL, false, MIPS64_FAMILY_AUTHORITY_AUTO);
}

int mips64_family_create_with_authority(mips64_family_t **out,
                                     mips64_family_storage_authority_t authority)
{
    if (out == NULL || !mips64_family_authority_valid(authority)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    struct rlimit native_fsize;
    if (getrlimit(RLIMIT_FSIZE, &native_fsize) != 0)
        return -1;
    bool zero_backing = native_fsize.rlim_max == 0;
    if (!zero_backing && authority != MIPS64_FAMILY_AUTHORITY_AUTO) {
        errno = EOPNOTSUPP; /* No policy transport through native exec yet. */
        return -1;
    }
#ifndef __linux__
    if (zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
#endif
    char path[] = MIPS64_FAMILY_DIR_TEMPLATE;
    if (mkdtemp(path) == NULL)
        return -1;
    if (chmod(path, 0700) != 0) {
        int saved = errno;
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir_fd < 0) {
        int saved = errno;
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    if (mips64_family_normalize_owned_fd(&dir_fd) != 0) {
        int saved = errno;
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    int control_fd = openat(dir_fd, "control", O_RDWR | O_CREAT | O_EXCL |
                            O_CLOEXEC | O_NOFOLLOW, 0600);
    if (control_fd < 0) {
        int saved = errno;
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    if (mips64_family_normalize_owned_fd(&control_fd) != 0) {
        int saved = errno;
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    uint64_t control_extent = 0;
    if (!mips64_family_catalog_reserved_end(&control_extent) || fchmod(control_fd, 0600) != 0 ||
        (zero_backing ? (control_extent > MIPS64_ZERO_CONTROL_HEAD_SIZE ||
                         !mips64_family_family_authorize_fd(dir_fd, true, authority) ||
                         !mips64_family_family_authorize_fd(control_fd, false, authority)) :
                        ftruncate(control_fd, (off_t)control_extent) != 0)) {
        int saved = errno;
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    mips64_family_zero_segment_t zero_control = {0};
    void *mapping;
    if (zero_backing) {
        int result = mips64_family_zero_segment_create(
            MIPS64_FAMILY_ZERO_SEGMENT_CONTROL, 0,
            MIPS64_ZERO_CONTROL_HEAD_SIZE,
            &zero_control);
        if (result == 0)
            result = mips64_family_zero_segment_publish_fd(control_fd,
                                                        &zero_control);
        mapping = result == 0 ? zero_control.payload : MAP_FAILED;
    } else {
        mapping = mmap(NULL, sizeof(mips64_family_control_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, control_fd, 0);
    }
    if (mapping == MAP_FAILED) {
        int saved = errno;
        mips64_family_zero_segment_detach(&zero_control);
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    memset(mapping, 0, sizeof(mips64_family_control_t));
    mips64_family_control_t *control = mapping;
    control->magic = MIPS64_FAMILY_MAGIC;
    control->version = MIPS64_FAMILY_VERSION;
    control->size = (uint32_t)sizeof(mips64_family_control_t);
    control->next_incarnation = 1;
    control->next_object_id = 1;
    control->next_wait_id = 1;
    control->next_mm_id = 1;
    control->next_file_id = 1;
    control->next_source_id = 1;
    atomic_init(&control->log_marker, MIPS64_LOG_EMPTY);
    int sync_result = zero_backing ? 0 :
        msync(mapping, sizeof(mips64_family_control_t), MS_SYNC);
    int sync_errno = errno;
    if (!zero_backing)
        (void)munmap(mapping, sizeof(mips64_family_control_t));
    if (sync_result != 0) {
        mips64_family_zero_segment_detach(&zero_control);
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = sync_errno;
        return -1;
    }
    mips64_inode_pins_t pins = MIPS64_INODE_PINS_INITIALIZER;
    int created = mips64_inode_pins_create(&pins);
    int initialized;
    if (created == 0)
        initialized = mips64_family_initialize_family(out, control_fd, dir_fd, pins,
                                           (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER,
                                           true, path, false, authority);
    else {
        int saved = errno;
        mips64_family_close_owned_fds(control_fd, dir_fd);
        errno = saved;
        initialized = -1;
    }
    if (initialized != 0) {
        int saved = errno;
        mips64_family_zero_segment_detach(&zero_control);
        int cleanup_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (cleanup_fd >= 0) {
            (void)unlinkat(cleanup_fd, "control", 0);
            (void)close(cleanup_fd);
        }
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    mips64_family_zero_segment_detach(&zero_control);
    return 0;
}

int mips64_family_create(mips64_family_t **out)
{
    return mips64_family_create_with_authority(out, MIPS64_FAMILY_AUTHORITY_AUTO);
}

/* Only for a new, never-published family: the service predates its creation,
 * and there are no workers, views or borrowed native capabilities. Discarding
 * unreachable staging does not need replay. Cancellation is restored only
 * when this guard is still held, and only after the local FDs are destroyed.
 * A guard that leave already released is not changed here. */
static void discard_unpublished_family(mips64_family_t *family, mips64_family_guard_t *guard)
{
    bool held = guard->held;
    int previous = guard->previous_cancel_state;
    if (held) {
        family->active_guard = NULL;
        guard->held = false;
        guard->family = NULL;
        (void)pthread_mutex_unlock(&family->local_mutex);
    }
    int scan_fd = fcntl(family->dir_fd, F_DUPFD_CLOEXEC, 3);
    DIR *stream = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (stream == NULL && scan_fd >= 0)
        (void)close(scan_fd);
    if (stream != NULL) {
        struct dirent *entry;
        while ((entry = readdir(stream)) != NULL) {
            if (!mips64_family_owned_entry_name(entry->d_name))
                continue;
            struct stat status;
            if (fstatat(family->dir_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
                (status.st_mode & 07777) == 0600 && status.st_nlink == 1)
                (void)unlinkat(family->dir_fd, entry->d_name, 0);
        }
        (void)closedir(stream);
    }
    /* Directory failure can leave private orphan files; native failure cannot
     * justify publishing an incomplete family or retaining a local FD owner. */
    (void)rmdir(family->directory);
    (void)mips64_family_destroy(family);
    if (held)
        (void)pthread_setcancelstate(previous, NULL);
}

int mips64_family_create_with_sources_authority(mips64_family_t **out,
    mips64_file_caps_client_t *owned, mips64_family_storage_authority_t authority)
{
    mips64_file_caps_client_t sources = MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    if (owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_file_caps_client_t supplied = *owned;
    *owned = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    if (out == NULL || *out != NULL || !mips64_family_authority_valid(authority)) {
        mips64_file_caps_client_close(&supplied);
        errno = EINVAL;
        return -1;
    }
    if (mips64_file_caps_client_adopt(&sources, supplied.request_fd,
                                   supplied.lifetime_fd) != 0)
        return -1;
    mips64_family_t *family = NULL;
    if (mips64_family_create_with_authority(&family, authority) != 0) {
        int saved = errno;
        mips64_file_caps_client_close(&sources);
        errno = saved;
        return -1;
    }
    mips64_family_guard_t guard = {0};
    uint64_t root = 0;
    int result = mips64_family_enter(family, &guard);
    if (result == 0)
        result = mips64_family_file_index_create_empty(&guard, &root);
    int saved = errno;
    if (result == 0) {
        result = mips64_family_leave(&guard);
        saved = errno;
    }
    if (result != 0) {
        mips64_file_caps_client_close(&sources);
        discard_unpublished_family(family, &guard);
        errno = saved;
        return -1;
    }
    /* No attachment/worker sees this private mode0 family before its complete
     * index, original client and immutable mode/root agree. */
    family->sources = sources;
    family->control->file_index_object = root;
    family->control->source_mode = 1;
    atomic_thread_fence(memory_order_release);
    *out = family;
    return 0;
}

int mips64_family_create_with_sources(mips64_family_t **out, mips64_file_caps_client_t *owned)
{
    return mips64_family_create_with_sources_authority(out, owned,
                                                   MIPS64_FAMILY_AUTHORITY_AUTO);
}

 int mips64_family_family_enter_internal(mips64_family_t *family, mips64_family_guard_t *guard,
                                 bool allow_retired)
{
    if (family == NULL || guard == NULL || !family->initialized || guard->held ||
        family->local_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    if (family->exec_active) {
        errno = EBUSY;
        return -1;
    }
    int old_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    result = pthread_mutex_lock(&family->local_mutex);
    if (result != 0) {
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = result;
        return -1;
    }
    if (family->destroying || family->cleaned || family->poisoned) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = family->poisoned ? EIO : EIDRM;
        return -1;
    }
    if (mips64_family_lock_file(family->control_fd, F_WRLCK) != 0) {
        int saved = errno;
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    atomic_thread_fence(memory_order_acquire);
    if (family->inode_observer != NULL &&
        mips64_family_scan_inodes(family->control_fd, family->dir_fd,
                              family->inode_observer,
                              family->inode_observer_context) != 0)
        goto unlock_fail;
    mips64_family_control_t *control = family->control;
    if (control->active != 0) {
        if (control->recovery_epoch == UINT64_MAX) {
            errno = EOVERFLOW;
            goto unlock_fail;
        }
        ++control->recovery_epoch;
        if (mips64_family_replay_committed(family) != 0)
            goto unlock_fail;
        if (atomic_load_explicit(&control->log_marker, memory_order_acquire) ==
            MIPS64_LOG_PREPARED)
            atomic_store_explicit(&control->log_marker, MIPS64_LOG_EMPTY,
                                  memory_order_release);
    } else {
        uint32_t marker = atomic_load_explicit(&control->log_marker, memory_order_acquire);
        if (marker == MIPS64_LOG_COMMITTED && mips64_family_replay_committed(family) != 0)
            goto unlock_fail;
        if (marker != MIPS64_LOG_EMPTY && marker != MIPS64_LOG_PREPARED && marker != MIPS64_LOG_COMMITTED) {
            errno = EIO;
            goto unlock_fail;
        }
        if (marker == MIPS64_LOG_PREPARED)
            atomic_store_explicit(&control->log_marker, MIPS64_LOG_EMPTY, memory_order_release);
    }
    if (family->incarnation == 0) {
        off_t ignored;
        if (!mips64_family_owner_lease_offset(control->next_incarnation, &ignored)) {
            errno = EOVERFLOW;
            goto unlock_fail;
        }
        /* Consume the identity before attempting its lease. A failed entry
         * may leave a gap, but must never allow an identity to be reused. */
        uint64_t incarnation = control->next_incarnation++;
        if (mips64_family_acquire_owner_lease(family, incarnation) != 0)
            goto unlock_fail;
        family->incarnation = incarnation;
    }
    if (control->retired != 0 && !allow_retired) {
        errno = EIDRM;
        goto unlock_fail;
    }
    control->active_incarnation = family->incarnation;
    control->active = 1;
    family->active_guard = guard;
    guard->family = family;
    guard->incarnation = family->incarnation;
    guard->owner_thread = pthread_self();
    guard->previous_cancel_state = old_cancel_state;
    guard->held = true;
    /* Ordinary redo above restores a cursor/payload pair first. The complete
     * resize then drains under a provisional guard before any caller sees it,
     * including an intent left by a graceful leave rather than process death. */
    if (control->source_mode != 0 && mips64_family_recover_file_state(guard) != 0) {
        family->active_guard = NULL;
        memset(guard, 0, sizeof(*guard));
        goto unlock_fail;
    }
    return 0;

unlock_fail: {
        int saved = errno;
        if (mips64_family_unlock_family_file(family) != 0) {
            family->poisoned = true;
            saved = EIO;
        }
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = saved;
        return -1;
    }
}

int mips64_family_enter(mips64_family_t *family, mips64_family_guard_t *guard)
{
    return mips64_family_family_enter_internal(family, guard, false);
}

int mips64_family_leave(mips64_family_guard_t *guard)
{
    return mips64_family_leave_with_cleanup(guard, NULL, NULL);
}

int mips64_family_leave_with_cleanup(mips64_family_guard_t *guard,
                                  void (*after_unlock)(void *context),
                                  void *context)
{
    if (!mips64_family_guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    if (family->exec_prepared != NULL) {
        errno = EBUSY;
        return -1;
    }
    family->control->active = 0;
    family->control->active_incarnation = 0;
    atomic_thread_fence(memory_order_release);
    int unlock_result = mips64_family_unlock_family_file(family);
    int saved = errno;
    if (unlock_result != 0)
        family->poisoned = true;
    guard->held = false;
    guard->family = NULL;
    family->active_guard = NULL;
    if (unlock_result == 0 && after_unlock != NULL)
        after_unlock(context);
    int mutex_result = pthread_mutex_unlock(&family->local_mutex);
    int cancel_result = pthread_setcancelstate(guard->previous_cancel_state, NULL);
    if (unlock_result != 0) {
        errno = saved;
        return -1;
    }
    if (mutex_result != 0) {
        errno = mutex_result;
        return -1;
    }
    if (cancel_result != 0) {
        errno = cancel_result;
        return -1;
    }
    return 0;
}

uint64_t mips64_family_incarnation(const mips64_family_t *family)
{
    return family == NULL ? 0 : family->incarnation;
}

bool mips64_family_zero_backing(const mips64_family_t *family)
{
    return family != NULL && family->zero_backing;
}

int mips64_family_owner_alive(const mips64_family_guard_t *guard, uint64_t incarnation,
                           bool *alive)
{
    off_t offset;
    if (!mips64_family_guard_valid(guard) || alive == NULL ||
        !mips64_family_owner_lease_offset(incarnation, &offset) ||
        incarnation >= guard->family->control->next_incarnation) {
        errno = EINVAL;
        return -1;
    }
    if (incarnation == guard->family->incarnation) {
        *alive = true;
        return 0;
    }
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = offset, .l_len = 1};
    int result;
    do { result = fcntl(guard->family->control_fd, F_GETLK, &lock); }
    while (result < 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (lock.l_type != F_UNLCK && lock.l_type != F_WRLCK) {
        errno = EIO;
        return -1;
    }
    *alive = lock.l_type == F_WRLCK;
    return 0;
}

int mips64_family_identity(const mips64_family_guard_t *guard,
                        mips64_family_identity_t *out)
{
    if (!mips64_family_guard_valid(guard) || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct stat control, directory;
    if (fstat(guard->family->control_fd, &control) != 0 ||
        fstat(guard->family->dir_fd, &directory) != 0)
        return -1;
    *out = (mips64_family_identity_t){
        .control_device = control.st_dev,
        .directory_device = directory.st_dev,
        .control_inode = control.st_ino,
        .directory_inode = directory.st_ino
    };
    return 0;
}

int mips64_family_pin_file(mips64_family_guard_t *guard, int source_fd)
{
    if (!mips64_family_guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    if (family->exec_prepared != NULL) {
        errno = EBUSY;
        return -1;
    }
    return mips64_inode_pins_keep(&family->pins, source_fd,
                               &family->control->inode_pin_attempts);
}

const mips64_file_caps_client_t *mips64_family_sources(const mips64_family_guard_t *guard)
{
    if (!mips64_family_guard_valid(guard)) {
        errno = EINVAL;
        return NULL;
    }
    if (!mips64_family_source_caps_present(guard->family->sources)) {
        errno = EOPNOTSUPP;
        return NULL;
    }
    return &guard->family->sources;
}

uint64_t mips64_family_file_index_object(const mips64_family_guard_t *guard)
{
    if (!mips64_family_guard_valid(guard)) { errno = EINVAL; return 0; }
    mips64_family_control_t *control = guard->family->control;
    if (control->source_mode == 0) { errno = EOPNOTSUPP; return 0; }
    if (control->file_index_object == 0 || control->file_index_object >= control->next_object_id) {
        errno = EIO; return 0;
    }
    return control->file_index_object;
}

static int reject_source_inode(void *context, const struct stat *candidate)
{
    const struct stat *source = context;
    if (source->st_dev == candidate->st_dev && source->st_ino == candidate->st_ino) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int mips64_family_file_target_check(mips64_family_guard_t *guard, int source_fd)
{
    if (!mips64_family_guard_valid(guard) || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    mips64_family_control_t *control = family->control;
    if (!mips64_family_source_caps_present(family->sources) || control->source_mode != 1) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (family->exec_prepared != NULL ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != MIPS64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    struct stat source;
    if (fstat(source_fd, &source) != 0)
        return -1;
    if (!S_ISREG(source.st_mode) || source.st_size < 0) {
        errno = EINVAL;
        return -1;
    }
    /* Never open/duplicate control or any alias while holding its POSIX lock.
     * Scan through nofollow stat only, retaining borrowed source ownership. */
    if (mips64_family_scan_inodes(family->control_fd, family->dir_fd,
                              reject_source_inode, &source) != 0)
        return -1;
    return 0;
}

int mips64_family_source_register(mips64_family_guard_t *guard,
                                int source_fd, uint64_t *source_id)
{
    if (source_id == NULL) { errno = EINVAL; return -1; }
    if (mips64_family_file_target_check(guard, source_fd) != 0)
        return -1;
    mips64_family_t *family = guard->family;
    mips64_family_control_t *control = family->control;
    if (control->next_source_id == 0 ||
        control->next_source_id > MIPS64_FILE_CAPS_MAX_ATTEMPTS + 1u ||
        control->source_attempts > MIPS64_FILE_CAPS_MAX_ATTEMPTS ||
        control->source_attempts >= control->next_source_id) {
        errno = EIO;
        return -1;
    }
    if (control->next_source_id > MIPS64_FILE_CAPS_MAX_ATTEMPTS ||
        control->source_attempts == MIPS64_FILE_CAPS_MAX_ATTEMPTS) {
        errno = ENOSPC;
        return -1;
    }
    uint64_t id = control->next_source_id++;
    atomic_thread_fence(memory_order_release);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_SOURCE_ALLOCATED, family->hook_context);
#endif
    if (mips64_file_caps_register(&family->sources, source_fd, id, &control->source_attempts) != 0)
        return -1;
    *source_id = id;
    return 0;
}

/* The sole control FD also owns this reserved extent. Never reopen/duplicate
 * it: closing any second descriptor would release the process's token lock. */
 int mips64_family_read_file_catalog(mips64_family_t *family, size_t count,
                              mips64_file_catalog_record_t **out)
{
    *out = NULL;
    uint64_t end;
    uint64_t extent;
    if (count > MIPS64_FILE_CATALOG_CAPACITY ||
        family->control->file_count > MIPS64_FILE_CATALOG_CAPACITY ||
        count > family->control->inode_pin_attempts ||
        family->control->next_file_id == 0 || !mips64_family_catalog_reserved_end(&end)) {
        errno = EIO;
        return -1;
    }
    if (mips64_family_family_control_extent(family, &extent) != 0)
        return -1;
    if (extent < end) {
        errno = EIO;
        return -1;
    }
    if (count == 0)
        return 0;
    size_t bytes = count * sizeof(mips64_file_catalog_record_t);
    mips64_file_catalog_record_t *records = malloc(bytes);
    if (records == NULL)
        return -1;
    uint64_t start = end - MIPS64_FILE_CATALOG_CAPACITY * sizeof(*records);
    if (mips64_family_family_control_read(family, records, bytes, start) != 0) {
        int saved = errno;
        free(records);
        errno = saved;
        return -1;
    }
    if (!mips64_file_catalog_validate(records, count, family->control->next_file_id)) {
        free(records);
        errno = EIO;
        return -1;
    }
    *out = records;
    return 0;
}
