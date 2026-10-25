/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_parts.h"

int mips64_family_object_create(mips64_family_guard_t *guard, uint32_t slot_count,
                            mips64_family_object_t **out)
{
    size_t size;
    if (out == NULL || !mips64_family_guard_valid(guard) ||
        !mips64_family_object_file_size(slot_count, &size)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    mips64_family_t *family = guard->family;
    uint64_t id = family->control->next_object_id;
    if (id == 0 || id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    char name[48];
    if (mips64_family_object_name(id, name) != 0)
        return -1;
    /* Like one-page creation, an interrupted O_EXCL may leave an orphan;
     * consume the ID first so that it can never identify a later object. */
    family->control->next_object_id = id + 1;
    int fd = openat(family->dir_fd, name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    if (mips64_family_normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    mips64_family_object_t *object = mips64_family_map_object(family, id, slot_count, fd, true);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (mips64_family_observe_open_inode(family, fd) != 0) {
        int saved = errno;
        mips64_family_object_close(object);
        /* A possibly registered identity retains this initialized inode. */
        errno = saved;
        return -1;
    }
    *out = object;
    return 0;
}

int mips64_family_object_open(mips64_family_guard_t *guard, uint64_t object_id,
                          mips64_family_object_t **out)
{
    if (out == NULL || !mips64_family_guard_valid(guard) || object_id == 0) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    char name[48];
    if (mips64_family_object_name(object_id, name) != 0)
        return -1;
    if (mips64_family_reject_control_alias(guard->family->control_fd,
                                        guard->family->dir_fd, name) != 0)
        return -1;
    int fd = openat(guard->family->dir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (mips64_family_normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        errno = saved;
        return -1;
    }
    mips64_family_object_t *object = mips64_family_map_object(guard->family, object_id, 0, fd, false);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (mips64_family_observe_open_inode(guard->family, fd) != 0) {
        int saved = errno;
        mips64_family_object_close(object);
        errno = saved;
        return -1;
    }
    *out = object;
    return 0;
}

void mips64_family_object_close(mips64_family_object_t *object)
{
    if (object == NULL)
        return;
    int saved = errno;
    if (object->mapping != NULL && !object->family->zero_backing)
        (void)munmap(object->mapping, object->mapping_size);
    if (object->fd >= 0)
        (void)close(object->fd);
    (void)atomic_fetch_sub_explicit(&object->family->live_views, 1,
                                    memory_order_relaxed);
    free(object);
    errno = saved;
}

uint64_t mips64_family_object_id(const mips64_family_object_t *object)
{
    return object == NULL ? 0 : object->object_id;
}

uint32_t mips64_family_object_count(const mips64_family_object_t *object)
{
    return object == NULL ? 0 : object->slot_count;
}

int mips64_family_object_snapshot_observed(const mips64_family_guard_t *guard,
                                       const mips64_family_object_t *object,
                                       uint32_t page_index, mips64_family_page_state_t *out,
                                       mips64_measure_observer_t *measure)
{
    if (!mips64_family_guard_valid_observed(guard, measure) || object == NULL || out == NULL ||
        object->family != guard->family || page_index >= object->slot_count) {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, &object->mapping->slots[page_index].state, sizeof(*out));
    return 0;
}

int mips64_family_object_snapshot(const mips64_family_guard_t *guard,
                              const mips64_family_object_t *object,
                              uint32_t page_index, mips64_family_page_state_t *out)
{
    return mips64_family_object_snapshot_observed(guard, object, page_index, out, NULL);
}

int mips64_family_object_commitv(mips64_family_guard_t *guard,
                             const mips64_family_object_update_t *updates,
                             size_t count)
{
    if (!mips64_family_guard_valid(guard) || updates == NULL || count == 0 || count > 2) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_page_key_t keys[2] = {{0, 0}, {0, 0}};
    mips64_family_page_state_t *destinations[2] = {NULL, NULL};
    const mips64_family_page_state_t *targets[2] = {NULL, NULL};
    for (size_t i = 0; i < count; ++i) {
        mips64_family_object_t *object = updates[i].object;
        if (object == NULL || updates[i].target == NULL ||
            object->family != guard->family ||
            updates[i].page_index >= object->slot_count) {
            errno = EINVAL;
            return -1;
        }
        keys[i] = (mips64_family_page_key_t){object->object_id, updates[i].page_index};
        destinations[i] = &object->mapping->slots[updates[i].page_index].state;
        targets[i] = updates[i].target;
    }
    return mips64_family_commit_states(guard, count == 2 ? MIPS64_LOG_OBJECT_PAIR : MIPS64_LOG_OBJECT,
                         count, keys, destinations, targets, false);
}

int mips64_family_object_commit(mips64_family_guard_t *guard, mips64_family_object_t *object,
                            uint32_t page_index,
                            const mips64_family_page_state_t *target)
{
    mips64_family_object_update_t update = {object, page_index, target};
    return mips64_family_object_commitv(guard, &update, 1);
}

int mips64_family_object_commit_file_refresh(mips64_family_guard_t *guard,
                                         mips64_family_object_t *object,
                                         uint32_t page_index,
                                         const mips64_family_page_state_t *target)
{
    if (!mips64_family_guard_valid(guard) || object == NULL || target == NULL ||
        object->family != guard->family || page_index >= object->slot_count) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_page_key_t keys[2] = {{object->object_id, page_index}, {0, 0}};
    mips64_family_page_state_t *destinations[2] = {
        &object->mapping->slots[page_index].state, NULL
    };
    const mips64_family_page_state_t *targets[2] = {target, NULL};
    return mips64_family_commit_states(guard, MIPS64_LOG_OBJECT, 1, keys, destinations, targets, true);
}

static int cleanup_held(mips64_family_guard_t *guard, bool fresh_scan)
{
    if (!mips64_family_guard_valid(guard) || !guard->family->creator ||
        guard->family->cleaned) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    if (family->inode_observer != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (atomic_load_explicit(&family->live_views, memory_order_relaxed) != 0) {
        errno = EBUSY;
        return -1;
    }
    bool was_retired = family->control->retired != 0;
    family->control->retired = 1;
    atomic_thread_fence(memory_order_release);
    /* A service receiving a metadata-only directory right has no inherited
     * DIR* cursor. Open a fresh enumerator relative to that exact capability;
     * every authority-bearing fstatat/unlinkat still uses the retained FD. */
    int scan_fd = fresh_scan ?
        openat(family->dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) :
        fcntl(family->dir_fd, F_DUPFD_CLOEXEC, 3);
    if (scan_fd < 0) {
        int saved = errno;
        if (!was_retired)
            family->control->retired = 0;
        errno = saved;
        return -1;
    }
    if (fresh_scan) {
        struct stat exact, opened;
        int stat_error = 0;
        if (fstat(family->dir_fd, &exact) != 0 ||
            fstat(scan_fd, &opened) != 0)
            stat_error = errno;
        else if (exact.st_dev != opened.st_dev || exact.st_ino != opened.st_ino)
            stat_error = EIO;
        if (stat_error != 0) {
            (void)close(scan_fd);
            if (!was_retired)
                family->control->retired = 0;
            errno = stat_error;
            return -1;
        }
    }
    DIR *directory = fdopendir(scan_fd);
    if (directory == NULL) {
        int saved = errno;
        (void)close(scan_fd);
        if (!was_retired)
            family->control->retired = 0;
        errno = saved;
        return -1;
    }
    struct dirent *entry;
    int unlink_error = 0;
    /* The service's fresh openat(".") stream starts at offset zero; its
     * metadata-only host scan role need not implement cursor seek. An
     * ordinary duplicated local stream may share an advanced offset. */
    if (!fresh_scan)
        rewinddir(directory);
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0 && unlink_error == 0)
                unlink_error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!mips64_family_owned_entry_name(entry->d_name)) {
            if (unlink_error == 0)
                unlink_error = EBUSY;
            continue;
        }
        struct stat status;
        if (fstatat(family->dir_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            if (unlink_error == 0)
                unlink_error = errno;
            continue;
        }
        size_t object_maximum = 0;
        (void)mips64_family_object_file_size(MIPS64_FAMILY_OBJECT_MAX_SLOTS, &object_maximum);
        off_t maximum_size = strcmp(entry->d_name, "control") == 0
                           ? 0
                           : memcmp(entry->d_name, "object-", 7) == 0
                           ? (off_t)object_maximum
                           : (off_t)sizeof(mips64_family_page_file_t);
        bool control_file = strcmp(entry->d_name, "control") == 0;
        if (control_file && !mips64_family_wait_control_max_size(&maximum_size)) {
            if (unlink_error == 0)
                unlink_error = EOVERFLOW;
            continue;
        }
        if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
            status.st_uid != geteuid() || status.st_nlink != 1 ||
            status.st_size < 0 || status.st_size > maximum_size ||
            (control_file && !family->zero_backing &&
             status.st_size < (off_t)sizeof(mips64_family_control_t)) ||
            (family->zero_backing && status.st_size != 0)) {
            if (unlink_error == 0)
                unlink_error = EPERM;
            continue;
        }
        if (unlinkat(family->dir_fd, entry->d_name, 0) != 0 && unlink_error == 0)
            unlink_error = errno;
    }
    if (closedir(directory) != 0 && unlink_error == 0)
        unlink_error = errno;
    if (unlink_error != 0) {
        errno = unlink_error;
        return -1;
    }
    if (rmdir(family->directory) != 0) {
        return -1;
    }
    family->cleaned = true;
    return 0;
}

int mips64_family_cleanup(mips64_family_t *family)
{
    if (family == NULL || !family->creator || family->cleaned) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_guard_t guard = {0};
    if (mips64_family_family_enter_internal(family, &guard, true) != 0)
        return -1;
    int result = cleanup_held(&guard, false);
    int saved = errno;
    if (mips64_family_leave(&guard) != 0)
        return -1;
    errno = saved;
    return result;
}

int mips64_family_cleanup_held_terminal(mips64_family_guard_t *guard,
                                    bool sole_family_owner)
{
    /* The caller proves no other process can hold a family member, source
     * client, or view. Creator status by itself is never this proof. */
    if (!sole_family_owner) {
        errno = EPERM;
        return -1;
    }
    if (!mips64_family_guard_valid(guard) || guard->family->control->source_mode != 1 ||
        atomic_load_explicit(&guard->family->control->log_marker,
                             memory_order_acquire) != MIPS64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    return cleanup_held(guard, false);
}

int mips64_family_register_service_cleanup(mips64_family_guard_t *guard,
                                       bool *may_have_delegated)
{
    if (may_have_delegated != NULL)
        *may_have_delegated = false;
    if (!mips64_family_guard_valid(guard) || may_have_delegated == NULL ||
        !guard->family->creator || guard->family->cleaned ||
        guard->family->control->source_mode != 1 ||
        guard->family->directory[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    return mips64_file_caps_register_terminal_cleanup(&family->sources,
        family->control_fd, family->dir_fd, family->directory,
        may_have_delegated);
}

void mips64_family_cleanup_service_release(void *retained)
{
    mips64_zero_service_retained_t *owner = retained;
    if (owner == NULL)
        return;
    mips64_family_zero_segment_detach(&owner->root.segment);
    mips64_family_zero_segment_detach(&owner->control);
    free(owner);
}

int mips64_family_cleanup_service_prepare_authority(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    mips64_family_storage_authority_t authority)
{
    if (out == NULL || *out != NULL || borrowed_control_fd < 3 ||
        borrowed_directory_fd < 3 || directory == NULL ||
        !mips64_family_authority_valid(authority)) {
        errno = EINVAL;
        return -1;
    }
    struct stat control_status;
    if (fstat(borrowed_control_fd, &control_status) != 0)
        return -1;
    if (control_status.st_size != 0)
        return 0;
#ifndef __linux__
    errno = EOPNOTSUPP;
    return -1;
#else
    if (!mips64_family_family_authorize_fd(borrowed_directory_fd, true, authority) ||
        !mips64_family_family_authorize_fd(borrowed_control_fd, false, authority)) {
        errno = EACCES;
        return -1;
    }
    uint64_t minimum_size;
    if (!mips64_family_catalog_reserved_end(&minimum_size) ||
        minimum_size > MIPS64_ZERO_CONTROL_HEAD_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }
    mips64_zero_service_retained_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL)
        return -1;
    owner->storage_authority = authority;
    int result = mips64_family_zero_segment_attach_fd(borrowed_control_fd,
        MIPS64_FAMILY_ZERO_SEGMENT_CONTROL, 0, MIPS64_ZERO_CONTROL_HEAD_SIZE,
        &owner->control);
    if (result == 0) {
        mips64_family_control_t *control = owner->control.payload;
        uint64_t root_id = control->file_index_object;
        char name[48];
        if (control->magic != MIPS64_FAMILY_MAGIC ||
            control->version != MIPS64_FAMILY_VERSION ||
            control->size != sizeof(*control) || control->source_mode != 1 ||
            root_id == 0 || root_id >= control->next_object_id ||
            mips64_family_object_name(root_id, name) != 0) {
            errno = EIO;
            result = -1;
        } else {
            int root_fd = openat(borrowed_directory_fd, name,
                                 O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (root_fd < 0)
                result = -1;
            else {
                struct stat root_status;
                size_t root_size;
                if (fstat(root_fd, &root_status) != 0 ||
                    !mips64_family_object_file_size(1, &root_size) ||
                    !S_ISREG(root_status.st_mode) ||
                    (root_status.st_mode & 07777) != 0600 ||
                    root_status.st_uid != geteuid() ||
                    root_status.st_nlink != 1 || root_status.st_size != 0 ||
                    !mips64_family_family_authorize_fd(root_fd, false, authority)) {
                    errno = EACCES;
                    result = -1;
                } else {
                    result = mips64_family_zero_segment_attach_fd(root_fd,
                        MIPS64_FAMILY_ZERO_SEGMENT_OBJECT, root_id, root_size,
                        &owner->root.segment);
                    if (result == 0) {
                        mips64_family_object_file_t *root = owner->root.segment.payload;
                        if (root->magic != MIPS64_OBJECT_MAGIC ||
                            root->version != MIPS64_FAMILY_VERSION ||
                            root->header_size != MIPS64_OBJECT_HEADER_SIZE ||
                            root->object_id != root_id ||
                            root->slot_count != 1 || root->reserved != 0) {
                            errno = EIO;
                            result = -1;
                        } else {
                            owner->root.object_id = root_id;
                            owner->root.size = root_size;
                        }
                    }
                }
                int saved = errno;
                (void)close(root_fd);
                errno = saved;
            }
        }
    }
    if (result != 0) {
        int saved = errno;
        mips64_family_cleanup_service_release(owner);
        errno = saved;
        return -1;
    }
    *out = owner;
    return 0;
#endif
}

int mips64_family_cleanup_service_prepare(int borrowed_control_fd,
                                      int borrowed_directory_fd,
                                      const char *directory, void **out)
{
    return mips64_family_cleanup_service_prepare_authority(borrowed_control_fd,
        borrowed_directory_fd, directory, out, MIPS64_FAMILY_AUTHORITY_AUTO);
}

int mips64_family_cleanup_service_prepare_context(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    void *context)
{
    if (context == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mips64_family_cleanup_service_prepare_authority(borrowed_control_fd,
        borrowed_directory_fd, directory, out,
        *(const mips64_family_storage_authority_t *)context);
}

static int cleanup_service(int borrowed_control_fd,
                           int borrowed_directory_fd,
                           const char *directory, void *retained)
{
    if (borrowed_control_fd < 3 || borrowed_directory_fd < 3 ||
        borrowed_control_fd == borrowed_directory_fd || directory == NULL) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strnlen(directory, 64);
    struct stat control_status, named_status, directory_status, path_status;
    if (length == 0 || length >= 64 || directory[0] != '/' ||
        fstat(borrowed_control_fd, &control_status) != 0 ||
        fstat(borrowed_directory_fd, &directory_status) != 0 ||
        fstatat(borrowed_directory_fd, "control", &named_status,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(AT_FDCWD, directory, &path_status,
                AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    uint64_t minimum_size = 0;
    mips64_zero_service_retained_t *owner = retained;
    bool zero_backing = control_status.st_size == 0;
    if (!mips64_family_catalog_reserved_end(&minimum_size) ||
        !S_ISREG(control_status.st_mode) ||
        (control_status.st_mode & 07777) != 0600 ||
        control_status.st_uid != geteuid() || control_status.st_nlink != 1 ||
        control_status.st_size < 0 ||
        (!zero_backing && (uint64_t)control_status.st_size < minimum_size) ||
        (zero_backing && (owner == NULL ||
            !mips64_family_family_authorize_fd(borrowed_control_fd, false,
                                  owner->storage_authority) ||
            !mips64_family_family_authorize_fd(borrowed_directory_fd, true,
                                  owner->storage_authority))) ||
        (!zero_backing && owner != NULL) ||
        !S_ISDIR(directory_status.st_mode) ||
        (directory_status.st_mode & 07777) != 0700 ||
        directory_status.st_uid != geteuid() ||
        control_status.st_dev != named_status.st_dev ||
        control_status.st_ino != named_status.st_ino ||
        directory_status.st_dev != path_status.st_dev ||
        directory_status.st_ino != path_status.st_ino) {
        errno = EPERM;
        return -1;
    }
    int previous_cancel_state;
    int cancel_error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                                &previous_cancel_state);
    if (cancel_error != 0) {
        errno = cancel_error;
        return -1;
    }
    void *mapping = zero_backing ? owner->control.payload :
        mmap(NULL, sizeof(mips64_family_control_t),
             PROT_READ | PROT_WRITE, MAP_SHARED,
             borrowed_control_fd, 0);
    if (mapping == MAP_FAILED) {
        int saved = errno;
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    mips64_family_control_t *control = mapping;
    int result = -1;
    int saved = EIO;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                         .l_start = 0, .l_len = 1};
    if (fcntl(borrowed_control_fd, F_SETLK, &lock) != 0) {
        saved = errno;
        goto done;
    }
    atomic_thread_fence(memory_order_acquire);
    if (control->magic != MIPS64_FAMILY_MAGIC ||
        control->version != MIPS64_FAMILY_VERSION ||
        control->size != sizeof(*control) || control->source_mode != 1 ||
        control->source_reserved != 0 || control->file_index_object == 0 ||
        control->file_index_object >= control->next_object_id ||
        !atomic_is_lock_free(&control->log_marker) ||
        atomic_load_explicit(&control->log_marker,
                             memory_order_acquire) != MIPS64_LOG_EMPTY) {
        saved = EBUSY;
        goto unlock;
    }
    mips64_family_t family = {0};
    family.control_fd = borrowed_control_fd;
    family.dir_fd = borrowed_directory_fd;
    family.pins = (mips64_inode_pins_t)MIPS64_INODE_PINS_INITIALIZER;
    family.sources = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    family.control = control;
    family.zero_backing = zero_backing;
    if (zero_backing) {
        family.zero_control = owner->control;
        family.zero_objects = &owner->root;
        family.storage_authority = owner->storage_authority;
    }
    family.local_pid = getpid();
    family.initialized = true;
    family.creator = true;
    family.incarnation = control->active_incarnation != 0 ?
                         control->active_incarnation : 1;
    memcpy(family.directory, directory, length + 1u);
    mips64_family_guard_t guard = {.family = &family,
                               .incarnation = family.incarnation,
                               .owner_thread = pthread_self(), .held = true};
    family.active_guard = &guard;
    mips64_family_file_cursor_t cursor = {0};
    if (mips64_family_file_index_cursor_read(&guard, &cursor) != 0) {
        saved = errno;
        goto unlock;
    }
    if (cursor.phase != MIPS64_FILE_IDLE) {
        saved = EBUSY;
        goto unlock;
    }
    result = cleanup_held(&guard, true);
    saved = errno;
unlock:
    lock.l_type = F_UNLCK;
    if (fcntl(borrowed_control_fd, F_SETLK, &lock) != 0) {
        result = -1;
        saved = EIO;
    }
done:
    if (!zero_backing && munmap(mapping, sizeof(mips64_family_control_t)) != 0) {
        result = -1;
        saved = EIO;
    }
    (void)pthread_setcancelstate(previous_cancel_state, NULL);
    errno = saved;
    return result;
}

int mips64_family_cleanup_service(int borrowed_control_fd,
                              int borrowed_directory_fd,
                              const char *directory)
{
    return cleanup_service(borrowed_control_fd, borrowed_directory_fd,
                           directory, NULL);
}

int mips64_family_cleanup_service_retained(int borrowed_control_fd,
                                       int borrowed_directory_fd,
                                       const char *directory, void *retained)
{
    return cleanup_service(borrowed_control_fd, borrowed_directory_fd,
                           directory, retained);
}

int mips64_family_destroy(mips64_family_t *family)
{
    if (family == NULL)
        return 0;
    if (family->local_pid != getpid()) {
        errno = EPERM;
        return -1;
    }
    int result = pthread_mutex_trylock(&family->local_mutex);
    if (result != 0) {
        errno = result == EBUSY ? EBUSY : result;
        return -1;
    }
    if (family->active_guard != NULL ||
        family->exec_prepared != NULL ||
        atomic_load_explicit(&family->live_views, memory_order_relaxed) != 0 ||
        family->inode_observer != NULL) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        errno = EBUSY;
        return -1;
    }
    family->destroying = true;
    (void)pthread_mutex_unlock(&family->local_mutex);
    if (family->zero_backing) {
        if (family->zero_fragment_pending_fd >= 0)
            (void)close(family->zero_fragment_pending_fd);
        for (size_t i = 0; i < family->zero_fragment_count; ++i)
            mips64_family_zero_segment_detach(&family->zero_fragments[i]);
        mips64_zero_object_segment_t *entry = family->zero_objects;
        while (entry != NULL) {
            mips64_zero_object_segment_t *next = entry->next;
            mips64_family_zero_segment_detach(&entry->segment);
            free(entry);
            entry = next;
        }
        mips64_family_zero_segment_detach(&family->zero_control);
    } else if (family->control != NULL) {
        (void)munmap(family->control, sizeof(mips64_family_control_t));
    }
    mips64_family_close_family_sources(family->control_fd, family->dir_fd, family->pins, family->sources);
    if (family->creator && family->directory[0] != '\0')
        if (family->cleaned)
            (void)rmdir(family->directory);
    if (family->initialized)
        (void)pthread_mutex_destroy(&family->local_mutex);
    free(family);
    return 0;
}

#ifdef MIPS64_FAMILY_TESTING
void mips64_family_test_set_hook(mips64_family_t *family, mips64_family_test_hook_t hook,
                             void *context)
{
    if (family == NULL)
        return;
    family->hook = hook;
    family->hook_context = context;
}

void mips64_family_test_point(mips64_family_guard_t *guard, mips64_family_test_point_t point)
{
    if (mips64_family_guard_valid(guard) && guard->family->hook != NULL)
        guard->family->hook(point, guard->family->hook_context);
}

void mips64_family_test_fail_next_file_recovery(mips64_family_t *family)
{
    if (family != NULL)
        family->test_fail_file_recovery_once = true;
}

void mips64_family_test_fail_next_unlock(mips64_family_t *family)
{
    if (family != NULL)
        family->test_fail_unlock_once = true;
}

void mips64_family_test_fail_child_transfer_attach(mips64_family_t *family)
{
    if (family != NULL)
        family->test_fail_child_transfer_attach = true;
}

void mips64_family_test_fail_exec_activation(mips64_family_t *family)
{
    if (family != NULL) {
        family->test_fail_exec_activation = true;
        family->test_fail_exec_activation_index = 0;
    }
}

void mips64_family_test_fail_exec_activation_at(mips64_family_t *family, size_t index)
{
    if (family != NULL && index < 6) {
        family->test_fail_exec_activation = true;
        family->test_fail_exec_activation_index = index;
    }
}

void mips64_family_test_fail_next_wait_replay(mips64_family_t *family)
{
    if (family != NULL)
        family->test_fail_wait_replay_once = true;
}

void mips64_family_test_descriptors(const mips64_family_t *family,
                                 int *control_fd, int *dir_fd)
{
    if (family != NULL && control_fd != NULL && dir_fd != NULL) {
        *control_fd = family->control_fd;
        *dir_fd = family->dir_fd;
    }
}

void mips64_family_test_pin_state(const mips64_family_t *family,
                               mips64_inode_pins_t *pins, uint64_t *attempts)
{
    if (family == NULL)
        return;
    if (pins != NULL)
        *pins = family->pins;
    if (attempts != NULL)
        *attempts = family->control->inode_pin_attempts;
}
#endif
