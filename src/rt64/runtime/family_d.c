/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_parts.h"

static int find_file_record(const mips64_file_catalog_record_t *records, size_t count,
                             uint64_t next_id, const mips64_file_identity_t *identity,
                             uint64_t *id)
{
    for (size_t i = 0; i < count; ++i) {
        mips64_file_identity_t stored;
        uint64_t stored_id;
        if (!mips64_file_catalog_decode(&records[i], next_id, &stored_id, &stored)) {
            errno = EIO;
            return -1;
        }
        if (mips64_file_identity_equal(&stored, identity)) {
            *id = stored_id;
            return 1;
        }
    }
    return 0;
}

static int apply_file_record(mips64_family_t *family)
{
    mips64_family_control_t *control = family->control;
    uint64_t end;
    if (!mips64_family_catalog_reserved_end(&end)) {
        errno = EIO;
        return -1;
    }
    uint64_t start = end - MIPS64_FILE_CATALOG_CAPACITY * sizeof(control->file_target);
    uint64_t offset = start + control->file_target_slot * sizeof(control->file_target);
    if (mips64_family_family_control_write(family, &control->file_target,
                             sizeof(control->file_target), offset) != 0)
        return -1;
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_FILE_RECORD_APPLIED, family->hook_context);
#endif
    control->file_count = control->file_target_count;
    atomic_thread_fence(memory_order_release);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_FILE_COUNT_APPLIED, family->hook_context);
#endif
    return 0;
}

static int replay_file_record(mips64_family_t *family)
{
    mips64_family_control_t *control = family->control;
    uint64_t slot = control->file_target_slot, id;
    mips64_file_identity_t identity;
    if (slot >= MIPS64_FILE_CATALOG_CAPACITY || control->file_target_count != slot + 1 ||
        (control->file_count != slot && control->file_count != slot + 1) ||
        control->file_target_count > control->inode_pin_attempts ||
        !mips64_file_catalog_decode(&control->file_target, control->next_file_id,
                                   &id, &identity)) {
        errno = EIO;
        return -1;
    }
    /* The final slot/count may be only partly applied. Validate the immutable
     * prefix, then overwrite the target slot with the absolute redo bytes. */
    mips64_file_catalog_record_t *prefix = NULL;
    if (mips64_family_read_file_catalog(family, (size_t)slot, &prefix) != 0)
        return -1;
    uint64_t ignored;
    int found = find_file_record(prefix, (size_t)slot, control->next_file_id,
                                  &identity, &ignored);
    bool ordered = true;
    if (slot != 0) {
        uint64_t previous;
        mips64_file_identity_t previous_identity;
        ordered = mips64_file_catalog_decode(&prefix[slot - 1], control->next_file_id,
                                           &previous, &previous_identity) &&
                  previous < id;
    }
    free(prefix);
    if (found != 0 || !ordered) {
        errno = EIO;
        return -1;
    }
    return apply_file_record(family);
}

int mips64_family_file_intern(mips64_family_guard_t *guard,
                           const mips64_file_identity_t *identity, int source_fd,
                           uint64_t *file_id)
{
    if (file_id != NULL)
        *file_id = 0;
    if (!mips64_family_guard_valid(guard) || file_id == NULL || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!mips64_file_identity_valid(identity) || !identity->mapped_key_eligible) {
        errno = EOPNOTSUPP;
        return -1;
    }
    mips64_family_t *family = guard->family;
    mips64_family_control_t *control = family->control;
    if (family->exec_prepared != NULL ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != MIPS64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    mips64_file_catalog_record_t *records = NULL;
    if (mips64_family_read_file_catalog(family, (size_t)control->file_count, &records) != 0)
        return -1;
    uint64_t found_id;
    int found = find_file_record(records, (size_t)control->file_count,
                                  control->next_file_id, identity, &found_id);
    free(records);
    if (found < 0)
        return -1;
    if (found > 0) {
        *file_id = found_id;
        return 0;
    }
    if (control->file_count == MIPS64_FILE_CATALOG_CAPACITY) {
        errno = ENOSPC;
        return -1;
    }
    if (control->next_file_id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    /* Consume IDs before pinning. Failed/killed producers leave permanent
     * gaps; an uncertain queued pin is never refunded or repurposed. */
    uint64_t id = control->next_file_id++;
    mips64_file_catalog_record_t target;
    if (!mips64_file_catalog_encode(&target, id, identity)) {
        errno = EIO;
        return -1;
    }
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_FILE_ID_ALLOCATED, family->hook_context);
#endif
    if (mips64_family_pin_file(guard, source_fd) != 0)
        return -1;
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_FILE_PINNED, family->hook_context);
#endif
    control->file_target_slot = control->file_count;
    control->file_target_count = control->file_count + 1;
    control->file_target = target;
    control->log_kind = MIPS64_LOG_FILE;
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_PREPARED, memory_order_release);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_PREPARED, family->hook_context);
#endif
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_COMMITTED, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_COMMITTED, family->hook_context);
#endif
    /* No allocation after pin/publication in the normal path. Recovery may
     * allocate a bounded prefix snapshot before replaying the absolute record. */
    if (apply_file_record(family) != 0) {
        family->poisoned = true;
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_EMPTY, memory_order_release);
    *file_id = id;
    return 0;
}

static int catalog_wait_keys(mips64_family_t *family,
                               const mips64_family_wait_row_t *rows, size_t count)
{
    bool needed = false;
    for (size_t i = 0; i < count; ++i)
        needed = needed || rows[i].key.kind == MIPS64_FAMILY_WAIT_FILE;
    if (!needed)
        return 0;
    mips64_file_catalog_record_t *records = NULL;
    mips64_family_control_t *control = family->control;
    if (mips64_family_read_file_catalog(family, (size_t)control->file_count, &records) != 0)
        return -1;
    bool valid = true;
    for (size_t i = 0; i < count && valid; ++i) {
        if (rows[i].key.kind != MIPS64_FAMILY_WAIT_FILE)
            continue;
        bool found = false;
        for (size_t j = 0; j < control->file_count; ++j) {
            uint64_t id;
            mips64_file_identity_t identity;
            if (!mips64_file_catalog_decode(&records[j], control->next_file_id,
                                          &id, &identity)) {
                valid = false;
                break;
            }
            if (rows[i].key.identity == id) {
                found = true;
                break;
            }
        }
        /* This is an unsigned inode byte offset, not a native pread off_t.
         * The zero-filled tail of a valid final page can lie beyond EOF. */
        valid = valid && found && (rows[i].key.offset & 3u) == 0;
    }
    free(records);
    if (!valid) {
        errno = EIO;
        return -1;
    }
    return 0;
}

uint64_t mips64_family_recovery_epoch(const mips64_family_guard_t *guard)
{
    return mips64_family_guard_valid(guard) ? guard->family->control->recovery_epoch : 0;
}

const char *mips64_family_private_directory(const mips64_family_t *family)
{
    return family == NULL || !family->creator ? NULL : family->directory;
}

int mips64_family_observe_inodes(mips64_family_guard_t *guard,
                             mips64_family_inode_observer_t observer, void *context)
{
    if (!mips64_family_guard_valid(guard) || observer == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    if (family->inode_observer != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (mips64_family_scan_inodes(family->control_fd, family->dir_fd,
                              observer, context) != 0)
        return -1;
    family->inode_observer_context = context;
    family->inode_observer = observer;
    return 0;
}

int mips64_family_unobserve_inodes(mips64_family_guard_t *guard)
{
    if (!mips64_family_guard_valid(guard) || guard->family->inode_observer == NULL) {
        errno = EINVAL;
        return -1;
    }
    guard->family->inode_observer = NULL;
    guard->family->inode_observer_context = NULL;
    return 0;
}

int mips64_family_page_create(mips64_family_guard_t *guard, mips64_family_page_t **out)
{
    if (out == NULL || !mips64_family_guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    mips64_family_t *family = guard->family;
    if (family->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    uint64_t id = family->control->next_object_id;
    if (id == 0 || id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    mips64_family_page_key_t key = {.object_id = id, .page_index = 0};
    char name[48];
    if (mips64_family_page_name(key, name) != 0)
        return -1;
    /* Consume the identity before filesystem side effects. A creator killed
     * after O_EXCL may leave an orphan file; its key is never reused. */
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
    mips64_family_page_t *page = mips64_family_map_page(family, key, fd, true);
    if (page == NULL) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (mips64_family_observe_open_inode(family, fd) != 0) {
        int saved = errno;
        mips64_family_page_close(page);
        /* The callback may already have retained this inode identity.
         * Keep its valid file until resolver teardown and family cleanup. */
        errno = saved;
        return -1;
    }
    *out = page;
    return 0;
}

int mips64_family_page_open(mips64_family_guard_t *guard, mips64_family_page_key_t key,
                        mips64_family_page_t **out)
{
    if (out == NULL || !mips64_family_guard_valid(guard) ||
        key.object_id == 0 || key.page_index != 0) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (guard->family->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    char name[48];
    if (mips64_family_page_name(key, name) != 0)
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
    mips64_family_page_t *page = mips64_family_map_page(guard->family, key, fd, false);
    if (page == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (mips64_family_observe_open_inode(guard->family, fd) != 0) {
        int saved = errno;
        mips64_family_page_close(page);
        errno = saved;
        return -1;
    }
    *out = page;
    return 0;
}

void mips64_family_page_close(mips64_family_page_t *page)
{
    if (page == NULL)
        return;
    int saved = errno;
    if (page->mapping != NULL)
        (void)munmap(page->mapping, page->mapping_size);
    if (page->fd >= 0)
        (void)close(page->fd);
    (void)atomic_fetch_sub_explicit(&page->family->live_views, 1, memory_order_relaxed);
    free(page);
    errno = saved;
}

mips64_family_page_key_t mips64_family_page_key(const mips64_family_page_t *page)
{
    return page == NULL ? (mips64_family_page_key_t){0, 0} : page->key;
}

const mips64_family_page_state_t *mips64_family_page_readonly(const mips64_family_guard_t *guard,
                                                       const mips64_family_page_t *page)
{
    return !mips64_family_guard_valid(guard) || page == NULL || page->family != guard->family
         ? NULL : &page->mapping->state;
}

static int validate_target_mode(const mips64_family_page_state_t *current,
                                const mips64_family_page_state_t *target,
                                bool file_refresh)
{
    bool bytes_changed = false;
    if (file_refresh) {
        static const uint64_t zero[4] = {0};
        if (current->private_cow != 0 || target->private_cow != 0 ||
            current->reserved != 0 || target->reserved != 0 ||
            memcmp(target->notified, zero, sizeof(zero)) != 0) {
            errno = EINVAL;
            return -1;
        }
        if (current->content_generation == UINT64_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        if (target->content_generation != current->content_generation + 1u) {
            errno = EINVAL;
            return -1;
        }
    }
    if (target->private_cow > 1 || target->reserved != 0) {
        errno = EINVAL;
        return -1;
    }
    bool metadata_changed = target->private_cow != current->private_cow ||
        memcmp(target->notified, current->notified, sizeof(target->notified)) != 0;
    if (target->content_generation < current->content_generation) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < MIPS64_FAMILY_EPOCHS; ++i) {
        bool prepaid = file_refresh &&
            (current->notified[i / 64u] & (UINT64_C(1) << (i % 64u))) != 0;
        if (prepaid && current->epochs[i] == 0) {
            errno = EINVAL;
            return -1;
        }
        if (target->epochs[i] < current->epochs[i]) {
            errno = EINVAL;
            return -1;
        }
        size_t offset = i * 16;
        if (memcmp(target->bytes + offset, current->bytes + offset, 16) != 0) {
            bytes_changed = true;
            if (target->epochs[i] == current->epochs[i] && !prepaid) {
                errno = current->epochs[i] == UINT64_MAX ? EOVERFLOW : EINVAL;
                return -1;
            }
        }
    }
    /* COW and notification state affects later refresh even when bytes and
     * reservation epochs stay unchanged. It needs an observable publication. */
    if ((bytes_changed || metadata_changed) &&
        target->content_generation == current->content_generation) {
        errno = current->content_generation == UINT64_MAX ? EOVERFLOW : EINVAL;
        return -1;
    }
    return 0;
}

static int validate_target(const mips64_family_page_state_t *current,
                           const mips64_family_page_state_t *target)
{
    return validate_target_mode(current, target, false);
}

 int mips64_family_commit_states(mips64_family_guard_t *guard, uint32_t kind, size_t count,
                         const mips64_family_page_key_t keys[2],
                         mips64_family_page_state_t *const destinations[2],
                         const mips64_family_page_state_t *const targets[2],
                         bool file_refresh)
{
    mips64_family_t *family = guard->family;
    mips64_family_control_t *control = family->control;
    if (count == 0 || count > 2 ||
        (file_refresh && (kind != MIPS64_LOG_OBJECT || count != 1)) ||
        (count == 2 && mips64_family_key_equal(keys[0], keys[1]))) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < count; ++i)
        if (validate_target_mode(destinations[i], targets[i], file_refresh) != 0)
            return -1;
    if (atomic_load_explicit(&control->log_marker, memory_order_acquire) != MIPS64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    control->log_kind = kind;
    control->log_key = keys[0];
    memcpy(&control->log_target, targets[0], sizeof(*targets[0]));
    if (count == 2) {
        control->log_second_key = keys[1];
        memcpy(&control->log_second_target, targets[1], sizeof(*targets[1]));
    }
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_PREPARED, memory_order_release);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_PREPARED, family->hook_context);
#endif
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_COMMITTED, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_COMMITTED, family->hook_context);
#endif
    mips64_family_apply_absolute_state(destinations[0], &control->log_target, family, false);
    if (count == 2)
        mips64_family_apply_absolute_state(destinations[1], &control->log_second_target, family, false);
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_EMPTY, memory_order_release);
    return 0;
}

static int validate_wait_root(mips64_family_t *family,
                              mips64_family_wait_row_t **rows_out)
{
    mips64_family_control_t *control = family->control;
    if (control->wait_bank_capacity == 0) {
        if (control->wait_bank_base != 0 || control->wait_bank_index != 0 ||
            control->wait_count != 0 || control->wait_revision != 0) {
            errno = EIO;
            return -1;
        }
        if (rows_out != NULL)
            *rows_out = NULL;
        return 0;
    }
    uint64_t end = 0, minimum_base = 0;
    uint64_t extent;
    if (control->wait_bank_capacity > MIPS64_WAIT_MAX_ROWS ||
        control->wait_count > control->wait_bank_capacity ||
        control->wait_revision == 0 || control->wait_bank_index > 1 ||
        !mips64_family_catalog_reserved_end(&minimum_base) ||
        control->wait_bank_base < minimum_base ||
        control->wait_bank_base % MIPS64_FAMILY_PAGE_SIZE != 0 ||
        !mips64_family_wait_pair_end(control->wait_bank_base, control->wait_bank_capacity, &end)) {
        errno = EIO;
        return -1;
    }
    if (mips64_family_family_control_extent(family, &extent) != 0)
        return -1;
    if (end > extent) {
        errno = EIO;
        return -1;
    }
    mips64_family_wait_row_t *rows = NULL;
    if (mips64_family_read_wait_bank(family, control->wait_bank_base,
                       control->wait_bank_index, control->wait_bank_capacity,
                       control->wait_count, control->wait_revision, &rows) != 0)
        return -1;
    if (catalog_wait_keys(family, rows, (size_t)control->wait_count) != 0) {
        int saved = errno;
        free(rows);
        errno = saved;
        return -1;
    }
    if (rows_out != NULL)
        *rows_out = rows;
    else
        free(rows);
    return 0;
}

int mips64_family_wait_backend_read(mips64_family_guard_t *guard,
                                mips64_family_wait_table_t *table)
{
    if (!mips64_family_guard_valid(guard) || table == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    mips64_family_wait_row_t *rows = NULL;
    if (validate_wait_root(family, &rows) != 0)
        return -1;
    *table = (mips64_family_wait_table_t){
        .rows = rows,
        .count = (size_t)family->control->wait_count,
        .capacity = (size_t)family->control->wait_bank_capacity,
        .revision = family->control->wait_revision
    };
    return 0;
}

 bool mips64_family_catalog_reserved_end(uint64_t *end)
{
    size_t size = sizeof(mips64_family_control_t);
    if (size > SIZE_MAX - (MIPS64_FAMILY_PAGE_SIZE - 1u))
        return false;
    size_t aligned = (size + MIPS64_FAMILY_PAGE_SIZE - 1u) &
                     ~(size_t)(MIPS64_FAMILY_PAGE_SIZE - 1u);
    if (MIPS64_FILE_CATALOG_CAPACITY >
        ((uint64_t)INT64_MAX - aligned) / sizeof(mips64_file_catalog_record_t))
        return false;
    *end = (uint64_t)aligned +
           MIPS64_FILE_CATALOG_CAPACITY * sizeof(mips64_file_catalog_record_t);
    return *end <= (uint64_t)INT64_MAX;
}

static bool wait_aligned_control_end(uint64_t *end)
{
    return mips64_family_catalog_reserved_end(end);
}

 bool mips64_family_wait_control_max_size(off_t *size_out)
{
    uint64_t end = 0;
    if (size_out == NULL || !wait_aligned_control_end(&end))
        return false;
    for (uint64_t capacity = MIPS64_WAIT_INITIAL_CAPACITY;; capacity *= 2u) {
        size_t bank_size = 0;
        if (!mips64_family_wait_bank_size(capacity, &bank_size) ||
            bank_size > ((uint64_t)INT64_MAX - end) / 2u)
            return false;
        end += (uint64_t)bank_size * 2u;
        if (capacity == MIPS64_WAIT_MAX_ROWS)
            break;
        if (capacity > MIPS64_WAIT_MAX_ROWS / 2u)
            return false;
    }
    *size_out = (off_t)end;
    return true;
}

static void truncate_growth_tail(mips64_family_t *family, uint64_t old_end)
{
    if (!family->zero_backing && old_end <= (uint64_t)INT64_MAX)
        (void)ftruncate(family->control_fd, (off_t)old_end);
}

int mips64_family_wait_backend_commit(mips64_family_guard_t *guard,
                                  mips64_family_wait_table_t *table,
                                  const mips64_family_object_update_t *updates,
                                  size_t update_count)
{
    if (!mips64_family_guard_valid(guard) || table == NULL || update_count > 2 ||
        (update_count != 0 && updates == NULL) || table->count > table->capacity ||
        table->count > MIPS64_WAIT_MAX_ROWS ||
        (table->count != 0 && table->rows == NULL)) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_t *family = guard->family;
    mips64_family_control_t *control = family->control;
    mips64_family_wait_row_t *current_rows = NULL;
    if (catalog_wait_keys(family, table->rows, table->count) != 0)
        return -1;
    if (validate_wait_root(family, &current_rows) != 0)
        return -1;
    free(current_rows);
    if (table->revision != control->wait_revision) {
        errno = ESTALE;
        return -1;
    }
    if (table->revision == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }

    mips64_family_page_key_t keys[2] = {{0, 0}, {0, 0}};
    mips64_family_page_state_t *destinations[2] = {NULL, NULL};
    const mips64_family_page_state_t *targets[2] = {NULL, NULL};
    for (size_t i = 0; i < update_count; ++i) {
        mips64_family_object_t *object = updates[i].object;
        if (object == NULL || updates[i].target == NULL ||
            object->family != family || updates[i].page_index >= object->slot_count) {
            errno = EINVAL;
            return -1;
        }
        keys[i] = (mips64_family_page_key_t){object->object_id, updates[i].page_index};
        destinations[i] = &object->mapping->slots[updates[i].page_index].state;
        targets[i] = updates[i].target;
        if (i != 0 && mips64_family_key_equal(keys[0], keys[i])) {
            errno = EINVAL;
            return -1;
        }
        if (validate_target(destinations[i], targets[i]) != 0)
            return -1;
    }
    if (atomic_load_explicit(&control->log_marker, memory_order_acquire) != MIPS64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }

    uint64_t old_end = 0;
    if (control->wait_bank_capacity != 0) {
        if (!mips64_family_wait_pair_end(control->wait_bank_base, control->wait_bank_capacity,
                           &old_end)) {
            errno = EIO;
            return -1;
        }
    } else if (!wait_aligned_control_end(&old_end)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t target_capacity = control->wait_bank_capacity;
    uint64_t target_base = control->wait_bank_base;
    uint32_t target_index = control->wait_bank_index ^ 1u;
    bool growing = target_capacity == 0 || table->count > target_capacity;
    if (growing) {
        target_capacity = target_capacity == 0 ? MIPS64_WAIT_INITIAL_CAPACITY : target_capacity;
        while (target_capacity < table->count) {
            if (target_capacity > MIPS64_WAIT_MAX_ROWS / 2u) {
                errno = ENOSPC;
                return -1;
            }
            target_capacity *= 2u;
        }
        target_base = old_end;
        target_index = 0;
    }
    uint64_t target_end = 0;
    if (!mips64_family_wait_pair_end(target_base, target_capacity, &target_end)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (growing) {
        uint64_t extent;
        if (mips64_family_family_control_extent(family, &extent) != 0)
            return -1;
        if (family->zero_backing) {
            if (mips64_family_ensure_control_extent(family, target_end) != 0)
                return -1;
        } else {
            if (extent > old_end &&
                ftruncate(family->control_fd, (off_t)old_end) != 0)
                return -1;
            if (ftruncate(family->control_fd, (off_t)target_end) != 0)
                return -1;
        }
    }
    uint64_t target_revision = control->wait_revision + 1u;
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_WAIT_BEFORE_BANK_WRITE, family->hook_context);
#endif
    if (mips64_family_write_wait_bank(family, target_base, target_index, target_capacity,
                        table->count, target_revision, table->rows) != 0) {
        int saved = errno;
        if (growing)
            truncate_growth_tail(family, old_end);
        errno = saved;
        return -1;
    }
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_WAIT_BANK_WRITTEN, family->hook_context);
#endif
    control->wait_target_base = target_base;
    control->wait_target_capacity = target_capacity;
    control->wait_target_index = target_index;
    control->wait_target_count = table->count;
    control->wait_target_revision = target_revision;
    if (update_count != 0) {
        control->log_key = keys[0];
        memcpy(&control->log_target, targets[0], sizeof(*targets[0]));
    }
    if (update_count == 2) {
        control->log_second_key = keys[1];
        memcpy(&control->log_second_target, targets[1], sizeof(*targets[1]));
    }
    control->log_kind = update_count == 0 ? MIPS64_LOG_WAIT :
                        update_count == 1 ? MIPS64_LOG_WAIT_OBJECT : MIPS64_LOG_WAIT_PAIR;
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_PREPARED, memory_order_release);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_PREPARED, family->hook_context);
#endif
    atomic_store_explicit(&control->log_marker, MIPS64_LOG_COMMITTED, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_COMMITTED, family->hook_context);
#endif
    if (mips64_family_replay_committed(family) != 0) {
        int saved = errno == 0 ? EIO : errno;
        family->poisoned = true;
        errno = saved;
        return -1;
    }
    table->revision = target_revision;
    return 0;
}

int mips64_family_wait_backend_id(mips64_family_guard_t *guard, bool mm_id,
                              uint64_t *out)
{
    if (!mips64_family_guard_valid(guard) || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_control_t *control = guard->family->control;
    uint64_t *counter = mm_id ? &control->next_mm_id : &control->next_wait_id;
    if (*counter == 0 || *counter == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t value = *counter;
    *counter = value + 1u;
    *out = value;
    return 0;
}

int mips64_family_page_commit(mips64_family_guard_t *guard, mips64_family_page_t *page,
                          const mips64_family_page_state_t *target)
{
    if (!mips64_family_guard_valid(guard) || page == NULL || target == NULL ||
        guard->family != page->family) {
        errno = EINVAL;
        return -1;
    }
    mips64_family_page_key_t keys[2] = {page->key, {0, 0}};
    mips64_family_page_state_t *destinations[2] = {&page->mapping->state, NULL};
    const mips64_family_page_state_t *targets[2] = {target, NULL};
    return mips64_family_commit_states(guard, MIPS64_LOG_PAGE, 1, keys, destinations, targets, false);
}
