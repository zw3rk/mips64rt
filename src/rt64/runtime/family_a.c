/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_parts.h"

 bool mips64_family_key_equal(mips64_family_page_key_t left, mips64_family_page_key_t right)
{
    return left.object_id == right.object_id && left.page_index == right.page_index;
}

 bool mips64_family_wait_control_max_size(off_t *size_out);

 bool mips64_family_authority_valid(mips64_family_storage_authority_t authority)
{
    return authority == MIPS64_FAMILY_AUTHORITY_AUTO ||
           authority == MIPS64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1;
}

 bool mips64_family_family_authorize_fd(int fd, bool directory,
                                mips64_family_storage_authority_t authority)
{
    mips64_aot_authority_policy_t checked = authority ==
        MIPS64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 ?
        MIPS64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 : MIPS64_AOT_AUTHORITY_AUTO;
    return mips64_family_authority_valid(authority) &&
           mips64_aot_authorize_fd(fd, directory, checked);
}

 int mips64_family_family_control_extent(const mips64_family_t *family, uint64_t *out)
{
    if (family->zero_backing) {
        *out = family->zero_control.payload_size +
               family->zero_fragment_count * MIPS64_ZERO_CONTROL_FRAGMENT_SIZE;
        return 0;
    }
    struct stat status;
    int result;
    do {
        result = fstat(family->control_fd, &status);
    } while (result != 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (status.st_size < 0) {
        errno = EIO;
        return -1;
    }
    *out = (uint64_t)status.st_size;
    return 0;
}

static mips64_zero_object_segment_t *find_zero_object(mips64_family_t *family,
                                                   uint64_t object_id)
{
    for (mips64_zero_object_segment_t *entry = family->zero_objects;
         entry != NULL; entry = entry->next)
        if (entry->object_id == object_id)
            return entry;
    return NULL;
}

 void mips64_family_close_owned_fds(int control_fd, int dir_fd)
{
    if (control_fd >= 0)
        (void)close(control_fd);
    if (dir_fd >= 0 && dir_fd != control_fd)
        (void)close(dir_fd);
}

 void mips64_family_close_family_sources(int control_fd, int dir_fd, mips64_inode_pins_t pins,
                                  mips64_file_caps_client_t sources)
{
    int descriptors[6] = {control_fd, dir_fd, pins.sender, pins.receiver,
                          sources.request_fd, sources.lifetime_fd};
    for (size_t i = 0; i < 6; ++i) {
        bool seen = false;
        for (size_t j = 0; j < i; ++j)
            seen = seen || descriptors[i] == descriptors[j];
        if (descriptors[i] >= 0 && !seen)
            (void)close(descriptors[i]);
    }
}

void mips64_family_close_capabilities(int control_fd, int dir_fd, mips64_inode_pins_t pins)
{
    mips64_family_close_family_sources(control_fd, dir_fd, pins,
                           (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER);
}

void mips64_family_close_source_capabilities(int control_fd, int dir_fd,
                                          mips64_inode_pins_t pins,
                                          mips64_file_caps_client_t sources)
{
    mips64_family_close_family_sources(control_fd, dir_fd, pins, sources);
}

 bool mips64_family_source_caps_present(mips64_file_caps_client_t sources)
{
    return sources.request_fd >= 3 && sources.lifetime_fd >= 3;
}

 bool mips64_family_distinct_source_fds(int control_fd, int dir_fd, mips64_inode_pins_t pins,
                                mips64_file_caps_client_t sources)
{
    bool absent = sources.request_fd == -1 && sources.lifetime_fd == -1;
    int descriptors[6] = {control_fd, dir_fd, pins.sender, pins.receiver,
                          sources.request_fd, sources.lifetime_fd};
    size_t count = absent ? 4u : 6u;
    for (size_t i = 0; i < count; ++i) {
        if (descriptors[i] < 3)
            return false;
        for (size_t j = 0; j < i; ++j)
            if (descriptors[i] == descriptors[j])
                return false;
    }
    return true;
}

 void mips64_family_family_fds(const mips64_family_t *family, int descriptors[4])
{
    descriptors[0] = family->control_fd;
    descriptors[1] = family->dir_fd;
    descriptors[2] = family->pins.sender;
    descriptors[3] = family->pins.receiver;
}

 size_t mips64_family_family_all_fds(const mips64_family_t *family, int descriptors[6])
{
    mips64_family_family_fds(family, descriptors);
    descriptors[4] = family->sources.request_fd;
    descriptors[5] = family->sources.lifetime_fd;
    return mips64_family_source_caps_present(family->sources) ? 6u : 4u;
}

 int mips64_family_lock_file(int fd, short type)
{
    struct flock lock = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 1
    };
    int result;
    do {
        result = fcntl(fd, F_SETLKW, &lock);
    } while (result < 0 && errno == EINTR);
    return result;
}

/* Byte zero is the execution token. A nonreused incarnation owns one later
 * byte for its complete attachment lifetime, even while not executing guest
 * code. Locks beyond EOF are POSIX byte locks; no guest data lives here.
 * Never use another control descriptor: closing any such descriptor drops
 * ALL this process's POSIX locks for the inode. */
 bool mips64_family_owner_lease_offset(uint64_t incarnation, off_t *offset)
{
    if (incarnation == 0 || incarnation > (uint64_t)INT64_MAX - 1u)
        return false;
    off_t converted = (off_t)(incarnation + 1u);
    if (converted < 0 || (uint64_t)converted != incarnation + 1u)
        return false;
    *offset = converted;
    return true;
}

 int mips64_family_acquire_owner_lease(mips64_family_t *family, uint64_t incarnation)
{
    off_t offset;
    if (!mips64_family_owner_lease_offset(incarnation, &offset)) {
        errno = EOVERFLOW;
        return -1;
    }
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = offset, .l_len = 1};
    int result;
    do { result = fcntl(family->control_fd, F_SETLK, &lock); }
    while (result < 0 && errno == EINTR);
    return result;
}

 int mips64_family_unlock_family_file(mips64_family_t *family)
{
#ifdef MIPS64_FAMILY_TESTING
    if (family->test_fail_unlock_once) {
        family->test_fail_unlock_once = false;
        errno = EIO;
        return -1;
    }
#endif
    return mips64_family_lock_file(family->control_fd, F_UNLCK);
}

 bool mips64_family_guard_valid_observed(const mips64_family_guard_t *guard,
                                 mips64_measure_observer_t *measure)
{
    if (guard == NULL || !guard->held || guard->family == NULL ||
        !guard->family->initialized || guard->family->poisoned ||
        guard->family->exec_active || guard->family->active_guard != guard)
        return false;
    mips64_measure_stamp_t pid_stamp = mips64_measure_begin(measure, MIPS64_MEASURE_FAMILY_PID);
    bool local_pid = guard->family->local_pid == getpid();
    mips64_measure_end(measure, MIPS64_MEASURE_FAMILY_PID, pid_stamp);
    return local_pid && guard->incarnation == guard->family->incarnation &&
           pthread_equal(guard->owner_thread, pthread_self()) != 0;
}

 bool mips64_family_guard_valid(const mips64_family_guard_t *guard)
{
    return mips64_family_guard_valid_observed(guard, NULL);
}

 int mips64_family_recover_file_state(mips64_family_guard_t *guard)
{
#ifdef MIPS64_FAMILY_TESTING
    if (guard->family->test_fail_file_recovery_once) {
        guard->family->test_fail_file_recovery_once = false;
        errno = ENOMEM;
        return -1;
    }
#endif
    return mips64_family_file_recover(guard);
}

bool mips64_family_guard_matches(const mips64_family_guard_t *guard,
                             const mips64_family_t *family)
{
    return family != NULL && mips64_family_guard_valid(guard) && guard->family == family;
}

bool mips64_family_guard_matches_observed(const mips64_family_guard_t *guard,
                                      const mips64_family_t *family,
                                      mips64_measure_observer_t *measure)
{
    return family != NULL && mips64_family_guard_valid_observed(guard, measure) &&
           guard->family == family;
}

 int mips64_family_normalize_owned_fd(int *fd_pointer)
{
    int fd = *fd_pointer;
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (fd >= 3) {
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
            return -1;
        return 0;
    }
    int replacement = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (replacement < 0)
        return -1;
    int close_result = close(fd);
    int close_errno = errno;
    *fd_pointer = -1;
    if (close_result != 0) {
        (void)close(replacement);
        errno = close_errno;
        return -1;
    }
    *fd_pointer = replacement;
    return 0;
}

 int mips64_family_page_name(mips64_family_page_key_t key, char output[48])
{
    int length = snprintf(output, 48, "page-%016llx-%016llx",
                          (unsigned long long)key.object_id,
                          (unsigned long long)key.page_index);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

 int mips64_family_object_name(uint64_t object_id, char output[48])
{
    int length = snprintf(output, 48, "object-%016llx",
                          (unsigned long long)object_id);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int control_fragment_name(size_t index, char output[48])
{
    if (index >= MIPS64_ZERO_CONTROL_MAX_FRAGMENTS) {
        errno = EOVERFLOW;
        return -1;
    }
    int length = snprintf(output, 48, "control-frag-%02x", (unsigned)index);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

 bool mips64_family_object_file_size(uint32_t slot_count, size_t *size)
{
    if (slot_count == 0 || slot_count > MIPS64_FAMILY_OBJECT_MAX_SLOTS)
        return false;
    size_t header = MIPS64_OBJECT_HEADER_SIZE;
    if (slot_count > (SIZE_MAX - header - (MIPS64_OBJECT_HEADER_SIZE - 1u)) /
                     MIPS64_OBJECT_SLOT_SIZE)
        return false;
    size_t end = header + (size_t)slot_count * MIPS64_OBJECT_SLOT_SIZE;
    *size = (end + MIPS64_OBJECT_HEADER_SIZE - 1u) & ~(size_t)(MIPS64_OBJECT_HEADER_SIZE - 1u);
    return true;
}

 int mips64_family_observe_open_inode(mips64_family_t *family, int fd)
{
    if (family->inode_observer == NULL)
        return 0;
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    if (family->inode_observer(family->inode_observer_context, &status) != 0) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

/* A zero-size inode is an identity/authority handle, never the payload. Keep
 * one family attachment for every named object, including between short-lived
 * views and redo replay. The first phase has no cross-process family attach. */
static mips64_family_object_t *map_zero_object(mips64_family_t *family,
                                           uint64_t object_id,
                                           uint32_t requested_count, int fd,
                                           bool initialize)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        status.st_size != 0 ||
        !mips64_family_family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        return NULL;
    }
    size_t size = 0;
    mips64_zero_object_segment_t *entry = find_zero_object(family, object_id);
    bool new_entry = false;
    if (initialize) {
        if (entry != NULL || !mips64_family_object_file_size(requested_count, &size)) {
            errno = EINVAL;
            return NULL;
        }
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL)
            return NULL;
        if (mips64_family_zero_segment_create(MIPS64_FAMILY_ZERO_SEGMENT_OBJECT,
                                           object_id, size, &entry->segment) != 0 ||
            mips64_family_zero_segment_publish_fd(fd, &entry->segment) != 0) {
            int saved = errno;
            mips64_family_zero_segment_detach(&entry->segment);
            free(entry);
            errno = saved;
            return NULL;
        }
        entry->object_id = object_id;
        entry->size = size;
        new_entry = true;
    } else {
        if (entry == NULL) {
            errno = EIDRM;
            return NULL;
        }
        size = entry->size;
        mips64_family_zero_segment_t checked = {0};
        if (mips64_family_zero_segment_attach_fd(fd, MIPS64_FAMILY_ZERO_SEGMENT_OBJECT,
                                              object_id, size, &checked) != 0)
            return NULL;
        bool same = memcmp(checked.descriptor, entry->segment.descriptor,
                           MIPS64_FAMILY_ZERO_SEGMENT_WIRE_SIZE) == 0;
        mips64_family_zero_segment_detach(&checked);
        if (!same) {
            errno = EIO;
            return NULL;
        }
    }
    mips64_family_object_file_t *mapping = entry->segment.payload;
    if (initialize) {
        memset(mapping, 0, size);
        mapping->magic = MIPS64_OBJECT_MAGIC;
        mapping->version = MIPS64_FAMILY_VERSION;
        mapping->header_size = MIPS64_OBJECT_HEADER_SIZE;
        mapping->object_id = object_id;
        mapping->slot_count = requested_count;
        atomic_thread_fence(memory_order_release);
    } else if (mapping->magic != MIPS64_OBJECT_MAGIC ||
               mapping->version != MIPS64_FAMILY_VERSION ||
               mapping->header_size != MIPS64_OBJECT_HEADER_SIZE ||
               mapping->object_id != object_id || mapping->reserved != 0 ||
               !mips64_family_object_file_size(mapping->slot_count, &size) ||
               size != entry->size) {
        errno = EIO;
        return NULL;
    }
    mips64_family_object_t *object = calloc(1, sizeof(*object));
    if (object == NULL) {
        if (new_entry) {
            int saved = errno;
            mips64_family_zero_segment_detach(&entry->segment);
            free(entry);
            errno = saved;
        }
        return NULL;
    }
    object->family = family;
    object->fd = fd;
    object->mapping_size = size;
    object->mapping = mapping;
    object->object_id = object_id;
    object->slot_count = mapping->slot_count;
    if (new_entry) {
        entry->next = family->zero_objects;
        family->zero_objects = entry;
    }
    (void)atomic_fetch_add_explicit(&family->live_views, 1,
                                    memory_order_relaxed);
    return object;
}

 mips64_family_object_t *mips64_family_map_object(mips64_family_t *family, uint64_t object_id,
                                      uint32_t requested_count, int fd,
                                      bool initialize)
{
    if (fd < 3 || object_id == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (family->zero_backing)
        return map_zero_object(family, object_id, requested_count, fd,
                               initialize);
    size_t size = 0;
    if (initialize) {
        if (!mips64_family_object_file_size(requested_count, &size)) {
            errno = EINVAL;
            return NULL;
        }
        if (ftruncate(fd, (off_t)size) != 0)
            return NULL;
    }
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1) {
        errno = EIO;
        return NULL;
    }
    if (!initialize) {
        mips64_family_object_header_t header;
        /* Only the fixed header is read before validating the file extent.
         * No mapping is dereferenced across a malformed short file. */
        ssize_t got = pread(fd, &header, sizeof(header), 0);
        if (got != (ssize_t)sizeof(header)) {
            errno = EIO;
            return NULL;
        }
        if (header.magic != MIPS64_OBJECT_MAGIC || header.version != MIPS64_FAMILY_VERSION ||
            header.header_size != MIPS64_OBJECT_HEADER_SIZE ||
            header.object_id != object_id || header.reserved != 0 ||
            !mips64_family_object_file_size(header.slot_count, &size)) {
            errno = EIO;
            return NULL;
        }
    }
    if (status.st_size != (off_t)size) {
        errno = EIO;
        return NULL;
    }
    size_t mapped_size = size;
    void *address = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED)
        return NULL;
    mips64_family_object_file_t *mapping = address;
    if (initialize) {
        memset(mapping, 0, mapped_size);
        mapping->magic = MIPS64_OBJECT_MAGIC;
        mapping->version = MIPS64_FAMILY_VERSION;
        mapping->header_size = MIPS64_OBJECT_HEADER_SIZE;
        mapping->object_id = object_id;
        mapping->slot_count = requested_count;
        if (msync(mapping, mapped_size, MS_SYNC) != 0) {
            int saved = errno;
            (void)munmap(mapping, mapped_size);
            errno = saved;
            return NULL;
        }
    } else if (mapping->magic != MIPS64_OBJECT_MAGIC ||
               mapping->version != MIPS64_FAMILY_VERSION ||
               mapping->header_size != MIPS64_OBJECT_HEADER_SIZE ||
               mapping->object_id != object_id || mapping->reserved != 0 ||
               !mips64_family_object_file_size(mapping->slot_count, &size) ||
               mapped_size != size) {
        (void)munmap(mapping, mapped_size);
        errno = EIO;
        return NULL;
    }
    mips64_family_object_t *object = calloc(1, sizeof(*object));
    if (object == NULL) {
        int saved = errno;
        (void)munmap(mapping, mapped_size);
        errno = saved;
        return NULL;
    }
    object->family = family;
    object->fd = fd;
    object->mapping_size = mapped_size;
    object->mapping = mapping;
    object->object_id = object_id;
    object->slot_count = mapping->slot_count;
    (void)atomic_fetch_add_explicit(&family->live_views, 1, memory_order_relaxed);
    return object;
}

 mips64_family_page_t *mips64_family_map_page(mips64_family_t *family, mips64_family_page_key_t key,
                                  int fd, bool initialize)
{
    size_t size = sizeof(mips64_family_page_file_t);
    if (fd < 3) {
        errno = EBADF;
        return NULL;
    }
    if (initialize && ftruncate(fd, (off_t)size) != 0)
        return NULL;
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        status.st_size != (off_t)size) {
        errno = EIO;
        return NULL;
    }
    void *address = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED)
        return NULL;
    mips64_family_page_file_t *mapping = address;
    if (initialize) {
        memset(mapping, 0, size);
        mapping->magic = MIPS64_PAGE_MAGIC;
        mapping->version = MIPS64_FAMILY_VERSION;
        mapping->size = (uint32_t)size;
        mapping->key = key;
        if (msync(mapping, size, MS_SYNC) != 0) {
            int saved = errno;
            (void)munmap(mapping, size);
            errno = saved;
            return NULL;
        }
    } else if (mapping->magic != MIPS64_PAGE_MAGIC ||
               mapping->version != MIPS64_FAMILY_VERSION ||
               mapping->size != size || !mips64_family_key_equal(mapping->key, key)) {
        (void)munmap(mapping, size);
        errno = EIO;
        return NULL;
    }
    mips64_family_page_t *page = calloc(1, sizeof(*page));
    if (page == NULL) {
        int saved = errno;
        (void)munmap(mapping, size);
        errno = saved;
        return NULL;
    }
    page->family = family;
    page->fd = fd;
    page->mapping_size = size;
    page->mapping = mapping;
    page->key = key;
    (void)atomic_fetch_add_explicit(&family->live_views, 1, memory_order_relaxed);
    return page;
}

 void mips64_family_apply_absolute_state(mips64_family_page_state_t *destination,
                                 const mips64_family_page_state_t *target,
                                 mips64_family_t *family, bool recovery)
{
    destination->content_generation = target->content_generation;
    memcpy(destination->epochs, target->epochs, sizeof(target->epochs));
    memcpy(destination->notified, target->notified, sizeof(target->notified));
    destination->private_cow = target->private_cow;
    atomic_thread_fence(memory_order_seq_cst);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(recovery ? MIPS64_FAMILY_TEST_RECOVERY_EPOCHS_APPLIED
                              : MIPS64_FAMILY_TEST_EPOCHS_APPLIED,
                     family->hook_context);
#else
    (void)family;
    (void)recovery;
#endif
    memcpy(destination->bytes, target->bytes, sizeof(target->bytes));
    atomic_thread_fence(memory_order_seq_cst);
#ifdef MIPS64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(MIPS64_FAMILY_TEST_BYTES_APPLIED, family->hook_context);
#endif
}

 mips64_family_object_t *mips64_family_open_logged_object(mips64_family_t *family,
                                               mips64_family_page_key_t key)
{
    if (key.object_id == 0 || key.page_index >= MIPS64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EIO;
        return NULL;
    }
    char name[48];
    if (mips64_family_object_name(key.object_id, name) != 0)
        return NULL;
    if (mips64_family_reject_control_alias(family->control_fd, family->dir_fd, name) != 0)
        return NULL;
    int fd = openat(family->dir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (mips64_family_normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        errno = saved;
        return NULL;
    }
    mips64_family_object_t *object = mips64_family_map_object(family, key.object_id, 0, fd, false);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return NULL;
    }
    if (key.page_index >= object->slot_count || mips64_family_observe_open_inode(family, fd) != 0) {
        int saved = key.page_index >= object->slot_count ? EIO : errno;
        mips64_family_object_close(object);
        errno = saved;
        return NULL;
    }
    return object;
}

 uint64_t mips64_family_wait_checksum(const void *data, size_t size)
{
    const unsigned char *bytes = data;
    uint64_t value = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < size; ++i) {
        value ^= bytes[i];
        value *= UINT64_C(1099511628211);
    }
    return value;
}

 bool mips64_family_wait_bank_size(uint64_t capacity, size_t *size)
{
    if (capacity == 0 || capacity > MIPS64_WAIT_MAX_ROWS ||
        capacity > (SIZE_MAX - sizeof(mips64_family_wait_bank_header_t)) /
                       sizeof(mips64_family_wait_row_t))
        return false;
    size_t raw = sizeof(mips64_family_wait_bank_header_t) +
                 (size_t)capacity * sizeof(mips64_family_wait_row_t);
    if (raw > SIZE_MAX - (MIPS64_FAMILY_PAGE_SIZE - 1u))
        return false;
    *size = (raw + MIPS64_FAMILY_PAGE_SIZE - 1u) & ~(size_t)(MIPS64_FAMILY_PAGE_SIZE - 1u);
    return true;
}

 bool mips64_family_wait_pair_end(uint64_t base, uint64_t capacity, uint64_t *end)
{
    size_t bank_size = 0;
    if (!mips64_family_wait_bank_size(capacity, &bank_size) || base > (uint64_t)INT64_MAX ||
        bank_size > (size_t)(((uint64_t)INT64_MAX - base) / 2u))
        return false;
    *end = base + (uint64_t)bank_size * 2u;
    return true;
}

 bool mips64_family_wait_offset(uint64_t base, uint32_t index, uint64_t capacity,
                        uint64_t *offset)
{
    size_t bank_size = 0;
    if (index > 1 || !mips64_family_wait_bank_size(capacity, &bank_size) ||
        base > (uint64_t)INT64_MAX || bank_size > (uint64_t)INT64_MAX - base)
        return false;
    *offset = base + (uint64_t)bank_size * index;
    return *offset <= (uint64_t)INT64_MAX;
}

 int mips64_family_wait_pread_full(int fd, void *buffer, size_t size, uint64_t offset)
{
    unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        if (offset > (uint64_t)INT64_MAX - done) {
            errno = EOVERFLOW;
            return -1;
        }
        ssize_t got = pread(fd, bytes + done, size - done, (off_t)(offset + done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            if (got == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

 int mips64_family_wait_pwrite_full(int fd, const void *buffer, size_t size, uint64_t offset)
{
    const unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        if (offset > (uint64_t)INT64_MAX - done) {
            errno = EOVERFLOW;
            return -1;
        }
        ssize_t put = pwrite(fd, bytes + done, size - done, (off_t)(offset + done));
        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0) {
            if (put == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)put;
    }
    return 0;
}

/* Every fragment has its own zero-length authority inode and one marked
 * segment. Keep the attachment until family destruction: the descriptor is
 * only a locator and cannot revive a segment after its final detach. */
static int create_control_fragment(mips64_family_t *family)
{
    size_t index = family->zero_fragment_count;
    char name[48];
    if (control_fragment_name(index, name) != 0)
        return -1;
    if (!mips64_family_family_authorize_fd(family->dir_fd, true,
                              family->storage_authority)) {
        errno = EACCES;
        return -1;
    }
    int fd = openat(family->dir_fd, name, O_CREAT | O_EXCL | O_RDWR |
                    O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0)
        return -1;
    struct stat created = {0};
    bool identified = fstat(fd, &created) == 0;
    mips64_family_zero_segment_t segment = {0};
    bool published = false;
    int result = -1;
    if (!identified || mips64_family_normalize_owned_fd(&fd) != 0 || fchmod(fd, 0600) != 0)
        goto fragment_done;
    if (!mips64_family_family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        goto fragment_done;
    }
    if (mips64_family_zero_segment_create(MIPS64_FAMILY_ZERO_SEGMENT_CONTROL_FRAGMENT,
            index + 1u, MIPS64_ZERO_CONTROL_FRAGMENT_SIZE, &segment) != 0 ||
        mips64_family_zero_segment_publish_fd(fd, &segment) != 0)
        goto fragment_done;
    if (!mips64_family_family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        goto fragment_done;
    }
    /* The observer may retain this inode even if it reports failure. Once
     * published, keep the fragment and its name for the next guarded scan. */
    family->zero_fragments[index] = segment;
    family->zero_fragment_count = index + 1u;
    published = true;
    if (mips64_family_observe_open_inode(family, fd) != 0) {
        /* The callback may have retained this identity. Keep the exact fd
         * until it accepts a later guarded retry; never reuse the name. */
        family->zero_fragment_pending_fd = fd;
        fd = -1;
        goto fragment_done;
    }
    result = 0;
fragment_done:
    ;
    int saved = errno;
    if (fd >= 0 && close(fd) != 0 && result == 0) {
        result = -1;
        saved = errno;
    }
    if (result != 0) {
        if (!published)
            mips64_family_zero_segment_detach(&segment);
        if (!published && identified) {
            struct stat named;
            if (fstatat(family->dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
                named.st_dev == created.st_dev && named.st_ino == created.st_ino)
                (void)unlinkat(family->dir_fd, name, 0);
        }
        errno = saved != 0 ? saved : EIO;
        return -1;
    }
    return 0;
}

 int mips64_family_ensure_control_extent(mips64_family_t *family, uint64_t end)
{
    if (!family->zero_backing)
        return 0;
    if (family->zero_fragment_pending_fd >= 0) {
        if (family->inode_observer == NULL) {
            errno = EIO;
            return -1;
        }
        if (mips64_family_observe_open_inode(family, family->zero_fragment_pending_fd) != 0)
            return -1;
        int pending_fd = family->zero_fragment_pending_fd;
        family->zero_fragment_pending_fd = -1;
        if (close(pending_fd) != 0)
            return -1;
    }
    off_t maximum;
    if (!mips64_family_wait_control_max_size(&maximum) || end > (uint64_t)maximum) {
        errno = ENOSPC;
        return -1;
    }
    while (end > MIPS64_ZERO_CONTROL_HEAD_SIZE +
                 family->zero_fragment_count * MIPS64_ZERO_CONTROL_FRAGMENT_SIZE)
        if (create_control_fragment(family) != 0)
            return -1;
    return 0;
}
