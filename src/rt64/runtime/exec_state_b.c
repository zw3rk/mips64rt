/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "exec_state_parts.h"

int mips64_exec_state_export_activate(mips64_exec_state_export_t *owner)
{
    if (owner == NULL || owner->poisoned || owner->active) {
        errno = owner != NULL && owner->active ? EALREADY : EINVAL;
        return -1;
    }
    int flags = fcntl(owner->metadata, F_GETFD);
    if (flags < 0 || fcntl(owner->metadata, F_SETFD,
                           flags & ~FD_CLOEXEC) < 0)
        return -1;
    owner->old_flags = flags;
    size_t activated = 0;
    for (; activated < owner->child_count; ++activated) {
        if (fcntl(owner->child_caps[activated], F_SETFD,
                  owner->child_flags[activated] & ~FD_CLOEXEC) < 0)
            break;
    }
    if (activated != owner->child_count) {
        int saved = errno;
        bool rollback_failed = false;
        while (activated != 0) {
            --activated;
            if (fcntl(owner->child_caps[activated], F_SETFD,
                      owner->child_flags[activated]) < 0)
                rollback_failed = true;
        }
        if (fcntl(owner->metadata, F_SETFD, flags) < 0)
            rollback_failed = true;
        owner->poisoned = rollback_failed;
        errno = rollback_failed ? EIO : saved;
        return -1;
    }
    owner->active = true;
    return 0;
}

int mips64_exec_state_export_deactivate(mips64_exec_state_export_t *owner)
{
    if (owner == NULL || owner->poisoned) {
        errno = EIO;
        return -1;
    }
    if (owner->active) {
        bool failed = false;
        for (size_t i = 0; i < owner->child_count; ++i)
            if (fcntl(owner->child_caps[i], F_SETFD,
                      owner->child_flags[i]) < 0)
                failed = true;
        if (fcntl(owner->metadata, F_SETFD, owner->old_flags) < 0)
            failed = true;
        if (failed) {
            owner->poisoned = true;
            errno = EIO;
            return -1;
        }
    }
    owner->active = false;
    return 0;
}

int mips64_exec_state_import(int owned_fd, mips64_exec_state_t *out)
{
    if (out == NULL) {
        if (owned_fd >= 3)
            (void)close(owned_fd);
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (owned_fd < 3) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *data = NULL;
    mips64_exec_state_t staged = {0};
    int result = -1;
    int flags = fcntl(owned_fd, F_GETFD);
    if (flags < 0 || fcntl(owned_fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        goto done;
    struct stat before, after;
    if (!mips64_exec_state_private_metadata(owned_fd, &before) ||
        before.st_size < (off_t)EXEC_RECORD_HEADER ||
        (uint64_t)before.st_size > EXEC_RECORD_MAX) {
        errno = EINVAL;
        goto done;
    }
    size_t length = (size_t)before.st_size;
    data = malloc(length);
    if (data == NULL)
        goto done;
    if (mips64_exec_state_read_all(owned_fd, data, length) != 0)
        goto done;
    if (!mips64_exec_state_private_metadata(owned_fd, &after) ||
        !mips64_exec_state_same_record_stat(&before, &after)) {
        errno = EINVAL;
        goto done;
    }
    if (!mips64_exec_state_decode(data, length, &staged))
        goto done;
    result = 0;
done: {
        int saved = errno;
        free(data);
        if (close(owned_fd) != 0 && result == 0) {
            saved = errno;
            result = -1;
        }
        if (result == 0)
            *out = staged;
        else
            mips64_exec_state_destroy(&staged);
        errno = saved;
        return result;
    }
}
