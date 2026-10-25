/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/mm_join.h"
#include "runtime/mm_view_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct mips64_mm_join_image {
    mips64_family_mm_t mm;
    mips64_family_identity_t family;
    uint64_t parent_incarnation;
    pid_t parent_pid;
};

int mips64_mm_join_prepare(mips64_mm_view_t *parent, mips64_family_guard_t *guard,
                        mips64_mm_join_image_t **out)
{
    if (parent == NULL || guard == NULL || out == NULL || *out != NULL ||
        parent->space == NULL || parent->space->internal_failure ||
        !mips64_family_backing_guard_matches(parent->backing, guard)) {
        errno = EINVAL; return -1;
    }
    mips64_family_identity_t identity;
    if (mips64_family_identity(guard, &identity) != 0 ||
        mips64_family_sources(guard) == NULL)
        return -1;
    mips64_family_mm_state_t current = {0};
    if (mips64_family_mm_read(guard, parent->mm, &current) != 0)
        return -1;
    bool member = false;
    for (size_t i = 0; i < current.member_count; ++i)
        if (current.members[i].owner_incarnation == guard->incarnation)
            member = true;
    int failure = current.revision != parent->applied.revision ? EAGAIN :
                  !member ? EINVAL : 0;
    mips64_family_mm_state_destroy(&current);
    if (failure != 0) { errno = failure; return -1; }
    mips64_mm_join_image_t *image = calloc(1, sizeof(*image));
    if (image == NULL)
        return -1;
    *image = (mips64_mm_join_image_t){parent->mm, identity, guard->incarnation, getpid()};
    *out = image;
    return 0;
}

static bool join_same_family(mips64_family_identity_t a, mips64_family_identity_t b)
{
    return a.control_device == b.control_device &&
           a.control_inode == b.control_inode &&
           a.directory_device == b.directory_device &&
           a.directory_inode == b.directory_inode;
}

static int join_member_order(mips64_family_mm_member_t a, mips64_family_mm_member_t b)
{
    if (a.owner_incarnation != b.owner_incarnation)
        return (a.owner_incarnation > b.owner_incarnation) -
               (a.owner_incarnation < b.owner_incarnation);
    return (a.task_id > b.task_id) - (a.task_id < b.task_id);
}

int mips64_mm_join_child_adopt(mips64_mm_join_image_t **owned,
                            mips64_family_guard_t *guard,
                            mips64_family_backing_t *backing,
                            mips64_space_t *space, mips64_linux_memory_t *memory,
                            mips64_file_identity_policy_t policy,
                            uint64_t task_id, mips64_mm_view_t **out)
{
    if (owned == NULL || *owned == NULL || guard == NULL || backing == NULL ||
        space == NULL || memory == NULL || out == NULL || *out != NULL ||
        task_id == 0 || getpid() == (*owned)->parent_pid ||
        !mips64_family_backing_guard_matches(backing, guard)) {
        errno = EINVAL; return -1;
    }
    mips64_family_identity_t identity;
    if (mips64_family_identity(guard, &identity) != 0)
        return -1;
    if (!join_same_family(identity, (*owned)->family)) {
        errno = EXDEV; return -1;
    }
    if (guard->incarnation == (*owned)->parent_incarnation) {
        errno = EINVAL; return -1;
    }
    mips64_mm_view_t *view = NULL;
    mips64_family_mm_state_t state = {0};
    mips64_mm_view_plan_t plan = {0};
    int result = -1;
    if (mips64_mm_view_create(&view, (*owned)->mm, backing, space, memory) != 0 ||
        mips64_mm_view_bind_family_sources(view, guard, policy) != 0 ||
        mips64_family_mm_read(guard, (*owned)->mm, &state) != 0)
        goto done;
    if (state.limit != space->limit) { errno = EINVAL; goto done; }
    mips64_family_mm_member_t member = {guard->incarnation, task_id};
    size_t at = 0;
    while (at < state.member_count && join_member_order(state.members[at], member) < 0)
        ++at;
    if (at < state.member_count && join_member_order(state.members[at], member) == 0) {
        errno = EEXIST; goto done;
    }
    if (state.member_count == MIPS64_FAMILY_MM_MAX_RECORDS) {
        errno = ENOSPC; goto done;
    }
    mips64_family_mm_member_t *rows = realloc(state.members,
        (state.member_count + 1u) * sizeof(*rows));
    if (rows == NULL)
        goto done;
    state.members = rows;
    memmove(&rows[at + 1u], &rows[at], (state.member_count - at) * sizeof(*rows));
    rows[at] = member;
    ++state.member_count;
    if (mips64_mm_view_plan_prepare(view, &state, &plan) != 0)
        goto done;
    if (mips64_family_mm_commit(guard, (*owned)->mm, &plan.state) != 0) {
        result = -2; goto done;
    }
    mips64_mm_view_plan_apply(view, &plan);
    *out = view;
    view = NULL;
    mips64_mm_join_image_destroy(owned);
    result = 0;
done: {
        int saved = errno;
        mips64_mm_view_plan_discard(&plan);
        mips64_family_mm_state_destroy(&state);
        mips64_mm_view_destroy(&view);
        errno = saved;
        return result;
    }
}

void mips64_mm_join_image_destroy(mips64_mm_join_image_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    free(*owned);
    *owned = NULL;
}

int mips64_mm_retire_exec_owner(mips64_family_guard_t *guard, mips64_family_mm_t mm,
                            uint64_t caller_task_id)
{
    if (guard == NULL || caller_task_id == 0) { errno = EINVAL; return -1; }
    mips64_family_mm_state_t state = {0};
    if (mips64_family_mm_read(guard, mm, &state) != 0)
        return -1;
    bool caller_found = false;
    size_t local = 0, retained = 0;
    for (size_t i = 0; i < state.member_count; ++i) {
        if (state.members[i].owner_incarnation == guard->incarnation) {
            ++local;
            if (state.members[i].task_id == caller_task_id)
                caller_found = true;
        } else
            state.members[retained++] = state.members[i];
    }
    if (!caller_found || local > 4096) {
        mips64_family_mm_state_destroy(&state);
        errno = EINVAL;
        return -1;
    }
    state.member_count = retained;
    int result = mips64_family_mm_commit(guard, mm, &state);
    int saved = errno;
    mips64_family_mm_state_destroy(&state);
    errno = saved;
    return result;
}
