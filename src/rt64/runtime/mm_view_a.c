/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mm_view_parts.h"

#include "runtime/mm_view_internal.h"
#include "memory/family_file.h"
#include "runtime/family_file_index.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int mips64_mm_view_create(mips64_mm_view_t **out, mips64_family_mm_t mm,
                       mips64_family_backing_t *backing, mips64_space_t *space,
                       mips64_linux_memory_t *memory)
{
    if (out == NULL || *out != NULL || mm.mm_id == 0 || mm.root_object == 0 ||
        backing == NULL || space == NULL || memory == NULL || memory->space != space ||
        space->count != 0 || memory->count != 0 || memory->vmas != NULL ||
        space->page_factory.context != backing || space->managed.context != backing ||
        space->internal_failure) {
        errno = EINVAL;
        return -1;
    }
    mips64_mm_view_t *view = calloc(1, sizeof(*view));
    if (view == NULL)
        return -1;
    view->mm = mm; view->backing = backing; view->space = space; view->memory = memory;
    view->file_client = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    *out = view;
    return 0;
}

int mips64_mm_view_bind_family_sources(mips64_mm_view_t *view,
                                    mips64_family_guard_t *guard,
                                    mips64_file_identity_policy_t policy)
{
    if (view == NULL || !mips64_file_identity_policy_valid(policy) ||
        !mips64_family_backing_guard_matches(view->backing, guard) ||
        view->file_client.request_fd >= 0 || view->file_client.lifetime_fd >= 0) {
        errno = EINVAL; return -1;
    }
    const mips64_file_caps_client_t *client = mips64_family_sources(guard);
    if (client == NULL)
        return -1;
    if (mips64_file_caps_client_duplicate(client, &view->file_client) != 0)
        return -1;
    view->file_identity_policy = policy;
    return 0;
}

static mips64_file_source_t *cached_file(const mips64_mm_file_cache_entry_t *entries,
                                      size_t count, uint64_t id)
{
    for (size_t i = 0; i < count; ++i)
        if (entries[i].id == id)
            return entries[i].source;
    return NULL;
}

static const mips64_family_mm_file_assoc_t *file_association(
    const mips64_family_mm_state_t *state, mips64_family_page_key_t key)
{
    for (size_t i = 0; i < state->file_assoc_count; ++i)
        if (state->file_assocs[i].key.object_id == key.object_id &&
            state->file_assocs[i].key.page_index == key.page_index)
            return &state->file_assocs[i];
    return NULL;
}

 bool mips64_mm_view_same_key(mips64_family_page_key_t a, mips64_family_page_key_t b)
{
    return a.object_id == b.object_id && a.page_index == b.page_index;
}

static bool local_matches(const mips64_mm_view_t *view)
{
    if (view->space->count != view->applied.page_count ||
        view->memory->count != view->applied.vma_count ||
        view->memory->next_id != view->applied.next_vma_id ||
        view->memory->brk_id != view->applied.brk_id ||
        view->memory->minimum_break != view->applied.minimum_break ||
        view->memory->current_break != view->applied.current_break)
        return false;
    for (size_t i = 0; i < view->memory->count; ++i) {
        const mips64_vma_t *a = &view->memory->vmas[i], *b = &view->applied.vmas[i];
        if (a->start != b->start || a->end != b->end || a->backing_id != b->backing_id ||
            a->offset != b->offset || a->permissions != b->permissions ||
            a->may_permissions != b->may_permissions || a->kind != b->kind)
            return false;
    }
    for (size_t i = 0; i < view->space->count; ++i) {
        const mips64_page_t *page = &view->space->pages[i];
        const mips64_family_mm_page_t *applied = &view->applied.pages[i];
        mips64_family_page_key_t key;
        const mips64_family_mm_file_assoc_t *assoc =
            file_association(&view->applied, applied->key);
        mips64_file_source_t *expected_file = assoc == NULL ? NULL :
            cached_file(view->file_sources, view->file_source_count, assoc->source_id);
        if (page->address != applied->address || page->permissions != applied->permissions ||
            page->binding_base != view->local_bindings[i] ||
            (assoc != NULL && expected_file == NULL) ||
            page->backing->file != expected_file ||
            (assoc != NULL && page->backing->file_offset != assoc->file_offset) ||
            page->backing->bus_fault != (applied->kind == MIPS64_MM_BUS))
            return false;
        if (applied->kind == MIPS64_MM_BUS) {
            if (page->backing->payload != NULL || page->backing->bytes != NULL ||
                page->backing->epochs != NULL)
                return false;
        } else if (!mips64_family_backing_key(view->backing, page->backing->payload, &key) ||
                   !mips64_mm_view_same_key(key, applied->key)) {
            return false;
        }
    }
    return true;
}

int mips64_mm_view_adopt(mips64_mm_view_t **out, mips64_family_mm_t mm,
                       mips64_family_backing_t *backing, mips64_family_guard_t *guard,
                       mips64_space_t *space, mips64_linux_memory_t *memory)
{
    if (out == NULL || *out != NULL || mm.mm_id == 0 || mm.root_object == 0 ||
        backing == NULL || space == NULL || memory == NULL || memory->space != space ||
        !mips64_family_backing_guard_matches(backing, guard) || space->internal_failure ||
        space->page_factory.context != backing || space->managed.context != backing ||
        (space->count != 0 && space->pages == NULL) ||
        (memory->count != 0 && memory->vmas == NULL)) {
        errno = EINVAL;
        return -1;
    }
    mips64_mm_view_t *view = calloc(1, sizeof(*view));
    if (view == NULL)
        return -1;
    view->mm = mm; view->backing = backing; view->space = space; view->memory = memory;
    view->file_client = (mips64_file_caps_client_t)MIPS64_FILE_CAPS_CLIENT_INITIALIZER;
    if (mips64_family_mm_read(guard, mm, &view->applied) != 0) {
        int saved = errno;
        mips64_mm_view_destroy(&view); errno = saved; return -1;
    }
    /* An already mapped file image needs an exact source-cap-aware adoption
     * transaction. Reject it before interpreting anonymous pages as files. */
    if (view->applied.file_assoc_count != 0) {
        mips64_mm_view_destroy(&view); errno = EOPNOTSUPP; return -1;
    }
    if (space->limit != view->applied.limit || space->count != view->applied.page_count) {
        mips64_mm_view_destroy(&view); errno = EIO; return -1;
    }
    view->local_bindings = space->count == 0 ? NULL :
        malloc(space->count * sizeof(*view->local_bindings));
    if (space->count != 0 && view->local_bindings == NULL) {
        mips64_mm_view_destroy(&view); errno = ENOMEM; return -1;
    }
    for (size_t i = 0; i < space->count; ++i)
        view->local_bindings[i] = space->pages[i].binding_base;
    if (!local_matches(view)) {
        mips64_mm_view_destroy(&view); errno = EIO; return -1;
    }
    *out = view;
    return 0;
}

int mips64_mm_view_seed(mips64_mm_view_t **out, mips64_family_backing_t *backing,
                      mips64_family_guard_t *guard, mips64_space_t *space,
                      mips64_linux_memory_t *memory, uint64_t initial_task_id)
{
    if (out == NULL || *out != NULL || backing == NULL || space == NULL ||
        memory == NULL || memory->space != space || initial_task_id == 0 ||
        !mips64_family_backing_guard_matches(backing, guard) || space->internal_failure ||
        space->page_factory.context != backing || space->managed.context != backing ||
        space->count > MIPS64_FAMILY_MM_MAX_RECORDS ||
        memory->count > MIPS64_FAMILY_MM_MAX_RECORDS ||
        (space->count != 0 && space->pages == NULL) ||
        (memory->count != 0 && memory->vmas == NULL)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < memory->count; ++i) {
        if (memory->vmas[i].kind == MIPS64_VMA_FILE_PRIVATE ||
            memory->vmas[i].kind == MIPS64_VMA_ANONYMOUS_SHARED) {
            /* A current VMA extent cannot recover the immutable original
             * shared extent after shrink. Startup has no supplied manifest. */
            errno = EOPNOTSUPP; return -1;
        }
    }
    mips64_family_mm_page_t *pages = space->count == 0 ? NULL :
        calloc(space->count, sizeof(*pages));
    mips64_vma_t *vmas = memory->count == 0 ? NULL :
        malloc(memory->count * sizeof(*vmas));
    if ((space->count != 0 && pages == NULL) || (memory->count != 0 && vmas == NULL)) {
        free(pages); free(vmas); errno = ENOMEM; return -1;
    }
    if (memory->count != 0)
        memcpy(vmas, memory->vmas, memory->count * sizeof(*vmas));
    for (size_t i = 0; i < space->count; ++i) {
        const mips64_page_t *page = &space->pages[i];
        if (page->backing->file != NULL) {
            free(pages); free(vmas); errno = EOPNOTSUPP; return -1;
        }
        mips64_family_page_key_t key;
        if (!mips64_family_backing_key(backing, page->backing->payload, &key)) {
            free(pages); free(vmas); errno = EIO; return -1;
        }
        pages[i] = (mips64_family_mm_page_t){page->address, i + 1u, 1, key, page->permissions, MIPS64_MM_DATA};
    }
    mips64_family_mm_member_t member = {guard->incarnation, initial_task_id};
    /* The one member is borrowed only through synchronous serialization;
     * mapping metadata is copied before publishing the new root. */
    mips64_family_mm_state_t state = {.vmas = vmas, .vma_count = memory->count,
        .pages = pages, .page_count = space->count, .members = &member, .member_count = 1,
        .limit = space->limit, .minimum_break = memory->minimum_break,
        .current_break = memory->current_break, .brk_id = memory->brk_id,
        .next_vma_id = memory->next_id, .next_mapping_id = space->count + 1u};
    mips64_family_mm_t mm = {0};
    int result = mips64_family_mm_create(guard, &state, &mm), saved = errno;
    free(pages); free(vmas);
    if (result != 0) { errno = saved; return -1; }
    return mips64_mm_view_adopt(out, mm, backing, guard, space, memory);
}

mips64_family_mm_t mips64_mm_view_identity(const mips64_mm_view_t *view)
{
    return view == NULL ? (mips64_family_mm_t){0} : view->mm;
}

bool mips64_mm_view_has_member(const mips64_mm_view_t *view,
                           const mips64_family_guard_t *guard, uint64_t task_id)
{
    if (view == NULL || task_id == 0 ||
        !mips64_family_backing_guard_matches(view->backing, guard))
        return false;
    for (size_t i = 0; i < view->applied.member_count; ++i) {
        const mips64_family_mm_member_t *member = &view->applied.members[i];
        if (member->owner_incarnation == guard->incarnation &&
            member->task_id == task_id)
            return true;
    }
    return false;
}

 int mips64_mm_view_space_error(const mips64_space_t *space)
{
    return space->fault_reason == MIPS64_FAULT_RESOURCE ? ENOMEM : EIO;
}

void mips64_mm_view_plan_discard(mips64_mm_view_plan_t *plan)
{
    mips64_space_destroy(&plan->space);
    mips64_family_mm_state_destroy(&plan->state);
    free(plan->vmas); free(plan->bindings);
    for (size_t i = plan->old_file_source_count; i < plan->file_source_count; ++i)
        plan->file_sources[i].source->release(plan->file_sources[i].source);
    free(plan->file_sources);
    memset(plan, 0, sizeof(*plan));
}

/* Stage every previously unseen source before publishing even a metadata-only
 * association. Source IDs are trusted only after an exact capability fetch. */
static int stage_file_sources(mips64_mm_view_t *view,
                                const mips64_family_mm_state_t *fresh,
                                mips64_mm_view_plan_t *plan)
{
    if (fresh->file_assoc_count == 0)
        return 0;
    if (view->file_client.request_fd < 0 || view->file_client.lifetime_fd < 0) {
        errno = EOPNOTSUPP; return -1;
    }
    size_t capacity = view->file_source_count + fresh->file_assoc_count;
    if (capacity < view->file_source_count ||
        capacity > SIZE_MAX / sizeof(*plan->file_sources)) {
        errno = EOVERFLOW; return -1;
    }
    plan->file_sources = calloc(capacity, sizeof(*plan->file_sources));
    if (plan->file_sources == NULL)
        return -1;
    if (view->file_source_count != 0)
        memcpy(plan->file_sources, view->file_sources,
               view->file_source_count * sizeof(*plan->file_sources));
    plan->file_source_count = plan->old_file_source_count = view->file_source_count;
    for (size_t i = 0; i < fresh->file_assoc_count; ++i) {
        uint64_t id = fresh->file_assocs[i].source_id;
        if (cached_file(plan->file_sources, plan->file_source_count, id) != NULL)
            continue;
        int owned_fd = -1;
        if (mips64_file_caps_fetch(&view->file_client, id, &owned_fd) != 0)
            return -1;
        mips64_file_source_t *source = NULL;
        if (mips64_family_file_source_create(&source, view->backing, view->space,
                                         id, owned_fd) != 0)
            return -1;
        plan->file_sources[plan->file_source_count++] =
            (mips64_mm_file_cache_entry_t){id, source};
    }
    return 0;
}

static bool same_layout(const mips64_family_mm_state_t *a, const mips64_family_mm_state_t *b)
{
    if (a->limit != b->limit || a->minimum_break != b->minimum_break || a->brk_id != b->brk_id ||
        a->vma_count != b->vma_count || a->page_count != b->page_count)
        return false;
    for (size_t i = 0; i < a->vma_count; ++i) {
        const mips64_vma_t *x = &a->vmas[i], *y = &b->vmas[i];
        if (x->start != y->start || x->end != y->end || x->backing_id != y->backing_id ||
            x->offset != y->offset || x->permissions != y->permissions ||
            x->may_permissions != y->may_permissions || x->kind != y->kind)
            return false;
    }
    for (size_t i = 0; i < a->page_count; ++i) {
        const mips64_family_mm_page_t *x = &a->pages[i], *y = &b->pages[i];
        if (x->address != y->address || x->mapping_id != y->mapping_id ||
            x->mapping_generation != y->mapping_generation || x->permissions != y->permissions ||
            x->kind != y->kind ||
            !mips64_mm_view_same_key(x->key, y->key))
            return false;
    }
    return true;
}

/* Borrow state through failure; consume it only on successful preparation.
 * The caller holds one uninterrupted guard through prepare/publication/apply. */
int mips64_mm_view_plan_prepare(mips64_mm_view_t *view, mips64_family_mm_state_t *state,
                          mips64_mm_view_plan_t *plan)
{
    mips64_family_mm_state_t fresh = *state;
    if (stage_file_sources(view, &fresh, plan) != 0)
        return -1;
    if (same_layout(&view->applied, &fresh)) {
        plan->state = fresh;
        plan->metadata_only = true;
        memset(state, 0, sizeof(*state));
        return 0;
    }
    if (view->space->generation == UINT64_MAX) {
        errno = EOVERFLOW; return -1;
    }
    mips64_space_t candidate;
    mips64_space_init_abi(&candidate, mips64_space_is_n32_limit(fresh.limit));
    candidate.limit = fresh.limit;
    candidate.next_binding = view->space->next_binding;
    if (!mips64_family_backing_install(view->backing, &candidate)) {
        errno = EIO; return -1;
    }
    candidate.pages = fresh.page_count == 0 ? NULL :
        calloc(fresh.page_count, sizeof(*candidate.pages));
    mips64_vma_t *vmas = fresh.vma_count == 0 ? NULL :
        malloc(fresh.vma_count * sizeof(*vmas));
    uint64_t *bindings = fresh.page_count == 0 ? NULL :
        malloc(fresh.page_count * sizeof(*bindings));
    if ((fresh.page_count != 0 && (candidate.pages == NULL || bindings == NULL)) ||
        (fresh.vma_count != 0 && vmas == NULL)) {
        mips64_space_destroy(&candidate);
        free(vmas); free(bindings); errno = ENOMEM; return -1;
    }
    candidate.capacity = fresh.page_count;
    if (fresh.vma_count != 0)
        memcpy(vmas, fresh.vmas, fresh.vma_count * sizeof(*vmas));
    int saved = 0;
    size_t old = 0;
    for (size_t i = 0; i < fresh.page_count; ++i) {
        const mips64_family_mm_page_t *page = &fresh.pages[i];
        while (old < view->applied.page_count &&
               view->applied.pages[old].address < page->address)
            ++old;
        bool retained = old < view->applied.page_count &&
            view->applied.pages[old].address == page->address &&
            view->applied.pages[old].mapping_id == page->mapping_id &&
            view->applied.pages[old].mapping_generation == page->mapping_generation;
        if (retained) {
            const mips64_page_t *previous = &view->space->pages[old];
            /* map_shared_payload replaces the array with an exact-size one.
             * A preceding new page may therefore have reduced our capacity. */
            if (candidate.count == candidate.capacity) {
                mips64_page_t *pages = malloc(fresh.page_count * sizeof(*pages));
                if (pages == NULL) { saved = ENOMEM; goto done; }
                if (candidate.count != 0)
                    memcpy(pages, candidate.pages, candidate.count * sizeof(*pages));
                free(candidate.pages);
                candidate.pages = pages;
                candidate.capacity = fresh.page_count;
            }
            /* Reader validation is defensive even if an earlier publisher
             * violated the stable-ID transition contract. */
            if (!mips64_mm_view_same_key(view->applied.pages[old].key, page->key) ||
                view->applied.pages[old].kind != page->kind ||
                previous->permissions != page->permissions ||
                !mips64_backing_retain(previous->backing)) {
                saved = EIO; goto done;
            }
            candidate.pages[candidate.count++] = *previous;
            /* Checked file fetch/refresh must remain selected after an
             * unrelated transaction retains executable file-backed pages. */
            if (previous->backing->file != NULL)
                candidate.has_file_pages = true;
        } else {
            if (candidate.next_binding > UINT64_MAX - MIPS64_PAGE_GRANULES) {
                saved = EOVERFLOW; goto done;
            }
            const mips64_family_mm_file_assoc_t *assoc =
                file_association(&fresh, page->key);
            bool mapped = page->kind == MIPS64_MM_BUS ?
                mips64_space_map_bus(&candidate, page->address, MIPS64_PAGE_SIZE, page->permissions, false) :
                assoc != NULL ? mips64_family_file_stage(
                    cached_file(plan->file_sources, plan->file_source_count, assoc->source_id),
                    &candidate, page->address, page->permissions, page->key,
                    assoc->file_offset) :
                mips64_family_backing_map_shared(view->backing, &candidate,
                                               page->address, page->permissions, page->key);
            if (!mapped) {
                saved = mips64_mm_view_space_error(&candidate); goto done;
            }
        }
        bindings[i] = candidate.pages[i].binding_base;
    }
    plan->space = candidate;
    plan->state = fresh;
    plan->vmas = vmas;
    plan->bindings = bindings;
    plan->metadata_only = false;
    memset(state, 0, sizeof(*state));
    return 0;
done:
    mips64_space_destroy(&candidate);
    free(vmas); free(bindings); errno = saved;
    return -1;
}

void mips64_mm_view_plan_apply(mips64_mm_view_t *view, mips64_mm_view_plan_t *plan)
{
    if (plan->file_sources != NULL) {
        free(view->file_sources);
        view->file_sources = plan->file_sources;
        view->file_source_count = plan->file_source_count;
        plan->file_sources = NULL;
        plan->file_source_count = plan->old_file_source_count = 0;
    }
    if (plan->metadata_only) {
        /* Scalar counters/member changes cannot alter any mapping, borrowed
         * space, binding, scratch reservation or generated-code dependency. */
        view->memory->next_id = plan->state.next_vma_id;
        view->memory->current_break = plan->state.current_break;
        mips64_family_mm_state_destroy(&view->applied);
        view->applied = plan->state;
        memset(plan, 0, sizeof(*plan));
        return;
    }
    /* Preparation and root publication have succeeded. No allocation/failure
     * point remains; preserve the fixed space and reserved copyout scratch. */
    mips64_space_t candidate = plan->space;
    mips64_family_mm_state_t fresh = plan->state;
    mips64_vma_t *vmas = plan->vmas;
    uint64_t *bindings = plan->bindings;
    candidate.generation = view->space->generation + 1u;
    candidate.measure = view->space->measure;
    candidate.fault_reason = view->space->fault_reason;
    candidate.fault_address = view->space->fault_address;
    candidate.epoch_scratch = view->space->epoch_scratch;
    candidate.epoch_scratch_capacity = view->space->epoch_scratch_capacity;
    mips64_space_t previous = *view->space;
    previous.epoch_scratch = NULL; previous.epoch_scratch_capacity = 0;
    *view->space = candidate;
    free(view->memory->vmas);
    *view->memory = (mips64_linux_memory_t){.space = view->space, .vmas = vmas,
        .count = fresh.vma_count, .next_id = fresh.next_vma_id, .brk_id = fresh.brk_id,
        .minimum_break = fresh.minimum_break, .current_break = fresh.current_break};
    mips64_family_mm_state_destroy(&view->applied);
    view->applied = fresh;
    free(view->local_bindings); view->local_bindings = bindings;
    mips64_space_destroy(&previous);
    memset(plan, 0, sizeof(*plan));
}

int mips64_mm_view_refresh(mips64_mm_view_t *view, mips64_family_guard_t *guard)
{
    if (view == NULL || !mips64_family_backing_guard_matches(view->backing, guard) ||
        view->space->internal_failure || !local_matches(view)) {
        errno = EIO;
        return -1;
    }
    mips64_family_mm_state_t fresh = {0};
    if (mips64_family_mm_read(guard, view->mm, &fresh) != 0)
        return -1;
    if (fresh.limit != view->space->limit || fresh.revision < view->applied.revision) {
        mips64_family_mm_state_destroy(&fresh); errno = EIO; return -1;
    }
    if (fresh.revision == view->applied.revision) {
        mips64_family_mm_state_destroy(&fresh);
        return 0;
    }
    mips64_mm_view_plan_t plan = {0};
    int result = mips64_mm_view_plan_prepare(view, &fresh, &plan), saved = errno;
    if (result == 0)
        mips64_mm_view_plan_apply(view, &plan);
    mips64_mm_view_plan_discard(&plan);
    mips64_family_mm_state_destroy(&fresh);
    errno = saved;
    return result;
}

static bool mergeable(const mips64_vma_t *a, const mips64_vma_t *b)
{
    return a->end == b->start && a->backing_id == b->backing_id &&
        a->offset + (a->end - a->start) == b->offset && a->kind == b->kind &&
        a->permissions == b->permissions && a->may_permissions == b->may_permissions;
}

static void append_vma(mips64_vma_t *vmas, size_t *count, mips64_vma_t vma)
{
    if (*count != 0 && mergeable(&vmas[*count - 1], &vma))
        vmas[*count - 1].end = vma.end;
    else
        vmas[(*count)++] = vma;
}

/* Only the two interval boundaries can add records. The input catalog already
 * bounds all offset arithmetic. Preserve requested versus effective permissions. */
static int protect_vmas(mips64_family_mm_state_t *state, uint64_t start, uint64_t end,
                          unsigned int permissions)
{
    mips64_vma_t *vmas = malloc((state->vma_count + 2u) * sizeof(*vmas));
    if (vmas == NULL)
        return -1;
    size_t count = 0;
    for (size_t i = 0; i < state->vma_count; ++i) {
        mips64_vma_t original = state->vmas[i];
        if (original.end <= start || original.start >= end) {
            append_vma(vmas, &count, original);
            continue;
        }
        if (original.start < start) {
            mips64_vma_t prefix = original;
            prefix.end = start;
            append_vma(vmas, &count, prefix);
        }
        mips64_vma_t changed = original;
        if (changed.start < start) {
            changed.offset += start - changed.start;
            changed.start = start;
        }
        if (changed.end > end)
            changed.end = end;
        changed.permissions = permissions;
        append_vma(vmas, &count, changed);
        if (original.end > end) {
            mips64_vma_t suffix = original;
            suffix.offset += end - suffix.start;
            suffix.start = end;
            append_vma(vmas, &count, suffix);
        }
    }
    if (count > MIPS64_FAMILY_MM_MAX_RECORDS) {
        free(vmas); errno = ENOMEM; return -1;
    }
    free(state->vmas); state->vmas = vmas; state->vma_count = count;
    return 0;
}

int mips64_mm_view_mprotect(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                          uint64_t address, uint64_t length, uint64_t protection,
                          uint64_t *guest_result)
{
    if (guest_result == NULL) { errno = EINVAL; return -1; }
    /* Even an error/no-op must not admit a stale local view. Catch-up failure
     * is an infrastructure result, never a successfully entered guest task. */
    if (mips64_mm_view_refresh(view, guard) != 0)
        return -1;
    unsigned int failure = 0;
    if (address % MIPS64_PAGE_SIZE != 0 || (protection & ~UINT64_C(7)) != 0)
        failure = 22;
    else if (length == 0) {
        *guest_result = 0; return 0;
    } else if (length > UINT64_MAX - (MIPS64_PAGE_SIZE - 1) ||
               address < MIPS64_PAGE_SIZE || address >= view->space->limit) {
        failure = 12;
    }
    uint64_t size = failure == 0 ?
        (length + MIPS64_PAGE_SIZE - 1) & ~(MIPS64_PAGE_SIZE - 1) : 0;
    /* A non-wrapping range beyond the supported VA limit encounters a later
     * hole; any valid mapped prefix must still take effect before ENOMEM. */
    if (failure == 0 && size > UINT64_MAX - address)
        failure = 12;
    if (failure != 0) { *guest_result = UINT64_C(0) - failure; return 0; }

    mips64_family_mm_state_t state = {0};
    if (mips64_family_mm_read(guard, view->mm, &state) != 0)
        return -1;
    uint64_t end = address + size, prefix = address;
    bool changed = false;
    for (size_t i = 0; prefix < end; ++i) {
        if (i == state.vma_count || state.vmas[i].start > prefix) {
            failure = 12; break;
        }
        const mips64_vma_t *vma = &state.vmas[i];
        if (vma->end <= prefix)
            continue;
        if ((protection & ~vma->may_permissions) != 0) {
            failure = 13; break;
        }
        changed |= vma->permissions != (unsigned int)protection;
        prefix = vma->end < end ? vma->end : end;
    }
    int result = 0, saved = 0;
    mips64_mm_view_plan_t plan = {0};
    if (!changed)
        goto done;
    if (state.revision == UINT64_MAX) { saved = EOVERFLOW; result = -1; goto done; }
    unsigned int effective = (unsigned int)protection |
        ((protection & MIPS64_MEM_WRITE) != 0 ? MIPS64_MEM_READ : 0u);
    for (size_t i = 0; i < state.page_count; ++i) {
        mips64_family_mm_page_t *page = &state.pages[i];
        if (page->address < address || page->address >= prefix ||
            page->permissions == effective)
            continue;
        if (page->mapping_generation == UINT64_MAX) {
            saved = EOVERFLOW; result = -1; goto done;
        }
        page->permissions = effective;
        ++page->mapping_generation;
    }
    if (protect_vmas(&state, address, prefix, (unsigned int)protection) != 0 ||
        mips64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        mips64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        saved = errno; result = -1; goto done;
    }
    mips64_mm_view_plan_apply(view, &plan);
done:
    mips64_mm_view_plan_discard(&plan);
    mips64_family_mm_state_destroy(&state);
    if (result == 0)
        *guest_result = failure == 0 ? 0 : UINT64_C(0) - failure;
    else
        errno = saved;
    return result;
}

int mips64_mm_view_state_unmap(mips64_family_mm_state_t *state, uint64_t start, uint64_t end)
{
    /* At most one original interval can contain both boundaries. */
    mips64_vma_t *vmas = malloc((state->vma_count + 1u) * sizeof(*vmas));
    if (vmas == NULL)
        return -1;
    size_t count = 0;
    for (size_t i = 0; i < state->vma_count; ++i) {
        mips64_vma_t original = state->vmas[i];
        if (original.end <= start || original.start >= end) {
            append_vma(vmas, &count, original);
            continue;
        }
        if (original.start < start) {
            mips64_vma_t prefix = original;
            prefix.end = start;
            append_vma(vmas, &count, prefix);
        }
        if (original.end > end) {
            mips64_vma_t suffix = original;
            suffix.offset += end - suffix.start;
            suffix.start = end;
            append_vma(vmas, &count, suffix);
        }
    }
    if (count > MIPS64_FAMILY_MM_MAX_RECORDS) {
        free(vmas); errno = ENOMEM; return -1;
    }
    free(state->vmas); state->vmas = vmas; state->vma_count = count;
    size_t pages = 0;
    for (size_t i = 0; i < state->page_count; ++i) {
        if (state->pages[i].address < start || state->pages[i].address >= end)
            state->pages[pages++] = state->pages[i];
    }
    state->page_count = pages;
    return 0;
}

int mips64_mm_view_munmap(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                        uint64_t address, uint64_t length, uint64_t *guest_result)
{
    if (guest_result == NULL) { errno = EINVAL; return -1; }
    if (mips64_mm_view_refresh(view, guard) != 0)
        return -1;
    uint64_t limit = view->space->limit;
    if (address % MIPS64_PAGE_SIZE != 0 || length == 0 ||
        length > UINT64_MAX - (MIPS64_PAGE_SIZE - 1) || address >= limit) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    uint64_t size = (length + MIPS64_PAGE_SIZE - 1) & ~(MIPS64_PAGE_SIZE - 1);
    if (size > limit - address) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    uint64_t end = address + size;
    bool overlap = false;
    for (size_t i = 0; i < view->applied.vma_count; ++i) {
        const mips64_vma_t *vma = &view->applied.vmas[i];
        if (vma->start >= end)
            break;
        if (vma->end > address) { overlap = true; break; }
    }
    if (!overlap) { *guest_result = 0; return 0; }
    if (view->applied.revision == UINT64_MAX) { errno = EOVERFLOW; return -1; }
    mips64_family_mm_state_t state = {0};
    if (mips64_family_mm_read(guard, view->mm, &state) != 0)
        return -1;
    mips64_mm_view_plan_t plan = {0};
    int result = 0, saved = 0;
    if (mips64_mm_view_state_unmap(&state, address, end) != 0 ||
        mips64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        mips64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        result = -1; saved = errno;
    } else {
        mips64_mm_view_plan_apply(view, &plan);
        *guest_result = 0;
    }
    mips64_mm_view_plan_discard(&plan);
    mips64_family_mm_state_destroy(&state);
    if (result != 0)
        errno = saved;
    return result;
}

int mips64_mm_view_state_insert(mips64_mm_view_t *view, mips64_family_mm_state_t *state,
                            mips64_space_t *fresh, mips64_vma_t added)
{
    uint64_t address = added.start, size = added.end - added.start;
    if (mips64_mm_view_state_unmap(state, address, address + size) != 0)
        return -1;
    size_t page_count = state->page_count + fresh->count;
    mips64_vma_t *vmas = malloc((state->vma_count + 1u) * sizeof(*vmas));
    mips64_family_mm_page_t *pages = malloc(page_count * sizeof(*pages));
    if (vmas == NULL || pages == NULL) {
        free(vmas); free(pages); errno = ENOMEM; return -1;
    }
    size_t at = 0;
    while (at < state->vma_count && state->vmas[at].start < address)
        ++at;
    size_t count = 0;
    for (size_t i = 0; i < at; ++i)
        append_vma(vmas, &count, state->vmas[i]);
    append_vma(vmas, &count, added);
    for (size_t i = at; i < state->vma_count; ++i)
        append_vma(vmas, &count, state->vmas[i]);
    if (count > MIPS64_FAMILY_MM_MAX_RECORDS) {
        free(vmas); free(pages); errno = ENOMEM; return -1;
    }
    at = 0;
    while (at < state->page_count && state->pages[at].address < address)
        ++at;
    if (at != 0)
        memcpy(pages, state->pages, at * sizeof(*pages));
    for (size_t i = 0; i < fresh->count; ++i) {
        mips64_family_page_key_t key = {0};
        bool bus = fresh->pages[i].backing->bus_fault;
        if (!bus && !mips64_family_backing_key(view->backing, fresh->pages[i].backing->payload, &key)) {
            free(vmas); free(pages); errno = EIO; return -1;
        }
        pages[at + i] = (mips64_family_mm_page_t){fresh->pages[i].address,
            state->next_mapping_id + i, 1, key, fresh->pages[i].permissions,
            bus ? MIPS64_MM_BUS : MIPS64_MM_DATA};
    }
    if (at != state->page_count)
        memcpy(pages + at + fresh->count, state->pages + at,
                (state->page_count - at) * sizeof(*pages));
    free(state->vmas); free(state->pages);
    state->vmas = vmas; state->vma_count = count;
    state->pages = pages; state->page_count = page_count;
    state->next_mapping_id += fresh->count;
    return 0;
}

static int origin_order(mips64_family_page_key_t a, mips64_family_page_key_t b)
{
    if (a.object_id != b.object_id)
        return (a.object_id > b.object_id) - (a.object_id < b.object_id);
    return (a.page_index > b.page_index) - (a.page_index < b.page_index);
}

 size_t mips64_mm_view_origin_position(const mips64_family_file_index_state_t *index, mips64_family_page_key_t key)
{
    size_t left = 0, right = index->association_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        if (origin_order(index->associations[middle].key, key) < 0) left = middle + 1u;
        else right = middle;
    }
    return left;
}

 size_t mips64_mm_view_source_position(const mips64_family_file_index_state_t *index, uint64_t id)
{
    size_t left = 0, right = index->source_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        if (index->sources[middle].source_id < id) left = middle + 1u;
        else right = middle;
    }
    return left;
}

 bool mips64_mm_view_transaction_key(mips64_mm_view_t *view, const mips64_space_t *fresh,
                               mips64_family_page_key_t key)
{
    for (size_t i = 0; i < fresh->count; ++i) {
        mips64_family_page_key_t candidate;
        if (mips64_family_backing_key(view->backing, fresh->pages[i].backing->payload, &candidate) &&
            mips64_mm_view_same_key(candidate, key))
            return true;
    }
    return false;
}
