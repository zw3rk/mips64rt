/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "space_parts.h"

static void heap_payload_dispose(mips64_page_payload_t *payload)
{
    free(payload); /* payload is the first member of heap_payload_t. */
}

static mips64_page_payload_t *heap_payload_create(void *context)
{
    (void)context;
    heap_payload_t *heap = calloc(1, sizeof(*heap));
    if (heap == NULL)
        return NULL;
    heap->payload = (mips64_page_payload_t){
        .bytes = heap->bytes, .epochs = heap->epochs,
        .references = 1, .dispose = heap_payload_dispose
    };
    return &heap->payload;
}

static bool payload_retain(mips64_page_payload_t *payload)
{
    if (payload->references == SIZE_MAX)
        return false;
    ++payload->references;
    return true;
}

static void payload_release(mips64_page_payload_t *payload)
{
    assert(payload != NULL && payload->references != 0);
    if (--payload->references == 0)
        payload->dispose(payload);
}

static mips64_backing_t *create_backing(mips64_space_t *space, bool file_private,
                                    mips64_fault_reason_t *reason)
{
    mips64_page_factory_t factory = file_private ?
        (mips64_page_factory_t){heap_payload_create, NULL} : space->page_factory;
    mips64_page_payload_t *payload = factory.create(factory.context);
    if (payload == NULL) {
        /* Only the built-in heap factory has a defined NULL=allocation failure
         * contract. A custom factory may have failed after external effects. */
        *reason = factory.create == heap_payload_create ?
                  MIPS64_FAULT_RESOURCE : MIPS64_FAULT_INTERNAL;
        return NULL;
    }
    if (payload->bytes == NULL || payload->epochs == NULL ||
        payload->references != 1 || payload->dispose == NULL) {
        if (payload->dispose != NULL)
            payload->dispose(payload);
        *reason = MIPS64_FAULT_INTERNAL;
        return NULL;
    }
    payload->backend = !file_private && space->managed.commitv != NULL ?
                       MIPS64_PAYLOAD_MANAGED : MIPS64_PAYLOAD_HEAP;
    mips64_backing_t *backing = calloc(1, sizeof(*backing));
    if (backing == NULL) {
        payload_release(payload);
        *reason = MIPS64_FAULT_RESOURCE;
        return NULL;
    }
    backing->bytes = payload->bytes;
    backing->epochs = payload->epochs;
    backing->payload = payload;
    backing->references = 1;
    return backing;
}

static mips64_backing_t *alias_backing(mips64_backing_t *source,
                                    mips64_fault_reason_t *reason)
{
    if (source->bus_fault) {
        mips64_backing_t *fault = calloc(1, sizeof(*fault));
        if (fault == NULL) { *reason = MIPS64_FAULT_RESOURCE; return NULL; }
        fault->bus_fault = true; fault->references = 1;
        return fault;
    }
    if (!payload_retain(source->payload)) {
        *reason = MIPS64_FAULT_INTERNAL;
        return NULL;
    }
    mips64_backing_t *alias = calloc(1, sizeof(*alias));
    if (alias == NULL) {
        payload_release(source->payload);
        *reason = MIPS64_FAULT_RESOURCE;
        return NULL;
    }
    alias->bytes = source->payload->bytes;
    alias->epochs = source->payload->epochs;
    alias->payload = source->payload;
    alias->references = 1;
    return alias;
}

 bool mips64_space_fail(mips64_space_t *space, uint64_t address, mips64_fault_reason_t reason)
{
    space->fault_address = address;
    space->fault_reason = reason;
    if (reason == MIPS64_FAULT_INTERNAL)
        space->internal_failure = true;
    return false;
}

 bool mips64_space_managed_guard(mips64_space_t *space, uint64_t address)
{
    if (space->managed.commitv == NULL)
        return true;
    mips64_measure_stamp_t stamp = mips64_measure_begin(space->measure,
                                                MIPS64_MEASURE_MANAGED_GUARD);
    bool held = space->managed.check_guard(space->managed.context);
    mips64_measure_end(space->measure, MIPS64_MEASURE_MANAGED_GUARD, stamp);
    return held || mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
}

void mips64_space_init_abi(mips64_space_t *space, int is_n32)
{
    if (space == NULL)
        return;
    memset(space, 0, sizeof(*space));
    space->limit = is_n32 != 0 ? MIPS64_N32_TASK_SIZE : MIPS64_N64_TASK_SIZE;
    space->generation = 1;
    space->next_binding = 1;
    space->page_factory = (mips64_page_factory_t){heap_payload_create, NULL};
}

void mips64_space_init(mips64_space_t *space)
{
    mips64_space_init_abi(space, 0);
}

bool mips64_space_set_page_factory(mips64_space_t *space, mips64_page_factory_t factory)
{
    if (space == NULL || space->count != 0 || factory.create == NULL ||
        space->managed.commitv != NULL)
        return false;
    space->page_factory = factory;
    return true;
}

bool mips64_space_set_managed_factory(mips64_space_t *space, mips64_page_factory_t factory,
                                  mips64_managed_page_ops_t managed)
{
    if (space == NULL || space->count != 0 || factory.create == NULL ||
        managed.check_guard == NULL || managed.refresh == NULL ||
        managed.check_write == NULL || managed.commitv == NULL)
        return false;
    space->page_factory = factory;
    space->managed = managed;
    return true;
}

bool mips64_backing_retain(mips64_backing_t *backing)
{
    if (backing == NULL || backing->references == SIZE_MAX)
        return false;
    ++backing->references;
    return true;
}

void mips64_backing_release(mips64_backing_t *backing)
{
    if (backing == NULL)
        return;
    assert(backing->references != 0);
    if (--backing->references != 0)
        return;
    if (backing->file != NULL)
        backing->file->release(backing->file);
    if (!backing->bus_fault)
        payload_release(backing->payload);
    free(backing);
}

void mips64_space_destroy(mips64_space_t *space)
{
    if (space == NULL)
        return;
    for (size_t i = 0; i < space->count; ++i)
        mips64_backing_release(space->pages[i].backing);
    free(space->pages);
    free(space->epoch_scratch);
    memset(space, 0, sizeof(*space));
}

 size_t mips64_space_page_position(const mips64_space_t *space, uint64_t address)
{
    size_t left = 0, right = space->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (space->pages[middle].address < address)
            left = middle + 1;
        else
            right = middle;
    }
    return left;
}

static bool valid_range(mips64_space_t *space, uint64_t address, uint64_t size)
{
    if (size == 0)
        return true;
    if (address < MIPS64_PAGE_SIZE || address >= space->limit)
        return mips64_space_fail(space, address, MIPS64_FAULT_RANGE);
    if (size > space->limit - address)
        return mips64_space_fail(space, space->limit, MIPS64_FAULT_RANGE);
    return true;
}

static bool mapping_range(mips64_space_t *space, uint64_t address, uint64_t size,
                           unsigned int permissions)
{
    space->fault_reason = MIPS64_FAULT_NONE;
    if (size == 0 || address % MIPS64_PAGE_SIZE != 0 || size % MIPS64_PAGE_SIZE != 0 ||
        (permissions & ~(unsigned int)7) != 0)
        return mips64_space_fail(space, address, MIPS64_FAULT_RANGE);
    if (!valid_range(space, address, size))
        return false;
    return true;
}

static bool map_pages(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, enum map_mode mode,
                      mips64_file_source_t *source, uint64_t file_offset, bool bus_fault)
{
    if (space == NULL || !mapping_range(space, address, size, permissions))
        return false;
    if (!mips64_space_managed_guard(space, address))
        return false;
    if (source != NULL && (source->space != space || source->retain == NULL ||
                          source->release == NULL || source->refresh == NULL ||
                          file_offset % MIPS64_PAGE_SIZE != 0 || size > UINT64_MAX - file_offset))
        return mips64_space_fail(space, address, MIPS64_FAULT_RANGE);
    uint64_t page_count = size / MIPS64_PAGE_SIZE;
    if (page_count > MIPS64_R1_MAX_PAGES)
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    size_t first = mips64_space_page_position(space, address);
    size_t last = mips64_space_page_position(space, address + size);
    if (mode == MAP_EXCLUSIVE && first != last)
        return mips64_space_fail(space, space->pages[first].address, MIPS64_FAULT_RANGE);
    size_t count = space->count - (last - first) + (size_t)page_count;
    if (count > MIPS64_R1_MAX_PAGES)
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    if (page_count > (UINT64_MAX - space->next_binding) / MIPS64_PAGE_GRANULES)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    if (space->generation == UINT64_MAX)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    /* Prepare a complete replacement registry without modifying live objects.
     * Track only new allocations so failed merges never free reused backing. */
    mips64_page_t *pages = malloc(count * sizeof(*pages));
    mips64_backing_t **created = malloc((size_t)page_count * sizeof(*created));
    if (pages == NULL || created == NULL) {
        free(pages);
        free(created);
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    }
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    size_t old = first, allocated = 0;
    uint64_t binding = space->next_binding;
    for (size_t i = 0; i < (size_t)page_count; ++i) {
        uint64_t at = address + (uint64_t)i * MIPS64_PAGE_SIZE;
        bool present = old < last && space->pages[old].address == at;
        mips64_backing_t *backing;
        unsigned int access = permissions;
        if (mode == MAP_MERGE && present) {
            backing = space->pages[old].backing;
            access |= space->pages[old].permissions;
        } else {
            mips64_fault_reason_t reason = MIPS64_FAULT_INTERNAL;
            if (bus_fault) {
                backing = calloc(1, sizeof(*backing));
                if (backing != NULL) {
                    backing->bus_fault = true; backing->references = 1;
                } else {
                    reason = MIPS64_FAULT_RESOURCE;
                }
            } else {
                backing = create_backing(space, source != NULL, &reason);
            }
            if (backing == NULL) {
                for (size_t j = 0; j < allocated; ++j)
                    mips64_backing_release(created[j]);
                free(created);
                free(pages);
                return mips64_space_fail(space, at, reason);
            }
            if (source != NULL) {
                source->retain(source);
                backing->file = source;
                backing->file_offset = file_offset + (uint64_t)i * MIPS64_PAGE_SIZE;
            }
            created[allocated++] = backing;
        }
        pages[first + i] = (mips64_page_t){at, access, backing, binding};
        binding += MIPS64_PAGE_GRANULES;
        if (present)
            ++old;
    }
    if (last != space->count)
        memcpy(pages + first + (size_t)page_count, space->pages + last,
                (space->count - last) * sizeof(*pages));
    /* Invalidate before replacing bytes/ownership. No guest instruction or
     * blocking operation can observe the middle of this single-thread commit. */
    ++space->generation;
    if (source != NULL)
        space->has_file_pages = true;
    if (mode == MAP_REPLACE)
        for (size_t i = first; i < last; ++i)
            mips64_backing_release(space->pages[i].backing);
    free(space->pages);
    free(created);
    space->pages = pages;
    space->count = count;
    space->capacity = count;
    space->next_binding = binding;
    return true;
}

bool mips64_space_map(mips64_space_t *space, uint64_t address, uint64_t size,
                  unsigned int permissions, bool merge)
{
    return map_pages(space, address, size, permissions,
                     merge ? MAP_MERGE : MAP_EXCLUSIVE, NULL, 0, false);
}

bool mips64_space_map_bus(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, bool replace)
{
    return map_pages(space, address, size, permissions,
                     replace ? MAP_REPLACE : MAP_EXCLUSIVE, NULL, 0, true);
}

bool mips64_space_replace(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions)
{
    return map_pages(space, address, size, permissions, MAP_REPLACE, NULL, 0, false);
}

bool mips64_space_map_file(mips64_space_t *space, uint64_t address, uint64_t size,
                       unsigned int permissions, bool replace,
                       mips64_file_source_t *source, uint64_t file_offset)
{
    if (source == NULL)
        return false;
    return map_pages(space, address, size, permissions,
                     replace ? MAP_REPLACE : MAP_EXCLUSIVE, source, file_offset, false);
}

static bool map_managed_payload(mips64_space_t *space, uint64_t address,
                                 unsigned int permissions,
                                 mips64_page_payload_t *payload,
                                 mips64_file_source_t *source, uint64_t offset,
                                 bool staging)
{
    if (space == NULL || !mapping_range(space, address, MIPS64_PAGE_SIZE, permissions))
        return false;
    if (!mips64_space_managed_guard(space, address))
        return false;
    if (space->managed.commitv == NULL || payload == NULL ||
        payload->backend != MIPS64_PAYLOAD_MANAGED || payload->bytes == NULL ||
        payload->epochs == NULL || payload->dispose == NULL)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    if (source != NULL && (source->space == NULL ||
        (source->space != space && (!staging ||
         source->space->managed.context != space->managed.context ||
         source->space->limit != space->limit)) || source->retain == NULL ||
        source->release == NULL || source->refresh == NULL ||
        offset % MIPS64_PAGE_SIZE != 0 || offset > UINT64_MAX - MIPS64_PAGE_SIZE))
        return mips64_space_fail(space, address, MIPS64_FAULT_RANGE);
    size_t first = mips64_space_page_position(space, address);
    if (first < space->count && space->pages[first].address == address)
        return mips64_space_fail(space, address, MIPS64_FAULT_RANGE);
    if (space->count == MIPS64_R1_MAX_PAGES)
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    if (space->generation == UINT64_MAX ||
        space->next_binding > UINT64_MAX - MIPS64_PAGE_GRANULES ||
        payload->references == SIZE_MAX)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    mips64_page_t *pages = malloc((space->count + 1) * sizeof(*pages));
    mips64_backing_t *view = calloc(1, sizeof(*view));
    if (pages == NULL || view == NULL) {
        free(pages);
        free(view);
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    }
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    if (first != space->count)
        memcpy(pages + first + 1, space->pages + first,
               (space->count - first) * sizeof(*pages));
    ++payload->references;
    *view = (mips64_backing_t){.bytes = payload->bytes, .epochs = payload->epochs,
                           .payload = payload, .references = 1,
                           .file = source, .file_offset = offset};
    if (source != NULL)
        source->retain(source);
    pages[first] = (mips64_page_t){address, permissions, view, space->next_binding};
    ++space->generation;
    space->next_binding += MIPS64_PAGE_GRANULES;
    ++space->count;
    space->capacity = space->count;
    free(space->pages);
    space->pages = pages;
    if (source != NULL)
        space->has_file_pages = true;
    return true;
}

bool mips64_space_map_shared_payload(mips64_space_t *space, uint64_t address,
                                 unsigned int permissions, mips64_page_payload_t *payload)
{
    return map_managed_payload(space, address, permissions, payload, NULL, 0, false);
}

bool mips64_space_map_managed_file_payload(mips64_space_t *space, uint64_t address,
                                        unsigned int permissions,
                                        mips64_page_payload_t *payload,
                                        mips64_file_source_t *source, uint64_t offset)
{
    if (source == NULL)
        return false;
    return map_managed_payload(space, address, permissions, payload, source, offset, false);
}

bool mips64_space_stage_managed_file_payload(mips64_space_t *space, uint64_t address,
                                          unsigned int permissions,
                                          mips64_page_payload_t *payload,
                                          mips64_file_source_t *source, uint64_t offset)
{
    if (source == NULL)
        return false;
    return map_managed_payload(space, address, permissions, payload, source, offset, true);
}

bool mips64_space_alias(mips64_space_t *space, uint64_t source, uint64_t destination,
                    uint64_t size, unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, source, size, permissions) ||
        !mapping_range(space, destination, size, permissions))
        return false;
    if (!mips64_space_managed_guard(space, source))
        return false;
    uint64_t page_count = size / MIPS64_PAGE_SIZE;
    if (page_count > MIPS64_R1_MAX_PAGES)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    size_t count = (size_t)page_count;
    size_t source_first = mips64_space_page_position(space, source);
    for (size_t i = 0; i < count; ++i) {
        uint64_t at = source + (uint64_t)i * MIPS64_PAGE_SIZE;
        if (source_first + i >= space->count ||
            space->pages[source_first + i].address != at)
            return mips64_space_fail(space, at, MIPS64_FAULT_UNMAPPED);
        if (space->pages[source_first + i].backing->file != NULL)
            return mips64_space_fail(space, at, MIPS64_FAULT_RANGE);
    }
    size_t first = mips64_space_page_position(space, destination);
    size_t last = mips64_space_page_position(space, destination + size);
    if (first != last)
        return mips64_space_fail(space, space->pages[first].address, MIPS64_FAULT_RANGE);
    if (count > MIPS64_R1_MAX_PAGES - space->count)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    if (count > (UINT64_MAX - space->next_binding) / MIPS64_PAGE_GRANULES ||
        space->generation == UINT64_MAX)
        return mips64_space_fail(space, destination, MIPS64_FAULT_INTERNAL);
    mips64_page_t *pages = malloc((space->count + count) * sizeof(*pages));
    if (pages == NULL)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    if (first != space->count)
        memcpy(pages + first + count, space->pages + first,
               (space->count - first) * sizeof(*pages));
    uint64_t binding = space->next_binding;
    for (size_t i = 0; i < count; ++i) {
        mips64_fault_reason_t reason = MIPS64_FAULT_INTERNAL;
        mips64_backing_t *backing = alias_backing(
            space->pages[source_first + i].backing, &reason);
        if (backing == NULL) {
            for (size_t j = 0; j < i; ++j)
                mips64_backing_release(pages[first + j].backing);
            free(pages);
            return mips64_space_fail(space, destination + (uint64_t)i * MIPS64_PAGE_SIZE,
                        reason);
        }
        pages[first + i] = (mips64_page_t){destination + (uint64_t)i * MIPS64_PAGE_SIZE,
                                      permissions, backing, binding};
        binding += MIPS64_PAGE_GRANULES;
    }
    ++space->generation;
    free(space->pages);
    space->pages = pages;
    space->count += count;
    space->capacity = space->count;
    space->next_binding = binding;
    return true;
}

bool mips64_space_unmap(mips64_space_t *space, uint64_t address, uint64_t size)
{
    if (space == NULL || !mapping_range(space, address, size, 0))
        return false;
    if (!mips64_space_managed_guard(space, address))
        return false;
    size_t first = mips64_space_page_position(space, address);
    size_t last = mips64_space_page_position(space, address + size);
    if (first == last)
        return true;
    if (space->generation == UINT64_MAX)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    ++space->generation;
    for (size_t i = first; i < last; ++i)
        mips64_backing_release(space->pages[i].backing);
    memmove(space->pages + first, space->pages + last,
            (space->count - last) * sizeof(*space->pages));
    space->count -= last - first;
    return true;
}

bool mips64_space_protect(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, address, size, permissions))
        return false;
    if (!mips64_space_managed_guard(space, address))
        return false;
    uint64_t page_count = size / MIPS64_PAGE_SIZE;
    size_t first = mips64_space_page_position(space, address);
    size_t last = mips64_space_page_position(space, address + size);
    if ((uint64_t)(last - first) != page_count)
        return mips64_space_fail(space, address, MIPS64_FAULT_UNMAPPED);
    if (space->generation == UINT64_MAX ||
        page_count > (UINT64_MAX - space->next_binding) / MIPS64_PAGE_GRANULES)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    ++space->generation;
    for (size_t i = first; i < last; ++i) {
        space->pages[i].permissions = permissions;
        space->pages[i].binding_base = space->next_binding;
        space->next_binding += MIPS64_PAGE_GRANULES;
    }
    return true;
}

bool mips64_space_find_hole(const mips64_space_t *space, uint64_t start, uint64_t size,
                        uint64_t *address)
{
    if (space == NULL || address == NULL || size == 0 ||
        size % MIPS64_PAGE_SIZE != 0 || start < MIPS64_PAGE_SIZE ||
        start > UINT64_MAX - (MIPS64_PAGE_SIZE - 1))
        return false;
    uint64_t candidate = (start + MIPS64_PAGE_SIZE - 1) & ~(MIPS64_PAGE_SIZE - 1);
    size_t first = mips64_space_page_position(space, candidate);
    for (size_t i = first; i < space->count; ++i) {
        if (candidate >= space->limit || size > space->limit - candidate)
            return false;
        if (space->pages[i].address - candidate >= size) {
            *address = candidate;
            return true;
        }
        candidate = space->pages[i].address + MIPS64_PAGE_SIZE;
    }
    if (candidate >= space->limit || size > space->limit - candidate)
        return false;
    *address = candidate;
    return true;
}

static int compare_pages(const void *left, const void *right)
{
    const mips64_page_t *a = left, *b = right;
    return a->address < b->address ? -1 : a->address != b->address;
}

bool mips64_space_remap(mips64_space_t *space, uint64_t source, uint64_t old_size,
                    uint64_t destination, uint64_t new_size,
                    unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, source, old_size, permissions) ||
        !mapping_range(space, destination, new_size, permissions))
        return false;
    if (!mips64_space_managed_guard(space, source))
        return false;
    uint64_t old_end = source + old_size, new_end = destination + new_size;
    if (source != destination && source < new_end && destination < old_end)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RANGE);
    size_t first = mips64_space_page_position(space, source), last = mips64_space_page_position(space, old_end);
    if ((uint64_t)(last - first) != old_size / MIPS64_PAGE_SIZE)
        return mips64_space_fail(space, source, MIPS64_FAULT_UNMAPPED);
    mips64_backing_t *original = space->pages[first].backing;
    if (original->file != NULL && new_size > UINT64_MAX - original->file_offset)
        return mips64_space_fail(space, source, MIPS64_FAULT_RANGE);
    uint64_t new_count = new_size / MIPS64_PAGE_SIZE;
    if (new_count > MIPS64_R1_MAX_PAGES)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    if (space->generation == UINT64_MAX ||
        new_count > (UINT64_MAX - space->next_binding) / MIPS64_PAGE_GRANULES)
        return mips64_space_fail(space, destination, MIPS64_FAULT_INTERNAL);
    size_t retained = 0;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        if (!(at >= source && at < old_end) && !(at >= destination && at < new_end))
            ++retained;
    }
    if (new_count > MIPS64_R1_MAX_PAGES - retained)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    size_t count = retained + (size_t)new_count;
    mips64_page_t *pages = malloc(count * sizeof(*pages));
    if (pages == NULL)
        return mips64_space_fail(space, destination, MIPS64_FAULT_RESOURCE);
    size_t at_new = 0;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        if (!(at >= source && at < old_end) && !(at >= destination && at < new_end))
            pages[at_new++] = space->pages[i];
    }
    size_t reused = last - first;
    if (reused > (size_t)new_count)
        reused = (size_t)new_count;
    uint64_t binding = space->next_binding;
    size_t created = 0;
    for (size_t i = 0; i < (size_t)new_count; ++i) {
        mips64_fault_reason_t reason = MIPS64_FAULT_INTERNAL;
        mips64_backing_t *backing = i < reused ? space->pages[first + i].backing :
                                          create_backing(space, original->file != NULL,
                                                         &reason);
        if (backing == NULL) {
            for (size_t j = 0; j < created; ++j)
                mips64_backing_release(pages[retained + reused + j].backing);
            free(pages);
            return mips64_space_fail(space, destination, reason);
        }
        if (i >= reused) {
            if (original->file != NULL) {
                original->file->retain(original->file);
                backing->file = original->file;
                backing->file_offset = original->file_offset + (uint64_t)i * MIPS64_PAGE_SIZE;
            }
            ++created;
        }
        pages[at_new++] = (mips64_page_t){destination + (uint64_t)i * MIPS64_PAGE_SIZE,
                                    permissions, backing, binding};
        binding += MIPS64_PAGE_GRANULES;
    }
    qsort(pages, count, sizeof(*pages), compare_pages);
    ++space->generation;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        bool moved = i >= first && i - first < reused;
        if (!moved && ((at >= source && at < old_end) ||
                       (at >= destination && at < new_end)))
            mips64_backing_release(space->pages[i].backing);
    }
    free(space->pages);
    space->pages = pages;
    space->count = count;
    space->capacity = count;
    space->next_binding = binding;
    return true;
}

 bool mips64_space_validate_access(mips64_space_t *space, uint64_t address, size_t size,
                            unsigned int permissions)
{
    space->fault_reason = MIPS64_FAULT_NONE;
    if (!valid_range(space, address, (uint64_t)size))
        return false;
    uint64_t start = address;
    size_t remaining = size;
    while (remaining != 0) {
        uint64_t base = address & ~(MIPS64_PAGE_SIZE - 1);
        size_t position = mips64_space_page_position(space, base);
        if (position == space->count || space->pages[position].address != base)
            return mips64_space_fail(space, address, MIPS64_FAULT_UNMAPPED);
        if ((space->pages[position].permissions & permissions) != permissions)
            return mips64_space_fail(space, address, MIPS64_FAULT_PERMISSION);
        size_t amount = (size_t)(MIPS64_PAGE_SIZE - (address - base));
        if (amount > remaining)
            amount = remaining;
        address += amount;
        remaining -= amount;
    }
    /* Permission/range checks finish before filesystem reads. Refresh also
     * precedes LR/SC's direct backing access and reservation-token sampling. */
    if (size != 0 && !mips64_space_managed_guard(space, start))
        return false;
    address = start;
    remaining = size;
    while (remaining != 0) {
        uint64_t base = address & ~(MIPS64_PAGE_SIZE - 1);
        mips64_backing_t *backing = space->pages[mips64_space_page_position(space, base)].backing;
        if (backing->bus_fault)
            return mips64_space_fail(space, address, MIPS64_FAULT_BUS);
        if (backing->payload->backend != MIPS64_PAYLOAD_HEAP &&
            backing->payload->backend != MIPS64_PAYLOAD_MANAGED)
            return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
        if (backing->payload->backend == MIPS64_PAYLOAD_MANAGED) {
            if (space->managed.commitv == NULL)
                return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
            bool changed = false;
            mips64_measure_stamp_t refresh_stamp = mips64_measure_begin(space->measure,
                                                                 MIPS64_MEASURE_FILE_REFRESH);
            bool refreshed = space->managed.refresh(space->managed.context,
                                                     backing->payload,
                                                     space->generation != UINT64_MAX,
                                                     &changed, space->measure);
            mips64_measure_end(space->measure, MIPS64_MEASURE_FILE_REFRESH, refresh_stamp);
            if (!refreshed)
                return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
            if (changed)
                ++space->generation;
        }
        if (backing->file != NULL && !backing->file->refresh(backing->file, backing, address)) {
            switch (space->fault_reason) {
            case MIPS64_FAULT_RANGE:
            case MIPS64_FAULT_UNMAPPED:
            case MIPS64_FAULT_PERMISSION:
            case MIPS64_FAULT_BUS:
            case MIPS64_FAULT_RESOURCE:
                break;
            case MIPS64_FAULT_INTERNAL:
                space->internal_failure = true;
                break;
            case MIPS64_FAULT_NONE:
            default:
                return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
            }
            return false;
        }
        size_t amount = (size_t)(MIPS64_PAGE_SIZE - (address - base));
        if (amount > remaining)
            amount = remaining;
        address += amount;
        remaining -= amount;
    }
    return true;
}

bool mips64_space_read(mips64_space_t *space, uint64_t address, void *bytes,
                   size_t size, unsigned int permissions)
{
    if (space == NULL)
        return false;
    if (bytes == NULL && size != 0)
        return mips64_space_fail(space, address, MIPS64_FAULT_INTERNAL);
    if (!mips64_space_validate_access(space, address, size, permissions))
        return false;
    unsigned char *out = bytes;
    while (size != 0) {
        uint64_t base = address & ~(MIPS64_PAGE_SIZE - 1);
        size_t position = mips64_space_page_position(space, base);
        size_t offset = (size_t)(address - base);
        size_t amount = (size_t)MIPS64_PAGE_SIZE - offset;
        if (amount > size)
            amount = size;
        memcpy(out, space->pages[position].backing->bytes + offset, amount);
        address += amount;
        out += amount;
        size -= amount;
    }
    return true;
}

 bool mips64_space_first_managed_file_write(const mips64_backing_t *view)
{
    return view->file != NULL && view->payload->backend == MIPS64_PAYLOAD_MANAGED &&
        view->payload->canonical_private_cow != NULL &&
        *view->payload->canonical_private_cow == 0;
}

 int mips64_space_compare_epoch_touches(const void *left, const void *right)
{
    const epoch_touch_t *a = left, *b = right;
    uintptr_t a_key = (uintptr_t)a->payload, b_key = (uintptr_t)b->payload;
    if (a_key != b_key)
        return a_key < b_key ? -1 : 1;
    return a->address < b->address ? -1 : a->address != b->address;
}

/* Aliased VAs may touch one physical granule more than once in one write.
 * Count every hit before committing any epoch/byte mutation. In a managed
 * space the retained, payload-sorted touches also reserve the batch plan
 * before a caller can consume native input. */
 bool mips64_space_shared_epoch_capacity(mips64_space_t *space, uint64_t address, size_t size)
{
    uint64_t last = address + (uint64_t)size - 1;
    size_t page_count = (size_t)(last / MIPS64_PAGE_SIZE - address / MIPS64_PAGE_SIZE + 1);
    bool new_scratch = page_count > space->epoch_scratch_capacity;
    epoch_touch_t *touches = new_scratch ? malloc(page_count * sizeof(*touches)) :
                                           space->epoch_scratch;
    if (touches == NULL)
        return mips64_space_fail(space, address, MIPS64_FAULT_RESOURCE);
    uint64_t cursor = address;
    size_t remaining = size, used = 0;
    while (remaining != 0) {
        uint64_t base = cursor & ~(MIPS64_PAGE_SIZE - 1);
        mips64_backing_t *backing = space->pages[mips64_space_page_position(space, base)].backing;
        size_t offset = (size_t)(cursor - base);
        size_t amount = (size_t)MIPS64_PAGE_SIZE - offset;
        if (amount > remaining)
            amount = remaining;
        touches[used++] = (epoch_touch_t){
            .payload = backing->payload, .view = backing, .address = cursor,
            .first = offset / MIPS64_RESERVATION_GRANULE,
            .last = (offset + amount - 1) / MIPS64_RESERVATION_GRANULE,
            .amount = amount
        };
        remaining -= amount;
        cursor += amount;
    }
    qsort(touches, used, sizeof(*touches), mips64_space_compare_epoch_touches);
    size_t first = 0;
    while (first < used) {
        mips64_page_payload_t *payload = touches[first].payload;
        uint32_t counts[MIPS64_PAGE_GRANULES] = {0};
        size_t end = first;
        bool cow = false;
        while (end < used && touches[end].payload == payload) {
            cow = cow || mips64_space_first_managed_file_write(touches[end].view);
            ++end;
        }
        if (cow)
            for (size_t i = 0; i < MIPS64_PAGE_GRANULES; ++i) {
                counts[i] = 1;
                if (payload->epochs[i] == UINT64_MAX) {
                    uint64_t fault = touches[first].address;
                    if (new_scratch)
                        free(touches);
                    return mips64_space_fail(space, fault, MIPS64_FAULT_INTERNAL);
                }
            }
        end = first;
        while (end < used && touches[end].payload == payload) {
            for (size_t granule = touches[end].first;
                 granule <= touches[end].last; ++granule) {
                ++counts[granule];
                if (payload->epochs[granule] > UINT64_MAX - counts[granule]) {
                    uint64_t fault = touches[end].address;
                    if (new_scratch)
                        free(touches);
                    return mips64_space_fail(space, fault, MIPS64_FAULT_INTERNAL);
                }
            }
            ++end;
        }
        first = end;
    }
    if (new_scratch) {
        free(space->epoch_scratch);
        space->epoch_scratch = touches;
        space->epoch_scratch_capacity = page_count;
    }
    return true;
}
