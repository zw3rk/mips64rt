/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_SPACE_PARTS_H
#define MIPS64RT_SPACE_PARTS_H

#include "memory/space.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mips64_page_payload_t payload;
    unsigned char bytes[MIPS64_PAGE_SIZE];
    uint64_t epochs[MIPS64_PAGE_GRANULES];
} heap_payload_t;

enum map_mode { MAP_EXCLUSIVE, MAP_MERGE, MAP_REPLACE };

typedef struct {
    mips64_page_payload_t *payload;
    mips64_backing_t *view;
    uint64_t address;
    size_t first, last;
    size_t amount;
} epoch_touch_t;

typedef struct {
    uint64_t address, binding_base;
    unsigned int permissions;
    mips64_backing_t *backing;
} copyout_page_t;

struct mips64_copyout {
    mips64_space_t *space;
    uint64_t address, generation;
    size_t maximum, count;
    epoch_touch_t *touches;
    bool consumed;
    copyout_page_t pages[];
};

struct mips64_io_copyout {
    mips64_copyout_t *pinned;
    bool consumed;
    epoch_touch_t touches[];
};
/* Cross-part prototypes (Phase 0 mechanical split). */

 void heap_payload_dispose(mips64_page_payload_t *payload);

 mips64_page_payload_t *heap_payload_create(void *context);

 bool payload_retain(mips64_page_payload_t *payload);

 void payload_release(mips64_page_payload_t *payload);

 mips64_backing_t *create_backing(mips64_space_t *space, bool file_private,
                                    mips64_fault_reason_t *reason);

 mips64_backing_t *alias_backing(mips64_backing_t *source,
                                    mips64_fault_reason_t *reason);

 bool mips64_space_fail(mips64_space_t *space, uint64_t address, mips64_fault_reason_t reason);

 bool mips64_space_managed_guard(mips64_space_t *space, uint64_t address);

void mips64_space_init(mips64_space_t *space);
void mips64_space_init_abi(mips64_space_t *space, int is_n32);

bool mips64_space_set_page_factory(mips64_space_t *space, mips64_page_factory_t factory);

bool mips64_space_set_managed_factory(mips64_space_t *space, mips64_page_factory_t factory,
                                  mips64_managed_page_ops_t managed);

bool mips64_backing_retain(mips64_backing_t *backing);

void mips64_backing_release(mips64_backing_t *backing);

void mips64_space_destroy(mips64_space_t *space);

 size_t mips64_space_page_position(const mips64_space_t *space, uint64_t address);

 bool valid_range(mips64_space_t *space, uint64_t address, uint64_t size);

 bool mapping_range(mips64_space_t *space, uint64_t address, uint64_t size,
                           unsigned int permissions);

 bool map_pages(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, enum map_mode mode,
                      mips64_file_source_t *source, uint64_t file_offset, bool bus_fault);

bool mips64_space_map(mips64_space_t *space, uint64_t address, uint64_t size,
                  unsigned int permissions, bool merge);

bool mips64_space_map_bus(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, bool replace);

bool mips64_space_replace(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);

bool mips64_space_map_file(mips64_space_t *space, uint64_t address, uint64_t size,
                       unsigned int permissions, bool replace,
                       mips64_file_source_t *source, uint64_t file_offset);

 bool map_managed_payload(mips64_space_t *space, uint64_t address,
                                 unsigned int permissions,
                                 mips64_page_payload_t *payload,
                                 mips64_file_source_t *source, uint64_t offset,
                                 bool staging);

bool mips64_space_map_shared_payload(mips64_space_t *space, uint64_t address,
                                 unsigned int permissions, mips64_page_payload_t *payload);

bool mips64_space_map_managed_file_payload(mips64_space_t *space, uint64_t address,
                                        unsigned int permissions,
                                        mips64_page_payload_t *payload,
                                        mips64_file_source_t *source, uint64_t offset);

bool mips64_space_stage_managed_file_payload(mips64_space_t *space, uint64_t address,
                                          unsigned int permissions,
                                          mips64_page_payload_t *payload,
                                          mips64_file_source_t *source, uint64_t offset);

bool mips64_space_alias(mips64_space_t *space, uint64_t source, uint64_t destination,
                    uint64_t size, unsigned int permissions);

bool mips64_space_unmap(mips64_space_t *space, uint64_t address, uint64_t size);

bool mips64_space_protect(mips64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);

bool mips64_space_find_hole(const mips64_space_t *space, uint64_t start, uint64_t size,
                        uint64_t *address);

 int compare_pages(const void *left, const void *right);

bool mips64_space_remap(mips64_space_t *space, uint64_t source, uint64_t old_size,
                    uint64_t destination, uint64_t new_size,
                    unsigned int permissions);

 bool mips64_space_validate_access(mips64_space_t *space, uint64_t address, size_t size,
                            unsigned int permissions);

bool mips64_space_read(mips64_space_t *space, uint64_t address, void *bytes,
                   size_t size, unsigned int permissions);

 bool mips64_space_first_managed_file_write(const mips64_backing_t *view);

 int mips64_space_compare_epoch_touches(const void *left, const void *right);

/* Aliased VAs may touch one physical granule more than once in one write.
 * Count every hit before committing any epoch/byte mutation. In a managed
 * space the retained, payload-sorted touches also reserve the batch plan
 * before a caller can consume native input. */
 bool mips64_space_shared_epoch_capacity(mips64_space_t *space, uint64_t address, size_t size);

 bool prepare_write(mips64_space_t *space, uint64_t address,
                           size_t size, unsigned int permissions);

bool mips64_space_prepare_write(mips64_space_t *space, uint64_t address, size_t size);

bool mips64_space_cow_file_page(mips64_space_t *space, uint64_t address);

mips64_copyout_t *mips64_space_copyout_prepare(mips64_space_t *space, uint64_t address,
                                       size_t maximum);

void mips64_space_copyout_discard(mips64_copyout_t *copyout);

mips64_io_copyout_t *mips64_space_io_copyout_prepare(mips64_space_t *space, uint64_t address,
                                            size_t maximum);

void mips64_space_io_copyout_discard(mips64_io_copyout_t *copyout);

/* The sorted plan is immutable while unlocked. Recheck counter capacity from
 * the refreshed, current payloads without touching shared scratch or allocating.
 * Multiple aliases of one granule consume one epoch for each VA hit. */
 bool io_copyout_capacity(mips64_io_copyout_t *copyout, size_t prefix);

/* The preparation scratch is sorted by payload, then guest VA. Thus every
 * alias contributes in guest-address order and each managed payload is
 * committed once. Normal I/O uses the installed backend: input may already
 * have been consumed, so it cannot allocate, refresh or discover new capacity
 * failure here. Only the four-byte transaction supplies an explicit callback,
 * which may mips64_space_fail before committing its external state. */
 bool write_managed_bytes(mips64_space_t *space, uint64_t address,
                                const unsigned char *bytes, size_t size,
                                const epoch_touch_t *touches, size_t count,
                                bool *published, mips64_space_word_commit_fn commit,
                                void *context, bool *commit_called);

 bool write_prepared_bytes(mips64_space_t *space, uint64_t address,
                                  const void *bytes, size_t size,
                                  const epoch_touch_t *touches,
                                  size_t touch_count,
                                  mips64_space_word_commit_fn commit, void *context);

bool mips64_space_io_copyout_commit(mips64_io_copyout_t *copyout, const void *bytes,
                                 size_t actual, size_t *committed);

bool mips64_space_copyout_commit(mips64_copyout_t *copyout, const void *bytes,
                              size_t actual);

 bool write_bytes(mips64_space_t *space, uint64_t address, const void *bytes,
                         size_t size, unsigned int permissions);

bool mips64_space_write_word_commit(mips64_space_t *space, uint64_t address,
                                const unsigned char bytes[4],
                                mips64_space_word_commit_fn commit, void *context);

bool mips64_space_write(mips64_space_t *space, uint64_t address, const void *bytes,
                    size_t size);

bool mips64_space_write_initial(mips64_space_t *space, uint64_t address,
                            const void *bytes, size_t size);

bool mips64_space_atomic(mips64_space_t *space, const mips64_atomic_request_t *request,
                      mips64_atomic_result_t *result);
#endif /* MIPS64RT_SPACE_PARTS_H */
