/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_MM_VIEW_PARTS_H
#define MIPS64RT_MM_VIEW_PARTS_H
/* Cross-part prototypes (Phase 0 mechanical split). */

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
                       mips64_linux_memory_t *memory);

int mips64_mm_view_bind_family_sources(mips64_mm_view_t *view,
                                    mips64_family_guard_t *guard,
                                    mips64_file_identity_policy_t policy);

 mips64_file_source_t *cached_file(const mips64_mm_file_cache_entry_t *entries,
                                      size_t count, uint64_t id);

 const mips64_family_mm_file_assoc_t *file_association(
    const mips64_family_mm_state_t *state, mips64_family_page_key_t key);

 bool mips64_mm_view_same_key(mips64_family_page_key_t a, mips64_family_page_key_t b);

 bool local_matches(const mips64_mm_view_t *view);

int mips64_mm_view_adopt(mips64_mm_view_t **out, mips64_family_mm_t mm,
                       mips64_family_backing_t *backing, mips64_family_guard_t *guard,
                       mips64_space_t *space, mips64_linux_memory_t *memory);

int mips64_mm_view_seed(mips64_mm_view_t **out, mips64_family_backing_t *backing,
                      mips64_family_guard_t *guard, mips64_space_t *space,
                      mips64_linux_memory_t *memory, uint64_t initial_task_id);

mips64_family_mm_t mips64_mm_view_identity(const mips64_mm_view_t *view);

bool mips64_mm_view_has_member(const mips64_mm_view_t *view,
                           const mips64_family_guard_t *guard, uint64_t task_id);

 int mips64_mm_view_space_error(const mips64_space_t *space);

void mips64_mm_view_plan_discard(mips64_mm_view_plan_t *plan);

/* Stage every previously unseen source before publishing even a metadata-only
 * association. Source IDs are trusted only after an exact capability fetch. */
 int stage_file_sources(mips64_mm_view_t *view,
                                const mips64_family_mm_state_t *fresh,
                                mips64_mm_view_plan_t *plan);

 bool same_layout(const mips64_family_mm_state_t *a, const mips64_family_mm_state_t *b);

/* Borrow state through failure; consume it only on successful preparation.
 * The caller holds one uninterrupted guard through prepare/publication/apply. */
int mips64_mm_view_plan_prepare(mips64_mm_view_t *view, mips64_family_mm_state_t *state,
                          mips64_mm_view_plan_t *plan);

void mips64_mm_view_plan_apply(mips64_mm_view_t *view, mips64_mm_view_plan_t *plan);

int mips64_mm_view_refresh(mips64_mm_view_t *view, mips64_family_guard_t *guard);

 bool mergeable(const mips64_vma_t *a, const mips64_vma_t *b);

 void append_vma(mips64_vma_t *vmas, size_t *count, mips64_vma_t vma);

/* Only the two interval boundaries can add records. The input catalog already
 * bounds all offset arithmetic. Preserve requested versus effective permissions. */
 int protect_vmas(mips64_family_mm_state_t *state, uint64_t start, uint64_t end,
                          unsigned int permissions);

int mips64_mm_view_mprotect(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                          uint64_t address, uint64_t length, uint64_t protection,
                          uint64_t *guest_result);

int mips64_mm_view_state_unmap(mips64_family_mm_state_t *state, uint64_t start, uint64_t end);

int mips64_mm_view_munmap(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                        uint64_t address, uint64_t length, uint64_t *guest_result);

int mips64_mm_view_state_insert(mips64_mm_view_t *view, mips64_family_mm_state_t *state,
                            mips64_space_t *fresh, mips64_vma_t added);

 int origin_order(mips64_family_page_key_t a, mips64_family_page_key_t b);

 size_t mips64_mm_view_origin_position(const mips64_family_file_index_state_t *index, mips64_family_page_key_t key);

 size_t mips64_mm_view_source_position(const mips64_family_file_index_state_t *index, uint64_t id);

 bool mips64_mm_view_transaction_key(mips64_mm_view_t *view, const mips64_space_t *fresh,
                               mips64_family_page_key_t key);

/* Only this fresh-file mapping transaction may admit origins. Refresh and
 * generic plan preparation must reject missing authority, never create it. */
int mips64_mm_view_plan_admit_files(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                              mips64_mm_view_plan_t *plan, const mips64_space_t *fresh);

int mips64_mm_view_map_file_private(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, unsigned int may_permissions,
                                  uint64_t source_id,
                                  uint64_t file_offset);

int mips64_mm_view_map_file_readonly(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, uint64_t source_id,
                                  uint64_t file_offset);

 int stage_shared_source(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                                 mips64_family_mm_state_t *state, mips64_space_t *fresh,
                                 uint64_t backing_id);

 int mmap_pages(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                           uint64_t address, uint64_t length, uint64_t protection,
                           uint64_t flags, uint64_t offset, int file_fd,
                           uint64_t *guest_result);

int mips64_mm_view_mmap_anon(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                           uint64_t address, uint64_t length, uint64_t protection,
                           uint64_t flags, uint64_t offset, uint64_t *guest_result);

int mips64_mm_view_mmap_file_private_fd(mips64_mm_view_t *view, mips64_family_guard_t *guard,
    uint64_t address, uint64_t length, uint64_t protection, uint64_t flags,
    int borrowed_readable_fd, uint64_t offset, uint64_t *guest_result);

 bool overlaps(const mips64_family_mm_state_t *state, uint64_t start, uint64_t end);

int mips64_mm_view_brk(mips64_mm_view_t *view, mips64_family_guard_t *guard,
                     uint64_t address, uint64_t *guest_result);

uint64_t mips64_mm_view_revision(const mips64_mm_view_t *view);

void mips64_mm_view_destroy(mips64_mm_view_t **owned);
#endif /* MIPS64RT_MM_VIEW_PARTS_H */
