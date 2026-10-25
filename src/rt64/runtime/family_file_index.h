/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_RUNTIME_FAMILY_FILE_INDEX_H
#define MIPS64RT_RT64_RUNTIME_FAMILY_FILE_INDEX_H

#include "memory/file_identity.h"
#include "runtime/family.h"

#include <stddef.h>
#include <stdint.h>

#define MIPS64_FAMILY_FILE_INDEX_MAX_SOURCES 4096u
#define MIPS64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS 65536u

/* Source IDs name exact capabilities in this family's one file service. Two
 * independently registered descriptions stay distinct even if their proven
 * inode identities compare equal. A zero identity is explicitly unknown.
 * Trusted callers must query a nonzero identity from this exact fetched FD
 * under their selected provider policy before admission. This codec validates
 * representation/immutability, not that provenance; no guest supplies rows. */
typedef struct {
    uint64_t source_id;
    mips64_file_identity_t identity;
    uint64_t reconciled_size;
    uint64_t mutation_sequence;
} mips64_family_file_index_source_t;

/* A key's file origin is immutable for the full family lifetime, including
 * after the last mapping is removed. The source ID is never an inode key.
 * Trusted admission may add only freshly allocated file payload keys, never
 * retrofit a key already used as anonymous in any MM or shared manifest. */
typedef struct {
    mips64_family_page_key_t key;
    uint64_t source_id;
    uint64_t file_offset;
} mips64_family_file_index_assoc_t;

typedef struct {
    uint64_t revision;
    mips64_family_file_index_source_t *sources;
    size_t source_count;
    mips64_family_file_index_assoc_t *associations;
    size_t association_count;
} mips64_family_file_index_state_t;

void mips64_family_file_index_state_destroy(mips64_family_file_index_state_t *state);

/* Bootstrap the complete empty schema while the new family is still in
 * private mode 0. Caller installs the returned immutable anchor ID in its
 * control root only after success; an orphan object on failure is unreachable.
 * Does not change *out_root_object on failure. */
int mips64_family_file_index_create_empty(mips64_family_guard_t *guard,
                                       uint64_t *out_root_object);

/* Read/commit require a held guard and the exact anchor returned by
 * mips64_family_file_index_object(guard). Read replaces an owned output only after
 * full validation. Commit compares revision, immutably retains every old row,
 * and changes caller revision only after its root redo succeeds. An EIO after
 * the redo commit point is infrastructure-uncertain: recover/fail closed, never
 * blindly retry or publish an MM root using this candidate. */
int mips64_family_file_index_read(mips64_family_guard_t *guard, uint64_t root_object,
                               mips64_family_file_index_state_t *out);
int mips64_family_file_index_commit(mips64_family_guard_t *guard, uint64_t root_object,
                                 mips64_family_file_index_state_t *state);

#endif
