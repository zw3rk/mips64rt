/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_RUNTIME_FAMILY_WAIT_H
#define MIPS64RT_RT64_RUNTIME_FAMILY_WAIT_H

#include "runtime/family.h"

#define MIPS64_FAMILY_WAIT_MAX_ROWS 65536u

/* A process-local snapshot of the shared family waiter table. Rows contain
 * only values; no mapped-bank addresses or persistent indices escape. */
typedef struct {
    uint64_t kind;
    uint64_t identity;
    uint64_t offset;
} mips64_family_wait_key_t;

enum {
    MIPS64_FAMILY_WAIT_PRIVATE = 1,
    MIPS64_FAMILY_WAIT_MM_SHARED = 2,
    MIPS64_FAMILY_WAIT_OBJECT = 3,
    MIPS64_FAMILY_WAIT_FILE = 4
};

typedef struct {
    uint64_t wait_id;
    uint64_t owner_incarnation;
    uint64_t mm_id;
    uint64_t worker_id;
    mips64_family_wait_key_t key;
    uint32_t bitset;
    uint32_t state;
} mips64_family_wait_row_t;

enum {
    MIPS64_FAMILY_WAITING = 1,
    MIPS64_FAMILY_WOKEN = 2
};

typedef struct {
    mips64_family_wait_row_t *rows;
    size_t count;
    size_t capacity;
    uint64_t revision;
} mips64_family_wait_table_t;

/* Read an owned process-local copy under the held family guard. Initialize
 * table to {0} before its first read; subsequent reads replace its allocation. */
int mips64_family_wait_table_read(mips64_family_guard_t *guard,
                              mips64_family_wait_table_t *table);
/* Ensure process-local storage for at least capacity rows. */
int mips64_family_wait_table_reserve(mips64_family_wait_table_t *table,
                                 size_t capacity);
void mips64_family_wait_table_destroy(mips64_family_wait_table_t *table);
/* Commit a complete new table and up to two object-slot updates atomically.
 * The snapshot revision must still match. On failure the caller's snapshot and
 * shared table remain unchanged unless the family is poisoned by failed recovery
 * after the COMMITTED marker. */
int mips64_family_wait_table_commit(mips64_family_guard_t *guard,
                                mips64_family_wait_table_t *table,
                                const mips64_family_object_update_t *updates,
                                size_t update_count);
/* Consume monotonically increasing, never-reused family-wide IDs. */
int mips64_family_wait_id(mips64_family_guard_t *guard, uint64_t *out);
int mips64_family_mm_id(mips64_family_guard_t *guard, uint64_t *out);
/* Remove rows whose owner incarnation is dead. Preserve all remaining order. */
int mips64_family_wait_table_sweep(mips64_family_guard_t *guard,
                               mips64_family_wait_table_t *table);

#endif
