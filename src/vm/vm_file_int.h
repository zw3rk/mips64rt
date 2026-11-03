/*
 * src/vm/vm_file_int.h — Repo-local shared state for the file-backed
 * provider TUs (src/vm/vm_file.c + src/vm/vm_file_sync.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U12-owned. NOT a public interface: it exposes the inode
 * table, lock, and locked helpers so the sync TU can share one table
 * with the hook TU. Guest-facing entry points stay in vm_file.h.
 */

#ifndef MIPS64RT_VM_VM_FILE_INT_H
#define MIPS64RT_VM_VM_FILE_INT_H

#include <stdint.h>
#include <sys/types.h>

#include "core/cpu.h"

/* Lane U12 family-shared inode/EOF tracking. */
#define VM_INODE_MAX 64u
#define VM_INODE_MAPS 128u

typedef struct {
    pid_t pid;
    int fd_dup, shared, native;
    uint64_t va, len, file_offset, min_size, seen_write_seq, seen_resize_seq;
    uint32_t prot;
} vm_inode_map_t;

typedef struct {
    int used, nmaps, wide;
    uint64_t dev, ino, size, write_seq, resize_seq;
    /* LL/SC shared generation (R7-2): bumped under vm_lock on every
     * guest store overlapping a shared mapping of this inode, so an
     * ABA through another alias (same or another process) breaks the
     * snapshot an LL armed on this backing. Same-file cross-offset
     * writes only cause safe spurious SC failures. */
    uint64_t llsc_seq;
    vm_inode_map_t maps[VM_INODE_MAPS];
} vm_inode_t;

extern vm_inode_t *vm_inode_table_ptr;
extern int vm_inode_table_tried;
extern int vm_has_shared_fallback;

void vm_lock(void);
void vm_unlock(void);
vm_inode_t *vm_inode_table(void);
vm_inode_t *vm_inode_lookup(uint64_t dev, uint64_t ino, int create,
                            uint64_t size);
void vm_inode_note_resize_locked(vm_inode_t *in, uint64_t newsize,
                                 pid_t self);
void vm_inode_apply_write_locked(mips64_ctx_t *ctx, vm_inode_t *in,
                                 int fd_hint, uint64_t off, uint64_t n);
void vm_inode_post_truncate_locked(mips64_ctx_t *ctx, vm_inode_t *in,
                                   uint64_t newsize);
int mips_vm_file_is_retained_fd(int fd);
int mips_vm_file_has_shared(uint64_t va, uint64_t len);

#endif /* MIPS64RT_VM_VM_FILE_INT_H */
