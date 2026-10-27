/*
 * src/vm/vm_file.h — File-backed provider + the 6-step contract.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L-U0-C-owned. The file-backed sibling of Provider A: the same
 * 6-step contract from src/vm/vm64.h (reserve/map/protect/query/
 * unmap/release) over a file mapping, for AOT images and other
 * file-backed guest segments. `mips_vmfile_map` maps [off, off+len)
 * of an open fd at VA with shared file visibility; every other step
 * dispatches to the same provider ops table shape.
 */

#ifndef MIPS64RT_VM_VM_FILE_H
#define MIPS64RT_VM_VM_FILE_H

#include "vm/vm64.h"

#include <stddef.h>
#include <stdint.h>

/* Provider F (file-backed mmap storage). priv carries the fd. */
extern const mips_provider_ops_t mips_provider_f;

/* Map len bytes of fd at [off, off+len) onto VA (page-aligned va,
 * len, off; prot uses MIPS_PROT_* numbering, EXEC rejected). The
 * reservation must already exist (step 1 via mips_vm64_reserve with
 * &mips_provider_f). Returns 0 or MIPS_FAULT. */
int mips_vmfile_map(mips_vm64_t *vm, int fd, uint64_t off, uint64_t va,
                    uint64_t len, uint32_t prot);

/* Lane U12 live file-map hook: record the (dev, ino) identity and
 * the mapping for EOF tracking, mark private pages COW_CLEAN, and
 * take MAP_SHARED native (writes through) when the host page size
 * divides va, len, and file_offset. Best-effort: never fails the
 * mapping. is_shared mirrors the guest MAP_SHARED bit. */
void mips_vm_file_map_hook(mips64_ctx_t *ctx, int fd, uint64_t va,
                           uint64_t len, uint64_t file_offset,
                           uint32_t prot, int is_shared);
void mips_vm_file_unmap_hook(uint64_t va, uint64_t len);
void mips_vm_file_shared_sync(mips64_ctx_t *ctx, uint64_t va, uint64_t len);
void mips_vm_file_reconcile(mips64_ctx_t *ctx);

/* File-mutation hooks (called after a successful host mutation):
 * grow/refresh CLEAN pages, zero discarded tails, drop wholly
 * removed CLEAN pages, and retire translated code over the touched
 * ranges. post_write covers write/pwrite64/pwritev (off_known selects
 * the range; sequential writes pass off_known 0 and the hook reads
 * the current file position). The truncate variants cover
 * ftruncate (fd) and truncate (resolved host path). */
void mips_vm_file_post_write(mips64_ctx_t *ctx, int fd, uint64_t off,
                             uint64_t n);
void mips_vm_file_post_write_seq(mips64_ctx_t *ctx, int fd, uint64_t n);
void mips_vm_file_post_truncate_fd(mips64_ctx_t *ctx, int fd,
                                   uint64_t newsize);
void mips_vm_file_post_truncate_path(mips64_ctx_t *ctx,
                                     const char *host_path,
                                     uint64_t newsize);

#endif /* MIPS64RT_VM_VM_FILE_H */
