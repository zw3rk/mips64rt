/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_LINUX_MEMORY_H
#define MIPS64RT_RT64_LINUX_MEMORY_H

#include "memory/space.h"

typedef enum {
    MIPS64_VMA_INITIAL, MIPS64_VMA_ANONYMOUS, MIPS64_VMA_BRK, MIPS64_VMA_FILE_PRIVATE,
    MIPS64_VMA_ANONYMOUS_SHARED
} mips64_vma_kind_t;

typedef struct {
    uint64_t start, end, backing_id, offset;
    unsigned int permissions, may_permissions;
    mips64_vma_kind_t kind;
} mips64_vma_t;

typedef struct {
    mips64_space_t *space;
    mips64_vma_t *vmas;
    size_t count;
    uint64_t next_id, brk_id, minimum_break, current_break;
} mips64_linux_memory_t;

/* Seed loader/stack coverage before any guest syscall. The context owns only
 * VMA records; space owns backing through its selected factory. Production
 * anonymous mappings use the managed family factory under the family guard.
 * Shared/private VMA kind remains explicit for later process inheritance;
 * accepting a shared anonymous mapping does not enable fork or file sharing. */
bool mips64_linux_memory_init(mips64_linux_memory_t *memory, mips64_space_t *space,
                          uint64_t program_break);
void mips64_linux_memory_destroy(mips64_linux_memory_t *memory);
uint64_t mips64_linux_mmap(mips64_linux_memory_t *memory, uint64_t address,
                       uint64_t length, uint64_t protection, uint64_t flags,
                       uint64_t fd, uint64_t offset);
/* Caller owns one source ref independently. Mapping retains page references. */
uint64_t mips64_linux_mmap_source(mips64_linux_memory_t *memory, uint64_t address,
                              uint64_t length, uint64_t protection, uint64_t flags,
                              mips64_file_source_t *source, uint64_t offset);
uint64_t mips64_linux_munmap(mips64_linux_memory_t *memory, uint64_t address, uint64_t length);
uint64_t mips64_linux_mprotect(mips64_linux_memory_t *memory, uint64_t address,
                           uint64_t length, uint64_t protection);
uint64_t mips64_linux_brk(mips64_linux_memory_t *memory, uint64_t address);
uint64_t mips64_linux_mremap(mips64_linux_memory_t *memory, uint64_t address,
                         uint64_t old_length, uint64_t new_length,
                         uint64_t flags, uint64_t new_address);

#endif
