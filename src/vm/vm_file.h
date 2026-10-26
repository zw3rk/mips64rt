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

#endif /* MIPS64RT_VM_VM_FILE_H */
