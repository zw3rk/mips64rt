/*
 * src/loader.h — Static ELF loader for mips64rt (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Admits static MIPS64r2 images: ELFCLASS64/N64
 * ((e_flags & EF_MIPS_ABI) == 0) vs ELFCLASS32/N32
 * ((e_flags & EF_MIPS_ABI2) == 0x20), both endians; rejects others.
 * Maps PT_LOADs MAP_FIXED into the Phase 1 reservation with PROT_EXEC
 * stripped from host data pages (W^X: the interpreter fetches via
 * mips64_guest_ptr, never executes host-side), builds the initial
 * stack (argc/argv/envp/auxv) at the per-ABI stack top, sets
 * is_be/is_n32/task_size/mmap_base, and reports the entry pc in ctx.
 */

#ifndef MIPS64RT_LOADER_H
#define MIPS64RT_LOADER_H

#include "core/cpu.h"

void mips_loader_init_ctx(mips64_ctx_t *ctx);
int mips_load_elf(mips64_ctx_t *ctx, const char *path, char **argv,
                  char **envp);

#endif /* MIPS64RT_LOADER_H */
