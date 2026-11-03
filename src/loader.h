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

#include <stdint.h>

#include "core/cpu.h"

/* ELF flag bits (binutils elf/mips.h): arch revision occupies the top
 * nibble (32R2 0x7, 64R2 0x8, 32R6 0x9, 64R6 0xA); NAN2008 selects
 * IEEE-2008 NaN polarity. Only R2 revisions execute (R7-1, R7-6). */
#define MIPS_EF_ARCH 0xF0000000U
#define MIPS_EF_ARCH_32R2 0x70000000U
#define MIPS_EF_ARCH_64R2 0x80000000U
#define MIPS_EF_NAN2008 0x00000800U

/* Store a native stack/auxv word (4 bytes N32, 8 bytes N64) in guest
 * byte order. N32 values always fit: placements stay below 4 GiB. */
static inline void mips_loader_st_word(uint8_t *p, uint64_t v, int w32,
                                       int be)
{
    if (w32) {
        uint32_t w = (uint32_t)v;

        if (be) {
            p[0] = (uint8_t)((w >> 24) & 0xFFU);
            p[1] = (uint8_t)((w >> 16) & 0xFFU);
            p[2] = (uint8_t)((w >> 8) & 0xFFU);
            p[3] = (uint8_t)(w & 0xFFU);
        } else {
            p[0] = (uint8_t)(w & 0xFFU);
            p[1] = (uint8_t)((w >> 8) & 0xFFU);
            p[2] = (uint8_t)((w >> 16) & 0xFFU);
            p[3] = (uint8_t)((w >> 24) & 0xFFU);
        }
        return;
    }
    if (be) {
        p[0] = (uint8_t)((v >> 56) & 0xFFU);
        p[1] = (uint8_t)((v >> 48) & 0xFFU);
        p[2] = (uint8_t)((v >> 40) & 0xFFU);
        p[3] = (uint8_t)((v >> 32) & 0xFFU);
        p[4] = (uint8_t)((v >> 24) & 0xFFU);
        p[5] = (uint8_t)((v >> 16) & 0xFFU);
        p[6] = (uint8_t)((v >> 8) & 0xFFU);
        p[7] = (uint8_t)(v & 0xFFU);
    } else {
        p[0] = (uint8_t)(v & 0xFFU);
        p[1] = (uint8_t)((v >> 8) & 0xFFU);
        p[2] = (uint8_t)((v >> 16) & 0xFFU);
        p[3] = (uint8_t)((v >> 24) & 0xFFU);
        p[4] = (uint8_t)((v >> 32) & 0xFFU);
        p[5] = (uint8_t)((v >> 40) & 0xFFU);
        p[6] = (uint8_t)((v >> 48) & 0xFFU);
        p[7] = (uint8_t)((v >> 56) & 0xFFU);
    }
}

void mips_loader_init_ctx(mips64_ctx_t *ctx);
/* path names the host file to open; guest_path is the guest-visible
 * image path (AT_EXECFN and /proc/self/exe). NULL guest_path falls
 * back to path. */
int mips_load_elf(mips64_ctx_t *ctx, const char *path,
                  const char *guest_path, char **argv, char **envp);

#endif /* MIPS64RT_LOADER_H */
