/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a guest-ABI page rules: the 4 KiB alignment, validation, and
 * rounding contract every Class-B translator enforces in software
 * (`HOST-CONTRACT.md` section 2.1, matching `rvrt/src/linux/memory.c`
 * line 212). Pure predicates: they never touch memory, so the
 * coordinator can wire them into the guest syscall layer without
 * changing its shape. Curated C11 only.
 */

#ifndef MIPS64RT_OS_PAGE_RULES_H
#define MIPS64RT_OS_PAGE_RULES_H

#include <stdint.h>

/* Guest ABI page size (`AT_PAGESZ = 4096` for every translator). */
#define MIPS64_GUEST_PAGE_SHIFT 12u
#define MIPS64_GUEST_PAGE_SIZE 4096u
#define MIPS64_GUEST_PAGE_MASK 4095u

/* Linux asm-generic flag values on the guest ABI. */
#define MIPS64_GUEST_MAP_FIXED 0x10u
#define MIPS64_GUEST_MAP_FIXED_NOREPLACE 0x100000u
#define MIPS64_GUEST_MREMAP_FIXED 1u

/* Each check returns 0 when the call is admitted, `-EINVAL` when the
 * guest must observe `EINVAL`. Positive lengths round up to a 4 KiB
 * multiple for the mapped VMA extent (`mips64_page_align_up`). */

/* `mmap`/`mmap2`: non-zero `addr` with `MAP_FIXED`/`MAP_FIXED_NOREPLACE`
 * and `addr % 4096 != 0` fails; `offset % 4096 != 0` fails;
 * `len == 0` fails. */
int mips64_page_mmap_check(uint64_t addr, uint64_t len, uint64_t flags,
                         uint64_t offset);

/* `mprotect`: `addr % 4096 != 0` fails; `len == 0` succeeds as a
 * no-op. */
int mips64_page_mprotect_check(uint64_t addr, uint64_t len);

/* `munmap`: `addr % 4096 != 0` fails; `len == 0` fails. */
int mips64_page_munmap_check(uint64_t addr, uint64_t len);

/* `mremap`: `old_address % 4096 != 0` fails; `new_address % 4096 != 0`
 * under `MREMAP_FIXED` fails; `new_size == 0` fails. `old_size`
 * rounds up and needs no check. */
int mips64_page_mremap_check(uint64_t old_addr, uint64_t new_len,
                           uint64_t flags, uint64_t new_addr);

/* Round a positive length up to a 4 KiB multiple. */
uint64_t mips64_page_align_up(uint64_t len);

#endif /* MIPS64RT_OS_PAGE_RULES_H */
