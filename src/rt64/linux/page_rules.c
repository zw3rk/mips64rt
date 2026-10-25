/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a guest-ABI page rules. See `page_rules.h`.
 */

#include "rt64/linux/page_rules.h"

#include <errno.h>

uint64_t mips64_page_align_up(uint64_t len)
{
    return (len + (uint64_t)MIPS64_GUEST_PAGE_MASK) &
           ~((uint64_t)MIPS64_GUEST_PAGE_MASK);
}

int mips64_page_mmap_check(uint64_t addr, uint64_t len, uint64_t flags,
                         uint64_t offset)
{
    uint64_t fixed;

    if (len == 0)
        return -EINVAL;
    if ((offset & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    fixed = flags & ((uint64_t)MIPS64_GUEST_MAP_FIXED |
                     (uint64_t)MIPS64_GUEST_MAP_FIXED_NOREPLACE);
    if (addr != 0 && fixed != 0 &&
        (addr & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    return 0;
}

int mips64_page_mprotect_check(uint64_t addr, uint64_t len)
{
    /* `len == 0` succeeds as a no-op (contract section 2.1); the
     * length needs no validation beyond that. */
    (void)len;
    if ((addr & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    return 0;
}

int mips64_page_munmap_check(uint64_t addr, uint64_t len)
{
    if (len == 0)
        return -EINVAL;
    if ((addr & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    return 0;
}

int mips64_page_mremap_check(uint64_t old_addr, uint64_t new_len,
                           uint64_t flags, uint64_t new_addr)
{
    if (new_len == 0)
        return -EINVAL;
    if ((old_addr & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    if ((flags & (uint64_t)MIPS64_GUEST_MREMAP_FIXED) != 0 &&
        (new_addr & (uint64_t)MIPS64_GUEST_PAGE_MASK) != 0)
        return -EINVAL;
    return 0;
}
