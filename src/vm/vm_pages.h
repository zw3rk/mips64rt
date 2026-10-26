/*
 * src/vm/vm_pages.h — Lane U12 per-page write-gate flags.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Backs the soft-TLB write gate (Rev4 section 4.3): a page carries
 * write_tag only when it is region-writable AND no flag below is
 * set. Flags are conservative: any unknown or overflowed state
 * closes the gate (slow path), never opens it.
 *
 *   PTE_COW_CLEAN  private file page never written by the guest
 *                  (first store promotes through the miss path);
 *   PTE_HAS_CODE   translated code resident (a store retires the
 *                  code first — the SMC path);
 *   (LL reservations are checked inline from ctx, not stored here.)
 */

#ifndef MIPS64RT_VM_VM_PAGES_H
#define MIPS64RT_VM_VM_PAGES_H

#include <stdint.h>

#define MIPS_VM_PAGE_COW_CLEAN 0x01u
#define MIPS_VM_PAGE_HAS_CODE 0x02u

/* Mark/clear flags for every 4 KiB page in [va, va+len). */
void mips_vm_pages_mark(uint64_t va, uint64_t len, unsigned flags);
void mips_vm_pages_clear(uint64_t va, uint64_t len, unsigned flags);

/* Raw flags for a page (0 when unknown). */
unsigned mips_vm_page_flags(uint64_t vpn);

/* The write gate: nonzero when a store to vpn may inline
 * (region-writable AND no COW_CLEAN AND no HAS_CODE). The region
 * check runs first; reservation state is the filler's inline job. */
int mips_vm_page_writable(uint64_t vpn);

#endif /* MIPS64RT_VM_VM_PAGES_H */
