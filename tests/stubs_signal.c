/*
 * tests/stubs_signal.c — Host-test stubs for the Phase 4 signal seams.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * test_decode links the real src/os/mem.c, whose mips_fault traps
 * SIGSEGV and consults the lane L4a delivery seams. The decoder test
 * installs no guest handlers, so the stubs report "no handler" and
 * every fault records exactly as in Phase 1/2. Full delivery is
 * exercised by the RC4 gate (test_p4_threads_signals), not here.
 */

#include "core/cpu.h"

#include <stdint.h>

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    (void)signo;
    (void)addr;
}

int mips_signal_has_handler(int signo)
{
    (void)signo;
    return 0;
}

int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr)
{
    (void)ctx;
    (void)signo;
    (void)fault_addr;
    return 1;
}
