/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "os/signal_core.h"

#include <stddef.h>

uint64_t mips64_signal_trampoline_addr(int is_n32)
{
    return is_n32 != 0 ? MIPS64_N32_SIGTRAMP : MIPS64_N64_SIGTRAMP;
}

void mips64_ctx_clear_ll(mips64_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    ctx->llbit = 0;
    ctx->lladdr = 0;
    ctx->llval = 0;
}
