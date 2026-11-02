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

int mips64_sigpend_enqueue(mips64_ctx_t *ctx, uint32_t signo, int32_t code,
                           int32_t errnum, uint64_t addr)
{
    uint32_t slot;

    if (ctx == NULL || ctx->pend_count >= 16U) {
        return 0;
    }
    slot = (ctx->pend_head + ctx->pend_count) % 16U;
    ctx->pend_queue[slot].signo = signo;
    ctx->pend_queue[slot].code = code;
    ctx->pend_queue[slot].errnum = errnum;
    ctx->pend_queue[slot].addr = addr;
    ctx->pend_count++;
    return 0;
}
