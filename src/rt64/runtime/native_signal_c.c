/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_signal_parts.h"

mips64_native_signals_t *mips64_native_signals_create(void)
{
    mips64_native_signal_process_t *process = mips64_native_signal_process_create();
    if (process == NULL)
        return NULL;
    mips64_native_signals_t *signals = mips64_native_signal_worker_attach(process);
    if (signals == NULL) {
        int saved = errno;
        if (!mips64_native_signal_process_destroy(process))
            _exit(125);
        errno = saved;
        return NULL;
    }
    signals->compatibility_owner = true;
    return signals;
}

bool mips64_native_signals_destroy(mips64_native_signals_t *signals)
{
    if (signals == NULL || !mips64_native_signal_local_process(signals->process) ||
        !signals->compatibility_owner || !pthread_equal(signals->owner, pthread_self())) {
        errno = EINVAL;
        return false;
    }
    mips64_native_signal_process_t *process = signals->process;
    if (!signals->detached) {
        if (atomic_load_explicit(&process->attached_workers, memory_order_acquire) != 1) {
            errno = EBUSY;
            return false;
        }
        if (!mips64_native_signal_worker_detach_internal(signals, false))
            return false;
    }
    int old_cancel_state = process->creator_cancel_state;
    if (!mips64_native_signal_process_destroy_internal(process, false))
        return false;
    free(signals);
    if (pthread_setcancelstate(old_cancel_state, NULL) != 0)
        _exit(125);
    return true;
}
