/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_LINUX_POLL_H
#define MIPS64RT_RT64_LINUX_POLL_H

#include "linux/file.h"

/* MIPS64 ppoll/pselect6 with private descriptor leases and explicit wire
 * codecs. pselect6 uses per-call signal-mask hooks supplied by R5; ppoll's
 * non-NULL mask path remains outside this component. */
bool mips64_linux_poll_dispatch(mips64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result);
bool mips64_linux_poll_dispatch_io(mips64_linux_file_t *files,
                               const mips64_linux_file_io_t *io, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result);

#endif
