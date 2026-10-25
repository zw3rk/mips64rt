/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_LINUX_SOCKET_H
#define MIPS64RT_RT64_LINUX_SOCKET_H

#include "linux/file.h"
#include <stdbool.h>
#include <stdint.h>

/* Linux MIPS64 (N64/N32) socket UAPI. Unknown numbers are left for the caller. */
bool mips64_linux_socket_dispatch(mips64_linux_file_t *files, uint64_t number,
                              const uint64_t arguments[6], uint64_t *result);

#endif
