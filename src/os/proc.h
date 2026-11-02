/*
 * src/os/proc.h — Guest /proc/self interception declarations (lane L5a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MIPS64RT_OS_PROC_H
#define MIPS64RT_OS_PROC_H

#include "core/cpu.h"

#include <stddef.h>
#include <stdint.h>

void mips_proc_note_exec(const char *guest_path, int argc, char **argv,
                         const mips64_ctx_t *ctx);
const char *mips_proc_exe_path(void);
void mips_proc_note_auxv(const uint64_t *pairs, size_t npairs);
long mips_proc_open(const char *guest_path, uint64_t flags);
long mips_proc_readlink(const char *guest_path, uint64_t buf_va,
                        uint64_t bufsiz);

#endif /* MIPS64RT_OS_PROC_H */
