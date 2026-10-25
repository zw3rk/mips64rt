/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 worker loop: engine selection and run dispatch. Guest execution
 * arrives in Phase 1+; this module owns CLI/engine plumbing so `src/main.c`
 * stays a thin argument parser.
 */
#ifndef MIPS64RT_RT64_RUNTIME_WORKER_LOOP_H
#define MIPS64RT_RT64_RUNTIME_WORKER_LOOP_H

#include "core/cpu.h"

#include <stdbool.h>

/* Engine selectors are frozen in `core/cpu.h` (`MIPS64_ENGINE_INTERP`,
 * `MIPS64_ENGINE_DBT`); the run config carries one as an `int` so this
 * header never redefines them. */
typedef int mips64_engine_t;

typedef struct {
    mips64_engine_t engine;
    bool difftest;
    bool trace;
} mips64_run_config_t;

mips64_engine_t mips64_engine_from_name(const char *name, bool *ok);
const char *mips64_engine_name(mips64_engine_t engine);
int mips64_worker_loop_run(const mips64_run_config_t *config, int guest_argc,
                         char **guest_argv);

#endif
