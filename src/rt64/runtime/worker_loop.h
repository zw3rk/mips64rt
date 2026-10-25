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
#include "os/host_args.h"

#include <stdbool.h>

/* Engine selectors are frozen in `core/cpu.h` (`MIPS64_ENGINE_INTERP`,
 * `MIPS64_ENGINE_DBT`); the run config carries one as an `int` so this
 * header never redefines them. */
typedef int mips64_engine_t;

/* Lane L6a host-contract start-up config: engine selectors plus the
 * parsed `mips64_host_args_t` surface (sysroot, cache dir, explicit
 * guest path, image descriptor, separate authorities). `main.c` fills
 * it from the parser; fixed-size buffers mirror `host_args.h` so no
 * allocation or guest state is involved. */
typedef struct {
    mips64_engine_t engine;
    bool difftest;
    bool trace;
    char sysroot[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_sysroot;
    char cache_dir[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_cache_dir;
    char exec_path[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_exec_path;
    int image_fd;
    int has_image_fd;
    char cache_authority[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    char file_identity[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    char family_authority[MIPS64RT_HOST_ARGS_TOKEN_MAX];
} mips64_run_config_t;

mips64_engine_t mips64_engine_from_name(const char *name, bool *ok);
const char *mips64_engine_name(mips64_engine_t engine);
int mips64_worker_loop_run(const mips64_run_config_t *config, int guest_argc,
                         char **guest_argv);

#endif
