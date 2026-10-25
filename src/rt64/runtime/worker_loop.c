/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/worker_loop.h"

#include <stdio.h>
#include <string.h>

mips64_engine_t mips64_engine_from_name(const char *name, bool *ok)
{
    if (name != NULL && strcmp(name, "interp") == 0) {
        if (ok != NULL)
            *ok = true;
        return MIPS64_ENGINE_INTERP;
    }
    if (name != NULL && strcmp(name, "dbt") == 0) {
        if (ok != NULL)
            *ok = true;
        return MIPS64_ENGINE_DBT;
    }
    if (ok != NULL)
        *ok = false;
    return MIPS64_ENGINE_INTERP;
}

const char *mips64_engine_name(mips64_engine_t engine)
{
    return engine == MIPS64_ENGINE_DBT ? "dbt" : "interp";
}

int mips64_worker_loop_run(const mips64_run_config_t *config, int guest_argc,
                         char **guest_argv)
{
    if (config == NULL || guest_argc < 1 || guest_argv == NULL)
        return 2;
    if (config->trace)
        fputs("mips64rt: trace enabled\n", stderr);
    if (config->difftest && config->engine != MIPS64_ENGINE_DBT) {
        fputs("mips64rt: --difftest requires the dbt engine\n", stderr);
        return 2;
    }
    /* Guest execution lands in Phase 1 (interp) / Phase 2 (dbt). */
    fprintf(stderr, "mips64rt: cannot execute '%s' yet (engine=%s): "
            "Phase 0 bootstrap only supports --version/--help\n",
            guest_argv[0], mips64_engine_name(config->engine));
    return 2;
}
