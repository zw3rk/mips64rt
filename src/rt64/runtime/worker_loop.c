/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * RC2 integration (coordinator): dispatch to the Phase 1 loader +
 * reference interpreter or the Phase 2 AArch64 DBT engine.
 */
#include "runtime/worker_loop.h"

#include "dbt/dbt.h"
#include "interp/interp.h"
#include "loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

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
    {
        /* Single guest thread through Phase 2: one static context
         * (large region table; Phase 4 moves contexts per thread). */
        static mips64_ctx_t ctx;
        int rc;

        mips_loader_init_ctx(&ctx);
        if (mips_load_elf(&ctx, guest_argv[0], guest_argv, environ) != 0) {
            fprintf(stderr, "mips64rt: cannot load '%s'\n", guest_argv[0]);
            return 1;
        }
        /* Flags after the load: mips_load_elf re-initialises the context. */
        ctx.engine = config->engine;
        ctx.trace_enabled = config->trace;
        ctx.difftest_enabled = config->difftest;
        if (config->engine == MIPS64_ENGINE_DBT) {
            rc = dbt_run(&ctx);
        } else {
            rc = interp_run(&ctx);
        }
        if (rc != 0) {
            fprintf(stderr, "mips64rt: guest fault at pc=0x%llx (exit %d)\n",
                    (unsigned long long)ctx.pc, rc);
            if (getenv("MIPS64RT_DUMPSTATE") != NULL) {
                mips_dump_regs(&ctx, stderr);
            }
            return 139;
        }
        return 0; /* unreachable: guest exit() ends the process via _Exit */
    }
}
