/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * RC2 integration (coordinator): dispatch to the Phase 1 loader +
 * reference interpreter or the Phase 2 AArch64 DBT engine.
 *
 * Lane L6a host-contract wiring (additive): start-up resolves the
 * guest image (`--image-fd` / `AT_EXECFD` / path, sysroot join),
 * admits the three separate Class-B authorities (`auto` only on local
 * Linux), computes the SHA-256 runtime digest, keys `--cache-dir`
 * entries by it, and joins-or-creates the family broker rendezvous
 * `.mips64rt-family-<pid>-<seq>` before the loader runs.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "runtime/worker_loop.h"

#include "dbt/dbt.h"
#include "interp/interp.h"
#include "loader.h"
#include "os/host_args.h"
#include "rt64/aot/identity.h"
#include "rt64/runtime/family_broker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* Decline any non-`auto` authority with a clear diagnostic: the
 * `hyper-linux-*` values name qualified `hyper-linux` facades (APFS
 * ACL xattr synthesis, inode identity) that are absent on local
 * Linux, so admission under them would certify nothing. */
static int admit_authorities(const mips64_run_config_t *config)
{
    if (strcmp(config->cache_authority, "auto") != 0) {
        fprintf(stderr,
                "mips64rt: --cache-authority '%s' declined: only 'auto' "
                "is admitted on local Linux (needs the qualified "
                "hyper-linux APFS ACL facade)\n",
                config->cache_authority);
        return 2;
    }
    if (strcmp(config->file_identity, "auto") != 0) {
        fprintf(stderr,
                "mips64rt: --file-identity '%s' declined: only 'auto' "
                "is admitted on local Linux (needs the qualified "
                "hyper-linux APFS identity facade)\n",
                config->file_identity);
        return 2;
    }
    if (strcmp(config->family_authority, "auto") != 0) {
        fprintf(stderr,
                "mips64rt: --family-authority '%s' declined: only 'auto' "
                "is admitted on local Linux (needs the qualified "
                "hyper-linux APFS ACL facade)\n",
                config->family_authority);
        return 2;
    }
    return 0;
}

/* Render the digest-keyed cache leaf and ensure the `--cache-dir`
 * holds the entry: create the directory (single level; `EEXIST` is
 * fine) and reserve the `<hex>.aot` leaf with `O_CREAT | O_EXCL` so
 * an existing entry is never truncated. The leaf is a reservation
 * for the future AOT writer; readers treat a short entry as a miss. */
static int prepare_cache_dir(const mips64_run_config_t *config,
                             const uint8_t digest[MIPS64_SHA256_BYTES],
                             int have_digest, int trace)
{
    char leaf[MIPS64_CACHE_LEAF_BYTES];
    char entry[MIPS64RT_HOST_ARGS_PATH_MAX + 64u];
    size_t dn;
    size_t ln;
    int fd;

    if (!config->has_cache_dir)
        return 0;
    if (!have_digest) {
        fprintf(stderr, "mips64rt: cannot key --cache-dir '%s': runtime "
                "digest unavailable\n", config->cache_dir);
        return 1;
    }
    if (mips64_cache_leaf(digest, leaf, sizeof leaf) != 0) {
        fprintf(stderr, "mips64rt: cannot render cache leaf: %s\n",
                strerror(errno));
        return 1;
    }
    if (mkdir(config->cache_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mips64rt: cannot create --cache-dir '%s': %s\n",
                config->cache_dir, strerror(errno));
        return 1;
    }
    dn = strlen(config->cache_dir);
    ln = strlen(leaf);
    while (dn > 0 && config->cache_dir[dn - 1u] == '/')
        dn--;
    if (dn + 1u + ln >= sizeof entry) {
        fprintf(stderr, "mips64rt: --cache-dir entry path too long\n");
        return 1;
    }
    memcpy(entry, config->cache_dir, dn);
    entry[dn] = '/';
    memcpy(entry + dn + 1u, leaf, ln + 1u);
    fd = open(entry, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0 && errno != EEXIST) {
        fprintf(stderr, "mips64rt: warning: cannot reserve cache entry "
                "'%s': %s\n", entry, strerror(errno));
        return 0;
    }
    if (fd >= 0)
        close(fd);
    if (trace)
        fprintf(stderr, "mips64rt: cache entry '%s'\n", entry);
    return 0;
}

/* Join or create the family broker rendezvous for this process:
 * `.mips64rt-family-<pid>-<seq>` (contract section 5). A fresh pid
 * creates sequence 0; a re-exec lineage that already rendezvoused
 * joins the existing directory instead. */
static int prepare_family_broker(int trace)
{
    char path[MIPS64_FAMILY_BROKER_PATH_MAX];
    pid_t pid = getpid();

    if (mips64_family_broker_join(pid, 0u, path, sizeof path) == 0) {
        if (trace)
            fprintf(stderr, "mips64rt: family broker join '%s'\n", path);
        return 0;
    }
    if (mips64_family_broker_create(pid, path, sizeof path, NULL) != 0) {
        fprintf(stderr, "mips64rt: cannot create family broker: %s\n",
                strerror(errno));
        return 1;
    }
    if (trace)
        fprintf(stderr, "mips64rt: family broker create '%s'\n", path);
    return 0;
}

/* Resolve which host path the loader opens. `store_fd` receives the
 * loader-private image descriptor to close after mapping (`-1` when
 * the loader opens (and closes) its own descriptor from `open_path`).
 *
 * Priority (contract section 3.1): `--image-fd FD` wins over ambient
 * `AT_EXECFD`, which wins over opening `exec_path`. When the supplied
 * descriptor names the same regular file as `exec_path` (dev/ino
 * match), the path is opened instead so `AT_EXECFN` keeps naming the
 * guest path; otherwise `/proc/self/fd/<fd>` is opened, which refers
 * to the same open file description (pinned identity, never
 * re-resolved by path) and reads position-independently. */
static int resolve_image(const mips64_run_config_t *config,
                         const char *exec_path, char *open_path,
                         size_t open_size, int *store_fd)
{
    char joined[MIPS64RT_HOST_ARGS_PATH_MAX + 32u];
    long aux_fd;
    int found = 0;
    int fd;

    *store_fd = -1;
    if (mips64_sysroot_join(config->has_sysroot ? config->sysroot : NULL,
                            exec_path, joined, sizeof joined) != 0) {
        fprintf(stderr, "mips64rt: guest path too long\n");
        return -1;
    }
    if (config->has_image_fd) {
        fd = config->image_fd;
    } else {
        aux_fd = mips64_self_execfd(&found);
        if (!found) {
            size_t n = strlen(joined);

            if (n >= open_size) {
                fprintf(stderr, "mips64rt: guest path too long\n");
                return -1;
            }
            memcpy(open_path, joined, n + 1u);
            return 0;
        }
        fd = (int)aux_fd;
    }
    {
        struct stat fst;
        struct stat pst;

        if (fstat(fd, &fst) != 0) {
            fprintf(stderr, "mips64rt: image fd %d invalid: %s\n", fd,
                    strerror(errno));
            return -1;
        }
        if (stat(joined, &pst) == 0 &&
            S_ISREG(fst.st_mode) && S_ISREG(pst.st_mode) &&
            fst.st_dev == pst.st_dev && fst.st_ino == pst.st_ino) {
            size_t n = strlen(joined);

            if (n >= open_size) {
                fprintf(stderr, "mips64rt: guest path too long\n");
                return -1;
            }
            memcpy(open_path, joined, n + 1u);
            *store_fd = fd;
            return 0;
        }
    }
    {
        /* Same-description reference: no path re-resolution, so the
         * `hyper-linux` single-open pinning (D188/D189) holds. */
        int n = snprintf(open_path, open_size, "/proc/self/fd/%d", fd);

        if (n < 0 || (size_t)n >= open_size) {
            fprintf(stderr, "mips64rt: image fd path too long\n");
            return -1;
        }
        *store_fd = fd;
        return 0;
    }
}

int mips64_worker_loop_run(const mips64_run_config_t *config, int guest_argc,
                         char **guest_argv)
{
    uint8_t digest[MIPS64_SHA256_BYTES];
    char open_path[MIPS64RT_HOST_ARGS_PATH_MAX + 32u];
    const char *exec_path;
    int have_digest = 0;
    int store_fd = -1;
    int rc_auth;

    if (config == NULL || guest_argc < 1 || guest_argv == NULL)
        return 2;
    if (config->trace)
        fputs("mips64rt: trace enabled\n", stderr);
    if (config->difftest && config->engine != MIPS64_ENGINE_DBT) {
        fputs("mips64rt: --difftest requires the dbt engine\n", stderr);
        return 2;
    }
    rc_auth = admit_authorities(config);
    if (rc_auth != 0)
        return rc_auth;
    /* Publish the sysroot for loader/exec/openat translation (single
     * start-up write before any guest thread runs). */
    mips64_host_set_sysroot(config->has_sysroot ? config->sysroot : NULL);
    if (mips64_runtime_digest_self(digest) == 0) {
        have_digest = 1;
        if (config->trace) {
            char hex[MIPS64_DIGEST_HEX_BYTES];

            mips64_digest_hex(digest, hex);
            fprintf(stderr, "mips64rt: runtime digest %s\n", hex);
        }
    } else if (config->trace) {
        fprintf(stderr, "mips64rt: runtime digest unavailable: %s\n",
                strerror(errno));
    }
    if (prepare_cache_dir(config, digest, have_digest,
                          config->trace ? 1 : 0) != 0)
        return 1;
    if (prepare_family_broker(config->trace ? 1 : 0) != 0)
        return 1;
    exec_path = config->has_exec_path ? config->exec_path : guest_argv[0];
    if (resolve_image(config, exec_path, open_path, sizeof open_path,
                      &store_fd) != 0)
        return 2;
    {
        /* Single guest thread through Phase 2: one static context
         * (large region table; Phase 4 moves contexts per thread). */
        static mips64_ctx_t ctx;
        int rc;

        mips_loader_init_ctx(&ctx);
        if (mips_load_elf(&ctx, open_path, guest_argv, environ) != 0) {
            int e = errno;

            fprintf(stderr, "mips64rt: cannot load '%s'\n", open_path);
            errno = e;
            return 1;
        }
        /* The loader-private image descriptor is consumed: close it
         * after mapping so the guest fd table starts clean. No other
         * caller descriptor (0, 1, 2 or otherwise) is touched. */
        if (store_fd >= 0)
            close(store_fd);
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
