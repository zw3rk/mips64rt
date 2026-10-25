/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a host-contract CLI/env parsing. See `host_args.h`.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "os/host_args.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Allowed engines (`--engine` is an alias of `--interp`/`--dbt`;
 * `mips64rt` has no `jit`: rejected with a diagnostic). */
static const char *const engine_values[] = {
    "interp", "dbt", NULL
};

/* Allowed Class-B authority descriptors (`HOST-CONTRACT.md` section 5).
 * `auto` admits local Linux; the `hyper-linux-*` values name the
 * qualified `hyper-linux` facades and are declined with a diagnostic
 * when those facades are absent. */
static const char *const cache_authority_values[] = {
    "auto", "hyper-linux-apfs-acl-v1", NULL
};
static const char *const file_identity_values[] = {
    "auto", "hyper-linux-apfs-v1", NULL
};
static const char *const family_authority_values[] = {
    "auto", "hyper-linux-apfs-acl-v1", NULL
};

/* Copy `value` into the fixed `out` buffer (`out_size` bytes). Fails
 * when `value` is NULL, empty, or does not fit (with NUL). */
static int copy_token(char *out, size_t out_size, const char *value,
                      const char **error, const char *what)
{
    size_t n;

    if (value == NULL || value[0] == '\0') {
        *error = what;
        return -1;
    }
    n = strlen(value);
    if (n >= out_size) {
        *error = what;
        return -1;
    }
    memcpy(out, value, n + 1u);
    return 0;
}

static int copy_engine(mips64_host_args_t *out, const char *value,
                       const char **error)
{
    const char *const *known = engine_values;

    while (*known != NULL) {
        if (strcmp(*known, value) == 0) {
            if (copy_token(out->engine, sizeof out->engine, value, error,
                           "engine value too long") != 0)
                return -1;
            out->has_engine = 1;
            return 0;
        }
        known++;
    }
    *error = "unknown engine (want interp|dbt)";
    return -1;
}

/* Validate `value` against a NULL-terminated allow-list and store it. */
static int copy_authority(char *field, size_t field_size, const char *value,
                          const char *const *allowed, const char **error,
                          const char *what)
{
    const char *const *known = allowed;

    if (value == NULL || value[0] == '\0') {
        *error = what;
        return -1;
    }
    while (*known != NULL) {
        if (strcmp(*known, value) == 0) {
            if (copy_token(field, field_size, value, error, what) != 0)
                return -1;
            return 0;
        }
        known++;
    }
    *error = what;
    return -1;
}

/* Parse a non-negative descriptor number (`--image-fd`): any `fd >= 0`
 * is valid, including 0 (stdin closed at `execve` still leaves a valid
 * descriptor 0 behind). */
static int set_image_fd(mips64_host_args_t *out, const char *text,
                        const char **error)
{
    const char *p = text;
    long v = 0;

    if (p == NULL || *p == '\0') {
        *error = "--image-fd needs a non-negative fd";
        return -1;
    }
    while (*p != '\0') {
        if (*p < '0' || *p > '9') {
            *error = "--image-fd needs a non-negative fd";
            return -1;
        }
        v = v * 10 + (long)(*p - '0');
        if (v > (long)INT_MAX) {
            *error = "--image-fd value out of range";
            return -1;
        }
        p++;
    }
    out->image_fd = (int)v;
    out->has_image_fd = 1;
    return 0;
}

static const char *env_value(const char *name)
{
    const char *v = getenv(name);

    if (v == NULL || v[0] == '\0')
        return NULL;
    return v;
}

int mips64_host_args_init(mips64_host_args_t *out)
{
    const char *v;

    if (out == NULL) {
        errno = EINVAL;
        return MIPS64RT_HOST_ARGS_ERROR;
    }
    memset(out, 0, sizeof *out);
    out->image_fd = -1;
    out->guest_index = -1;
    memcpy(out->cache_authority, "auto", 5u);
    memcpy(out->file_identity, "auto", 5u);
    memcpy(out->family_authority, "auto", 5u);
    v = env_value("MIPS64RT_SYSROOT");
    if (v == NULL)
        v = env_value("MIPS64RT_ROOTFS");
    if (v != NULL) {
        if (copy_token(out->sysroot, sizeof out->sysroot, v, &out->error,
                       "MIPS64RT_SYSROOT value too long") != 0)
            return MIPS64RT_HOST_ARGS_ERROR;
        out->has_sysroot = 1;
    }
    v = env_value("MIPS64RT_CACHE");
    if (v == NULL)
        v = env_value("MIPS64RT_CACHE_DIR");
    if (v != NULL) {
        if (copy_token(out->cache_dir, sizeof out->cache_dir, v,
                       &out->error,
                       "MIPS64RT_CACHE value too long") != 0)
            return MIPS64RT_HOST_ARGS_ERROR;
        out->has_cache_dir = 1;
    }
    v = env_value("MIPS64RT_ENGINE");
    if (v != NULL && copy_engine(out, v, &out->error) != 0)
        return MIPS64RT_HOST_ARGS_ERROR;
    v = env_value("MIPS64RT_EXECFN");
    if (v != NULL) {
        if (copy_token(out->execfn, sizeof out->execfn, v, &out->error,
                       "MIPS64RT_EXECFN value too long") != 0)
            return MIPS64RT_HOST_ARGS_ERROR;
        out->has_execfn = 1;
    }
    v = env_value("MIPS64RT_CACHE_AUTHORITY");
    if (v != NULL &&
        copy_authority(out->cache_authority, sizeof out->cache_authority,
                       v, cache_authority_values, &out->error,
                       "bad MIPS64RT_CACHE_AUTHORITY (want auto|"
                       "hyper-linux-apfs-acl-v1)") != 0)
        return MIPS64RT_HOST_ARGS_ERROR;
    v = env_value("MIPS64RT_FILE_IDENTITY");
    if (v != NULL &&
        copy_authority(out->file_identity, sizeof out->file_identity, v,
                       file_identity_values, &out->error,
                       "bad MIPS64RT_FILE_IDENTITY (want auto|"
                       "hyper-linux-apfs-v1)") != 0)
        return MIPS64RT_HOST_ARGS_ERROR;
    v = env_value("MIPS64RT_FAMILY_AUTHORITY");
    if (v != NULL &&
        copy_authority(out->family_authority, sizeof out->family_authority,
                       v, family_authority_values, &out->error,
                       "bad MIPS64RT_FAMILY_AUTHORITY (want auto|"
                       "hyper-linux-apfs-acl-v1)") != 0)
        return MIPS64RT_HOST_ARGS_ERROR;
    return MIPS64RT_HOST_ARGS_OK;
}

/* Fetch the value of a `--flag value` pair; `i` points at the flag. */
static int take_value(int argc, char **argv, int *i, const char *what,
                      const char **value, const char **error)
{
    if (*i + 1 >= argc) {
        *error = what;
        return -1;
    }
    (*i)++;
    *value = argv[*i];
    return 0;
}

int mips64_parse_host_args(int argc, char **argv, mips64_host_args_t *out)
{
    int i;

    if (out == NULL || argc < 0 || (argc > 0 && argv == NULL)) {
        return MIPS64RT_HOST_ARGS_ERROR;
    }
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (strcmp(arg, "--") == 0) {
            /* Option terminator: every remaining token is guest argv,
             * verbatim (contract section 3.1 consumer rules). */
            i++;
            if (i < argc)
                out->guest_index = i;
            return MIPS64RT_HOST_ARGS_OK;
        }
        if (strcmp(arg, "--help") == 0) {
            out->wants_help = 1;
            return MIPS64RT_HOST_ARGS_HELP;
        }
        if (strcmp(arg, "--version") == 0) {
            out->wants_version = 1;
            return MIPS64RT_HOST_ARGS_VERSION;
        }
        if (strcmp(arg, "--interp") == 0) {
            memcpy(out->engine, "interp", 7u);
            out->has_engine = 1;
            out->engine_cli = 1;
            continue;
        }
        if (strcmp(arg, "--dbt") == 0) {
            memcpy(out->engine, "dbt", 4u);
            out->has_engine = 1;
            out->engine_cli = 1;
            continue;
        }
        if (strcmp(arg, "--difftest") == 0) {
            out->difftest = 1;
            continue;
        }
        if (strcmp(arg, "--trace") == 0) {
            out->trace = 1;
            continue;
        }
        if (strcmp(arg, "--sysroot") == 0 ||
            strcmp(arg, "--rootfs") == 0) {
            /* Space-separated `--flag value` only (Phase 0 CLI style);
             * `--flag=value` falls through to unknown-option below. */
            if (take_value(argc, argv, &i, "--sysroot needs a path",
                           &value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_token(out->sysroot, sizeof out->sysroot, value,
                           &out->error, "--sysroot path too long") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            out->has_sysroot = 1;
            continue;
        }
        if ((strcmp(arg, "--cache") == 0) ||
            (strcmp(arg, "--cache-dir") == 0)) {
            if (take_value(argc, argv, &i, "--cache-dir needs a path",
                           &value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_token(out->cache_dir, sizeof out->cache_dir, value,
                           &out->error, "--cache-dir path too long") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            out->has_cache_dir = 1;
            continue;
        }
        if (strcmp(arg, "--execfn") == 0) {
            if (take_value(argc, argv, &i, "--execfn needs a path",
                           &value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_token(out->execfn, sizeof out->execfn, value,
                           &out->error, "--execfn path too long") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            out->has_execfn = 1;
            continue;
        }
        if (strcmp(arg, "--image-fd") == 0) {
            if (take_value(argc, argv, &i, "--image-fd needs an fd",
                           &value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (set_image_fd(out, value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            continue;
        }
        if (strcmp(arg, "--engine") == 0) {
            if (take_value(argc, argv, &i, "--engine needs interp|dbt",
                           &value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_engine(out, value, &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            out->engine_cli = 1;
            continue;
        }
        if (strcmp(arg, "--cache-authority") == 0) {
            if (take_value(argc, argv, &i,
                           "--cache-authority needs a value", &value,
                           &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_authority(out->cache_authority,
                               sizeof out->cache_authority, value,
                               cache_authority_values, &out->error,
                               "bad --cache-authority (want auto|"
                               "hyper-linux-apfs-acl-v1)") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            continue;
        }
        if (strcmp(arg, "--file-identity") == 0) {
            if (take_value(argc, argv, &i,
                           "--file-identity needs a value", &value,
                           &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_authority(out->file_identity,
                               sizeof out->file_identity, value,
                               file_identity_values, &out->error,
                               "bad --file-identity (want auto|"
                               "hyper-linux-apfs-v1)") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            continue;
        }
        if (strcmp(arg, "--family-authority") == 0) {
            if (take_value(argc, argv, &i,
                           "--family-authority needs a value", &value,
                           &out->error) != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            if (copy_authority(out->family_authority,
                               sizeof out->family_authority, value,
                               family_authority_values, &out->error,
                               "bad --family-authority (want auto|"
                               "hyper-linux-apfs-acl-v1)") != 0)
                return MIPS64RT_HOST_ARGS_ERROR;
            continue;
        }
        if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0') {
            out->error = "unknown option";
            return MIPS64RT_HOST_ARGS_ERROR;
        }
        out->guest_index = i;
        return MIPS64RT_HOST_ARGS_OK;
    }
    return MIPS64RT_HOST_ARGS_OK;
}

int mips64_sysroot_join(const char *sysroot, const char *guest_path,
                        char *out, size_t out_size)
{
    size_t sn;
    size_t gn;

    if (guest_path == NULL || out == NULL || out_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (sysroot == NULL || sysroot[0] == '\0' || guest_path[0] != '/') {
        gn = strlen(guest_path);
        if (gn >= out_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, guest_path, gn + 1u);
        return 0;
    }
    sn = strlen(sysroot);
    gn = strlen(guest_path);
    while (sn > 0 && sysroot[sn - 1u] == '/')
        sn--;
    if (sn + gn >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, sysroot, sn);
    memcpy(out + sn, guest_path, gn + 1u);
    return 0;
}

long mips64_auxv_find_execfd(const unsigned long *pairs, size_t n,
                             int *found)
{
    size_t i;

    if (found != NULL)
        *found = 0;
    if (pairs == NULL || found == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (pairs[i * 2u] == (unsigned long)MIPS64RT_AT_EXECFD) {
            *found = 1;
            return (long)pairs[i * 2u + 1u];
        }
        if (pairs[i * 2u] == 0u)
            break;
    }
    return -1;
}

long mips64_self_execfd(int *found)
{
    /* `/proc/self/auxv` carries the raw kernel auxv as (key, value)
     * pairs: scanning it detects `AT_EXECFD` presence without ever
     * confusing "present with value 0" with absent (contract 3.1). */
    unsigned long pairs[64];
    int fd;
    size_t done = 0;
    size_t n;

    if (found == NULL) {
        errno = EINVAL;
        return -1;
    }
    *found = 0;
    fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t got;

        if (done >= sizeof pairs)
            break;
        got = read(fd, (char *)pairs + done, sizeof pairs - done);
        if (got < 0) {
            int saved = errno;

            if (errno == EINTR)
                continue;
            close(fd);
            errno = saved;
            return -1;
        }
        if (got == 0)
            break;
        done += (size_t)got;
    }
    close(fd);
    n = done / (2u * sizeof(unsigned long));
    return mips64_auxv_find_execfd(pairs, n, found);
}

const char *mips64_host_args_help(void)
{
    return "  --sysroot DIR  guest sysroot prefix for the main image path\n"
           "                   (alias --rootfs; MIPS64RT_SYSROOT or\n"
           "                   MIPS64RT_ROOTFS)\n"
           "  --cache DIR    persistent AOT cache directory, entries keyed\n"
           "                   by the SHA-256 runtime digest (alias\n"
           "                   --cache-dir; MIPS64RT_CACHE or\n"
           "                   MIPS64RT_CACHE_DIR)\n"
           "  --engine E     execution engine: interp|dbt (aliases --interp\n"
           "                   and --dbt; MIPS64RT_ENGINE; explicit CLI\n"
           "                   overrides env)\n"
           "  --execfn PATH  guest executable path for AT_EXECFN, decoupled\n"
           "                   from guest argv[0] (MIPS64RT_EXECFN)\n"
           "  --image-fd FD  open descriptor holding the guest ELF image\n"
           "                   (any fd >= 0, incl. 0; overrides AT_EXECFD)\n"
           "  --cache-authority NAME   auto|hyper-linux-apfs-acl-v1\n"
           "  --file-identity NAME     auto|hyper-linux-apfs-v1\n"
           "  --family-authority NAME  auto|hyper-linux-apfs-acl-v1\n";
}
