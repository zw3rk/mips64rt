/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a family broker rendezvous. See `family_broker.h`.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "rt64/runtime/family_broker.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int mips64_family_broker_path(pid_t pid, unsigned seq, char *out,
                            size_t out_size)
{
    int n;

    if (out == NULL || out_size == 0) {
        errno = EINVAL;
        return -1;
    }
    n = snprintf(out, out_size, "/tmp/.mips64rt-family-%ld-%u",
                 (long)pid, seq);
    if (n < 0 || (size_t)n >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int mips64_family_broker_create(pid_t pid, char *out, size_t out_size,
                              unsigned *seq_out)
{
    char path[MIPS64_FAMILY_BROKER_PATH_MAX];
    unsigned seq;

    if (pid <= 0) {
        errno = EINVAL;
        return -1;
    }
    for (seq = 0; seq < MIPS64_FAMILY_BROKER_MAX_SEQ; seq++) {
        if (mips64_family_broker_path(pid, seq, path, sizeof path) != 0)
            return -1;
        if (mkdir(path, 0700) == 0) {
            if (out != NULL &&
                mips64_family_broker_path(pid, seq, out, out_size) != 0) {
                rmdir(path);
                return -1;
            }
            if (seq_out != NULL)
                *seq_out = seq;
            return 0;
        }
        if (errno != EEXIST)
            return -1;
    }
    errno = EEXIST;
    return -1;
}

int mips64_family_broker_join(pid_t pid, unsigned seq, char *out,
                            size_t out_size)
{
    char path[MIPS64_FAMILY_BROKER_PATH_MAX];
    struct stat status;

    if (pid <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (mips64_family_broker_path(pid, seq, path, sizeof path) != 0)
        return -1;
    /* `stat` (not `access`): the broker must be a directory, and the
     * caller needs a stable identity to pin, not a momentary
     * permission answer. */
    if (stat(path, &status) != 0)
        return -1;
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    if (out != NULL &&
        mips64_family_broker_path(pid, seq, out, out_size) != 0)
        return -1;
    return 0;
}
