/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a family broker rendezvous: join or create the broker file
 * `.mips64rt-family-<pid>-<seq>` below `/tmp`
 * (`HOST-CONTRACT.md` section 5). Directories are private (`0700`);
 * creation scans for a free sequence number, joining opens exactly
 * the named one. Curated C11 only.
 */

#ifndef MIPS64RT_OS_FAMILY_BROKER_H
#define MIPS64RT_OS_FAMILY_BROKER_H

#include <stddef.h>
#include <sys/types.h>

/* Broker path buffer: `/tmp/.mips64rt-family-<pid>-<seq>` + NUL. */
#define MIPS64_FAMILY_BROKER_PATH_MAX 128u
/* Highest sequence number probed by `mips64_family_broker_create`. */
#define MIPS64_FAMILY_BROKER_MAX_SEQ 1024u

/* Render the broker path for (`pid`, `seq`). Returns 0 on success,
 * -1 when `out_size` is too small. */
int mips64_family_broker_path(pid_t pid, unsigned seq, char *out,
                            size_t out_size);

/* Create a fresh broker directory for `pid` (`0700`), scanning
 * `seq` from 0. On success stores the path in `out` and the chosen
 * sequence in `seq_out` (either may be NULL) and returns 0; returns
 * -1 with `errno` set when no slot is free or `mkdir` fails. A
 * pre-existing directory owned by another sequence is skipped, never
 * reused. */
int mips64_family_broker_create(pid_t pid, char *out, size_t out_size,
                              unsigned *seq_out);

/* Join the broker directory for (`pid`, `seq`): succeeds only when
 * the directory exists. Renders the path in `out` (may be NULL) and
 * returns 0, else -1 with `errno` set. */
int mips64_family_broker_join(pid_t pid, unsigned seq, char *out,
                            size_t out_size);

#endif /* MIPS64RT_OS_FAMILY_BROKER_H */
