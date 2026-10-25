/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_AOT_READER_H
#define MIPS64RT_RT64_AOT_READER_H
#include "aot/format.h"
#include "aot/authority.h"
#include <stddef.h>
#include <stdint.h>

typedef struct mips64_aot_identity {
    uint8_t input_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[MIPS64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
} mips64_aot_identity_t;

typedef struct mips64_aot_snapshot {
    uint8_t *bytes;
    size_t size;
    mips64_aot_view_t view;
} mips64_aot_snapshot_t;

typedef enum mips64_aot_read_result {
    MIPS64_AOT_READ_ERROR = -1,
    MIPS64_AOT_READ_MISS = 0,
    MIPS64_AOT_READ_HIT = 1
} mips64_aot_read_result_t;

/* Digest domain: the 20 ASCII bytes "mips64rt-cache-record-v2", followed by the
 * COMPLETE encoded v2 record with its 32-byte digest slot replaced by zeros.
 * The terminating C NUL is not hashed. V1 and malformed records are rejected.
 * This detects corruption; it does not authenticate same-UID cache writers.
 * Output is unchanged on failure. This function creates no executable mapping. */
int mips64_aot_record_digest(const uint8_t *bytes, size_t size,
                          uint8_t out[MIPS64_AOT_DIGEST_BYTES]);

/* Borrowed directory FD must identify an effective-UID-owned mode0700
 * directory; caller must not close/reuse it during this call. Leaf is one nonempty filename of <=255 bytes, excluding . and ..
 * and any slash. Open uses CLOEXEC, NOFOLLOW and NONBLOCK. Only a regular,
 * single-link, effective-UID-owned mode0600 file of <=16MiB is eligible.
 * Elevated UID/GID operation declines caching. Metadata is rechecked after
 * bounded pread into malloc-owned bytes. V2 structure, whole-record digest,
 * and ALL expected identity fields must match before a HIT is returned.
 *
 * Missing/stale/unsafe/corrupt/changing files return MISS; invalid arguments,
 * resource failure and unexpected I/O return ERROR. Output bytes/view.encoded must be NULL and size must be zero; output
 * is unchanged on MISS/ERROR. No guest effects, relocations or RX publish
 * occur. The snapshot owns its borrowed view and remains valid after the
 * original file is renamed, modified or closed. Same-UID native writers are
 * inside the trust domain. Checks cover POSIX owner/mode fields; extended ACL
 * authorization is not established. A HIT alone is not permission to execute
 * code; filesystem authorization and relocation remain activation requirements. */
mips64_aot_read_result_t mips64_aot_snapshot_read(int directory_fd, const char *leaf,
                                          const mips64_aot_identity_t *expected,
                                          mips64_aot_snapshot_t *out);
/* Runtime activation must use this exact-FD ACL-certified form. A failed
 * authority query is a MISS, never permission to execute cached code. */
mips64_aot_read_result_t mips64_aot_snapshot_read_authorized(
    int directory_fd, const char *leaf, const mips64_aot_identity_t *expected,
    mips64_aot_authority_policy_t policy, mips64_aot_snapshot_t *out);
void mips64_aot_snapshot_destroy(mips64_aot_snapshot_t *snapshot);
#endif
