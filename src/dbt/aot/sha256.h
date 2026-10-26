/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a: self-contained SHA-256 (FIPS 180-4) for the AOT cache
 * runtime digest. No host crypto dependency; never maps executable
 * memory. Curated C11 only.
 */

#ifndef MIPS64RT_DBT_AOT_SHA256_H
#define MIPS64RT_DBT_AOT_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define MIPS64_SHA256_BYTES 32u
#define MIPS64_SHA256_BLOCK_BYTES 64u

typedef struct mips64_sha256 {
    uint32_t state[8];
    uint64_t total;
    uint8_t block[MIPS64_SHA256_BLOCK_BYTES];
    size_t buffered;
} mips64_sha256_t;

void mips64_sha256_init(mips64_sha256_t *ctx);
void mips64_sha256_update(mips64_sha256_t *ctx, const uint8_t *data, size_t len);
void mips64_sha256_final(mips64_sha256_t *ctx, uint8_t out[MIPS64_SHA256_BYTES]);

/* One-shot convenience wrapper. */
void mips64_sha256(const uint8_t *data, size_t len,
                 uint8_t out[MIPS64_SHA256_BYTES]);

#endif /* MIPS64RT_DBT_AOT_SHA256_H */
