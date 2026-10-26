/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a AOT cache identity: SHA-256 runtime digest over the
 * translator binary at startup, digest-keyed cache leaf names, and a
 * static-PIE (`ET_DYN`, `DF_1_PIE`, zero `DT_NEEDED`) ELF admission
 * check. File reads only; no executable mapping is created here.
 * Curated C11 only.
 */

#ifndef MIPS64RT_DBT_AOT_IDENTITY_H
#define MIPS64RT_DBT_AOT_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "dbt/aot/sha256.h"

/* `mips64_elf_static_pie_check` outcomes. */
#define MIPS64_ELF_OK 0
#define MIPS64_ELF_NOT_STATIC_PIE 1
#define MIPS64_ELF_IO_ERROR 2

/* Hex digest text length including the NUL (`64` chars + NUL). */
#define MIPS64_DIGEST_HEX_BYTES (MIPS64_SHA256_BYTES * 2u + 1u)
/* Cache leaf: `<64 hex>.aot` + NUL. */
#define MIPS64_CACHE_LEAF_BYTES (MIPS64_SHA256_BYTES * 2u + 5u)

/* AOT site-record emitter version. Version 1 was the U0 direct-map
 * assumption (untagged misses, no retained rows); version 2 is the
 * U12 relative `dbt_mem_site_t` format. The loader refuses any other
 * version, so a translator upgrade never misreads a stale leaf. */
#define MIPS64_AOT_EMITTER_VERSION 2u

/* Hash the file at `path` (opened `O_RDONLY`, streamed, never mapped).
 * Returns 0 on success, -1 on I/O failure (`errno` preserved). */
int mips64_runtime_digest(const char *path, uint8_t out[MIPS64_SHA256_BYTES]);

/* Hash the running translator binary via `/proc/self/exe`. Returns 0
 * on success, -1 where the platform exposes no self-exe link. */
int mips64_runtime_digest_self(uint8_t out[MIPS64_SHA256_BYTES]);

/* Lowercase hex of a 32-byte digest (`hex` needs
 * `MIPS64_DIGEST_HEX_BYTES`). */
void mips64_digest_hex(const uint8_t digest[MIPS64_SHA256_BYTES],
                     char hex[MIPS64_DIGEST_HEX_BYTES]);

/* Cache leaf keyed by the runtime digest: `<hex>.aot` (`out` needs
 * `MIPS64_CACHE_LEAF_BYTES`). Returns 0 on success, -1 when `out_size`
 * is too small. */
int mips64_cache_leaf(const uint8_t runtime_digest[MIPS64_SHA256_BYTES],
                    char *out, size_t out_size);

/* Verify the ELF file at `path` is a static-PIE object: `EM_MIPS` (8),
 * little-endian, `ELFCLASS64` (N64) or `ELFCLASS32` (N32), `ET_DYN`,
 * `DF_1_PIE` present, zero `DT_NEEDED` entries. Returns `MIPS64_ELF_OK`;
 * `MIPS64_ELF_NOT_STATIC_PIE` when the file opens but the shape is
 * unconfirmed (mismatch, truncation, or a later I/O fault);
 * `MIPS64_ELF_IO_ERROR` only when the file cannot be opened. */
int mips64_elf_static_pie_check(const char *path);

#endif /* MIPS64RT_DBT_AOT_IDENTITY_H */
