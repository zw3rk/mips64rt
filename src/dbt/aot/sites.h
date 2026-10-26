/*
 * src/dbt/aot/sites.h — Lane U12 versioned AOT miss-site records.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Persists each compiled block's relative miss-site rows into the
 * digest-keyed AOT leaf (`<hex>.aot`, reserved by the worker's
 * `--cache-dir` handling) so a future code cache can reload them
 * without re-emission. The writer appends one record per block
 * (best-effort: failures are silent, the run never depends on the
 * cache); the loader validates magic + `MIPS64_AOT_EMITTER_VERSION`
 * and replays rows through a visitor. Until the code cache lands,
 * only the writer is wired into the dispatcher; the loader is
 * exercised by the host unit test.
 */

#ifndef MIPS64RT_DBT_AOT_SITES_H
#define MIPS64RT_DBT_AOT_SITES_H

#include <stddef.h>
#include <stdint.h>

struct dbt_mem_site;

/* Point the writer at the reserved leaf (`path` copied, bounded;
 * NULL clears). Reads back via `mips_aot_leaf_path` for tests. */
void mips_aot_set_leaf(const char *path);
const char *mips_aot_leaf_path(void);

/* Append one block record (guest pc + rows) to the leaf. No leaf, no
 * rows, or any I/O failure: silent no-op. Never fails the run. */
void mips_aot_note_block(uint64_t guest_pc,
                         const struct dbt_mem_site *sites, size_t count);

/* Visitor over one loaded record; nonzero stops the walk. */
typedef int (*mips_aot_site_visit_t)(uint64_t guest_pc,
                                     const struct dbt_mem_site *sites,
                                     size_t count, void *arg);

/* Load and validate the leaf at `path`, replaying each record.
 * Returns 0 on success (including an empty file), -1 on I/O failure
 * (`errno` preserved), -2 on magic/version mismatch, -3 on a
 * truncated or overlong record. */
int mips_aot_sites_load(const char *path, mips_aot_site_visit_t visit,
                        void *arg);

#endif /* MIPS64RT_DBT_AOT_SITES_H */
