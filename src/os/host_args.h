/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a host-contract surface: CLI + environment parsing for every
 * `rt-series` Class-B contract flag (`HOST-CONTRACT.md` section 3) plus
 * the separate AOT/family authority descriptors (section 5).
 *
 * `src/main.c` calls `mips64_host_args_init()` (environment defaults)
 * followed by `mips64_parse_host_args()` (explicit CLI overrides); this
 * module never touches guest state. The start-up wiring in
 * `src/os/worker_loop.c` consumes the parsed struct (image
 * resolution, sysroot join, digest, broker, authorities).
 *
 * Curated C11 only: no VLAs, no Annex K, no <threads.h>, no _Generic,
 * no sprintf/strcpy/strcat.
 */

#ifndef MIPS64RT_OS_HOST_ARGS_H
#define MIPS64RT_OS_HOST_ARGS_H

#include <stddef.h>
#include <stdint.h>

/* Longest accepted path value (`--sysroot`, `--cache-dir`, `--execfn`). */
#define MIPS64RT_HOST_ARGS_PATH_MAX 4096u
/* Longest accepted short token (`--engine`, authorities). */
#define MIPS64RT_HOST_ARGS_TOKEN_MAX 64u

/* `mips64_parse_host_args` outcomes. */
#define MIPS64RT_HOST_ARGS_OK 0
#define MIPS64RT_HOST_ARGS_ERROR 1
#define MIPS64RT_HOST_ARGS_HELP 2
#define MIPS64RT_HOST_ARGS_VERSION 3

/* Linux `AT_EXECFD` auxv key (uapi `linux/auxvec.h`). */
#define MIPS64RT_AT_EXECFD 21u

typedef struct mips64_host_args {
    /* `--sysroot DIR` (alias `--rootfs`) / `MIPS64RT_SYSROOT` (alias
     * `MIPS64RT_ROOTFS`). Last spelling on the CLI wins. */
    char sysroot[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_sysroot;
    /* `--cache DIR` (alias `--cache-dir`) / `MIPS64RT_CACHE` (alias
     * `MIPS64RT_CACHE_DIR`). Last spelling on the CLI wins. */
    char cache_dir[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_cache_dir;
    /* `--execfn PATH` / `MIPS64RT_EXECFN`: explicit guest path for
     * `AT_EXECFN`, decoupled from `guest_argv[0]`. */
    char execfn[MIPS64RT_HOST_ARGS_PATH_MAX];
    int has_execfn;
    /* `--image-fd FD`: open descriptor holding the guest ELF image.
     * Any `fd >= 0` is valid (descriptor 0 counts when stdin is
     * closed); `-1` means unset. The contract defines no env var. */
    int image_fd;
    int has_image_fd;
    /* `--engine interp|dbt` (aliases `--interp` / `--dbt`) /
     * `MIPS64RT_ENGINE`. Explicit CLI overrides env; `engine_cli`
     * records a CLI spelling so `--difftest` keeps implying `dbt`
     * unless `--interp` was pinned on the CLI (Phase 2 rule). */
    char engine[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    int has_engine;
    int engine_cli;
    /* `--difftest` / `--trace` (no env vars; kept from Phase 0 CLI). */
    int difftest;
    int trace;
    /* Separate Class-B authority descriptors (`HOST-CONTRACT.md`
     * section 5; never conflated). Each defaults to `"auto"`. */
    char cache_authority[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    char file_identity[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    char family_authority[MIPS64RT_HOST_ARGS_TOKEN_MAX];
    /* First guest token: index into `argv` past the `--` terminator,
     * or past the last parsed option. `-1` when no guest token
     * remains. `--help` / `--version` set the matching flag and
     * return the matching outcome code instead. */
    int guest_index;
    int wants_help;
    int wants_version;
    /* Static detail string when `MIPS64RT_HOST_ARGS_ERROR` is returned. */
    const char *error;
} mips64_host_args_t;

/* Fill `out` with environment defaults (`MIPS64RT_*`). Returns 0 on
 * success, `MIPS64RT_HOST_ARGS_ERROR` with `out->error` set when an env
 * value fails range validation. */
int mips64_host_args_init(mips64_host_args_t *out);

/* Parse `argv` (skipping `argv[0]`) over `out`, overriding environment
 * defaults. Stops at `--` (consumed) or the first non-option token.
 * Returns `MIPS64RT_HOST_ARGS_OK`, `MIPS64RT_HOST_ARGS_ERROR`,
 * `MIPS64RT_HOST_ARGS_HELP`, or `MIPS64RT_HOST_ARGS_VERSION`. */
int mips64_parse_host_args(int argc, char **argv, mips64_host_args_t *out);

/* Resolve a guest absolute path against the sysroot: when `sysroot` is
 * set and `guest_path` is absolute, join them (`sysroot` + `guest_path`,
 * collapsing the double slash); otherwise copy `guest_path` unchanged
 * (the no-sysroot behavior is byte-identical). Returns 0 on success,
 * -1 with `errno` set when the join does not fit `out_size`. */
int mips64_sysroot_join(const char *sysroot, const char *guest_path,
                        char *out, size_t out_size);

/* Process-wide guest sysroot for path translation (loader, execve,
 * *at). Set once at start-up from the parsed config before any guest
 * thread runs; read-only afterwards. NULL (or empty) clears it. */
void mips64_host_set_sysroot(const char *sysroot);
const char *mips64_host_sysroot(void);

/* Scan a raw auxv `(key, value)` pair vector (`n` pairs) for
 * `AT_EXECFD`. Returns the descriptor (any value `>= 0`, including 0)
 * with `*found` set to 1, or -1 with `*found` set to 0 when the key is
 * absent. Never confuses "present with value 0" with absent. */
long mips64_auxv_find_execfd(const unsigned long *pairs, size_t n,
                             int *found);

/* Scan this process's `/proc/self/auxv` for `AT_EXECFD`. Returns the
 * descriptor with `*found` set to 1, or -1 with `*found` set to 0 when
 * the key is absent (or the auxv is unreadable). */
long mips64_self_execfd(int *found);

/* One-paragraph `--help` fragment listing every contract flag (shared
 * by `main.c` usage text and the host-native contract check). */
const char *mips64_host_args_help(void);

#endif /* MIPS64RT_OS_HOST_ARGS_H */
