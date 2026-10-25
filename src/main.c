/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * `mips64rt` Phase 0 CLI entry. Curated C11 only.
 *
 * Phase 0 admits the guest ELF (EM_MIPS, ELFCLASS64/N64 or ELFCLASS32/N32)
 * and dispatches to the engine plumbing in `src/rt64/runtime/worker_loop`.
 * Guest execution arrives in Phase 1 (interp) / Phase 2 (dbt); until then
 * the worker loop reports the bootstrap status cleanly.
 *
 * Lane L6a: every contract flag parses through `src/os/host_args`
 * (environment defaults, explicit CLI overrides); this file maps the
 * parsed struct onto `mips64_run_config_t` and keeps the `--help` /
 * `--version` surface. The start-up wiring (image resolution, sysroot
 * join, digest, cache leaf, family broker, authorities) lives in
 * `src/rt64/runtime/worker_loop.c`.
 */
#define _POSIX_C_SOURCE 200809L

#include "core/cpu.h"
#include "os/host_args.h"
#include "os/syscall_nr.h"
#include "rt64/runtime/worker_loop.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIPS64RT_VERSION "0.0.0-phase0"

/* ELF admission (SPEC 1.1): little-endian MIPS object, N64 or N32. */
#define MIPS64RT_ELF_MAGIC0 0x7fu
#define MIPS64RT_ELF_MAGIC1 'E'
#define MIPS64RT_ELF_MAGIC2 'L'
#define MIPS64RT_ELF_MAGIC3 'F'
#define MIPS64RT_ELFCLASS32 1u
#define MIPS64RT_ELFCLASS64 2u
#define MIPS64RT_ELFDATA2LSB 1u
#define MIPS64RT_ELFDATA2MSB 2u
#define MIPS64RT_EM_MIPS 8u
#define MIPS64RT_ET_EXEC 2u
#define MIPS64RT_ET_DYN 3u

/* Exit-state dump for the RC2 difftest (frozen cpu.h contract, shared
 * by both engines; the L2d harness sets MIPS64RT_DUMPSTATE=1). */
void mips_dump_regs(const mips64_ctx_t *ctx, FILE *out)
{
    unsigned i;

    if (ctx == NULL || out == NULL) {
        return;
    }
    (void)fprintf(out, "REGS pc=%016llx hi=%016llx lo=%016llx\n",
                  (unsigned long long)ctx->pc,
                  (unsigned long long)ctx->hi,
                  (unsigned long long)ctx->lo);
    for (i = 0; i < 32U; i += 4U) {
        (void)fprintf(out, "REGS r%02u=%016llx r%02u=%016llx "
                      "r%02u=%016llx r%02u=%016llx\n",
                      i, (unsigned long long)ctx->gpr[i],
                      i + 1U, (unsigned long long)ctx->gpr[i + 1U],
                      i + 2U, (unsigned long long)ctx->gpr[i + 2U],
                      i + 3U, (unsigned long long)ctx->gpr[i + 3U]);
    }
}

static void usage(FILE *output)
{
    fputs("Usage: mips64rt [OPTION]... PROGRAM [ARGS]...\n"
          "       mips64rt [OPTION]... -- GUEST_ARGV0 [ARGS]...\n"
          "       mips64rt --version\n"
          "       mips64rt --help\n"
          "\n"
          "Execute a MIPS64r2 Linux ELF binary (N64 or N32).\n"
          "With --execfn, PROGRAM names the guest path while every token\n"
          "after -- becomes guest argv verbatim (custom argv[0]); without\n"
          "it, PROGRAM is both the guest path and argv[0].\n"
          "\n"
          "Options:\n"
          "  --interp     use the reference interpreter (default)\n"
          "  --dbt        use the AArch64 dynamic binary translator\n"
          "  --difftest   run under interp and dbt, compare (implies --dbt)\n"
          "  --trace      enable execution tracing\n",
          output);
    fputs(mips64_host_args_help(), output);
    fputs("  --version    print version and exit\n"
          "  --help       print this help and exit\n"
          "  --           option terminator: remaining tokens are guest argv\n"
          "\n"
          "Environment:\n"
          "  MIPS64RT_ENGINE=interp|dbt\n"
          "             default engine when neither --interp, --dbt nor\n"
          "             --engine is given\n",
          output);
    fputs("  MIPS64RT_SYSROOT / MIPS64RT_ROOTFS, MIPS64RT_CACHE /\n"
          "             MIPS64RT_CACHE_DIR, MIPS64RT_EXECFN,\n"
          "             MIPS64RT_CACHE_AUTHORITY, MIPS64RT_FILE_IDENTITY,\n"
          "             MIPS64RT_FAMILY_AUTHORITY (see above)\n"
          "  MIPS64RT_DUMPSTATE=1\n"
          "             dump registers to stderr at guest exit (difftest)\n",
          output);
}

/* Classify one 64-byte ELF header image. Returns 0 with `*is_n32` set
 * on success, -1 with `errno` set (ENOEXEC on shape mismatch). */
static int classify_ehdr(const unsigned char *ehdr, int *is_n32)
{
    int be;

    if (ehdr[0] != MIPS64RT_ELF_MAGIC0 || ehdr[1] != MIPS64RT_ELF_MAGIC1 ||
        ehdr[2] != MIPS64RT_ELF_MAGIC2 || ehdr[3] != MIPS64RT_ELF_MAGIC3 ||
        (ehdr[4] != MIPS64RT_ELFCLASS64 && ehdr[4] != MIPS64RT_ELFCLASS32) ||
        (ehdr[5] != MIPS64RT_ELFDATA2LSB &&
         ehdr[5] != MIPS64RT_ELFDATA2MSB)) {
        errno = ENOEXEC;
        return -1;
    }
    /* RC1 integration: e_type/e_machine follow the file's byte order
     * (BE files store 8 as 00 08); the loader revalidates fully. */
    be = ehdr[5] == MIPS64RT_ELFDATA2MSB;
    {
        unsigned et = be ? ((unsigned)ehdr[16] << 8 | (unsigned)ehdr[17]) :
                           ((unsigned)ehdr[16] | (unsigned)ehdr[17] << 8);
        unsigned em = be ? ((unsigned)ehdr[18] << 8 | (unsigned)ehdr[19]) :
                           ((unsigned)ehdr[18] | (unsigned)ehdr[19] << 8);

        if (em != MIPS64RT_EM_MIPS) {
            errno = ENOEXEC;
            return -1;
        }
        if (et != MIPS64RT_ET_EXEC && et != MIPS64RT_ET_DYN) {
            errno = ENOEXEC;
            return -1;
        }
    }
    *is_n32 = ehdr[4] == MIPS64RT_ELFCLASS32;
    return 0;
}

/* Admit the guest ELF from an open descriptor: `pread`-position-
 * independent (never disturbs the descriptor offset), never closes. */
static int admit_elf_fd(int fd, int *is_n32)
{
    unsigned char ehdr[64];
    size_t done = 0;

    while (done < sizeof ehdr) {
        ssize_t got = pread(fd, ehdr + done, sizeof ehdr - done,
                            (off_t)done);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            break;
        done += (size_t)got;
    }
    if (done < sizeof ehdr) {
        errno = ENOEXEC;
        return -1;
    }
    return classify_ehdr(ehdr, is_n32);
}

/* Admit the guest ELF (EM_MIPS, ELFCLASS64/N64 or ELFCLASS32/N32).
 * Returns 0 with `*is_n32` set on success, -1 with `errno` set (EIO on I/O
 * failure, ENOEXEC on shape mismatch). */
static int admit_elf(const char *path, int *is_n32)
{
    int fd = open(path, O_RDONLY);
    int rc;

    if (fd < 0)
        return -1;
    rc = admit_elf_fd(fd, is_n32);
    {
        int saved = errno;

        close(fd);
        errno = saved;
    }
    return rc;
}

int main(int argc, char **argv)
{
    mips64_host_args_t ha;
    mips64_run_config_t config;
    const char *exec_path;
    int guest_argc;
    char **guest_argv;
    int image_fd = -1;
    int found_aux = 0;
    int is_n32 = 0;
    int rc;

    memset(&config, 0, sizeof config);
    config.image_fd = -1;
    if (mips64_host_args_init(&ha) != MIPS64RT_HOST_ARGS_OK) {
        fprintf(stderr, "mips64rt: %s\n",
                ha.error != NULL ? ha.error : "bad environment");
        return 2;
    }
    rc = mips64_parse_host_args(argc, argv, &ha);
    if (rc == MIPS64RT_HOST_ARGS_HELP) {
        usage(stdout);
        return 0;
    }
    if (rc == MIPS64RT_HOST_ARGS_VERSION) {
        printf("mips64rt %s\n", MIPS64RT_VERSION);
        return 0;
    }
    if (rc != MIPS64RT_HOST_ARGS_OK) {
        fprintf(stderr, "mips64rt: %s\n",
                ha.error != NULL ? ha.error : "bad arguments");
        usage(stderr);
        return 2;
    }
    if (ha.guest_index < 0 || ha.guest_index >= argc) {
        usage(stderr);
        return 2;
    }
    config.engine = MIPS64_ENGINE_INTERP;
    if (ha.has_engine) {
        bool ok = false;

        config.engine = mips64_engine_from_name(ha.engine, &ok);
        if (!ok) {
            fprintf(stderr, "mips64rt: unknown engine '%s' "
                    "(want interp|dbt)\n", ha.engine);
            return 2;
        }
    }
    config.difftest = ha.difftest != 0;
    config.trace = ha.trace != 0;
    if (ha.has_sysroot) {
        size_t n = strlen(ha.sysroot);

        if (n >= sizeof config.sysroot) {
            fprintf(stderr, "mips64rt: --sysroot path too long\n");
            return 2;
        }
        memcpy(config.sysroot, ha.sysroot, n + 1u);
        config.has_sysroot = 1;
    }
    if (ha.has_cache_dir) {
        size_t n = strlen(ha.cache_dir);

        if (n >= sizeof config.cache_dir) {
            fprintf(stderr, "mips64rt: --cache-dir path too long\n");
            return 2;
        }
        memcpy(config.cache_dir, ha.cache_dir, n + 1u);
        config.has_cache_dir = 1;
    }
    /* `--execfn` decouples the guest path / AT_EXECFN from argv[0]
     * (contract section 3.1 consumer rule); without it, the first
     * guest token stays both path and argv[0] (backward compatible). */
    exec_path = ha.has_execfn ? ha.execfn : argv[ha.guest_index];
    {
        size_t n = strlen(exec_path);

        if (n >= sizeof config.exec_path) {
            fprintf(stderr, "mips64rt: guest path too long\n");
            return 2;
        }
        memcpy(config.exec_path, exec_path, n + 1u);
        config.has_exec_path = 1;
    }
    if (ha.has_image_fd) {
        image_fd = ha.image_fd;
    } else {
        long aux_fd = mips64_self_execfd(&found_aux);

        if (found_aux)
            image_fd = (int)aux_fd;
    }
    if (ha.has_image_fd || found_aux) {
        config.image_fd = image_fd;
        config.has_image_fd = 1;
    }
    {
        size_t n;

        n = strlen(ha.cache_authority) + 1u;
        memcpy(config.cache_authority, ha.cache_authority, n);
        n = strlen(ha.file_identity) + 1u;
        memcpy(config.file_identity, ha.file_identity, n);
        n = strlen(ha.family_authority) + 1u;
        memcpy(config.family_authority, ha.family_authority, n);
    }
    /* `--difftest` compares both engines; it implies `--dbt` unless
     * the caller explicitly pinned `--interp` (then the worker loop
     * reports the conflict). */
    if (config.difftest && config.engine != MIPS64_ENGINE_DBT &&
        ha.engine_cli == 0)
        config.engine = MIPS64_ENGINE_DBT;
    /* Admission pre-check (the loader revalidates fully): from the
     * image descriptor when one supplies the ELF (`pread`, offset
     * preserving), else from the sysroot-joined guest path (the same
     * path the start-up wiring hands the loader). */
    if (image_fd >= 0) {
        if (admit_elf_fd(image_fd, &is_n32) != 0) {
            fprintf(stderr, "mips64rt: cannot admit image fd %d: %s\n",
                    image_fd,
                    errno == ENOEXEC ? "not a MIPS N64/N32 ELF" :
                                       strerror(errno));
            return 1;
        }
    } else {
        char admit_path[MIPS64RT_HOST_ARGS_PATH_MAX + 32u];

        if (mips64_sysroot_join(ha.has_sysroot ? ha.sysroot : NULL,
                                exec_path, admit_path,
                                sizeof admit_path) != 0) {
            fprintf(stderr, "mips64rt: guest path too long\n");
            return 2;
        }
        if (admit_elf(admit_path, &is_n32) != 0) {
            fprintf(stderr, "mips64rt: cannot admit '%s': %s\n",
                    admit_path,
                    errno == ENOEXEC ? "not a MIPS N64/N32 ELF" :
                                       strerror(errno));
            return 1;
        }
    }
    if (config.trace) {
        /* Frozen window + trap encoding (SPEC 1.1/2.1/2.2): N64 xuseg is
         * 1 TiB, N32 useg is 2 GiB; guests trap with `syscall 0`. */
        fprintf(stderr, "mips64rt: %s guest, window 0x%llx, trap 0x%08x\n",
                is_n32 != 0 ? "N32" : "N64",
                (unsigned long long)(is_n32 != 0 ? MIPS64_N32_TASK_SIZE :
                                                   MIPS64_N64_TASK_SIZE),
                MIPS64_SYSCALL_INSN);
    }
    guest_argc = argc - ha.guest_index;
    guest_argv = &argv[ha.guest_index];
    return mips64_worker_loop_run(&config, guest_argc, guest_argv);
}
