/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * `mips64rt` Phase 0 CLI entry. Curated C11 only.
 *
 * Phase 0 admits the guest ELF (EM_MIPS, ELFCLASS64/N64 or ELFCLASS32/N32)
 * and dispatches to the engine plumbing in `src/rt64/runtime/worker_loop`.
 * Guest execution arrives in Phase 1 (interp) / Phase 2 (dbt); until then
 * the worker loop reports the bootstrap status cleanly.
 */
#define _POSIX_C_SOURCE 200809L

#include "core/cpu.h"
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

static void usage(FILE *output)
{
    fputs("Usage: mips64rt [OPTION]... PROGRAM [ARGS]...\n"
          "       mips64rt --version\n"
          "       mips64rt --help\n"
          "\n"
          "Execute a MIPS64r2 Linux ELF binary (N64 or N32).\n"
          "\n"
          "Options:\n"
          "  --interp     use the reference interpreter (default)\n"
          "  --dbt        use the AArch64 dynamic binary translator\n"
          "  --difftest   run under interp and dbt, compare (implies --dbt)\n"
          "  --trace      enable execution tracing\n"
          "  --version    print version and exit\n"
          "  --help       print this help and exit\n"
          "\n"
          "Environment:\n"
          "  MIPS64RT_ENGINE=interp|dbt\n"
          "             default engine when neither --interp nor --dbt is given\n",
          output);
}

/* Admit the guest ELF: magic, class (N64/N32), byte order, machine, type.
 * Returns 0 with `*is_n32` set on success, -1 with `errno` set (EIO on I/O
 * failure, ENOEXEC on shape mismatch). */
static int admit_elf(const char *path, int *is_n32)
{
    unsigned char ehdr[64];
    int fd;
    size_t done = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    while (done < sizeof ehdr) {
        ssize_t got = read(fd, ehdr + done, sizeof ehdr - done);

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
    if (done < sizeof ehdr) {
        errno = ENOEXEC;
        return -1;
    }
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
    {
        int be = ehdr[5] == MIPS64RT_ELFDATA2MSB;
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

int main(int argc, char **argv)
{
    mips64_run_config_t config;
    int guest_at = -1;
    const char *engine_env;
    int is_n32 = 0;
    int explicit_engine = 0;
    int i;

    config.engine = MIPS64_ENGINE_INTERP;
    config.difftest = false;
    config.trace = false;

    engine_env = getenv("MIPS64RT_ENGINE");
    if (engine_env != NULL && engine_env[0] != '\0') {
        bool ok = false;

        config.engine = mips64_engine_from_name(engine_env, &ok);
        if (!ok) {
            fprintf(stderr, "mips64rt: unknown MIPS64RT_ENGINE '%s' "
                    "(want interp|dbt)\n", engine_env);
            return 2;
        }
    }
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--version") == 0) {
            printf("mips64rt %s\n", MIPS64RT_VERSION);
            return 0;
        }
        if (strcmp(arg, "--help") == 0) {
            usage(stdout);
            return 0;
        }
        if (strcmp(arg, "--interp") == 0) {
            config.engine = MIPS64_ENGINE_INTERP;
            explicit_engine = 1;
            continue;
        }
        if (strcmp(arg, "--dbt") == 0) {
            config.engine = MIPS64_ENGINE_DBT;
            explicit_engine = 1;
            continue;
        }
        if (strcmp(arg, "--difftest") == 0) {
            config.difftest = true;
            continue;
        }
        if (strcmp(arg, "--trace") == 0) {
            config.trace = true;
            continue;
        }
        if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0') {
            fprintf(stderr, "mips64rt: unknown option '%s'\n", arg);
            usage(stderr);
            return 2;
        }
        guest_at = i;
        break;
    }
    if (guest_at < 0) {
        usage(stderr);
        return 2;
    }
    /* `--difftest` compares both engines; it implies `--dbt` unless the
     * caller explicitly pinned `--interp` (then the worker loop reports
     * the conflict). */
    if (config.difftest && explicit_engine == 0)
        config.engine = MIPS64_ENGINE_DBT;
    if (admit_elf(argv[guest_at], &is_n32) != 0) {
        fprintf(stderr, "mips64rt: cannot admit '%s': %s\n", argv[guest_at],
                errno == ENOEXEC ? "not a MIPS N64/N32 ELF" : strerror(errno));
        return 1;
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
    return mips64_worker_loop_run(&config, argc - guest_at, &argv[guest_at]);
}
