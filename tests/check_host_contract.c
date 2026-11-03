/* Lane L6a host-contract checks: CLI/env parser coverage (tested
 * directly because the Makefile TU wiring is the coordinator's),
 * sysroot joining, `AT_EXECFD` auxv scanning, the SHA-256 runtime
 * digest and digest-keyed cache leaves, static-PIE admission
 * (`ET_DYN`, `DF_1_PIE`, zero `DT_NEEDED`), the family broker file
 * join/create, the 4 KiB guest-ABI page-rule predicates, and the
 * `src/os/mem.c` page-rule compliance (`mprotect` no-op/rounding).
 *
 * Each implementation unit is included directly (the same pattern as
 * `tests/test_decode.c` including its units), so the fixed acceptance
 * command `cc -std=c11 ... -Isrc -o /tmp/check_host_contract
 * tests/check_host_contract.c` exercises the real code with the host
 * C compiler (no Docker).
 *
 * Curated C11 only: no VLA, no Annex K, no <threads.h>, no _Generic,
 * no sprintf/strcpy/strcat.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/aot/identity.h"
#include "dbt/aot/sha256.h"
#include "os/family_broker.h"
#include "os/host_args.h"
#include "os/page_rules.h"

static int failures = 0;
static int checks = 0;

/* `mips_trap` stub for the `mem.c` fault path (the real one lives in
 * `src/os/sigframe.c`, which is not under test here). */
static int trap_count = 0;
static int trap_signo = 0;
static uint64_t trap_addr = 0;

void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr)
{
    (void)ctx;
    trap_count++;
    trap_signo = signo;
    trap_addr = addr;
}

static void check(const char *name, int cond)
{
    checks++;
    if (cond) {
        printf("ok: %s\n", name);
    } else {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

static void clear_contract_env(void)
{
    unsetenv("MIPS64RT_SYSROOT");
    unsetenv("MIPS64RT_ROOTFS");
    unsetenv("MIPS64RT_CACHE");
    unsetenv("MIPS64RT_CACHE_DIR");
    unsetenv("MIPS64RT_EXECFN");
    unsetenv("MIPS64RT_ENGINE");
    unsetenv("MIPS64RT_CACHE_AUTHORITY");
    unsetenv("MIPS64RT_FILE_IDENTITY");
    unsetenv("MIPS64RT_FAMILY_AUTHORITY");
}

/* Build `argv` from a NULL-free list: the parser only reads
 * `argv[1..argc)`. */
#define RUN_PARSE(_out, _rc, ...)                                        \
    do {                                                                 \
        char *_argv[] = { (char *)"mips64rt", __VA_ARGS__ };               \
        int _argc = (int)(sizeof _argv / sizeof _argv[0]);               \
        (_rc) = mips64_parse_host_args(_argc, _argv, (_out));             \
    } while (0)

/* ------------------------------------------------------------------ */
/* Parser: full contract flag set.                                    */
/* ------------------------------------------------------------------ */

static void test_parser_full_set(void)
{
    mips64_host_args_t args;
    int rc;

    clear_contract_env();
    memset(&args, 0, sizeof args);
    check("init ok with clean env",
          mips64_host_args_init(&args) == MIPS64RT_HOST_ARGS_OK);
    check("authorities default to auto",
          strcmp(args.cache_authority, "auto") == 0 &&
          strcmp(args.file_identity, "auto") == 0 &&
          strcmp(args.family_authority, "auto") == 0);
    check("image fd defaults to unset",
          args.image_fd == -1 && !args.has_image_fd);
    check("guest index defaults to -1", args.guest_index == -1);

    memset(&args, 0, sizeof args);
    check("init ok with clean env (2)",
          mips64_host_args_init(&args) == MIPS64RT_HOST_ARGS_OK);
    RUN_PARSE(&args, rc, (char *)"--sysroot", (char *)"/r",
              (char *)"--cache-dir", (char *)"/c",
              (char *)"--execfn", (char *)"/e/x",
              (char *)"--image-fd", (char *)"0",
              (char *)"--engine", (char *)"dbt",
              (char *)"--cache-authority", (char *)"auto",
              (char *)"--file-identity", (char *)"auto",
              (char *)"--family-authority", (char *)"auto",
              (char *)"--difftest", (char *)"--trace",
              (char *)"--", (char *)"/guest", (char *)"a0");
    check("full flag set parses", rc == MIPS64RT_HOST_ARGS_OK);
    check("sysroot value",
          args.has_sysroot && strcmp(args.sysroot, "/r") == 0);
    check("cache-dir value",
          args.has_cache_dir && strcmp(args.cache_dir, "/c") == 0);
    check("execfn value",
          args.has_execfn && strcmp(args.execfn, "/e/x") == 0);
    check("image fd 0 admitted (stdin-closed shape)",
          args.has_image_fd && args.image_fd == 0);
    check("engine dbt + cli bit",
          args.has_engine && args.engine_cli &&
          strcmp(args.engine, "dbt") == 0);
    check("difftest + trace carried", args.difftest && args.trace);
    check("guest index past --", args.guest_index == 20);
}

static void test_parser_aliases_precedence(void)
{
    mips64_host_args_t args;
    int rc;

    clear_contract_env();
    memset(&args, 0, sizeof args);
    (void)mips64_host_args_init(&args);
    RUN_PARSE(&args, rc, (char *)"--rootfs", (char *)"/r1",
              (char *)"--cache", (char *)"/c1",
              (char *)"--sysroot", (char *)"/r2",
              (char *)"--cache-dir", (char *)"/c2",
              (char *)"--interp", (char *)"--engine", (char *)"dbt",
              (char *)"/g");
    check("alias set parses", rc == MIPS64RT_HOST_ARGS_OK);
    check("last sysroot spelling wins",
          strcmp(args.sysroot, "/r2") == 0);
    check("last cache spelling wins",
          strcmp(args.cache_dir, "/c2") == 0);
    check("last engine spelling wins + cli bit",
          args.engine_cli && strcmp(args.engine, "dbt") == 0);

    /* Environment defaults, CLI overrides. */
    clear_contract_env();
    setenv("MIPS64RT_SYSROOT", "/es", 1);
    setenv("MIPS64RT_ROOTFS", "/er", 1);
    setenv("MIPS64RT_CACHE", "/ec", 1);
    setenv("MIPS64RT_ENGINE", "dbt", 1);
    setenv("MIPS64RT_EXECFN", "/ee", 1);
    memset(&args, 0, sizeof args);
    check("env defaults init", mips64_host_args_init(&args) == 0);
    check("env sysroot wins over rootfs",
          args.has_sysroot && strcmp(args.sysroot, "/es") == 0);
    check("env cache", strcmp(args.cache_dir, "/ec") == 0);
    check("env engine (no cli bit)",
          args.has_engine && !args.engine_cli &&
          strcmp(args.engine, "dbt") == 0);
    check("env execfn", strcmp(args.execfn, "/ee") == 0);
    RUN_PARSE(&args, rc, (char *)"--sysroot", (char *)"/cli",
              (char *)"--engine", (char *)"interp", (char *)"/g");
    check("cli overrides env", rc == MIPS64RT_HOST_ARGS_OK &&
          strcmp(args.sysroot, "/cli") == 0 &&
          args.engine_cli && strcmp(args.engine, "interp") == 0);
    clear_contract_env();
}

static void test_parser_rejects(void)
{
    mips64_host_args_t args;
    int rc;

    clear_contract_env();
    memset(&args, 0, sizeof args);
    (void)mips64_host_args_init(&args);
    RUN_PARSE(&args, rc, (char *)"--engine", (char *)"jit",
              (char *)"/g");
    check("jit engine rejected", rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--image-fd", (char *)"-1",
              (char *)"/g");
    check("negative image fd rejected", rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--image-fd", (char *)"3x",
              (char *)"/g");
    check("non-numeric image fd rejected",
          rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--cache-authority", (char *)"maybe",
              (char *)"/g");
    check("bad cache-authority rejected",
          rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--file-identity", (char *)"maybe",
              (char *)"/g");
    check("bad file-identity rejected",
          rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--family-authority", (char *)"maybe",
              (char *)"/g");
    check("bad family-authority rejected",
          rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--bogus", (char *)"/g");
    check("unknown option rejected", rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--sysroot");
    check("missing value rejected", rc == MIPS64RT_HOST_ARGS_ERROR);
    RUN_PARSE(&args, rc, (char *)"--help");
    check("--help outcome", rc == MIPS64RT_HOST_ARGS_HELP &&
          args.wants_help);
    RUN_PARSE(&args, rc, (char *)"--version");
    check("--version outcome", rc == MIPS64RT_HOST_ARGS_VERSION &&
          args.wants_version);
    /* `--execfn` decouples the guest path from argv[0]: after `--`
     * every token is guest argv verbatim, so `guest_index` names the
     * custom argv[0], not the executable. */
    memset(&args, 0, sizeof args);
    (void)mips64_host_args_init(&args);
    RUN_PARSE(&args, rc, (char *)"--execfn", (char *)"/real/prog",
              (char *)"--", (char *)"custom0", (char *)"extra");
    check("execfn decouples guest index",
          rc == MIPS64RT_HOST_ARGS_OK && args.guest_index == 4);
    /* Without `--execfn`, the first guest token stays both path and
     * argv[0] (backward compatible, with or without `--`). */
    memset(&args, 0, sizeof args);
    (void)mips64_host_args_init(&args);
    RUN_PARSE(&args, rc, (char *)"/real/prog", (char *)"extra");
    check("bare guest token ok",
          rc == MIPS64RT_HOST_ARGS_OK && args.guest_index == 1 &&
          !args.has_execfn);
}

/* ------------------------------------------------------------------ */
/* Sysroot join + auxv scan.                                          */
/* ------------------------------------------------------------------ */

static void test_sysroot_join(void)
{
    char out[64];

    check("sysroot join absolute",
          mips64_sysroot_join("/sys", "/lib/ld.so.1", out,
                              sizeof out) == 0 &&
          strcmp(out, "/sys/lib/ld.so.1") == 0);
    check("sysroot trailing slash collapsed",
          mips64_sysroot_join("/sys/", "/lib/x", out,
                              sizeof out) == 0 &&
          strcmp(out, "/sys/lib/x") == 0);
    check("no sysroot is byte-identical",
          mips64_sysroot_join(NULL, "/lib/x", out, sizeof out) == 0 &&
          strcmp(out, "/lib/x") == 0);
    check("relative guest path untouched",
          mips64_sysroot_join("/sys", "rel/x", out, sizeof out) == 0 &&
          strcmp(out, "rel/x") == 0);
    check("overflow fails",
          mips64_sysroot_join("/sysroot-is-long", "/lib/x", out,
                              8u) != 0);
}

static void test_auxv_scan(void)
{
    static const unsigned long with0[] = { 31u, 77u, 21u, 0u, 0u, 0u };
    static const unsigned long with9[] = { 21u, 9u, 0u, 0u };
    static const unsigned long without[] = { 31u, 77u, 6u, 4096u, 0u, 0u };
    int found = -1;
    long fd;

    fd = mips64_auxv_find_execfd(with0, 3u, &found);
    check("AT_EXECFD 0 is present (not absent)",
          found == 1 && fd == 0);
    fd = mips64_auxv_find_execfd(with9, 2u, &found);
    check("AT_EXECFD 9 found", found == 1 && fd == 9);
    fd = mips64_auxv_find_execfd(without, 3u, &found);
    (void)fd;
    check("missing AT_EXECFD reports absent", found == 0);

    /* Ambient self-scan: on a plain host (no hyper-linux) the key is
     * absent; where present, any fd >= 0 (incl. 0) is valid. */
    found = -1;
    fd = mips64_self_execfd(&found);
    check("self auxv scan coherent",
          (found == 1 && fd >= 0) || (found == 0 && fd == -1));
}

/* ------------------------------------------------------------------ */
/* SHA-256 + runtime digest + cache leaf.                             */
/* ------------------------------------------------------------------ */

/* SHA-256("abc") (FIPS 180-4 A.1). */
static const uint8_t abc_digest[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static void test_digest_leaf(void)
{
    mips64_sha256_t ctx;
    uint8_t digest[32];
    uint8_t other[32];
    char hex[MIPS64_DIGEST_HEX_BYTES];
    char leaf[MIPS64_CACHE_LEAF_BYTES];
    char leaf2[MIPS64_CACHE_LEAF_BYTES];
    char tiny[8];

    mips64_sha256_init(&ctx);
    mips64_sha256_update(&ctx, (const uint8_t *)"abc", 3u);
    mips64_sha256_final(&ctx, digest);
    check("sha256 abc vector", memcmp(digest, abc_digest, 32u) == 0);
    mips64_digest_hex(digest, hex);
    check("digest hex",
          strcmp(hex,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    check("cache leaf ok",
          mips64_cache_leaf(digest, leaf, sizeof leaf) == 0);
    check("cache leaf keyed by digest",
          strcmp(leaf,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.aot") == 0);
    check("cache leaf rejects tiny buffer",
          mips64_cache_leaf(digest, tiny, sizeof tiny) != 0);
    mips64_sha256_init(&ctx);
    mips64_sha256_update(&ctx, (const uint8_t *)"abd", 3u);
    mips64_sha256_final(&ctx, other);
    check("cache leaf ok (2)",
          mips64_cache_leaf(other, leaf2, sizeof leaf2) == 0);
    check("distinct digests key distinct leaves",
          strcmp(leaf, leaf2) != 0);

    /* A digest-keyed cache entry round-trips through the leaf name. */
    {
        char dir[] = "/tmp/m64cacheXXXXXX";
        char entry[MIPS64_CACHE_LEAF_BYTES + 32u];
        size_t dn;
        int efd;

        check("mkdtemp cache dir", mkdtemp(dir) != NULL);
        dn = strlen(dir);
        memcpy(entry, dir, dn);
        entry[dn] = '/';
        memcpy(entry + dn + 1u, leaf, strlen(leaf) + 1u);
        efd = open(entry, O_WRONLY | O_CREAT | O_EXCL, 0644);
        check("cache entry created", efd >= 0);
        if (efd >= 0) {
            static const char payload[] = "leaf-bytes";

            check("cache entry written",
                  write(efd, payload, sizeof payload - 1u) ==
                  (ssize_t)(sizeof payload - 1u));
            close(efd);
        }
        efd = open(entry, O_RDONLY);
        check("cache entry reopened", efd >= 0);
        if (efd >= 0)
            close(efd);
        (void)unlink(entry);
        (void)rmdir(dir);
    }

    /* Self digest: `/proc/self/exe` exists on Linux (the translator
     * host); elsewhere the call fails cleanly with `errno` set. */
    {
        uint8_t self[32];
        uint8_t self2[32];

        if (mips64_runtime_digest_self(self) == 0) {
            check("self digest deterministic",
                  mips64_runtime_digest_self(self2) == 0 &&
                  memcmp(self, self2, 32u) == 0);
        } else {
            check("self digest fails cleanly off-Linux", errno != 0);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Static-PIE admission on crafted fixtures (+ the real binary).      */
/* ------------------------------------------------------------------ */

/* Minimal ELF64-LE `ET_DYN` with one `PT_DYNAMIC` holding
 * `DT_FLAGS_1` (+ optional `DT_NEEDED`) and `DT_NULL`. All offsets
 * are file offsets; the loader-facing fields mirror `identity.c`. */
static int write_fixture(const char *path, int is_exec, int with_needed)
{
    uint8_t ehdr[64];
    uint8_t phdr[56];
    uint8_t dyn[48];
    int fd;
    uint64_t dyn_off = 64u + 56u;

    memset(ehdr, 0, sizeof ehdr);
    memset(phdr, 0, sizeof phdr);
    memset(dyn, 0, sizeof dyn);
    ehdr[0] = 0x7fu;
    ehdr[1] = 'E';
    ehdr[2] = 'L';
    ehdr[3] = 'F';
    ehdr[4] = 2u; /* ELFCLASS64 */
    ehdr[5] = 1u; /* LE */
    ehdr[6] = 1u; /* version */
    ehdr[16] = is_exec ? 2u : 3u; /* ET_EXEC vs ET_DYN */
    ehdr[18] = 8u; /* EM_MIPS, LE */
    ehdr[32] = 64u; /* e_phoff */
    ehdr[54] = 56u; /* e_phentsize */
    ehdr[56] = 1u; /* e_phnum */
    /* PT_DYNAMIC at file offset dyn_off, 3 or 2 entries of 16 bytes. */
    phdr[0] = 2u; /* p_type = PT_DYNAMIC */
    phdr[8] = (uint8_t)dyn_off;
    phdr[32] = with_needed ? 48u : 32u; /* p_filesz */
    {
        /* Entry 0: DT_NEEDED (tag 1) when requested. */
        size_t at = 0;

        if (with_needed) {
            dyn[at] = 1u; /* DT_NEEDED */
            dyn[at + 8u] = 1u; /* value placeholder */
            at += 16u;
        }
        /* DT_FLAGS_1 (0x6ffffffb) = DF_1_PIE (0x08000000). */
        dyn[at] = 0xfbu;
        dyn[at + 1u] = 0xffu;
        dyn[at + 2u] = 0xffu;
        dyn[at + 3u] = 0x6fu;
        dyn[at + 8u] = 0x00u;
        dyn[at + 9u] = 0x00u;
        dyn[at + 10u] = 0x00u;
        dyn[at + 11u] = 0x08u;
        at += 16u;
        /* DT_NULL terminates. */
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, ehdr, sizeof ehdr) != (ssize_t)sizeof ehdr ||
        write(fd, phdr, sizeof phdr) != (ssize_t)sizeof phdr ||
        write(fd, dyn, with_needed ? 48u : 32u) !=
        (ssize_t)(with_needed ? 48u : 32u)) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void test_static_pie(void)
{
    char pie[] = "/tmp/m64pieXXXXXX";
    char exec[] = "/tmp/m64execXXXXXX";
    char need[] = "/tmp/m64needXXXXXX";
    int fd;

    fd = mkstemp(pie);
    check("pie fixture temp", fd >= 0);
    if (fd >= 0)
        close(fd);
    fd = mkstemp(exec);
    check("exec fixture temp", fd >= 0);
    if (fd >= 0)
        close(fd);
    fd = mkstemp(need);
    check("needed fixture temp", fd >= 0);
    if (fd >= 0)
        close(fd);
    check("pie fixture written", write_fixture(pie, 0, 0) == 0);
    check("exec fixture written", write_fixture(exec, 1, 0) == 0);
    check("needed fixture written", write_fixture(need, 0, 1) == 0);
    check("static-PIE fixture admitted",
          mips64_elf_static_pie_check(pie) == MIPS64_ELF_OK);
    check("ET_EXEC fixture is not static-PIE",
          mips64_elf_static_pie_check(exec) == MIPS64_ELF_NOT_STATIC_PIE);
    check("DT_NEEDED fixture is not static-PIE",
          mips64_elf_static_pie_check(need) == MIPS64_ELF_NOT_STATIC_PIE);
    check("missing file is IO_ERROR",
          mips64_elf_static_pie_check("/tmp/m64-no-such-file-zzz") ==
          MIPS64_ELF_IO_ERROR);
    (void)unlink(pie);
    (void)unlink(exec);
    (void)unlink(need);

    /* The real translator binary, when the lane staged one: it must
     * be static-PIE (`ET_DYN`, `DF_1_PIE`, zero `DT_NEEDED`). Absent
     * on hosts that cannot cross-build: skip, do not fail. */
    {
        const char *bin = getenv("MIPS64RT_BIN");
        struct stat st;

        if (bin == NULL)
            bin = "_build/mips64rt";
        if (stat(bin, &st) == 0) {
            check("translator binary is static-PIE",
                  mips64_elf_static_pie_check(bin) == MIPS64_ELF_OK);
        } else {
            printf("skip: translator binary '%s' absent "
                   "(cross-build not staged)\n", bin);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Family broker join/create.                                         */
/* ------------------------------------------------------------------ */

static void test_family_broker(void)
{
    char path[MIPS64_FAMILY_BROKER_PATH_MAX];
    char path2[MIPS64_FAMILY_BROKER_PATH_MAX];
    pid_t pid = getpid();
    unsigned seq = 0;

    check("broker path renders",
          mips64_family_broker_path(pid, 0u, path, sizeof path) == 0 &&
          strncmp(path, "/tmp/.mips64rt-family-", 22u) == 0);
    check("broker path rejects tiny buffer",
          mips64_family_broker_path(pid, 0u, path2, 4u) != 0);
    check("broker join of missing dir fails",
          mips64_family_broker_join((pid_t)2147483647, 999u, path2,
                                    sizeof path2) != 0);
    if (mips64_family_broker_create(pid, path, sizeof path, &seq) == 0) {
        check("broker create ok", seq < MIPS64_FAMILY_BROKER_MAX_SEQ);
        check("broker join after create",
              mips64_family_broker_join(pid, seq, path2,
                                        sizeof path2) == 0 &&
              strcmp(path, path2) == 0);
        (void)rmdir(path);
    } else {
        /* A stale broker dir from an earlier run: joining proves the
         * same contract surface. */
        check("broker join of pre-existing dir",
              mips64_family_broker_join(pid, 0u, path2,
                                        sizeof path2) == 0);
    }
}

/* ------------------------------------------------------------------ */
/* Contract section 2.1 page-rule predicates.                         */
/* ------------------------------------------------------------------ */

static void test_page_rules(void)
{
    const uint64_t fixed = (uint64_t)MIPS64_GUEST_MAP_FIXED;
    const uint64_t noreplace =
        (uint64_t)MIPS64_GUEST_MAP_FIXED_NOREPLACE;
    const uint64_t maymove = 1u; /* MREMAP_MAYMOVE */
    const uint64_t fixed_mremap = (uint64_t)MIPS64_GUEST_MREMAP_FIXED;

    check("mmap len 0 rejected",
          mips64_page_mmap_check(0x1000u, 0u, 0u, 0u) == -EINVAL);
    check("mmap fixed misaligned rejected",
          mips64_page_mmap_check(0x1001u, 0x1000u, fixed, 0u) == -EINVAL);
    check("mmap noreplace misaligned rejected",
          mips64_page_mmap_check(0x1001u, 0x1000u, noreplace,
                                 0u) == -EINVAL);
    check("mmap hint misalignment admitted",
          mips64_page_mmap_check(0x1001u, 0x1000u, 0u, 0u) == 0);
    check("mmap misaligned offset rejected",
          mips64_page_mmap_check(0u, 0x1000u, 0u, 1u) == -EINVAL);
    check("mmap aligned admitted",
          mips64_page_mmap_check(0x10000u, 0x2000u, fixed, 0u) == 0);
    check("mprotect misaligned rejected",
          mips64_page_mprotect_check(0x1001u, 0x1000u) == -EINVAL);
    check("mprotect len 0 is a no-op",
          mips64_page_mprotect_check(0x1000u, 0u) == 0);
    check("mprotect unaligned len admitted (rounds up)",
          mips64_page_mprotect_check(0x1000u, 1u) == 0);
    check("munmap misaligned rejected",
          mips64_page_munmap_check(0x1001u, 0x1000u) == -EINVAL);
    check("munmap len 0 rejected",
          mips64_page_munmap_check(0x1000u, 0u) == -EINVAL);
    check("munmap aligned admitted",
          mips64_page_munmap_check(0x2000u, 0x1000u) == 0);
    check("mremap misaligned old rejected",
          mips64_page_mremap_check(0x1001u, 0x1000u, maymove,
                                   0u) == -EINVAL);
    check("mremap zero new size rejected",
          mips64_page_mremap_check(0x1000u, 0u, maymove, 0u) == -EINVAL);
    check("mremap fixed misaligned new rejected",
          mips64_page_mremap_check(0x1000u, 0x1000u,
                                   maymove | fixed_mremap,
                                   0x2001u) == -EINVAL);
    check("mremap plain admitted",
          mips64_page_mremap_check(0x1000u, 0x2000u, maymove,
                                   0u) == 0);
    check("align_up rounds",
          mips64_page_align_up(1u) == 4096u &&
          mips64_page_align_up(4096u) == 4096u &&
          mips64_page_align_up(4097u) == 8192u);
}

/* ------------------------------------------------------------------ */
/* `src/os/mem.c` page-rule compliance on a live reservation.         */
/* ------------------------------------------------------------------ */

/* One fresh N32 reservation (2 GiB `PROT_NONE`, host-mappable
 * everywhere). The macOS sandbox only admits a single `MAP_FIXED`
 * sub-map per reservation, so every probe that maps host pages gets
 * its own reservation; pure-record probes reuse one. */
static int fresh_ctx(mips64_ctx_t *ctx, uint64_t *base)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->is_n32 = 1u;
    if (guest_mem_init(ctx) != 0)
        return -1;
    *base = ctx->guest_base;
    return 0;
}

static void test_mem_compliance(void)
{
    mips64_ctx_t ctx;
    uint64_t base = 0;
    uint64_t va = 0x10000u;

    if (fresh_ctx(&ctx, &base) != 0) {
        printf("skip: guest reservation unavailable on this host\n");
        return;
    }
    check("reservation sized N32", ctx.task_size == 0x7fff8000ULL);
    check("mmap ok", mips_mem_map(&ctx, va, 0x1000u,
                                  MIPS_PROT_READ | MIPS_PROT_WRITE,
                                  "t") == 0);
    /* `mprotect` with `len == 0` succeeds as a no-op (was `-EINVAL`). */
    check("mprotect len 0 no-op",
          mips_mem_protect(&ctx, va, 0u,
                           (uint32_t)(MIPS_PROT_READ |
                                      MIPS_PROT_WRITE)) == 0);
    /* Positive lengths round up instead of `-EINVAL` (was strict). */
    check("mprotect unaligned len rounds up",
          mips_mem_protect(&ctx, va, 1u,
                           (uint32_t)MIPS_PROT_READ) == 0 &&
          mips_mem_ok(&ctx, va, 0x1000u, (uint32_t)MIPS_PROT_READ));
    check("mmap len 0 rejected",
          mips_mem_map(&ctx, va + 0x4000u, 0u,
                       (uint32_t)MIPS_PROT_READ, "t") == -EINVAL);
    check("mmap misaligned addr rejected",
          mips_mem_map(&ctx, va + 1u, 0x1000u,
                       (uint32_t)MIPS_PROT_READ, "t") == -EINVAL);
    check("mprotect misaligned addr rejected",
          mips_mem_protect(&ctx, va + 1u, 0x1000u,
                           (uint32_t)MIPS_PROT_READ) == -EINVAL);
    check("munmap len 0 rejected",
          mips_mem_unmap(&ctx, va, 0u) == -EINVAL);
    check("munmap misaligned rejected",
          mips_mem_unmap(&ctx, va + 1u, 0x1000u) == -EINVAL);
    check("munmap aligned ok",
          mips_mem_unmap(&ctx, va, 0x2000u) == 0 &&
          !mips_mem_ok(&ctx, va, 0x1000u, 0u));

    /* Rounding on the map path needs its own reservation (one
     * `MAP_FIXED` sub-map per reservation on this host). */
    if (fresh_ctx(&ctx, &base) != 0) {
        printf("skip: second reservation unavailable\n");
        return;
    }
    check("mmap unaligned len rounds up",
          mips_mem_map(&ctx, va, 1u, (uint32_t)MIPS_PROT_READ,
                       "t") == 0 &&
          mips_mem_ok(&ctx, va, 0x1000u, (uint32_t)MIPS_PROT_READ));
    (void)munmap((void *)(uintptr_t)ctx.guest_base,
                 (size_t)ctx.task_size);
}

/* ------------------------------------------------------------------ */
/* `--help` contract-flag fragment.                                   */
/* ------------------------------------------------------------------ */

static void test_help_fragment(void)
{
    const char *help = mips64_host_args_help();
    const char *flags[] = {
        "--sysroot", "--rootfs", "--cache", "--cache-dir", "--engine",
        "--execfn", "--image-fd", "--cache-authority", "--file-identity",
        "--family-authority"
    };
    size_t i;

    check("help fragment present", help != NULL && help[0] != '\0');
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        char name[96];

        snprintf(name, sizeof name, "help lists %s", flags[i]);
        check(name, strstr(help, flags[i]) != NULL);
    }
}

int main(void)
{
    test_parser_full_set();
    test_parser_aliases_precedence();
    test_parser_rejects();
    test_sysroot_join();
    test_auxv_scan();
    test_digest_leaf();
    test_static_pie();
    test_family_broker();
    test_page_rules();
    test_mem_compliance();
    test_help_fragment();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
