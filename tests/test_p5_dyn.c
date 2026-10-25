/*
 * tests/test_p5_dyn.c — Phase 5 dynamic-linking gate guest (lane L5b).
 *
 * Covers the L5b task card: dynamic dlopen/dlsym of p5_dynlib.so
 * (built -shared -fPIC alongside, one per ABI/endian variant),
 * _Thread_local TLS access across the library boundary, shared-library
 * calls (printf/qsort via the target libc), argv/envp/auxv self-checks
 * (AT_ENTRY against the ELF e_entry of /proc/self/exe, AT_BASE != 0,
 * AT_PAGESZ/AT_CLKTCK), and /proc/self/{maps,cmdline,exe,stat,auxv}
 * content checks (guest mappings present, argv[0] present, no host
 * paths). Output is deterministic only: booleans and argv/env-derived
 * bytes, no raw pointers or ASLR-dependent values; the qsort array is
 * sorted before printing.
 *
 * Variants like the P4 gate (test names p5-n64le etc.): N64/N32 x
 * LE/BE, all dynamic, -no-pie ET_EXEC so the recorded e_entry is the
 * absolute entry the kernel (and the translator) reports in AT_ENTRY:
 *   mips64el-linux-gnuabi64-gcc -O1 -std=c11 -Werror=vla -pedantic \
 *     -Wall -Wextra -Werror -no-pie -o p5-n64le tests/test_p5_dyn.c \
 *     -Wl,--dynamic-linker,/x/sysroot/n64le/lib/ld.so.1 \
 *     -Wl,-rpath,/x/sysroot/n64le/lib -ldl
 * (N32 adds -mabi=n32; big-endian uses mips64-linux-gnuabi64-gcc with
 * the matching sysroot; see tests/run_p5_busybox.sh for the full
 * recipe.) The .so path is derived from argv[0] so identical argv
 * gives identical output under qemu-mips*, --interp, and --dbt.
 *
 * Protocol: "P5-PASS <name>", "P5-FAIL <name> ...", and a final
 * "P5-RESULT: PASS|FAIL". Exit 0 iff zero failures.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#if defined(_MIPS_SIM) && defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define P5_ABI "N64"
#define P5_CLASS64 1
#else
#define P5_ABI "N32"
#define P5_CLASS64 0
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define P5_ENDIAN "le"
#else
#define P5_ENDIAN "be"
#endif

extern char **environ;

_Thread_local int main_tls = 7;

static unsigned g_pass = 0;
static unsigned g_fail = 0;

#define P5_CHECK(name, cond) do { \
    if (cond) { \
        g_pass++; \
        printf("P5-PASS %s\n", name); \
    } else { \
        g_fail++; \
        printf("P5-FAIL %s\n", name); \
    } \
} while (0)

/* "<dir-of-argv0>/p5_dynlib-<abi><endian>.so", or the bare filename
 * when argv[0] carries no directory. snprintf only, no strcat. */
static void so_path(const char *argv0, char *out, size_t n)
{
    const char *slash = strrchr(argv0, '/');

    if (slash != NULL) {
        size_t dlen = (size_t)(slash - argv0);

        snprintf(out, n, "%.*s/p5_dynlib-%s%s.so", (int)dlen, argv0,
                 P5_ABI, P5_ENDIAN);
    } else {
        snprintf(out, n, "p5_dynlib-%s%s.so", P5_ABI, P5_ENDIAN);
    }
}

/* Fetch a dlsym result without a data/function pointer cast. */
static void sym_copy(void *dst_fn, size_t fn_size, void *sym)
{
    size_t n = fn_size < sizeof sym ? fn_size : sizeof sym;

    memcpy(dst_fn, &sym, n);
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    if (x < y) {
        return -1;
    }
    if (x > y) {
        return 1;
    }
    return 0;
}

/* e_entry recorded in /proc/self/exe, honoring EI_DATA. Printed
 * nowhere; only compared against getauxval(AT_ENTRY). */
static int exe_entry(unsigned long long *out)
{
    unsigned char h[64];
    char path[4096];
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1U);
    FILE *f;
    size_t i;
    size_t off = 24U;
    unsigned long long v = 0ULL;

    if (n < 0) {
        return -1;
    }
    path[n] = '\0';
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    if (fread(h, 1U, sizeof h, f) != sizeof h) {
        fclose(f);
        return -1;
    }
    fclose(f);
    if (h[0] != 0x7fU || h[1] != (unsigned char)'E' ||
        h[2] != (unsigned char)'L' || h[3] != (unsigned char)'F') {
        return -1;
    }
    if (h[4] != 1U && h[4] != 2U) {
        return -1;
    }
    if (h[5] != 1U && h[5] != 2U) {
        return -1;
    }
    if (h[4] == 1U) {
        if (h[5] == 1U) {
            for (i = 0U; i < 4U; i++) {
                v |= (unsigned long long)h[off + i] << (8U * i);
            }
        } else {
            for (i = 0U; i < 4U; i++) {
                v = (v << 8U) | (unsigned long long)h[off + i];
            }
        }
    } else {
        if (h[5] == 1U) {
            for (i = 0U; i < 8U; i++) {
                v |= (unsigned long long)h[off + i] << (8U * i);
            }
        } else {
            for (i = 0U; i < 8U; i++) {
                v = (v << 8U) | (unsigned long long)h[off + i];
            }
        }
    }
    *out = v;
    return 0;
}

/* Digest of /proc/self/maps: readable-executable and writable guest
 * mappings must exist, and no line may name a translator-host path
 * (the translator serves maps without pathnames; qemu names only
 * guest-absolute paths, so host markers agree on both). */
static void check_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int rx = 0;
    int rw = 0;
    int nohost = 1;

    if (f == NULL) {
        P5_CHECK("maps-open", 0);
        return;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        if (strstr(line, "r-xp") != NULL) {
            rx = 1;
        }
        if (strstr(line, "rw-p") != NULL) {
            rw = 1;
        }
        if (strstr(line, "mips64rt") != NULL ||
            strstr(line, "qemu") != NULL ||
            strstr(line, "/b/") != NULL ||
            strstr(line, "/w/") != NULL ||
            strstr(line, "/nix/") != NULL) {
            nohost = 0;
        }
    }
    fclose(f);
    printf("maps: rx=%d rw=%d nohost=%d\n", rx, rw, nohost);
    P5_CHECK("maps-rx", rx);
    P5_CHECK("maps-rw", rw);
    P5_CHECK("maps-nohost", nohost);
}

/* argv joined with '|', compared against the expectation built from
 * argv itself; identical argv gives identical bytes everywhere. */
static void check_cmdline(int argc, char **argv)
{
    FILE *f = fopen("/proc/self/cmdline", "r");
    char buf[4097];
    char want[4097];
    size_t n;
    size_t w = 0U;
    int i;

    if (f == NULL) {
        P5_CHECK("cmdline-open", 0);
        return;
    }
    n = fread(buf, 1U, sizeof buf - 1U, f);
    fclose(f);
    while (n > 0U && buf[n - 1U] == '\0') {
        n--;
    }
    /* want mirrors the raw cmdline bytes: argv joined with NUL. */
    for (i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]);

        if (i > 0 && w < sizeof want - 1U) {
            want[w++] = '\0';
        }
        if (w + len >= sizeof want - 1U) {
            break;
        }
        memcpy(want + w, argv[i], len);
        w += len;
    }
    printf("cmdline:");
    for (i = 0; (size_t)i < n; i++) {
        putchar(buf[i] == '\0' ? '|' : buf[i]);
    }
    putchar('\n');
    P5_CHECK("cmdline-match", n == w && memcmp(buf, want, n) == 0);
}

static void check_exe(const char *argv0)
{
    char buf[4096];
    ssize_t n;

    n = readlink("/proc/self/exe", buf, sizeof buf - 1U);
    if (n < 0) {
        P5_CHECK("exe-readlink", 0);
        return;
    }
    buf[n] = '\0';
    printf("exe: %s\n", buf);
    P5_CHECK("exe-readlink", 1);
    P5_CHECK("exe-match", strcmp(buf, argv0) == 0);
}

static void check_stat(const char *argv0)
{
    FILE *f = fopen("/proc/self/stat", "r");
    char line[512];
    char *l;
    char *r;
    const char *base;

    if (f == NULL) {
        P5_CHECK("stat-open", 0);
        return;
    }
    if (fgets(line, sizeof line, f) == NULL) {
        fclose(f);
        P5_CHECK("stat-read", 0);
        return;
    }
    fclose(f);
    l = strchr(line, '(');
    r = strchr(line, ')');
    if (l == NULL || r == NULL || r <= l + 1) {
        P5_CHECK("stat-parse", 0);
        return;
    }
    *r = '\0';
    base = strrchr(argv0, '/');
    base = base == NULL ? argv0 : base + 1;
    printf("stat: comm=%s\n", l + 1);
    P5_CHECK("stat-comm", strcmp(l + 1, base) == 0);
}

/* /proc/self/auxv AT_ENTRY must equal getauxval(AT_ENTRY). The entry
 * word width follows the guest (4 bytes N32, 8 bytes N64). */
static void check_auxv_file(void)
{
    FILE *f = fopen("/proc/self/auxv", "r");
    unsigned long tag;
    unsigned long val;
    unsigned long entry = getauxval(AT_ENTRY);
    int match = 0;

    if (f == NULL) {
        P5_CHECK("auxv-open", 0);
        return;
    }
    while (fread(&tag, sizeof tag, 1U, f) == 1U &&
           fread(&val, sizeof val, 1U, f) == 1U) {
        if (tag == (unsigned long)AT_ENTRY && val == entry &&
            entry != 0UL) {
            match = 1;
        }
        if (tag == (unsigned long)AT_NULL) {
            break;
        }
    }
    fclose(f);
    P5_CHECK("auxv-entry-match", match);
}

/* No LD_* or MIPS64RT_* variable may reach the guest (the loader
 * scrubs host-only env so ld.so never sees it). */
static void check_env(void)
{
    const char *sent = getenv("P5_SENTINEL");
    int scrub = 1;
    int i;

    if (sent == NULL) {
        P5_CHECK("env-sentinel", 0);
    } else {
        printf("env-sentinel: %s\n", sent);
        P5_CHECK("env-sentinel", strcmp(sent, "dyn-env-ok") == 0);
    }
    for (i = 0; environ[i] != NULL; i++) {
        if (strncmp(environ[i], "LD_", 3) == 0 ||
            strncmp(environ[i], "MIPS64RT_", 9) == 0) {
            scrub = 0;
        }
    }
    P5_CHECK("env-scrub", scrub);
}

int main(int argc, char **argv)
{
    char soname[4096];
    void *h;
    void *sym;
    int (*answer)(void) = NULL;
    int (*bump)(void) = NULL;
    int (*tls_get)(void) = NULL;
    void (*tls_set)(int) = NULL;
    const char *(*get_name)(void) = NULL;
    unsigned long long entry = 0ULL;
    unsigned long long entry_aux = (unsigned long long)getauxval(AT_ENTRY);
    unsigned long pagesz = getauxval(AT_PAGESZ);
    unsigned long clktck = getauxval(AT_CLKTCK);
    int data[8] = { 5, 3, 8, 1, 4, 7, 2, 6 };
    int want[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    int i;

    printf("P5-ABI: %s %s\n", P5_ABI, P5_ENDIAN);
    printf("hello p5dyn\n");
    so_path(argv[0], soname, sizeof soname);
    h = dlopen(soname, RTLD_NOW);
    if (h == NULL) {
        printf("dlopen-fail: %s\n", dlerror());
        printf("P5-RESULT: FAIL\n");
        return 1;
    }
    printf("dlopen: ok\n");
    P5_CHECK("dlopen", 1);
    sym = dlsym(h, "lib_answer");
    sym_copy(&answer, sizeof answer, sym);
    sym = dlsym(h, "lib_bump");
    sym_copy(&bump, sizeof bump, sym);
    sym = dlsym(h, "lib_tls_get");
    sym_copy(&tls_get, sizeof tls_get, sym);
    sym = dlsym(h, "lib_tls_set");
    sym_copy(&tls_set, sizeof tls_set, sym);
    sym = dlsym(h, "lib_name");
    sym_copy(&get_name, sizeof get_name, sym);
    P5_CHECK("dlsym", answer != NULL && bump != NULL &&
             tls_get != NULL && tls_set != NULL && get_name != NULL);
    if (answer == NULL || bump == NULL || tls_get == NULL ||
        tls_set == NULL || get_name == NULL) {
        printf("P5-RESULT: FAIL\n");
        return 1;
    }
    P5_CHECK("lib-answer", answer() == 41);
    P5_CHECK("lib-name", strcmp(get_name(), "p5_dynlib") == 0);
    printf("lib-name: %s\n", get_name());
    P5_CHECK("main-tls-init", main_tls == 7);
    main_tls = 9;
    P5_CHECK("main-tls-set", main_tls == 9);
    tls_set(100);
    P5_CHECK("lib-tls-bump", bump() == 101);
    P5_CHECK("lib-tls-get", tls_get() == 101);
    qsort(data, 8U, sizeof data[0], cmp_int);
    printf("sorted:");
    for (i = 0; i < 8; i++) {
        printf(" %d", data[i]);
    }
    putchar('\n');
    P5_CHECK("qsort", memcmp(data, want, sizeof data) == 0);
    printf("auxv: pagesz=%lu clktck=%lu entry=%d base=%d phdr=%d\n",
           pagesz, clktck, entry_aux != 0ULL ? 1 : 0,
           getauxval(AT_BASE) != 0UL ? 1 : 0,
           getauxval(AT_PHDR) != 0UL ? 1 : 0);
    P5_CHECK("auxv-consts", pagesz == 4096UL && clktck == 100UL);
    P5_CHECK("auxv-entry-nonzero", entry_aux != 0ULL);
    P5_CHECK("auxv-base-nonzero", getauxval(AT_BASE) != 0UL);
    if (exe_entry(&entry) == 0) {
        P5_CHECK("auxv-entry-self", entry != 0ULL && entry == entry_aux);
    } else {
        P5_CHECK("auxv-entry-self", 0);
    }
    check_cmdline(argc, argv);
    check_exe(argv[0]);
    check_maps();
    check_stat(argv[0]);
    check_auxv_file();
    check_env();
    printf("argc: %d\n", argc);
    P5_CHECK("argc", argc == 3);
    dlclose(h);
    if (g_fail == 0U) {
        printf("P5-RESULT: PASS\n");
        return 0;
    }
    printf("P5-RESULT: FAIL\n");
    return 1;
}
