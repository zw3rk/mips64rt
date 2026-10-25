/*
 * tests/test_h1_smc.c — Phase 7 self-modifying-code & W^X suite (lane H1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest-side C (libc allowed: this is the test, not the translator).
 * Built `-static` for N64/N32, LE and BE (`-mabi=64` / `-mabi=n32` with
 * gcc-mips64el-linux-gnuabi64 / gcc-mips64-linux-gnuabi64), executed
 * under qemu-mips64el / qemu-mipsn32el / qemu-mips64 / qemu-mipsn32
 * (golden) and under mips64rt --interp / --dbt (byte-identical stdout
 * plus exit code, 0 difftest divergences).
 *
 * Covers:
 *  - SMC rewrite on the guest stack: RWX the stack page, emit a leaf,
 *    warm it (so dbt caches the translation), patch the immediate,
 *    flush, re-execute and observe the new return value.
 *  - SMC rewrite on the heap (malloc + RWX) with the same warm/patch
 *    discipline.
 *  - SMC rewrite on an anonymous mmap plus mprotect page-version
 *    invalidation: RX -> RW -> patch -> RX must retire the stale
 *    translation.
 *  - munmap page-version invalidation: calling the unmapped address
 *    faults; reclaiming the same address with MAP_FIXED and emitting
 *    new code executes the new code (never the stale block).
 *  - W^X probe: an RX page executes and rejects stores; an RW data
 *    page rejects execution (guest data pages are never host-executable);
 *    promote (RW->RX) and demote (RX->RW) transitions take effect, so a
 *    cached RX translation must not survive demotion.
 *
 * Cache discipline: every rewrite or permission change is followed by an
 * explicit MIPS64r2 SYNCI sweep plus __builtin___clear_cache (which gcc
 * lowers to the same SYNCI loop / cacheflush), so re-execution observes
 * the new bytes on real hardware as well as under every engine.
 *
 * The emitted leaf is `addiu $v0,$zero,imm; jr $ra; nop` (ADDIU is a
 * valid MIPS64 word, sign-extending its 32-bit result), written as
 * 32-bit words through ordinary stores, so LE and BE guests get the
 * right byte order by construction (no endian ifdefs needed).
 *
 * stdout is deterministic by construction: only page-relative offsets
 * (si_addr - mapping base), si_code numbers, and return values are
 * printed — never absolute addresses.
 *
 * Build (inside the debian lane container, run_p6.sh style):
 *   mips64el-linux-gnuabi64-gcc -mabi=64 -static -O1 -std=c11 -Wall -Wextra \
 *       -o /tmp/h1-n64le tests/test_h1_smc.c            # N64 LE
 *   mips64el-linux-gnuabi64-gcc -mabi=n32 -static ...   # N32 LE
 *   mips64-linux-gnuabi64-gcc -mabi=64 -static ... -o ... # N64 BE
 *   mips64-linux-gnuabi64-gcc -mabi=n32 -static ...      # N32 BE
 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Matches MIPS64_PAGE_SIZE (src/core/cpu.h, frozen): the guest page the
 * translator maps, protects, and unmaps. */
#define PAGE 4096UL
#define WARM_ITERS 64
#define LEAF_BYTES 12u

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond, const char *detail)
{
    if (cond != 0) {
        g_pass++;
        printf("H1 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("H1 %s: FAIL %s\n", name, detail);
    }
}

/* ---- fault capture (one attempt per forked child) ---- */

static sigjmp_buf g_jb;
static volatile int g_fcode;
static volatile const void *g_faddr;
static const char *g_fbase; /* mapping base for offset computation */

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)uc;
    if (si != NULL) {
        g_fcode = si->si_code;
        g_faddr = si->si_addr;
    }
    siglongjmp(g_jb, 1);
}

static void install_segv(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("H1 setup: FAIL sigaction errno=%d\n", errno);
        exit(1);
    }
}

/* ---- tiny JIT: emit a leaf returning imm ---- */

#define H1_ADDIU_V0_ZERO 0x24020000u /* addiu $v0,$zero,imm (MIPS64: valid) */
#define H1_JR_RA 0x03e00008u         /* jr $ra */
#define H1_NOP 0x00000000u           /* nop (delay slot) */

static void emit_leaf(void *dst, uint32_t imm)
{
    uint32_t words[3];

    words[0] = H1_ADDIU_V0_ZERO | (imm & 0xffffu);
    words[1] = H1_JR_RA;
    words[2] = H1_NOP;
    memcpy(dst, words, sizeof(words));
}

/* SYNCI sweep over [p, p+n): __builtin___clear_cache lowers to the same
 * SYNCI loop on MIPS64r2; issuing one explicit pass first exercises the
 * raw instruction under interp/dbt as well. */
static void synci_range(void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p;
    uintptr_t e = a + n;

    __asm__ volatile ("sync" ::: "memory");
    for (; a < e; a += 4u) {
        uint32_t *q = (uint32_t *)(uintptr_t)a;

        __asm__ volatile ("synci 0(%0)" :: "r" (q));
    }
    __asm__ volatile ("" ::: "memory");
}

static void flush_code(void *p, size_t n)
{
    char *b = (char *)p;

    synci_range(b, n);
    __builtin___clear_cache(b, b + n);
}

typedef int (*h1_fn_t)(void);

/* Data address to callable pointer without a direct object-pointer to
 * function-pointer cast (rejected by -pedantic): the dlsym-manual
 * memcpy idiom, byte-identical on every MIPS ABI. */
static h1_fn_t to_fn(void *addr)
{
    h1_fn_t f;

    memcpy(&f, &addr, sizeof(f));
    return f;
}

static int call_code(h1_fn_t f)
{
    int (* volatile vf)(void) = f;

    return vf();
}

/* Execute f WARM_ITERS times; every call must return want. Warming the
 * target first forces dbt to cache the translation, so a later
 * rewrite genuinely tests SMC invalidation rather than cold compile. */
static void check_warm(const char *name, h1_fn_t f, int want)
{
    char detail[64];
    int i;
    int v = 0;

    for (i = 0; i < WARM_ITERS; i++) {
        v = call_code(f);
        if (v != want) {
            break;
        }
    }
    snprintf(detail, sizeof(detail), "ret=%d iters=%d", v, i);
    check(name, v == want && i == WARM_ITERS, detail);
}

/* Call the code at addr. Returns 1 on SIGSEGV (fills code_out and
 * off_out), 0 when the call returns (fills ret_out). */
static int attempt_call(void *addr, int *code_out, unsigned long *off_out,
                        int *ret_out)
{
    h1_fn_t volatile f = to_fn(addr);

    if (sigsetjmp(g_jb, 1) == 0) {
        *ret_out = f();
        return 0;
    }
    *code_out = g_fcode;
    *off_out = (unsigned long)((const char *)g_faddr - g_fbase);
    return 1;
}

/* Read or write *p. Returns 1 on SIGSEGV (fills code_out and off_out),
 * 0 when the access completes without faulting. */
static int attempt_rw(volatile unsigned char *p, int is_write, int *code_out,
                      unsigned long *off_out)
{
    if (sigsetjmp(g_jb, 1) == 0) {
        if (is_write != 0) {
            *p = (unsigned char)0xAA;
        } else {
            volatile unsigned char c = *p;

            (void)c;
        }
        return 0;
    }
    *code_out = g_fcode;
    *off_out = (unsigned long)((const char *)g_faddr - g_fbase);
    return 1;
}

/* Fork a child that calls addr. want_fault == 0 expects a return of
 * want_ret; want_fault == 1 expects a fault at want_off, with want_code
 * matched unless it is negative (any code, still printed for the golden
 * byte-compare). */
static void child_call_probe(const char *name, void *addr, int want_fault,
                             int want_code, unsigned long want_off,
                             int want_ret)
{
    pid_t pid;
    int st;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        check(name, 0, "fork failed");
        return;
    }
    if (pid == 0) {
        int code = 0;
        unsigned long off = 0UL;
        int ret = 0;
        int faulted = attempt_call(addr, &code, &off, &ret);
        int ok = faulted == want_fault &&
            (want_fault != 0 ? ((want_code < 0 || code == want_code) &&
                                off == want_off)
                             : (ret == want_ret));

        if (ok != 0) {
            if (want_fault != 0) {
                printf("H1 %s: PASS code=%d off=%lu\n", name, code, off);
            } else {
                printf("H1 %s: PASS ret=%d\n", name, ret);
            }
            _exit(0);
        }
        printf("H1 %s: FAIL fault=%d code=%d off=%lu ret=%d\n", name,
               faulted, code, off, ret);
        _exit(1);
    }
    if (waitpid(pid, &st, 0) != pid) {
        check(name, 0, "wait failed");
        return;
    }
    if (WIFEXITED(st) != 0 && WEXITSTATUS(st) == 0) {
        g_pass++;
    } else {
        g_fail++;
        printf("H1 %s: FAIL child-status=%d\n", name, st);
    }
}

/* Fork a child that performs one data access; same verdict discipline as
 * the P6 permission probes. */
static void child_rw_probe(const char *name, void *addr, int is_write,
                           int want_fault, int want_code,
                           unsigned long want_off)
{
    pid_t pid;
    int st;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        check(name, 0, "fork failed");
        return;
    }
    if (pid == 0) {
        int code = 0;
        unsigned long off = 0UL;
        int faulted = attempt_rw((volatile unsigned char *)addr, is_write,
                                 &code, &off);

        if (faulted == want_fault &&
            (want_fault == 0 ||
             (code == want_code && off == want_off))) {
            printf("H1 %s: PASS code=%d off=%lu\n", name, code, off);
            _exit(0);
        }
        printf("H1 %s: FAIL fault=%d code=%d off=%lu\n", name, faulted,
               code, off);
        _exit(1);
    }
    if (waitpid(pid, &st, 0) != pid) {
        check(name, 0, "wait failed");
        return;
    }
    if (WIFEXITED(st) != 0 && WEXITSTATUS(st) == 0) {
        g_pass++;
    } else {
        g_fail++;
        printf("H1 %s: FAIL child-status=%d\n", name, st);
    }
}

static void *xmap(unsigned long bytes)
{
    void *p = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        printf("H1 setup: FAIL mmap errno=%d\n", errno);
        exit(1);
    }
    return p;
}

static uintptr_t page_down(uintptr_t x)
{
    return x & ~(PAGE - 1UL);
}

/* ---- scenarios ---- */

#define STACK_WORDS 768u /* 3072 B < PAGE, page-aligned stack slot */

/* Rewrite on the guest stack: RWX the stack page, emit, warm, patch. */
static void t_stack_smc(void)
{
    _Alignas(4096) uint32_t buf[STACK_WORDS];
    uintptr_t pg = page_down((uintptr_t)buf);
    char detail[64];
    int r;

    if (mprotect((void *)pg, (size_t)PAGE,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        check("stack-protect", 0, "mprotect rwx failed");
        return;
    }
    check("stack-protect", 1, "rwx");
    emit_leaf(buf, 11u);
    flush_code(buf, LEAF_BYTES);
    check_warm("stack-exec-1", to_fn(buf), 11);
    emit_leaf(buf, 12u);
    flush_code(buf, LEAF_BYTES);
    r = call_code(to_fn(buf));
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("stack-rewrite", r == 12, detail);
    if (mprotect((void *)pg, (size_t)PAGE, PROT_READ | PROT_WRITE) != 0) {
        check("stack-restore", 0, "mprotect rw failed");
        return;
    }
    check("stack-restore", 1, "rw");
}

/* Rewrite on the heap: malloc + RWX, emit, warm, patch. */
static void t_heap_smc(void)
{
    char *raw = (char *)malloc((size_t)(3UL * PAGE));
    uintptr_t a;
    char *base;
    char detail[64];
    int r;

    if (raw == NULL) {
        check("heap-protect", 0, "malloc failed");
        return;
    }
    a = (((uintptr_t)raw) + PAGE - 1UL) & ~(PAGE - 1UL);
    base = (char *)(uintptr_t)a;
    if (mprotect(base, (size_t)(2UL * PAGE),
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        check("heap-protect", 0, "mprotect rwx failed");
        free(raw);
        return;
    }
    check("heap-protect", 1, "rwx");
    emit_leaf(base, 21u);
    flush_code(base, LEAF_BYTES);
    check_warm("heap-exec-1", to_fn(base), 21);
    emit_leaf(base, 22u);
    flush_code(base, LEAF_BYTES);
    r = call_code(to_fn(base));
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("heap-rewrite", r == 22, detail);
    free(raw);
}

/* Anonymous mmap plus mprotect page-version invalidation:
 * RX -> RW -> patch -> RX must retire the stale translation. */
static void t_mmap_smc(void)
{
    char *base = (char *)xmap(PAGE);
    char detail[64];
    int r;

    emit_leaf(base, 31u);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("mmap-protect-rx", 0, "mprotect rx failed");
        return;
    }
    check("mmap-protect-rx", 1, "rx");
    flush_code(base, LEAF_BYTES);
    check_warm("mmap-exec-1", to_fn(base), 31);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_WRITE) != 0) {
        check("mmap-rewrite-protect", 0, "mprotect rw failed");
        return;
    }
    emit_leaf(base, 32u);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("mmap-rewrite-protect", 0, "mprotect rx failed");
        return;
    }
    check("mmap-rewrite-protect", 1, "rw-patch-rx");
    flush_code(base, LEAF_BYTES);
    check_warm("mmap-mprotect-rewrite", to_fn(base), 32);
    r = call_code(to_fn(base));
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("mmap-rewrite-again", r == 32, detail);
    if (munmap(base, (size_t)PAGE) != 0) {
        check("mmap-unmap", 0, "munmap failed");
        return;
    }
    check("mmap-unmap", 1, "unmapped");
}

/* munmap page-version invalidation: the unmapped address faults;
 * reclaiming it with MAP_FIXED and emitting new code runs the new
 * code, never the stale cached block. */
static void t_munmap(void)
{
    char *base = (char *)xmap(PAGE);
    char *nb;
    char detail[64];
    int r;

    emit_leaf(base, 31u + 10u);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("munmap-protect-rx", 0, "mprotect rx failed");
        return;
    }
    check("munmap-protect-rx", 1, "rx");
    flush_code(base, LEAF_BYTES);
    r = call_code(to_fn(base));
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("munmap-exec-1", r == 41, detail);
    if (munmap(base, (size_t)PAGE) != 0) {
        check("munmap-unmap", 0, "munmap failed");
        return;
    }
    check("munmap-unmap", 1, "unmapped");
    g_fbase = base;
    child_call_probe("munmap-stale", base, 1, -1, 0UL, 0);
    nb = (char *)mmap(base, (size_t)PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (nb == MAP_FAILED) {
        nb = (char *)xmap(PAGE);
    }
    emit_leaf(nb, 42u);
    if (mprotect(nb, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("munmap-remap-protect", 0, "mprotect rx failed");
        return;
    }
    check("munmap-remap-protect", 1, "rx");
    flush_code(nb, LEAF_BYTES);
    check_warm("munmap-remap", to_fn(nb), 42);
    if (munmap(nb, (size_t)PAGE) != 0) {
        check("munmap-cleanup", 0, "munmap failed");
        return;
    }
    check("munmap-cleanup", 1, "unmapped");
}

/* W^X probe: RX executes and rejects stores; RW data rejects execution
 * (guest data pages are never host-executable); RW->RX promotion and
 * RX->RW demotion take effect, so a cached RX translation must not
 * survive demotion. */
static void t_wx(void)
{
    char *base = (char *)xmap(2UL * PAGE);
    char detail[64];
    int r;

    emit_leaf(base, 43u);
    emit_leaf(base + PAGE, 44u);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("wx-protect", 0, "mprotect rx failed");
        return;
    }
    check("wx-protect", 1, "rx-rw");
    flush_code(base, LEAF_BYTES);
    flush_code(base + PAGE, LEAF_BYTES);
    r = call_code(to_fn(base));
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("wx-rx-exec", r == 43, detail);
    g_fbase = base;
    child_rw_probe("wx-rx-write", base + 0x10, 1, 1, SEGV_ACCERR, 0x10UL);
    child_call_probe("wx-rw-exec", base + PAGE, 1, SEGV_ACCERR, PAGE, 0);
    if (mprotect(base + PAGE, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("wx-promote", 0, "mprotect rx failed");
        return;
    }
    check("wx-promote", 1, "rw-to-rx");
    flush_code(base + PAGE, LEAF_BYTES);
    check_warm("wx-promote-exec", to_fn(base + PAGE), 44);
    if (mprotect(base + PAGE, (size_t)PAGE, PROT_READ | PROT_WRITE) != 0) {
        check("wx-demote", 0, "mprotect rw failed");
        return;
    }
    check("wx-demote", 1, "rx-to-rw");
    child_call_probe("wx-demote-noexec", base + PAGE, 1, SEGV_ACCERR, PAGE,
                     0);
    if (munmap(base, (size_t)(2UL * PAGE)) != 0) {
        check("wx-cleanup", 0, "munmap failed");
        return;
    }
    check("wx-cleanup", 1, "unmapped");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    install_segv();
    printf("H1-SMC: start\n");
    t_stack_smc();
    t_heap_smc();
    t_mmap_smc();
    t_munmap();
    t_wx();
    printf("H1-SUMMARY: pass=%d fail=%d\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("H1-SMC-RESULT: PASS\n");
        return 0;
    }
    printf("H1-SMC-RESULT: FAIL\n");
    return 1;
}
