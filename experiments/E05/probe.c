// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 *
 * E05: LL/SC (32-bit) and LLD/SCD (64-bit) reservation semantics probe.
 *
 * Single-threaded sequences only: SC with no prior LL, LL value check,
 * tight LL/SC and LLD/SCD pairs, repeated SC, an ordinary store to the
 * same address or to the same 32-byte cache line between LL and SC, and
 * a getpid() syscall between LL and SC. Prints the exact SC success code
 * (1 = store committed, 0 = reservation lost) and memory after each step.
 * ERET cannot be executed from user mode (see FINDINGS.md: UNVERIFIED).
 *
 * Build (examples, static: qemu-user has no dynamic-loader sysroot):
 *   mips64el-linux-gnuabi64-gcc -mabi=64 -march=mips64r2 -O1 -static probe.c
 *   mips64el-linux-gnuabi64-gcc -mabi=n32 -march=mips64r2 -O1 -static probe.c
 * Run:
 *   qemu-mips64el ./probe-n64le; qemu-mipsn32el ./probe-n32le
 *   qemu-mips64 ./probe-n64be;   qemu-mipsn32 ./probe-n32be
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_MIPS_SIM) && defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define E05_ABI "N64"
#elif defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define E05_ABI "N32"
#else
#define E05_ABI "UNKNOWN"
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define E05_ENDIAN "LE"
#else
#define E05_ENDIAN "BE"
#endif

static int g_fail = 0;

#define E05_CHECK(cond, name) do { \
    printf("%s %s\n", (cond) ? "E05-PASS" : "E05-FAIL", (name)); \
    if (!(cond)) { g_fail++; } \
} while (0)

/* Target word plus a same-cache-line neighbour (offset +4, same 32B line). */
static struct {
    volatile uint32_t w0;
    volatile uint32_t w1;
} g32pair __attribute__((aligned(64)));

/* Target doubleword plus a same-cache-line neighbour (offset +8). */
static struct {
    volatile uint64_t d0;
    volatile uint64_t d1;
} g64pair __attribute__((aligned(64)));

static uint32_t ll32(volatile uint32_t *p)
{
    uint32_t v;
    __asm__ volatile("ll %0, 0(%1)" : "=r"(v) : "r"(p) : "memory");
    return v;
}

static uint32_t sc32(volatile uint32_t *p, uint32_t v)
{
    uint32_t s = v;
    __asm__ volatile("sc %0, 0(%1)" : "+r"(s) : "r"(p) : "memory");
    return s;
}

/* Tight LL/SC pair in one asm block: nothing can slip between the two. */
static uint32_t llsc32(volatile uint32_t *p, uint32_t nv, uint32_t *old)
{
    uint32_t o;
    uint32_t s = nv;
    __asm__ volatile(
        "ll %0, 0(%2)\n\t"
        "sc %1, 0(%2)"
        : "=&r"(o), "+r"(s) : "r"(p) : "memory");
    *old = o;
    return s;
}

static uint64_t lld64(volatile uint64_t *p)
{
    uint64_t v;
    __asm__ volatile("lld %0, 0(%1)" : "=r"(v) : "r"(p) : "memory");
    return v;
}

static uint64_t scd64(volatile uint64_t *p, uint64_t v)
{
    uint64_t s = v;
    __asm__ volatile("scd %0, 0(%1)" : "+r"(s) : "r"(p) : "memory");
    return (uint32_t)s;
}

/* Tight LLD/SCD pair in one asm block. */
static uint32_t lldscd64(volatile uint64_t *p, uint64_t nv, uint64_t *old)
{
    uint64_t o;
    uint64_t s = nv;
    __asm__ volatile(
        "lld %0, 0(%2)\n\t"
        "scd %1, 0(%2)"
        : "=&r"(o), "+r"(s) : "r"(p) : "memory");
    *old = o;
    return (uint32_t)s;
}

int main(void)
{
    uint32_t v32;
    uint32_t old32;
    uint32_t s;
    uint64_t v64;
    uint64_t old64;
    volatile pid_t pid;

    printf("ABI=%s ENDIAN=%s\n", E05_ABI, E05_ENDIAN);
    printf("SIZEOF int=%u long=%u ptr=%u llong=%u u32=%u u64=%u\n",
        (unsigned)sizeof(int), (unsigned)sizeof(long),
        (unsigned)sizeof(void *), (unsigned)sizeof(long long),
        (unsigned)sizeof(uint32_t), (unsigned)sizeof(uint64_t));

    /* SC with no prior LL: no reservation exists, must fail, mem kept. */
    g32pair.w0 = 0xAAAAAAAAu;
    s = sc32(&g32pair.w0, 0x55555555u);
    printf("OBS NOLL32 sc=%u mem=0x%08X\n", s, g32pair.w0);
    E05_CHECK(s == 0u && g32pair.w0 == 0xAAAAAAAAu, "sc-without-ll-fails-32");

    g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
    s = (uint32_t)scd64(&g64pair.d0, 0x5555555555555555ULL);
    printf("OBS NOLL64 sc=%u mem=0x%llX\n", s, (unsigned long long)g64pair.d0);
    E05_CHECK(s == 0u && g64pair.d0 == 0xAAAAAAAAAAAAAAAAULL,
        "sc-without-ll-fails-64");

    /* LL / LLD return the current memory contents. */
    g32pair.w0 = 0x11112222u;
    v32 = ll32(&g32pair.w0);
    printf("OBS LL32 val=0x%08X mem=0x%08X\n", v32, g32pair.w0);
    E05_CHECK(v32 == 0x11112222u, "ll-loads-value-32");

    g64pair.d0 = 0x1111222233334444ULL;
    v64 = lld64(&g64pair.d0);
    printf("OBS LLD64 val=0x%llX mem=0x%llX\n",
        (unsigned long long)v64, (unsigned long long)g64pair.d0);
    E05_CHECK(v64 == 0x1111222233334444ULL, "lld-loads-value-64");

    /* Tight pairs succeed (sc == 1) and commit the new value. */
    g32pair.w0 = 0xAABBCCDDu;
    old32 = 0u;
    s = llsc32(&g32pair.w0, 0x12345678u, &old32);
    printf("OBS IMM32 ll=0x%08X sc=%u mem=0x%08X\n", old32, s, g32pair.w0);
    E05_CHECK(s == 1u && old32 == 0xAABBCCDDu && g32pair.w0 == 0x12345678u,
        "imm-llsc-succeeds-32");

    g64pair.d0 = 0xAABBCCDD11223344ULL;
    old64 = 0u;
    s = lldscd64(&g64pair.d0, 0x123456789ABCDEF0ULL, &old64);
    printf("OBS IMM64 lld=0x%llX sc=%u mem=0x%llX\n",
        (unsigned long long)old64, s, (unsigned long long)g64pair.d0);
    E05_CHECK(s == 1u && old64 == 0xAABBCCDD11223344ULL &&
        g64pair.d0 == 0x123456789ABCDEF0ULL, "imm-lldscd-succeeds-64");

    /* A second SC with no new LL: reservation consumed, must fail. */
    s = sc32(&g32pair.w0, 0xDEADBEEFu);
    printf("OBS REPEAT32 sc=%u mem=0x%08X\n", s, g32pair.w0);
    E05_CHECK(s == 0u && g32pair.w0 == 0x12345678u, "repeat-sc-fails-32");

    s = (uint32_t)scd64(&g64pair.d0, 0xDEADBEEFDEADBEEFULL);
    printf("OBS REPEAT64 sc=%u mem=0x%llX\n", s,
        (unsigned long long)g64pair.d0);
    E05_CHECK(s == 0u && g64pair.d0 == 0x123456789ABCDEF0ULL,
        "repeat-scd-fails-64");

    /* Ordinary store to the same address clears the reservation. */
    g32pair.w0 = 0xAAAAAAAAu;
    v32 = ll32(&g32pair.w0);
    g32pair.w0 = 0xBBBBBBBBu;
    s = sc32(&g32pair.w0, 0xCCCCCCCCu);
    printf("OBS STORECLR32 ll=0x%08X sc=%u mem=0x%08X\n", v32, s, g32pair.w0);
    E05_CHECK(s == 0u && g32pair.w0 == 0xBBBBBBBBu,
        "store-same-addr-clears-32");

    g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
    v64 = lld64(&g64pair.d0);
    g64pair.d0 = 0xBBBBBBBBBBBBBBBBULL;
    s = (uint32_t)scd64(&g64pair.d0, 0xCCCCCCCCCCCCCCCCULL);
    printf("OBS STORECLR64 lld=0x%llX sc=%u mem=0x%llX\n",
        (unsigned long long)v64, s, (unsigned long long)g64pair.d0);
    E05_CHECK(s == 0u && g64pair.d0 == 0xBBBBBBBBBBBBBBBBULL,
        "store-same-addr-clears-64");

    /* Ordinary store to the same 32-byte line (w1/d1) clears it. */
    g32pair.w0 = 0xAAAAAAAAu;
    g32pair.w1 = 0x00000000u;
    v32 = ll32(&g32pair.w0);
    g32pair.w1 = 0xDDDDDDDDu;
    s = sc32(&g32pair.w0, 0xCCCCCCCCu);
    printf("OBS LINECLR32 ll=0x%08X sc=%u mem0=0x%08X mem1=0x%08X\n",
        v32, s, g32pair.w0, g32pair.w1);
    printf("E05-NOTE same-line-store-32 sc=%u (granularity, see FINDINGS.md)\n",
        s);

    g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
    g64pair.d1 = 0x0000000000000000ULL;
    v64 = lld64(&g64pair.d0);
    g64pair.d1 = 0xDDDDDDDDDDDDDDDDULL;
    s = (uint32_t)scd64(&g64pair.d0, 0xCCCCCCCCCCCCCCCCULL);
    printf("OBS LINECLR64 lld=0x%llX sc=%u mem0=0x%llX mem1=0x%llX\n",
        (unsigned long long)v64, s,
        (unsigned long long)g64pair.d0, (unsigned long long)g64pair.d1);
    printf("E05-NOTE same-line-store-64 sc=%u (granularity, see FINDINGS.md)\n",
        s);

    /* getpid() syscall between LL and SC: observed, no hard expectation. */
    g32pair.w0 = 0xAAAAAAAAu;
    v32 = ll32(&g32pair.w0);
    pid = getpid();
    s = sc32(&g32pair.w0, 0xCCCCCCCCu);
    printf("OBS SYSCALL32 ll=0x%08X pid=%d sc=%u mem=0x%08X\n",
        v32, (int)pid, s, g32pair.w0);

    g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
    v64 = lld64(&g64pair.d0);
    pid = getpid();
    s = (uint32_t)scd64(&g64pair.d0, 0xCCCCCCCCCCCCCCCCULL);
    printf("OBS SYSCALL64 lld=0x%llX pid=%d sc=%u mem=0x%llX\n",
        (unsigned long long)v64, (int)pid, s,
        (unsigned long long)g64pair.d0);

    printf("ERET=UNVERIFIED (user mode cannot execute ERET)\n");
    printf("FAILURES=%d\n", g_fail);
    printf("DONE\n");
    return (g_fail != 0) ? 1 : 0;
}
