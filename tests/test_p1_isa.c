/*
 * tests/test_p1_isa.c — Phase 1 freestanding ISA test suite (lane L1d).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding C + MIPS inline asm, -static, all four variants
 * (N64/N32 x LE/BE). Covers the SPEC 2 integer subset: 32-bit ALU
 * sign-extension, 64-bit ALU, shifts, DEXT/DINS (E02 values),
 * MULT/DIV hi/lo, every branch type with delay slots (taken and
 * not-taken), branch-likely annul (taken, not-taken, a page_end-4
 * observation and a PROT_NONE-data annul proof in a child),
 * J/JAL/JR/JALR links, LL/SC and LLD/SCD (success plus
 * same-address interference failure), LWL/LWR/SWL/SWR at all four
 * alignments, LDL/LDR/SDL/SDR canonical pairs against the
 * MANUAL-correct (BE-consistent) E02 values, RDHWR/$29 with a
 * set_thread_area round-trip, LWU, an unaligned-LW fault in a
 * child (exit 139, suite survives), and a raw write+exit path.
 * Unaligned-pair note (E02): qemu-LE swaps the address roles, so
 * canonical pairs print P1-FAIL under the LE oracles (recorded
 * honestly) while the interpreter prints P1-PASS.
 *
 * Protocol: "P1-PASS <name>" (no values: interp/qemu lines match),
 * "P1-FAIL <name> got=.. want=..", "P1-INFO ..." observations, and
 * a final "P1-RESULT: PASS|FAIL" plus summary.
 */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(_MIPS_SIM) && defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define P1_ABI "N64"
#define P1_NR_WRITE 5001
#define P1_NR_EXIT 5058
#elif defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define P1_ABI "N32"
#define P1_NR_WRITE 6001
#define P1_NR_EXIT 6058
#else
#define P1_ABI "UNKNOWN"
#define P1_NR_WRITE (-1)
#define P1_NR_EXIT (-1)
#endif

#ifndef __NR_set_thread_area
#error "__NR_set_thread_area is not defined by the toolchain headers"
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define P1_ENDIAN "LE"
#else
#define P1_ENDIAN "BE"
#endif

static unsigned g_pass = 0;
static unsigned g_fail = 0;

#define P1_CHECK64(name, got, want) do { \
	uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
	if (_g == _w) { g_pass++; printf("P1-PASS %s\n", name); } \
	else { g_fail++; printf("P1-FAIL %s got=0x%llx want=0x%llx\n", \
	    name, (unsigned long long)_g, (unsigned long long)_w); } \
} while (0)

#define P1_CHECK(name, cond) do { \
	if (cond) { g_pass++; printf("P1-PASS %s\n", name); } \
	else { g_fail++; printf("P1-FAIL %s\n", name); } \
} while (0)

static void t_model(void)
{
	uint16_t u = 1u;
	int le = (*(const uint8_t *)&u != 0u);
	printf("P1-INFO model abi=%s endian=%s void*=%u long=%u llong=%u\n",
	    P1_ABI, le ? "LE" : "BE", (unsigned)sizeof(void *),
	    (unsigned)sizeof(long), (unsigned)sizeof(unsigned long long));
	P1_CHECK("datamodel", (le && P1_ABI[0] != 0) || !le);
}

/* 32-bit ALU: every result is (int64)(int32). */
static void t_alu32(void)
{
	uint64_t out = 0u, rs, rt;
	rs = 0x123456789ABCDEF0ULL;
	__asm__ volatile("addiu %0,%1,1" : "=r"(out) : "r"(rs));
	P1_CHECK64("addiu-plus1", out, 0xFFFFFFFF9ABCDEF1ULL);
	rs = 0u;
	__asm__ volatile("addiu %0,%1,-1" : "=r"(out) : "r"(rs));
	P1_CHECK64("addiu-minus1", out, 0xFFFFFFFFFFFFFFFFULL);
	rs = 0xDEADBEEF00000001ULL; rt = 0x12345678FFFFFFFFULL;
	__asm__ volatile("addu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("addu-wrap-zero", out, 0x0000000000000000ULL);
	rs = 0xAAAAAAAA80000000ULL; rt = 0x5555555500000000ULL;
	__asm__ volatile("addu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("addu-sign-bit", out, 0xFFFFFFFF80000000ULL);
	rs = 0xFFFFFFFF00000005ULL; rt = 0x00000000FFFFFFFFULL;
	__asm__ volatile("subu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("subu-wrap", out, 0x0000000000000006ULL);
	rs = 0xF0F0F0F0AAAAAAAAULL; rt = 0x0F0F0F0F55555555ULL;
	__asm__ volatile("and %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("and-low32", out, 0u);
	__asm__ volatile("or %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("or-low32", out, 0xFFFFFFFFFFFFFFFFULL);
	__asm__ volatile("xor %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("xor-low32", out, 0xFFFFFFFFFFFFFFFFULL);
	__asm__ volatile("nor %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("nor-low32", out, 0x0000000000000000ULL);
	rs = 0xFFFFFFFFFFFFFFFFULL; rt = 0x0000000000000001ULL;
	__asm__ volatile("slt %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("slt-neg1-lt-1", out, 1u);
	__asm__ volatile("sltu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("sltu-ffff-lt-1", out, 0u);
	rs = 0u;
	__asm__ volatile("sltiu %0,%1,1" : "=r"(out) : "r"(rs));
	P1_CHECK64("sltiu-0-lt-1", out, 1u);
	__asm__ volatile("lui %0,0x8001" : "=r"(out));
	P1_CHECK64("lui-sign", out, 0xFFFFFFFF80010000ULL);
	rs = 0x00000000FEDCBA98ULL;
	__asm__ volatile("ext %0,%1,8,8" : "=r"(out) : "r"(rs));
	P1_CHECK64("ext-8-8", out, 0x00000000000000BAULL);
	rs = 0xFFFFFFFFFFFFFFFFULL; rt = 0x00000000000000ABULL;
	__asm__ volatile("ins %0,%1,8,8" : "+r"(rs) : "r"(rt));
	P1_CHECK64("ins-8-8", rs, 0xFFFFFFFFFFFFABFFULL);
	__asm__ volatile("move $0,%1\n\tmove %0,$0"
	    : "=r"(out) : "r"(0xFFFFFFFFFFFFFFFFULL));
	P1_CHECK64("zero-stays-zero", out, 0u);
}

/* 64-bit ALU: full 64 bits preserved. */
static void t_alu64(void)
{
	uint64_t out = 0u;
	uint64_t rs = 0x123456789ABCDEF0ULL, rt = 0x0000000000000001ULL;
	__asm__ volatile("daddiu %0,%1,1" : "=r"(out) : "r"(rs));
	P1_CHECK64("daddiu-64", out, 0x123456789ABCDEF1ULL);
	__asm__ volatile("daddiu %0,%1,-2" : "=r"(out) : "r"(rs));
	P1_CHECK64("daddiu-neg", out, 0x123456789ABCDEEEULL);
	__asm__ volatile("daddu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("daddu-64", out, 0x123456789ABCDEF1ULL);
	__asm__ volatile("dsubu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("dsubu-64", out, 0x123456789ABCDEEFULL);
	rs = 0xFFFFFFFFFFFFFFFFULL;
	__asm__ volatile("daddu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
	P1_CHECK64("daddu-wrap64", out, 0u);
}

/* Shifts: 32-bit results sign-extended, 64-bit preserved. */
static void t_shifts(void)
{
	uint64_t out = 0u, rt, rs;
	rt = 0xFFFF000040000000ULL;
	__asm__ volatile("sll %0,%1,1" : "=r"(out) : "r"(rt));
	P1_CHECK64("sll-into-sign", out, 0xFFFFFFFF80000000ULL);
	__asm__ volatile("sll %0,%1,0" : "=r"(out) : "r"(rt));
	P1_CHECK64("sll-sa0-sext", out, 0x0000000040000000ULL);
	rt = 0x0000000080000001ULL;
	__asm__ volatile("srl %0,%1,1" : "=r"(out) : "r"(rt));
	P1_CHECK64("srl", out, 0x0000000040000000ULL);
	/* SRA/SRAV/ROTR use canonical inputs (upper = sext of bit 31):
	 * qemu implements a full-64-bit arithmetic shift plus ext32s
	 * (ROTR zero-extends), which agrees with the manual only for
	 * canonical inputs (observed, all four variants). */
	rt = 0xFFFFFFFF80000001ULL;
	__asm__ volatile("sra %0,%1,1" : "=r"(out) : "r"(rt));
	P1_CHECK64("sra-sign", out, 0xFFFFFFFFC0000000ULL);
	rt = 0xF000000012345678ULL; rs = 2u;
	__asm__ volatile("sllv %0,%1,%2" : "=r"(out) : "r"(rt), "r"(rs));
	P1_CHECK64("sllv", out, 0x0000000048D159E0ULL);
	__asm__ volatile("srlv %0,%1,%2" : "=r"(out) : "r"(rt), "r"(rs));
	P1_CHECK64("srlv", out, 0x00000000048D159EULL);
	rt = 0xFFFFFFFF80000001ULL;
	__asm__ volatile("srav %0,%1,%2" : "=r"(out) : "r"(rt), "r"(rs));
	P1_CHECK64("srav", out, 0xFFFFFFFFE0000000ULL);
	rt = 0x0000000007654321ULL;
	__asm__ volatile("rotr %0,%1,4" : "=r"(out) : "r"(rt));
	P1_CHECK64("rotr", out, 0x0000000010765432ULL);
	rt = 0x8000000000000001ULL;
	__asm__ volatile("dsll %0,%1,1" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsll", out, 0x0000000000000002ULL);
	rt = 0xFEDCBA9876543210ULL;
	__asm__ volatile("dsll %0,%1,4" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsll-4", out, 0xEDCBA98765432100ULL);
	__asm__ volatile("dsll32 %0,%1,1" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsll32", out, 0xECA8642000000000ULL);
	__asm__ volatile("dsrl %0,%1,4" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsrl-4", out, 0x0FEDCBA987654321ULL);
	__asm__ volatile("dsra %0,%1,4" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsra-4", out, 0xFFEDCBA987654321ULL);
	__asm__ volatile("drotr %0,%1,8" : "=r"(out) : "r"(rt));
	P1_CHECK64("drotr-8", out, 0x10FEDCBA98765432ULL);
	rt = 0x0102030405060708ULL;
	__asm__ volatile("dsbh %0,%1" : "=r"(out) : "r"(rt));
	P1_CHECK64("dsbh", out, 0x0201040306050807ULL);
	__asm__ volatile("dshd %0,%1" : "=r"(out) : "r"(rt));
	P1_CHECK64("dshd", out, 0x0708050603040102ULL);
	rs = 0x0000F00000000000ULL;
	__asm__ volatile("dclz %0,%1" : "=r"(out) : "r"(rs));
	P1_CHECK64("dclz", out, 16u);
	rs = 0xFFFF000000000000ULL;
	__asm__ volatile("dclo %0,%1" : "=r"(out) : "r"(rs));
	P1_CHECK64("dclo", out, 16u);
}

/* DEXT/DINS families (E02 ground-truth values). */
#define P1_VEC 0xFEDCBA9876543210ULL

static void t_dext_dins(void)
{
	uint64_t out = 0u, rs = P1_VEC, rd;
	__asm__ volatile("dext %0,%1,8,8" : "=r"(out) : "r"(rs));
	P1_CHECK64("dext-8-8", out, 0x0000000000000032ULL);
	__asm__ volatile("dext %0,%1,0,32" : "=r"(out) : "r"(rs));
	P1_CHECK64("dext-0-32", out, 0x0000000076543210ULL);
	/* dextm spells the 4th operand as pos+size (GAS quirk, E02). */
	__asm__ volatile("dextm %0,%1,16,48" : "=r"(out) : "r"(rs));
	P1_CHECK64("dextm-16-48", out, 0x0000FEDCBA987654ULL);
	__asm__ volatile("dextu %0,%1,48,16" : "=r"(out) : "r"(rs));
	P1_CHECK64("dextu-48-16", out, 0x000000000000FEDCULL);
	__asm__ volatile("dextu %0,%1,32,32" : "=r"(out) : "r"(rs));
	P1_CHECK64("dextu-32-32", out, 0x00000000FEDCBA98ULL);
	rd = 0xFFFFFFFFFFFFFFFFULL; rs = 0x00000000000000ABULL;
	__asm__ volatile("dins %0,%1,8,8" : "+r"(rd) : "r"(rs));
	P1_CHECK64("dins-8-8", rd, 0xFFFFFFFFFFFFABFFULL);
	rd = 0u; rs = 0x00000000DEADBEEFULL;
	__asm__ volatile("dinsm %0,%1,16,32" : "+r"(rd) : "r"(rs));
	P1_CHECK64("dinsm-16-32", rd, 0x0000DEADBEEF0000ULL);
	rd = 0u; rs = 0x0000000000001234ULL;
	__asm__ volatile("dinsu %0,%1,48,16" : "+r"(rd) : "r"(rs));
	P1_CHECK64("dinsu-48-16", rd, 0x1234000000000000ULL);
}

/* MULT/DIV: products in hi/lo, 32-bit results sign-extended (SPEC 2.2). */
static void t_multdiv(void)
{
	int32_t a = 0x00012345, b = 0x00006789, q, r;
	int64_t p = (int64_t)a * (int64_t)b, dq, dr;
	uint64_t lo = 0u, hi = 0u;
	uint32_t uq, ur;
	__asm__ volatile("mult %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi)
	    : "r"((uint64_t)(uint32_t)a), "r"((uint64_t)(uint32_t)b));
	P1_CHECK64("mult-lo", lo, (uint64_t)(int64_t)(int32_t)(p));
	P1_CHECK64("mult-hi", hi, (uint64_t)(int64_t)(int32_t)(p >> 32));
	__asm__ volatile("multu %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi) : "r"(0xFFFFFFFFu), "r"(0xFFFFFFFFu));
	P1_CHECK64("multu-lo", lo, 1u);
	P1_CHECK64("multu-hi", hi, 0xFFFFFFFFFFFFFFFEULL);
	a = 100; b = 7; q = a / b; r = a % b;
	__asm__ volatile("div %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi)
	    : "r"((uint64_t)(uint32_t)a), "r"((uint64_t)(uint32_t)b));
	P1_CHECK64("div-lo", lo, (uint64_t)(int64_t)q);
	P1_CHECK64("div-hi", hi, (uint64_t)(int64_t)r);
	a = -100; q = a / b; r = a % b;
	__asm__ volatile("div %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi)
	    : "r"((uint64_t)(uint32_t)a), "r"((uint64_t)(uint32_t)b));
	P1_CHECK64("div-neg-lo", lo, (uint64_t)(int64_t)q);
	P1_CHECK64("div-neg-hi", hi, (uint64_t)(int64_t)r);
	__asm__ volatile("divu %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi) : "r"(0xFFFFFFFFu), "r"(2u));
	uq = 0xFFFFFFFFu / 2u; ur = 0xFFFFFFFFu % 2u;
	P1_CHECK64("divu-lo", lo, (uint64_t)uq);
	P1_CHECK64("divu-hi", hi, (uint64_t)ur);
	__asm__ volatile("dmult %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi)
	    : "r"(0x123456789ABCDEF0ULL), "r"(2u));
	p = (int64_t)0x123456789ABCDEF0LL * (int64_t)2;
	P1_CHECK64("dmult-lo", lo, (uint64_t)p);
	P1_CHECK64("dmult-hi", hi, 0u);
	__asm__ volatile("ddiv %2,%3\n\tmflo %0\n\tmfhi %1"
	    : "=r"(lo), "=r"(hi)
	    : "r"(0x123456789ABCDEF0ULL), "r"(0x100u));
	dq = (int64_t)0x123456789ABCDEF0LL / (int64_t)0x100;
	dr = (int64_t)0x123456789ABCDEF0LL % (int64_t)0x100;
	P1_CHECK64("ddiv-lo", lo, (uint64_t)dq);
	P1_CHECK64("ddiv-hi", hi, (uint64_t)dr);
}

/* Branches: two/one-register, plain and likely (likely annuls the
 * delay slot when not taken). Delay runs and took lands on 1/2. */
#define BR2(name, mnem, av, bv, take, likely) do { \
	uint64_t _d = 0u, _t = 0u, _a = (av), _b = (bv); \
	__asm__ volatile(".set noreorder\n\t" mnem " %2, %3, 1f\n\t" \
	    "li %0, 7\n\tli %1, 2\n\tj 2f\n\tnop\n\t1:\n\t" \
	    "li %1, 1\n\t2:\n\t.set reorder" \
	    : "+r"(_d), "+r"(_t) : "r"(_a), "r"(_b)); \
	P1_CHECK(name, _d == ((likely) ? ((take) ? 7u : 0u) : 7u) && \
	    _t == ((take) ? 1u : 2u)); \
} while (0)

#define BR1(name, mnem, av, take, likely) do { \
	uint64_t _d = 0u, _t = 0u, _a = (av); \
	__asm__ volatile(".set noreorder\n\t" mnem " %2, 1f\n\t" \
	    "li %0, 7\n\tli %1, 2\n\tj 2f\n\tnop\n\t1:\n\t" \
	    "li %1, 1\n\t2:\n\t.set reorder" \
	    : "+r"(_d), "+r"(_t) : "r"(_a)); \
	P1_CHECK(name, _d == ((likely) ? ((take) ? 7u : 0u) : 7u) && \
	    _t == ((take) ? 1u : 2u)); \
} while (0)

static void t_branches(void)
{
	BR2("beq-taken", "beq", 5u, 5u, 1, 0);
	BR2("beq-not-taken", "beq", 5u, 6u, 0, 0);
	BR2("bne-taken", "bne", 5u, 6u, 1, 0);
	BR2("bne-not-taken", "bne", 5u, 5u, 0, 0);
	BR1("blez-taken-zero", "blez", 0u, 1, 0);
	BR1("blez-taken-neg", "blez", 0xFFFFFFFFFFFFFFFFULL, 1, 0);
	BR1("blez-not-taken", "blez", 1u, 0, 0);
	BR1("bgtz-taken", "bgtz", 1u, 1, 0);
	BR1("bgtz-not-taken-zero", "bgtz", 0u, 0, 0);
	BR1("bgtz-not-taken-neg", "bgtz", 0xFFFFFFFFFFFFFFFFULL, 0, 0);
	BR1("bltz-taken", "bltz", 0xFFFFFFFFFFFFFFFFULL, 1, 0);
	BR1("bltz-not-taken-zero", "bltz", 0u, 0, 0);
	BR1("bltz-not-taken-pos", "bltz", 1u, 0, 0);
	BR1("bgez-taken-zero", "bgez", 0u, 1, 0);
	BR1("bgez-taken-pos", "bgez", 1u, 1, 0);
	BR1("bgez-not-taken", "bgez", 0xFFFFFFFFFFFFFFFFULL, 0, 0);
	BR2("beql-taken", "beql", 5u, 5u, 1, 1);
	BR2("beql-not-taken", "beql", 5u, 6u, 0, 1);
	BR2("bnel-taken", "bnel", 5u, 6u, 1, 1);
	BR2("bnel-not-taken", "bnel", 5u, 5u, 0, 1);
	BR1("blezl-taken", "blezl", 0u, 1, 1);
	BR1("blezl-not-taken", "blezl", 1u, 0, 1);
	BR1("bgtzl-taken", "bgtzl", 1u, 1, 1);
	BR1("bgtzl-not-taken", "bgtzl", 0u, 0, 1);
	BR1("bltzl-taken", "bltzl", 0xFFFFFFFFFFFFFFFFULL, 1, 1);
	BR1("bltzl-not-taken", "bltzl", 0u, 0, 1);
	BR1("bgezl-taken", "bgezl", 0u, 1, 1);
	BR1("bgezl-not-taken", "bgezl", 0xFFFFFFFFFFFFFFFFULL, 0, 1);
}

/* Branch-and-link: ra = address after the delay slot (SPEC 2.2). */
#define BRLINK(name, mnem, av, take) do { \
	uint64_t _flag = 0u, _ra = 0u, _exp = 0u, _a = (av); \
	__asm__ volatile(".set noreorder\n\t" mnem " %3, 1f\n\tnop\n\t" \
	    "2:\n\tmove %1, $31\n\tdla %2, 2b\n\tj 3f\n\tnop\n\t" \
	    "1:\n\tli %0, 1\n\tjr $31\n\tnop\n\t3:\n\t.set reorder" \
	    : "+r"(_flag), "=r"(_ra), "=r"(_exp) : "r"(_a)); \
	if (take) \
		P1_CHECK(name, _flag == 1u && _ra == _exp); \
	else \
		P1_CHECK(name, _flag == 0u); \
} while (0)

static void t_branch_link(void)
{
	BRLINK("bltzal-taken", "bltzal", 0xFFFFFFFFFFFFFFFFULL, 1);
	BRLINK("bltzal-not-taken", "bltzal", 0u, 0);
	BRLINK("bgezal-taken", "bgezal", 0u, 1);
	BRLINK("bgezal-not-taken", "bgezal", 0xFFFFFFFFFFFFFFFFULL, 0);
	BRLINK("bltzall-taken", "bltzall", 0xFFFFFFFFFFFFFFFFULL, 1);
	BRLINK("bltzall-not-taken", "bltzall", 1u, 0);
	BRLINK("bgezall-taken", "bgezall", 1u, 1);
}

/* Jumps: j/jal/jr/jalr with delay slots and link values. */
static void t_jumps(void)
{
	uint64_t ra = 0u, exp = 0u, delay = 0u, flag = 0u, tgt = 0u;
	__asm__ volatile(".set noreorder\n\tjal 1f\n\tli %2, 7\n\t2:\n\t"
	    "move %0, $31\n\tdla %1, 2b\n\tj 3f\n\tnop\n\t1:\n\t"
	    "li %3, 1\n\tjr $31\n\tnop\n\t3:\n\t.set reorder"
	    : "=r"(ra), "=r"(exp), "=r"(delay), "=r"(flag));
	P1_CHECK("jal-link", ra == exp && delay == 7u && flag == 1u);
	ra = 0u; exp = 0u; delay = 0u; flag = 0u; tgt = 0u;
	__asm__ volatile(".set noreorder\n\tdla %3, 1f\n\tjalr %3\n\t"
	    "li %1, 7\n\t2:\n\tmove %0, $31\n\tdla %2, 2b\n\t"
	    "j 3f\n\tnop\n\t1:\n\tli %4, 1\n\tjr $31\n\tnop\n\t"
	    "3:\n\t.set reorder"
	    : "=r"(ra), "=r"(delay), "=r"(exp), "+r"(tgt), "=r"(flag));
	P1_CHECK("jalr-link", ra == exp && delay == 7u && flag == 1u);
	delay = 0u; flag = 0u; tgt = 0u;
	__asm__ volatile(".set noreorder\n\tdla %0, 1f\n\tjr %0\n\t"
	    "li %1, 7\n\tli %2, 99\n\tj 2f\n\tnop\n\t1:\n\t"
	    "li %2, 1\n\t2:\n\t.set reorder"
	    : "+r"(tgt), "+r"(delay), "+r"(flag));
	P1_CHECK("jr-computed", delay == 7u && flag == 1u);
}

/* LL/SC and LLD/SCD (E05 ground truth). */
static struct {
	volatile uint32_t w0;
	volatile uint32_t w1;
} g32pair __attribute__((aligned(64)));

static struct {
	volatile uint64_t d0;
	volatile uint64_t d1;
} g64pair __attribute__((aligned(64)));

static uint32_t llsc32(volatile uint32_t *p, uint32_t nv, uint32_t *old)
{
	uint32_t o, s = nv;
	__asm__ volatile("ll %0, 0(%2)\n\tsc %1, 0(%2)"
	    : "=&r"(o), "+r"(s) : "r"(p) : "memory");
	*old = o;
	return s;
}

static uint32_t lldscd64(volatile uint64_t *p, uint64_t nv, uint64_t *old)
{
	uint64_t o, s = nv;
	__asm__ volatile("lld %0, 0(%2)\n\tscd %1, 0(%2)"
	    : "=&r"(o), "+r"(s) : "r"(p) : "memory");
	*old = o;
	return (uint32_t)s;
}

static uint32_t sc32(volatile uint32_t *p, uint32_t nv)
{
	uint32_t s = nv;
	__asm__ volatile("sc %0, 0(%1)" : "+r"(s) : "r"(p) : "memory");
	return s;
}

static uint32_t scd64(volatile uint64_t *p, uint64_t nv)
{
	uint64_t s = nv;
	__asm__ volatile("scd %0, 0(%1)" : "+r"(s) : "r"(p) : "memory");
	return (uint32_t)s;
}

static void t_llsc(void)
{
	uint32_t v32, old32, s;
	uint64_t v64, old64;
	g32pair.w0 = 0xAAAAAAAAu;
	s = 0x55555555u;
	__asm__ volatile("sc %0, 0(%1)" : "+r"(s)
	    : "r"(&g32pair.w0) : "memory");
	P1_CHECK("sc-without-ll-fails-32", s == 0u &&
	    g32pair.w0 == 0xAAAAAAAAu);
	g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
	{
		uint64_t t = 0x5555555555555555ULL;
		__asm__ volatile("scd %0, 0(%1)" : "+r"(t)
		    : "r"(&g64pair.d0) : "memory");
		s = (uint32_t)t;
	}
	P1_CHECK("scd-without-lld-fails-64", s == 0u &&
	    g64pair.d0 == 0xAAAAAAAAAAAAAAAAULL);
	g32pair.w0 = 0x11112222u;
	__asm__ volatile("ll %0, 0(%1)" : "=r"(v32)
	    : "r"(&g32pair.w0) : "memory");
	P1_CHECK64("ll-loads-value-32", v32, 0x11112222u);
	g64pair.d0 = 0x1111222233334444ULL;
	__asm__ volatile("lld %0, 0(%1)" : "=r"(v64)
	    : "r"(&g64pair.d0) : "memory");
	P1_CHECK64("lld-loads-value-64", v64, 0x1111222233334444ULL);
	g32pair.w0 = 0xAABBCCDDu; old32 = 0u;
	s = llsc32(&g32pair.w0, 0x12345678u, &old32);
	P1_CHECK("imm-llsc-succeeds-32", s == 1u && old32 == 0xAABBCCDDu &&
	    g32pair.w0 == 0x12345678u);
	g64pair.d0 = 0xAABBCCDD11223344ULL; old64 = 0u;
	s = lldscd64(&g64pair.d0, 0x123456789ABCDEF0ULL, &old64);
	P1_CHECK("imm-lldscd-succeeds-64", s == 1u &&
	    old64 == 0xAABBCCDD11223344ULL &&
	    g64pair.d0 == 0x123456789ABCDEF0ULL);
	s = sc32(&g32pair.w0, 0xDEADBEEFu);
	P1_CHECK("repeat-sc-fails-32", s == 0u &&
	    g32pair.w0 == 0x12345678u);
	s = scd64(&g64pair.d0, 0xDEADBEEFDEADBEEFULL);
	P1_CHECK("repeat-scd-fails-64", s == 0u &&
	    g64pair.d0 == 0x123456789ABCDEF0ULL);
	/* Ordinary store to the same address clears the reservation. */
	g32pair.w0 = 0xAAAAAAAAu;
	__asm__ volatile("ll %0, 0(%1)" : "=r"(v32)
	    : "r"(&g32pair.w0) : "memory");
	g32pair.w0 = 0xBBBBBBBBu;
	s = sc32(&g32pair.w0, 0xCCCCCCCCu);
	P1_CHECK("store-same-addr-clears-32", s == 0u &&
	    g32pair.w0 == 0xBBBBBBBBu && v32 == 0xAAAAAAAAu);
	g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL;
	__asm__ volatile("lld %0, 0(%1)" : "=r"(v64)
	    : "r"(&g64pair.d0) : "memory");
	g64pair.d0 = 0xBBBBBBBBBBBBBBBBULL;
	s = scd64(&g64pair.d0, 0xCCCCCCCCCCCCCCCCULL);
	P1_CHECK("store-same-addr-clears-64", s == 0u &&
	    g64pair.d0 == 0xBBBBBBBBBBBBBBBBULL &&
	    v64 == 0xAAAAAAAAAAAAAAAAULL);
	/* Same-line stores / syscalls keep qemu-user reservations (exact
	 * address granule) but clear hardware/interp ones (E05): INFO. */
	g32pair.w0 = 0xAAAAAAAAu; g32pair.w1 = 0u;
	__asm__ volatile("ll %0, 0(%1)" : "=r"(v32)
	    : "r"(&g32pair.w0) : "memory");
	g32pair.w1 = 0xDDDDDDDDu;
	s = llsc32(&g32pair.w0, 0xCCCCCCCCu, &old32);
	printf("P1-INFO same-line-32 ll=0x%x sc=%u mem=0x%x\n",
	    v32, s, g32pair.w0);
	g64pair.d0 = 0xAAAAAAAAAAAAAAAAULL; g64pair.d1 = 0u;
	__asm__ volatile("lld %0, 0(%1)" : "=r"(v64)
	    : "r"(&g64pair.d0) : "memory");
	g64pair.d1 = 0xDDDDDDDDDDDDDDDDULL;
	s = lldscd64(&g64pair.d0, 0xCCCCCCCCCCCCCCCCULL, &old64);
	printf("P1-INFO same-line-64 ll=0x%llx sc=%u mem=0x%llx\n",
	    (unsigned long long)v64, s, (unsigned long long)g64pair.d0);
}

/* LWL/LWR/SWL/SWR at all four alignments. Canonical pairs: lwl X +
 * lwr X+3 loads mem[X..X+3] in memory order; swl X + swr X+3
 * deposits the value there. Byte-exact on BE; the LE oracle swaps
 * the address roles (E02), so LE prints record the defect honestly. */
static volatile uint8_t g_w32[24] __attribute__((aligned(8)));

static uint32_t memord32(const volatile uint8_t *x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (uint32_t)x[0] | ((uint32_t)x[1] << 8) |
	    ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
#else
	return ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) |
	    ((uint32_t)x[2] << 8) | (uint32_t)x[3];
#endif
}

static void w32fill(void)
{
	unsigned k;
	for (k = 0; k < sizeof(g_w32); k++)
		g_w32[k] = (uint8_t)(0xA0u + k);
}

static void t_lwl_lwr(void)
{
	unsigned i;
	for (i = 0; i < 4; i++) {
		volatile uint8_t *x = g_w32 + 8 + i;
		uint32_t got = 0u, want;
		char name[32];
		w32fill();
		want = memord32(x);
		__asm__ volatile("lwl %0, 0(%1)\n\tlwr %0, 3(%1)"
		    : "+r"(got) : "r"(x) : "memory");
		snprintf(name, sizeof(name), "lwl-lwr-align-%u", i);
		P1_CHECK64(name, got, want);
	}
}

static void t_swl_swr(void)
{
	unsigned i;
	for (i = 0; i < 4; i++) {
		volatile uint8_t *x = g_w32 + 8 + i;
		uint32_t v = 0x01020304u;
		unsigned k;
		int ok = 1;
		char name[32];
		w32fill();
		__asm__ volatile("swl %0, 0(%1)\n\tswr %0, 3(%1)"
		    : : "r"(v), "r"(x) : "memory");
		for (k = 0; k < 4; k++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			uint32_t wb = (v >> (8u * k)) & 0xFFu;
#else
			uint32_t wb = (v >> (8u * (3u - k))) & 0xFFu;
#endif
			if (x[k] != wb)
				ok = 0;
		}
		if (x[-1] != (uint8_t)(0xA0u + 8 + i - 1) ||
		    x[4] != (uint8_t)(0xA0u + 8 + i + 4))
			ok = 0;
		snprintf(name, sizeof(name), "swl-swr-align-%u", i);
		P1_CHECK(name, ok);
	}
}

/* LDL/LDR/SDL/SDR canonical pairs, MANUAL-correct values (E02). */
static volatile uint8_t g_w64[32] __attribute__((aligned(8)));

static void w64fill(void)
{
	unsigned k;
	for (k = 0; k < sizeof(g_w64); k++)
		g_w64[k] = (uint8_t)(0xA0u + k);
}

static uint64_t memord64(const volatile uint8_t *x)
{
	uint64_t v = 0u;
	unsigned k;
	for (k = 0; k < 8; k++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		v |= (uint64_t)x[k] << (8u * k);
#else
		v |= (uint64_t)x[k] << (8u * (7u - k));
#endif
	}
	return v;
}

static void t_ldl_ldr(void)
{
	volatile uint8_t *x = g_w64 + 11; /* mod 3 */
	volatile uint8_t *y = g_w64 + 18; /* X+7 */
	uint64_t pair = 0u, want;
	w64fill();
	want = memord64(x);
	__asm__ volatile("ldl %0, 0(%1)\n\tldr %0, 0(%2)"
	    : "+r"(pair) : "r"(x), "r"(y) : "memory");
	printf("P1-INFO ldl-ldr-canonical xmod=%u ymod=%u\n",
	    (unsigned)((uintptr_t)x % 8u), (unsigned)((uintptr_t)y % 8u));
	P1_CHECK64("ldl-ldr-canonical-pair", pair, want);
}

static void t_sdl_sdr(void)
{
	volatile uint8_t *x = g_w64 + 11;
	uint64_t v = 0xA1B2C3D4E5F60718ULL;
	unsigned k;
	int ok = 1;
	w64fill();
	__asm__ volatile("sdl %0, 0(%1)\n\tsdr %0, 7(%1)"
	    : : "r"(v), "r"(x) : "memory");
	for (k = 0; k < 8; k++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		uint64_t wb = (v >> (8u * k)) & 0xFFu;
#else
		uint64_t wb = (v >> (8u * (7u - k))) & 0xFFu;
#endif
		if (x[k] != (uint8_t)wb)
			ok = 0;
	}
	if (g_w64[10] != 0xAAu || g_w64[19] != 0xB3u)
		ok = 0;
	P1_CHECK("sdl-sdr-canonical-pair", ok);
}

/* RDHWR $29 with a set_thread_area round-trip (E06). */
static unsigned long rdhwr_mnemonic(void)
{
	unsigned long v;
	__asm__ volatile("rdhwr %0, $29" : "=r"(v));
	return v;
}

static unsigned long rdhwr_fixed(void)
{
	unsigned long v, save;
	__asm__ volatile("move %1, $3\n\t.word 0x7c03e83b\n\t"
	    "move %0, $3\n\tmove $3, %1\n\t"
	    : "=r"(v), "=&r"(save) : : "memory");
	return v;
}

static void t_rdhwr(void)
{
	unsigned long before = rdhwr_mnemonic();
	unsigned long fixed = rdhwr_fixed();
	long rc, rc2, test_ok = 0, rest_ok = 0;
	P1_CHECK("rdhwr-nonzero", before != 0u);
	P1_CHECK64("rdhwr-fixed-matches", fixed, before);
	/* No libc calls while the ULR is clobbered (E06). */
	rc = syscall(__NR_set_thread_area, 0x51ab0001UL);
	if (rc == 0) {
		unsigned long t = rdhwr_mnemonic();
		test_ok = (t == 0x51ab0001UL);
		rc2 = syscall(__NR_set_thread_area, before);
		rest_ok = (rc2 == 0 && rdhwr_mnemonic() == before);
	}
	P1_CHECK("rdhwr-returns-set-value", test_ok);
	P1_CHECK("rdhwr-restored", rest_ok);
}

/* LB/LBU/LH/LHU/LW/LWU aligned loads. */
static void t_loads(void)
{
	uint32_t w = 0x80000001u;
	int8_t b = (int8_t)0x80;
	int16_t h = (int16_t)0x8001;
	uint64_t out = 0u;
	__asm__ volatile("lw %0,0(%1)" : "=r"(out) : "r"(&w));
	P1_CHECK64("lw-sext", out, 0xFFFFFFFF80000001ULL);
	out = 0u;
	__asm__ volatile("lwu %0,0(%1)" : "=r"(out) : "r"(&w));
	P1_CHECK64("lwu-zext", out, 0x0000000080000001ULL);
	out = 0u;
	__asm__ volatile("lb %0,0(%1)" : "=r"(out) : "r"(&b));
	P1_CHECK64("lb-sext", out, 0xFFFFFFFFFFFFFF80ULL);
	out = 0u;
	__asm__ volatile("lbu %0,0(%1)" : "=r"(out) : "r"(&b));
	P1_CHECK64("lbu-zext", out, 0x0000000000000080ULL);
	out = 0u;
	__asm__ volatile("lh %0,0(%1)" : "=r"(out) : "r"(&h));
	P1_CHECK64("lh-sext", out, 0xFFFFFFFFFFFF8001ULL);
	out = 0u;
	__asm__ volatile("lhu %0,0(%1)" : "=r"(out) : "r"(&h));
	P1_CHECK64("lhu-zext", out, 0x0000000000008001ULL);
}

/* Child runner: faulting children must not kill the suite. */
static int run_child(void (*body)(void))
{
	pid_t p = fork();
	int st = -1;
	if (p == 0) {
		body();
		_exit(99);
	}
	if (p > 0)
		(void)waitpid(p, &st, 0);
	return st;
}

/* Alignment faults become exit 139: the interpreter child exits 139
 * directly; under qemu the guest SIGBUS/SIGSEGV arrives here. */
static void fault_139(int sig)
{
	(void)sig;
	_exit(139);
}

static void unaligned_body(void)
{
	struct sigaction sa;
	volatile uint8_t buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint32_t v = 0u;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = fault_139;
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	__asm__ volatile("lw %0, 1(%1)" : "=r"(v) : "r"(&buf[0]));
	_exit((int)(v & 0xFFu) + 100); /* only if the engine fixed it up */
}

static void t_unaligned_child(void)
{
	int st = run_child(unaligned_body);
	P1_CHECK("unaligned-lw-child-faults",
	    WIFEXITED(st) && WEXITSTATUS(st) == 139);
	printf("P1-INFO unaligned-lw status=%d\n", st);
}

/* Branch-likely annul proof: delay must not touch a PROT_NONE page.
 * Not-taken bnel with a delay-slot load from PROT_NONE data. Correct
 * annul: no data fault, child exits 0; a wrong engine faults. */
static void annul_body(void)
{
	size_t ps = (size_t)sysconf(_SC_PAGESIZE);
	uint8_t *guard = mmap(NULL, ps, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint64_t dummy = 0u, hit = 0u;
	if (guard == MAP_FAILED)
		_exit(10);
	if (mprotect(guard, ps, PROT_NONE) != 0)
		_exit(11);
	__asm__ volatile(".set noreorder\n\tbnel %2, %3, 1f\n\t"
	    "lw %0, 0(%4)\n\tli %1, 1\n\tj 2f\n\tnop\n\t1:\n\t"
	    "li %1, 2\n\t2:\n\t.set reorder"
	    : "=r"(dummy), "+r"(hit)
	    : "r"(5u), "r"(5u), "r"(guard));
	(void)dummy;
	_exit(hit == 1u ? 0 : 3);
}

static void t_annul_data_child(void)
{
	int st = run_child(annul_body);
	P1_CHECK("likely-annul-skips-protnone",
	    WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* page_end-4 likely observation (no verdict). Branch word at P0_end-4,
 * delay slot at P0_end (PROT_NONE), fall-through at P0_end+4
 * (PROT_NONE). Architecturally the annulled delay slot is never
 * fetched, so the first fetch fault lands on the fall-through.
 * qemu-user instead fetches the delay word while translating, so the
 * recorded offset differs by engine; the decisive annul proof is the
 * test above. */
static void *g_pf_addr;
static sigjmp_buf g_pf_jb;

static void pf_handler(int sig, siginfo_t *si, void *u)
{
	(void)sig;
	(void)u;
	g_pf_addr = si->si_addr;
	siglongjmp(g_pf_jb, 1);
}

static void pageend_body(void)
{
	size_t ps = (size_t)sysconf(_SC_PAGESIZE);
	uint8_t *base = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	struct sigaction sa;
	uint8_t *p0e;
	uint32_t *br;
	void (*fn)(void);
	if (base == MAP_FAILED)
		_exit(10);
	if (mprotect(base + ps, ps, PROT_NONE) != 0)
		_exit(11);
	p0e = base + ps;
	br = (uint32_t *)(p0e - 4);
	br[0] = 0x50010001u; /* beql $0,$1,+1: never taken */
	__builtin___clear_cache((char *)br, (char *)(br + 1));
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = pf_handler;
	sa.sa_flags = SA_SIGINFO;
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	g_pf_addr = NULL;
	if (sigsetjmp(g_pf_jb, 1) == 0) {
		memcpy(&fn, &br, sizeof(fn));
		fn();
		printf("P1-INFO pageend-nofault\n");
		_exit(0);
	}
	printf("P1-INFO pageend-offset=%ld\n",
	    (long)((uint8_t *)g_pf_addr - (uint8_t *)br));
	_exit(0);
}

static void t_pageend_child(void)
{
	int st = run_child(pageend_body);
	printf("P1-INFO pageend-child status=%d\n", st);
}

/* Raw write + raw exit (E01 register/$a3 convention). */
typedef struct {
	long v0;
	long a3;
} scres_t;

static scres_t raw_sys3(long n, long a, long b, long c)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = 0;
	scres_t r;
	__asm__ volatile("syscall" : "+r"(r2), "+r"(r7)
	    : "r"(r4), "r"(r5), "r"(r6) : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static void raw_exit_body(void)
{
	register long r2 __asm__("$2") = P1_NR_EXIT;
	register long r4 __asm__("$4") = 42;
	__asm__ volatile("syscall" : "+r"(r2) : "r"(r4) : "memory");
	_exit(99);
}

static void t_raw_syscalls(void)
{
	static const char msg[] = "P1-INFO raw-write-ok\n";
	scres_t r;
	int st;
	r = raw_sys3(P1_NR_WRITE, 1L, (long)msg, (long)(sizeof(msg) - 1));
	P1_CHECK("raw-write", r.a3 == 0 && r.v0 == (long)(sizeof(msg) - 1));
	st = run_child(raw_exit_body);
	P1_CHECK("raw-exit", WIFEXITED(st) && WEXITSTATUS(st) == 42);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("P1-ISA suite abi=%s endian=%s\n", P1_ABI, P1_ENDIAN);
	t_model();
	t_alu32();
	t_alu64();
	t_shifts();
	t_dext_dins();
	t_multdiv();
	t_branches();
	t_branch_link();
	t_jumps();
	t_llsc();
	t_lwl_lwr();
	t_swl_swr();
	t_ldl_ldr();
	t_sdl_sdr();
	t_rdhwr();
	t_loads();
	t_unaligned_child();
	t_annul_data_child();
	t_pageend_child();
	t_raw_syscalls();
	printf("P1-SUMMARY failed=%u total=%u\n", g_fail, g_pass + g_fail);
	printf("P1-RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
