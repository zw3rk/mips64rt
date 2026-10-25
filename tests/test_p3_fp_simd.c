/*
 * tests/test_p3_fp_simd.c — Phase 3 freestanding FP + SIMD test suite (lane L3c).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding C + MIPS inline asm, -static, all four variants
 * (N64/N32 x LE/BE). Covers the SPEC 2 FP subset: scalar S/D
 * arithmetic, conversions (incl. TRUNC/CEIL/FLOOR/ROUND), NaN
 * propagation (legacy quiet-NaN default 0x7fbfffff/0x7ff7ffffffffffff),
 * all sixteen C.cond comparisons with FCC + FCSR effects, BC1T/BC1F
 * and branch-likely taken + not-taken with delay-slot accounting,
 * FCSR rounding-mode coverage (RM 0..3), FPR moves (MFC1/MTC1/DMFC1/
 * DMTC1/CFC1/CTC1/LWC1/SWC1/LDC1/SDC1), and the adjudicated SIMD
 * scope: paired-single (ADD/SUB/MUL/ABS/NEG/MOV.PS + MFHC1) and scalar COP1X
 * (MADD/MSUB/NMADD/NMSUB .S/.D). MSA is deliberately OUT of scope:
 * under the qemu-user 10.0.13 default-CPU oracle MSA memory ops
 * execute without a trap but return zeros (silent wrong data), MSA
 * traps with SIGILL on the 20Kc and Octeon68XX CPU models, and the
 * target R2 CPUs (Loongson 3A3000, Octeon III) plus the toolchain
 * default FP ABI (readelf ASEs: None) have no MSA.
 *
 * Oracle quirks pinned by experiment (qemu-mips64el/qemu-mips64
 * 10.0.13, identical LE/BE): ADD.S with a signaling-NaN-shaped input
 * (legacy quiet bit set, e.g. 0x7FC00000) sets V cause + flag
 * (FCSR 0x10040) while quiet-NaN inputs propagate silently;
 * MUL/DIV/SQRT/CVT never set it for quiet NaN; invalid ops
 * (sqrt(-1), 0/0, inf-inf, 0*inf, out-of-range/NaN CVT) yield the
 * default NaN or integer indefinite value with V cause + flag
 * (FCSR 0x10040); 1.5/0.0 yields
 * +inf with Z cause + flag (FCSR 0x8020); ROUND.W/L uses
 * round-half-to-even (2.5->2, 3.5->4, -2.5->-2), unlike the
 * ties-away rule of some hardware; signaling C.cond on quiet NaN
 * (SF/SEQ/LT/LE) and the unordered-negated conditions
 * (NGLE/NGL/NGE/NGT) on NaN set V cause + flag.
 *
 * Protocol: "P3-PASS <name>", "P3-FAIL <name> got=.. want=..",
 * "P3-INFO ..." observations, and a final "P3-RESULT: PASS|FAIL"
 * plus summary. Exit 0 iff zero failures.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MIPS_SIM) && defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define P3_ABI "N64"
#elif defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define P3_ABI "N32"
#else
#define P3_ABI "UNKNOWN"
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define P3_ENDIAN "LE"
#else
#define P3_ENDIAN "BE"
#endif

static unsigned g_pass = 0;
static unsigned g_fail = 0;

#define P3_CHECK64(name, got, want) do { \
	uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
	if (_g == _w) { g_pass++; printf("P3-PASS %s\n", name); } \
	else { g_fail++; printf("P3-FAIL %s got=0x%llx want=0x%llx\n", \
	    name, (unsigned long long)_g, (unsigned long long)_w); } \
} while (0)

#define P3_CHECK(name, cond) do { \
	if (cond) { g_pass++; printf("P3-PASS %s\n", name); } \
	else { g_fail++; printf("P3-FAIL %s\n", name); } \
} while (0)

static uint32_t p3_bitsf(float f)
{
	uint32_t u;

	memcpy(&u, &f, 4);
	return u;
}

static uint64_t p3_bitsd(double d)
{
	uint64_t u;

	memcpy(&u, &d, 8);
	return u;
}

static uint32_t p3_fcsr(void)
{
	uint32_t v;

	__asm__ volatile("cfc1 %0, $31" : "=r"(v));
	return v;
}

static void p3_clear(void)
{
	__asm__ volatile("ctc1 $0, $31" ::: "memory");
}

static void p3_setrm(unsigned rm)
{
	uint32_t v = (p3_fcsr() & ~3u) | (rm & 3u);

	__asm__ volatile("ctc1 %0, $31" :: "r"(v) : "memory");
}

static void t_model(void)
{
	uint32_t fir = 0u;

	__asm__ volatile("cfc1 %0, $0" : "=r"(fir));
	printf("P3-INFO model abi=%s endian=%s void*=%u long=%u llong=%u\n",
	    P3_ABI, P3_ENDIAN, (unsigned)sizeof(void *),
	    (unsigned)sizeof(long), (unsigned)sizeof(unsigned long long));
	printf("P3-INFO simd-scope=ps+cop1x; msa excluded (silent zeros on "
	    "default oracle, SIGILL on 20Kc/Octeon68XX, no R2/MSA ASE)\n");
	printf("P3-INFO round-half-to-even observed (round(2.5)=2, "
	    "round(-2.5)=-2); add.s(snan) sets Invalid sticky flag\n");
	P3_CHECK64("fir-mips64r2", fir, 0x007f0000u);
	P3_CHECK64("fcsr-init-zero", p3_fcsr(), 0u);
}

/* Scalar single-precision arithmetic: exact results, bit-compared. */
static void t_arith_s(void)
{
	float r = 0.0f;

	p3_clear();
	__asm__ volatile("add.s %0,%1,%2" : "=f"(r) : "f"(1.5f), "f"(2.25f));
	P3_CHECK64("add-s", p3_bitsf(r), 0x40700000u);
	__asm__ volatile("sub.s %0,%1,%2" : "=f"(r) : "f"(2.5f), "f"(1.5f));
	P3_CHECK64("sub-s", p3_bitsf(r), 0x3F800000u);
	__asm__ volatile("mul.s %0,%1,%2" : "=f"(r) : "f"(1.5f), "f"(2.0f));
	P3_CHECK64("mul-s", p3_bitsf(r), 0x40400000u);
	__asm__ volatile("div.s %0,%1,%2" : "=f"(r) : "f"(7.5f), "f"(2.5f));
	P3_CHECK64("div-s", p3_bitsf(r), 0x40400000u);
	__asm__ volatile("sqrt.s %0,%1" : "=f"(r) : "f"(4.0f));
	P3_CHECK64("sqrt-s", p3_bitsf(r), 0x40000000u);
	__asm__ volatile("abs.s %0,%1" : "=f"(r) : "f"(-2.75f));
	P3_CHECK64("abs-s", p3_bitsf(r), 0x40300000u);
	__asm__ volatile("neg.s %0,%1" : "=f"(r) : "f"(-2.75f));
	P3_CHECK64("neg-s", p3_bitsf(r), 0x40300000u);
	__asm__ volatile("mov.s %0,%1" : "=f"(r) : "f"(1.5f));
	P3_CHECK64("mov-s", p3_bitsf(r), 0x3FC00000u);
	{
		float p0 = 0.0f, n0 = -0.0f;
		uint32_t u;

		__asm__ volatile("add.s %0,%1,%2" : "=f"(r) : "f"(p0), "f"(n0));
		memcpy(&u, &r, 4);
		P3_CHECK64("add-s-pzero-nzero", u, 0x00000000u);
		__asm__ volatile("sub.s %0,%1,%2" : "=f"(r) : "f"(p0), "f"(p0));
		memcpy(&u, &r, 4);
		P3_CHECK64("sub-s-pzero-pzero", u, 0x00000000u);
	}
}

/* Scalar double-precision arithmetic: exact results, bit-compared. */
static void t_arith_d(void)
{
	double r = 0.0;

	p3_clear();
	__asm__ volatile("add.d %0,%1,%2" : "=f"(r) : "f"(1.5), "f"(2.25));
	P3_CHECK64("add-d", p3_bitsd(r), 0x400E000000000000ULL);
	__asm__ volatile("sub.d %0,%1,%2" : "=f"(r) : "f"(2.5), "f"(1.5));
	P3_CHECK64("sub-d", p3_bitsd(r), 0x3FF0000000000000ULL);
	__asm__ volatile("mul.d %0,%1,%2" : "=f"(r) : "f"(1.5), "f"(2.0));
	P3_CHECK64("mul-d", p3_bitsd(r), 0x4008000000000000ULL);
	__asm__ volatile("div.d %0,%1,%2" : "=f"(r) : "f"(7.5), "f"(2.5));
	P3_CHECK64("div-d", p3_bitsd(r), 0x4008000000000000ULL);
	__asm__ volatile("sqrt.d %0,%1" : "=f"(r) : "f"(4.0));
	P3_CHECK64("sqrt-d", p3_bitsd(r), 0x4000000000000000ULL);
	__asm__ volatile("abs.d %0,%1" : "=f"(r) : "f"(-1.5));
	P3_CHECK64("abs-d", p3_bitsd(r), 0x3FF8000000000000ULL);
	__asm__ volatile("neg.d %0,%1" : "=f"(r) : "f"(-1.5));
	P3_CHECK64("neg-d", p3_bitsd(r), 0x3FF8000000000000ULL);
	__asm__ volatile("mov.d %0,%1" : "=f"(r) : "f"(1.5));
	P3_CHECK64("mov-d", p3_bitsd(r), 0x3FF8000000000000ULL);
}

/* Exact (rounding-mode independent) conversions. */
static void t_cvt(void)
{
	float f = 0.0f;
	double d = 0.0;
	int32_t w = 0;
	int64_t l = 0;

	p3_clear();
	__asm__ volatile("mtc1 %1, $f2\ncvt.s.w %0, $f2"
	    : "=f"(f) : "r"((uint64_t)42u));
	P3_CHECK64("cvt-s-w-42", p3_bitsf(f), 0x42280000u);
	__asm__ volatile("dmtc1 %1, $f2\ncvt.d.l %0, $f2"
	    : "=f"(d) : "r"((uint64_t)((int64_t)1 << 40)));
	P3_CHECK64("cvt-d-l-2p40", p3_bitsd(d), 0x4270000000000000ULL);
	__asm__ volatile("cvt.w.s %0,%1" : "=f"(w) : "f"(42.0f));
	P3_CHECK64("cvt-w-s-42", (uint64_t)(uint32_t)w, 42u);
	p3_clear();
	__asm__ volatile("cvt.w.d %0,%1" : "=f"(w) : "f"(7.5));
	P3_CHECK64("cvt-w-d-7p5-rn", (uint64_t)(uint32_t)w, 8u);
	__asm__ volatile("cvt.s.d %0,%1" : "=f"(f) : "f"(1.5));
	P3_CHECK64("cvt-s-d-1p5", p3_bitsf(f), 0x3FC00000u);
	__asm__ volatile("cvt.d.s %0,%1" : "=f"(d) : "f"(2.5f));
	P3_CHECK64("cvt-d-s-2p5", p3_bitsd(d), 0x4004000000000000ULL);
	__asm__ volatile("mtc1 %1, $f2\ncvt.s.w %0, $f2"
	    : "=f"(f) : "r"((uint64_t)0xFFFFFFFFu));
	P3_CHECK64("cvt-s-w-neg1", p3_bitsf(f), 0xBF800000u);
	__asm__ volatile("dmtc1 %1, $f2\ncvt.d.l %0, $f2"
	    : "=f"(d) : "r"((uint64_t)(uint64_t)(int64_t)-5));
	P3_CHECK64("cvt-d-l-neg5", p3_bitsd(d), 0xC014000000000000ULL);
	__asm__ volatile("cvt.l.s %0,%1" : "=f"(l) : "f"(100.0f));
	P3_CHECK64("cvt-l-s-100", (uint64_t)l, 100u);
}

/* NaN propagation: runtime-built legacy default NaN in, default NaN
 * out. ADD.S additionally sets the Invalid sticky flag (0x40). */
static void t_nan(void)
{
	float qf = 0.0f, r = 0.0f;
	double qd = 0.0, rd = 0.0;

	p3_clear();
	__asm__ volatile("div.s %0,%1,%2" : "=f"(qf) : "f"(0.0f), "f"(0.0f));
	P3_CHECK64("nan-s-build", p3_bitsf(qf), 0x7FBFFFFFu);
	__asm__ volatile("div.d %0,%1,%2" : "=f"(qd) : "f"(0.0), "f"(0.0));
	P3_CHECK64("nan-d-build", p3_bitsd(qd), 0x7FF7FFFFFFFFFFFFULL);
	p3_clear();
	__asm__ volatile("add.s %0,%1,%2" : "=f"(r) : "f"(1.5f), "f"(qf));
	P3_CHECK64("nan-add-s", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("nan-add-s-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("mul.s %0,%1,%2" : "=f"(r) : "f"(1.5f), "f"(qf));
	P3_CHECK64("nan-mul-s", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("nan-mul-s-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("div.s %0,%1,%2" : "=f"(r) : "f"(qf), "f"(1.5f));
	P3_CHECK64("nan-div-s", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("nan-div-s-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("sqrt.s %0,%1" : "=f"(r) : "f"(qf));
	P3_CHECK64("nan-sqrt-s", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("nan-sqrt-s-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("sqrt.d %0,%1" : "=f"(rd) : "f"(qd));
	P3_CHECK64("nan-sqrt-d", p3_bitsd(rd), 0x7FF7FFFFFFFFFFFFULL);
	P3_CHECK64("nan-sqrt-d-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("sub.d %0,%1,%2" : "=f"(rd) : "f"(1.5), "f"(qd));
	P3_CHECK64("nan-sub-d", p3_bitsd(rd), 0x7FF7FFFFFFFFFFFFULL);
	P3_CHECK64("nan-sub-d-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("cvt.d.s %0,%1" : "=f"(rd) : "f"(qf));
	P3_CHECK64("nan-cvt-d-s", p3_bitsd(rd), 0x7FF7FFFFFFFFFFFFULL);
	P3_CHECK64("nan-cvt-d-s-fcsr", p3_fcsr(), 0u);
	p3_clear();
	__asm__ volatile("cvt.s.d %0,%1" : "=f"(r) : "f"(qd));
	P3_CHECK64("nan-cvt-s-d", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("nan-cvt-s-d-fcsr", p3_fcsr(), 0u);
	/* Legacy crafted shapes (integer-loaded, host independent). */
	p3_clear();
	{
		float f = 0.0f;

		__asm__ volatile("mtc1 %1, $f2\nadd.s %0, $f2, $f2"
		    : "=f"(f) : "r"((uint64_t)0x7FC00000u));
		P3_CHECK64("nan-add-s-crafted", p3_bitsf(f), 0x7FBFFFFFu);
		P3_CHECK64("nan-add-s-crafted-fcsr", p3_fcsr(), 0x10040u);
		__asm__ volatile("mtc1 %1, $f2\nabs.s %0, $f2"
		    : "=f"(f) : "r"((uint64_t)0xFFC00001u));
		P3_CHECK64("nan-abs-s-crafted", p3_bitsf(f), 0x7FC00001u);
		__asm__ volatile("mtc1 %1, $f2\nneg.s %0, $f2"
		    : "=f"(f) : "r"((uint64_t)0x7FC00000u));
		P3_CHECK64("nan-neg-s-crafted", p3_bitsf(f), 0xFFC00000u);
	}
	{
		double dd = 0.0;

		__asm__ volatile("dmtc1 %1, $f2\nadd.d %0, $f2, $f2"
		    : "=f"(dd) : "r"(0x7FF8000000000000ULL));
		P3_CHECK64("nan-add-d-crafted", p3_bitsd(dd),
		    0x7FF7FFFFFFFFFFFFULL);
		__asm__ volatile("dmtc1 %1, $f2\nabs.d %0, $f2"
		    : "=f"(dd) : "r"(0xFFF0000000000001ULL));
		P3_CHECK64("nan-abs-d-crafted", p3_bitsd(dd),
		    0x7FF0000000000001ULL);
		__asm__ volatile("dmtc1 %1, $f2\nneg.d %0, $f2"
		    : "=f"(dd) : "r"(0x7FF8000000000000ULL));
		P3_CHECK64("nan-neg-d-crafted", p3_bitsd(dd),
		    0xFFF8000000000000ULL);
	}
}

/* Invalid / divide-by-zero ops: default results plus FCSR cause/flags. */
static void t_invalid(void)
{
	float r = 0.0f;
	int32_t w = 0;
	int64_t l = 0;

	p3_clear();
	__asm__ volatile("sqrt.s %0,%1" : "=f"(r) : "f"(-1.0f));
	P3_CHECK64("inv-sqrt-neg", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("inv-sqrt-neg-fcsr", p3_fcsr(), 0x00010040u);
	p3_clear();
	__asm__ volatile("div.s %0,%1,%2" : "=f"(r) : "f"(0.0f), "f"(0.0f));
	P3_CHECK64("inv-zero-div-zero", p3_bitsf(r), 0x7FBFFFFFu);
	P3_CHECK64("inv-zero-div-zero-fcsr", p3_fcsr(), 0x00010040u);
	p3_clear();
	{
		float inf = 0.0f;

		__asm__ volatile("div.s %0,%1,%2"
		    : "=f"(inf) : "f"(1.0f), "f"(0.0f));
		p3_clear();
		__asm__ volatile("sub.s %0,%1,%2"
		    : "=f"(r) : "f"(inf), "f"(inf));
		P3_CHECK64("inv-inf-minus-inf", p3_bitsf(r), 0x7FBFFFFFu);
		P3_CHECK64("inv-inf-minus-inf-fcsr", p3_fcsr(), 0x00010040u);
		p3_clear();
		__asm__ volatile("mul.s %0,%1,%2"
		    : "=f"(r) : "f"(0.0f), "f"(inf));
		P3_CHECK64("inv-zero-times-inf", p3_bitsf(r), 0x7FBFFFFFu);
		P3_CHECK64("inv-zero-times-inf-fcsr", p3_fcsr(), 0x00010040u);
	}
	p3_clear();
	__asm__ volatile("cvt.w.s %0,%1" : "=f"(w) : "f"(1e20f));
	P3_CHECK64("inv-cvt-w-s-huge", (uint64_t)(uint32_t)w, 0x7FFFFFFFu);
	P3_CHECK64("inv-cvt-w-s-huge-fcsr", p3_fcsr(), 0x00010040u);
	p3_clear();
	{
		float qf = 0.0f;

		__asm__ volatile("div.s %0,%1,%2"
		    : "=f"(qf) : "f"(0.0f), "f"(0.0f));
		p3_clear();
		__asm__ volatile("cvt.w.s %0,%1" : "=f"(w) : "f"(qf));
		P3_CHECK64("inv-cvt-w-s-nan", (uint64_t)(uint32_t)w,
		    0x7FFFFFFFu);
		P3_CHECK64("inv-cvt-w-s-nan-fcsr", p3_fcsr(), 0x00010040u);
	}
	p3_clear();
	{
		double qd = 0.0;

		__asm__ volatile("div.d %0,%1,%2"
		    : "=f"(qd) : "f"(0.0), "f"(0.0));
		p3_clear();
		__asm__ volatile("cvt.l.d %0,%1" : "=f"(l) : "f"(qd));
		P3_CHECK64("inv-cvt-l-d-nan", (uint64_t)l,
		    0x7FFFFFFFFFFFFFFFULL);
		P3_CHECK64("inv-cvt-l-d-nan-fcsr", p3_fcsr(), 0x00010040u);
	}
	p3_clear();
	__asm__ volatile("div.s %0,%1,%2" : "=f"(r) : "f"(1.5f), "f"(0.0f));
	P3_CHECK64("div-s-by-zero", p3_bitsf(r), 0x7F800000u);
	P3_CHECK64("div-s-by-zero-fcsr", p3_fcsr(), 0x00008020u);
	p3_clear();
}

/* Rounding modes (RM 0..3 via FCSR) and directed conversions. */
static void t_round(void)
{
	static const int32_t want25[4] = { 2, 2, 3, 2 };
	static const int32_t wantn25[4] = { -2, -2, -2, -3 };
	static const uint32_t wantfcsr25[4] = {
		0x00001004u, 0x00001005u, 0x00001006u, 0x00001007u
	};
	unsigned m;
	char name[48];

	for (m = 0; m < 4; m++) {
		float p = 2.5f;
		int32_t w = 0;

		p3_clear();
		p3_setrm(m);
		__asm__ volatile("cvt.w.s %0,%1" : "=f"(w) : "f"(p));
		snprintf(name, sizeof(name), "cvt-w-s-2p5-rm%u", m);
		P3_CHECK64(name, (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)want25[m]);
		snprintf(name, sizeof(name), "cvt-w-s-2p5-rm%u-fcsr", m);
		P3_CHECK64(name, p3_fcsr(), wantfcsr25[m]);
	}
	for (m = 0; m < 4; m++) {
		float n = -2.5f;
		int32_t w = 0;

		p3_clear();
		p3_setrm(m);
		__asm__ volatile("cvt.w.s %0,%1" : "=f"(w) : "f"(n));
		snprintf(name, sizeof(name), "cvt-w-s-neg2p5-rm%u", m);
		P3_CHECK64(name, (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)wantn25[m]);
		snprintf(name, sizeof(name), "cvt-w-s-neg2p5-rm%u-fcsr", m);
		P3_CHECK64(name, p3_fcsr(), wantfcsr25[m]);
	}
	p3_clear();
	p3_setrm(0);
	{
		float q = 7.5f;
		int32_t w = 0;

		__asm__ volatile("trunc.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("trunc-7p5", (uint64_t)(uint32_t)w, 7u);
		__asm__ volatile("ceil.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("ceil-7p5", (uint64_t)(uint32_t)w, 8u);
		__asm__ volatile("floor.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("floor-7p5", (uint64_t)(uint32_t)w, 7u);
		__asm__ volatile("round.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("round-7p5", (uint64_t)(uint32_t)w, 8u);
		q = -7.5f;
		__asm__ volatile("trunc.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("trunc-neg7p5", (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)-7);
		__asm__ volatile("ceil.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("ceil-neg7p5", (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)-7);
		__asm__ volatile("floor.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("floor-neg7p5", (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)-8);
		__asm__ volatile("round.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("round-neg7p5", (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)-8);
		q = 2.5f;
		__asm__ volatile("round.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("round-2p5-even", (uint64_t)(uint32_t)w, 2u);
		q = 3.5f;
		__asm__ volatile("round.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("round-3p5-even", (uint64_t)(uint32_t)w, 4u);
		q = -2.5f;
		__asm__ volatile("round.w.s %0,%1" : "=f"(w) : "f"(q));
		P3_CHECK64("round-neg2p5-even", (uint64_t)(uint32_t)w,
		    (uint64_t)(uint32_t)-2);
	}
	{
		double d = 123456.789;
		int64_t l = 0;

		__asm__ volatile("trunc.l.d %0,%1" : "=f"(l) : "f"(d));
		P3_CHECK64("trunc-l-d", (uint64_t)l, 123456u);
		d = -123456.789;
		__asm__ volatile("ceil.l.d %0,%1" : "=f"(l) : "f"(d));
		P3_CHECK64("ceil-l-d", (uint64_t)l,
		    (uint64_t)(int64_t)-123456);
		d = 2.5;
		__asm__ volatile("round.l.d %0,%1" : "=f"(l) : "f"(d));
		P3_CHECK64("round-l-d-2p5", (uint64_t)l, 2u);
		d = -2.5;
		__asm__ volatile("round.l.d %0,%1" : "=f"(l) : "f"(d));
		P3_CHECK64("round-l-d-neg2p5", (uint64_t)l,
		    (uint64_t)(int64_t)-2);
	}
	p3_clear();
	p3_setrm(0);
}

/* All sixteen C.cond comparisons x {ordered-lt, ordered-eq, unordered}:
 * FCC bit plus the full FCSR word (quiet vs signaling behavior). */
static const char *const k_cmn[16] = {
	"c.f.s", "c.un.s", "c.eq.s", "c.ueq.s",
	"c.olt.s", "c.ult.s", "c.ole.s", "c.ule.s",
	"c.sf.s", "c.ngle.s", "c.seq.s", "c.ngl.s",
	"c.lt.s", "c.nge.s", "c.le.s", "c.ngt.s"
};
static const unsigned k_c_lt[16] = {
	0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1
};
static const unsigned k_c_eq[16] = {
	0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1
};
static const unsigned k_c_un[16] = {
	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1
};
static const uint32_t k_f_lt[16] = {
	0, 0, 0, 0,
	0x00800000u, 0x00800000u, 0x00800000u, 0x00800000u,
	0, 0, 0, 0,
	0x00800000u, 0x00800000u, 0x00800000u, 0x00800000u
};
static const uint32_t k_f_eq[16] = {
	0, 0, 0x00800000u, 0x00800000u, 0, 0,
	0x00800000u, 0x00800000u, 0, 0, 0x00800000u, 0x00800000u,
	0, 0, 0x00800000u, 0x00800000u
};
static const uint32_t k_f_un[16] = {
	0, 0x00800000u, 0, 0x00800000u,
	0, 0x00800000u, 0, 0x00800000u,
	0x00010040u, 0x00810040u, 0x00010040u, 0x00810040u,
	0x00010040u, 0x00810040u, 0x00010040u, 0x00810040u
};

/* 48-cell sweep: ordered-lt, ordered-eq and unordered operand pairs,
 * each asserting the FCC bit and the complete FCSR word. */
static void t_cond_full(void)
{
	int i;
	float qn = 0.0f;

	__asm__ volatile("div.s %0,%1,%2" : "=f"(qn) : "f"(0.0f), "f"(0.0f));
	for (i = 0; i < 16; i++) {
		float a = 1.5f, b = 2.5f, e = 2.5f;
		uint32_t cc = 0u;
		char nm[48];

		p3_clear();
		if (i == 0) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.f.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 1) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.un.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 2) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.eq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 3) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ueq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 4) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.olt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 5) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ult.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 6) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ole.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 7) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ule.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 8) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.sf.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 9) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngle.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 10) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.seq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 11) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngl.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 12) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.lt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 13) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.nge.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else if (i == 14) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.le.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		else __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(a), "m"(b) : "memory");
		snprintf(nm, sizeof(nm), "cond-lt-%s-fcc", k_cmn[i]);
		P3_CHECK64(nm, (cc >> 23) & 1u, k_c_lt[i]);
		snprintf(nm, sizeof(nm), "cond-lt-%s-fcsr", k_cmn[i]);
		P3_CHECK64(nm, cc, k_f_lt[i]);
		p3_clear();
		if (i == 0) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.f.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 1) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.un.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 2) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.eq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 3) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ueq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 4) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.olt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 5) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ult.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 6) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ole.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 7) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ule.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 8) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.sf.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 9) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngle.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 10) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.seq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 11) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngl.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 12) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.lt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 13) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.nge.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else if (i == 14) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.le.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		else __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(e), "m"(e) : "memory");
		snprintf(nm, sizeof(nm), "cond-eq-%s-fcc", k_cmn[i]);
		P3_CHECK64(nm, (cc >> 23) & 1u, k_c_eq[i]);
		snprintf(nm, sizeof(nm), "cond-eq-%s-fcsr", k_cmn[i]);
		P3_CHECK64(nm, cc, k_f_eq[i]);
		p3_clear();
		if (i == 0) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.f.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 1) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.un.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 2) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.eq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 3) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ueq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 4) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.olt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 5) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ult.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 6) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ole.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 7) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ule.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 8) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.sf.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 9) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngle.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 10) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.seq.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 11) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngl.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 12) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.lt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 13) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.nge.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else if (i == 14) __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.le.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		else __asm__ volatile("lwc1 $f2, %1\nlwc1 $f4, %2\n"
		    "c.ngt.s $f2, $f4\ncfc1 %0, $31" : "=r"(cc) : "m"(qn), "m"(a) : "memory");
		snprintf(nm, sizeof(nm), "cond-un-%s-fcc", k_cmn[i]);
		P3_CHECK64(nm, (cc >> 23) & 1u, k_c_un[i]);
		snprintf(nm, sizeof(nm), "cond-un-%s-fcsr", k_cmn[i]);
		P3_CHECK64(nm, cc, k_f_un[i]);
	}
	{
		double x = 1.5, z = 2.5, qd = 0.0;
		uint32_t cc = 0u;

		__asm__ volatile("div.d %0,%1,%2" : "=f"(qd) : "f"(0.0), "f"(0.0));
		p3_clear();
		__asm__ volatile("ctc1 $0, $31\nldc1 $f2, %1\nldc1 $f4, %2\n"
		    "c.eq.d $f2, $f4\ncfc1 %0, $31"
		    : "=r"(cc) : "m"(x), "m"(x) : "memory");
		P3_CHECK64("cond-eq-d-fcc", (cc >> 23) & 1u, 1u);
		P3_CHECK64("cond-eq-d-fcsr", cc, 0x00800000u);
		p3_clear();
		__asm__ volatile("ctc1 $0, $31\nldc1 $f2, %1\nldc1 $f4, %2\n"
		    "c.lt.d $f2, $f4\ncfc1 %0, $31"
		    : "=r"(cc) : "m"(x), "m"(z) : "memory");
		P3_CHECK64("cond-lt-d-fcc", (cc >> 23) & 1u, 1u);
		P3_CHECK64("cond-lt-d-fcsr", cc, 0x00800000u);
		p3_clear();
		__asm__ volatile("ctc1 $0, $31\nldc1 $f2, %1\nldc1 $f4, %2\n"
		    "c.un.d $f2, $f4\ncfc1 %0, $31"
		    : "=r"(cc) : "m"(qd), "m"(x) : "memory");
		P3_CHECK64("cond-un-d-fcc", (cc >> 23) & 1u, 1u);
		P3_CHECK64("cond-un-d-fcsr", cc, 0x00800000u);
		p3_clear();
		__asm__ volatile("ctc1 $0, $31\nldc1 $f2, %1\nldc1 $f4, %2\n"
		    "c.lt.d $f2, $f4\ncfc1 %0, $31"
		    : "=r"(cc) : "m"(qd), "m"(x) : "memory");
		P3_CHECK64("cond-lt-d-nan-fcc", (cc >> 23) & 1u, 0u);
		P3_CHECK64("cond-lt-d-nan-fcsr", cc, 0x00010040u);
		p3_clear();
	}
}

/* BC1T/BC1F/BC1TL/BC1FL taken + not-taken with delay-slot accounting.
 * FCC is sourced from a real C.EQ.S (eq_true ? equal : unequal). */
#define P3_BC1(name, mnem, eq_true, take, likely) do { \
	uint64_t _d = 0u, _t = 0u; \
	float _x = 1.5f, _y = (eq_true) ? 1.5f : 2.5f; \
	__asm__ volatile(".set noreorder\n\t" \
	    "lwc1 $f2, %2\n\tlwc1 $f4, %3\n\tc.eq.s $f2, $f4\n\t" \
	    mnem " 1f\n\t" \
	    "li %0, 7\n\tli %1, 2\n\tj 2f\n\tnop\n\t1:\n\t" \
	    "li %1, 1\n\t2:\n\t.set reorder" \
	    : "+r"(_d), "+r"(_t) : "m"(_x), "m"(_y) : "memory"); \
	P3_CHECK(name, _d == ((likely) ? ((take) ? 7u : 0u) : 7u) && \
	    _t == ((take) ? 1u : 2u)); \
} while (0)

static void t_branch(void)
{
	p3_clear();
	P3_BC1("bc1t-taken", "bc1t", 1, 1, 0);
	P3_BC1("bc1t-not-taken", "bc1t", 0, 0, 0);
	P3_BC1("bc1f-taken", "bc1f", 0, 1, 0);
	P3_BC1("bc1f-not-taken", "bc1f", 1, 0, 0);
	P3_BC1("bc1tl-taken", "bc1tl", 1, 1, 1);
	P3_BC1("bc1tl-not-taken", "bc1tl", 0, 0, 1);
	P3_BC1("bc1fl-taken", "bc1fl", 0, 1, 1);
	P3_BC1("bc1fl-not-taken", "bc1fl", 1, 0, 1);
}

/* FPR data movement: MFC1 sign-extends, DMFC1/DMTC1 carry 64 bits,
 * LWC1 preserves the upper lane (FR=1), SWC1/SDC1 round-trip. */
static void t_moves(void)
{
	uint64_t v = 0u, got = 0u;
	float y = 0.0f;

	p3_clear();
	__asm__ volatile("mtc1 %1, $f2\nmfc1 %0, $f2"
	    : "=r"(v) : "r"((uint64_t)0xC0400000u));
	P3_CHECK64("mfc1-sign-extends", v, 0xFFFFFFFFC0400000ULL);
	__asm__ volatile("dmtc1 %1, $f2\ndmfc1 %0, $f2"
	    : "=r"(v) : "r"(0x400000003FC00000ULL));
	P3_CHECK64("dmfc1-full-64", v, 0x400000003FC00000ULL);
	{
		float x = 1.5f;

		__asm__ volatile("dmtc1 %1, $f2\nlwc1 $f2, %2\ndmfc1 %0, $f2"
		    : "=r"(got) : "r"(0xDEADBEEF00000000ULL), "m"(x));
		P3_CHECK64("lwc1-preserves-upper", got, 0xDEADBEEF3FC00000ULL);
		__asm__ volatile("lwc1 $f2, %1\nswc1 $f2, %0"
		    : "=m"(y) : "m"(x) : "memory");
		P3_CHECK64("swc1-roundtrip", p3_bitsf(y), 0x3FC00000u);
	}
	{
		double x = 7.5, z = 0.0;

		__asm__ volatile("ldc1 $f2, %1\nsdc1 $f2, %0"
		    : "=m"(z) : "m"(x) : "memory");
		P3_CHECK64("sdc1-roundtrip", p3_bitsd(z),
		    0x401E000000000000ULL);
	}
	{
		uint32_t w = 0u;

		__asm__ volatile("li %0, 3\nctc1 %0, $31\ncfc1 %0, $31"
		    : "+r"(w) :: "memory");
		P3_CHECK64("ctc1-cfc1-rm", w, 3u);
		p3_clear();
	}
}

/* Adjudicated SIMD scope: paired-single lanes plus scalar COP1X
 * fused multiply-add. MADD.S semantics: fd = fr + fs * ft. */
static void t_ps(void)
{
	uint64_t lo = 0u, hi = 0u;

	p3_clear();
	{
		uint64_t pat = 0x400000003FC00000ULL;

		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "add.ps $f4, $f2, $f2\nmfc1 %0, $f4\nmfhc1 %1, $f4\n"
		    ".set pop"
		    : "=r"(lo), "=r"(hi) : "m"(pat));
		P3_CHECK64("ps-add-lo", lo, 0x40400000u);
		P3_CHECK64("ps-add-hi", hi, 0x40800000u);
	}
	{
		uint64_t fs = 0x4080000040400000ULL;
		uint64_t ft = 0x400000003FC00000ULL;

		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "ldc1 $f4, %3\nsub.ps $f6, $f2, $f4\n"
		    "mfc1 %0, $f6\nmfhc1 %1, $f6\n.set pop"
		    : "=r"(lo), "=r"(hi) : "m"(fs), "m"(ft));
		P3_CHECK64("ps-sub-lo", lo, 0x3FC00000u);
		P3_CHECK64("ps-sub-hi", hi, 0x40000000u);
	}
	{
		uint64_t fs = 0x400000003FC00000ULL;
		uint64_t ft = 0x4020000040400000ULL;

		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "ldc1 $f4, %3\nmul.ps $f6, $f2, $f4\n"
		    "mfc1 %0, $f6\nmfhc1 %1, $f6\n.set pop"
		    : "=r"(lo), "=r"(hi) : "m"(fs), "m"(ft));
		P3_CHECK64("ps-mul-lo", lo, 0x40900000u);
		P3_CHECK64("ps-mul-hi", hi, 0x40A00000u);
	}
	{
		uint64_t pat = 0x40000000BFC00000ULL;

		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "abs.ps $f4, $f2\nmfc1 %0, $f4\nmfhc1 %1, $f4\n"
		    ".set pop"
		    : "=r"(lo), "=r"(hi) : "m"(pat));
		P3_CHECK64("ps-abs-lo", lo, 0x3FC00000u);
		P3_CHECK64("ps-abs-hi", hi, 0x40000000u);
		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "neg.ps $f4, $f2\nmfc1 %0, $f4\nmfhc1 %1, $f4\n"
		    ".set pop"
		    : "=r"(lo), "=r"(hi) : "m"(pat));
		P3_CHECK64("ps-neg-lo", lo, 0x3FC00000u);
		P3_CHECK64("ps-neg-hi", hi, 0xFFFFFFFFC0000000ULL);
		__asm__ volatile(".set push\n.set mips64r2\nldc1 $f2, %2\n"
		    "mov.ps $f4, $f2\nmfc1 %0, $f4\nmfhc1 %1, $f4\n"
		    ".set pop"
		    : "=r"(lo), "=r"(hi) : "m"(pat));
		P3_CHECK64("ps-mov-lo", lo, 0xFFFFFFFFBFC00000ULL);
		P3_CHECK64("ps-mov-hi", hi, 0x40000000u);
	}
	{
		float a = 1.5f, b = 2.0f, c = 3.0f, r = 0.0f;

		__asm__ volatile("madd.s %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("madd-s", p3_bitsf(r), 0x40F00000u);
		__asm__ volatile("msub.s %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("msub-s", p3_bitsf(r), 0x40900000u);
		__asm__ volatile("nmadd.s %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("nmadd-s", p3_bitsf(r), 0xC0F00000u);
		__asm__ volatile("nmsub.s %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("nmsub-s", p3_bitsf(r), 0xC0900000u);
	}
	{
		double a = 1.5, b = 2.0, c = 3.0, r = 0.0;

		__asm__ volatile("madd.d %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("madd-d", p3_bitsd(r), 0x401E000000000000ULL);
		__asm__ volatile("msub.d %0,%1,%2,%3"
		    : "=f"(r) : "f"(a), "f"(b), "f"(c));
		P3_CHECK64("msub-d", p3_bitsd(r), 0x4012000000000000ULL);
	}
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("P3-FP-SIMD suite abi=%s endian=%s\n", P3_ABI, P3_ENDIAN);
	t_model();
	t_arith_s();
	t_arith_d();
	t_cvt();
	t_nan();
	t_invalid();
	t_round();
	t_cond_full();
	t_branch();
	t_moves();
	t_ps();
	printf("P3-SUMMARY failed=%u total=%u\n", g_fail, g_pass + g_fail);
	printf("P3-RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
