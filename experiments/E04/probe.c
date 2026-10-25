/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * E04: Legacy vs IEEE-2008 NaN/ABS FPU semantics in 64-bit FR=1 mode.
 *
 * Compile-time: sizeof table for float/double, compiler NaN/ABS mode
 *   macros (__mips_nan2008, _MIPS_SIM, __mips_fpr).
 * Runtime (MIPS only, scalar FPU, no MSA): FIR/FCSR dump, ELF e_flags
 *   EF_MIPS_NAN2008 check of the running binary, default-NaN bit
 *   patterns from 0.0/0.0, and abs.fmt/neg.fmt/add.fmt behaviour plus
 *   FCSR Invalid Cause/Flag bits on quiet/signalling NaN payloads in
 *   both the IEEE-2008 (quiet-bit-set) and legacy (quiet-bit-clear)
 *   encodings.
 *
 * Cross (examples):
 *   mips64el-linux-gnuabi64-gcc -mabi=64 -std=c11 -Werror=vla -pedantic \
 *     -Wall -Wextra -Werror -static -O1 probe.c -o probe-n64le
 *   mips64el-linux-gnuabi64-gcc -mabi=n32 ... (run: qemu-mipsn32el)
 *   mips64-linux-gnuabi64-gcc -mabi=64 ...   (run: qemu-mips64)
 *   mips64-linux-gnuabi64-gcc -mabi=n32 ...  (run: qemu-mipsn32)
 */

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* EF_MIPS_NAN2008: bit 10 of the MIPS ELF e_flags (0x400). */
#define EF_MIPS_NAN2008 0x400u

#ifdef __mips__
static unsigned read_fcsr(void)
{
	unsigned v;

	__asm__ volatile("cfc1 %0, $31" : "=r" (v));
	return v;
}

static void write_fcsr(unsigned v)
{
	__asm__ volatile("ctc1 %0, $31" : : "r" (v));
}

static unsigned read_fir(void)
{
	unsigned v;

	__asm__ volatile("cfc1 %0, $0" : "=r" (v));
	return v;
}

static double op_abs_d(double x)
{
	double r;

	__asm__ volatile("abs.d %0, %1" : "=f" (r) : "f" (x));
	return r;
}

static double op_neg_d(double x)
{
	double r;

	__asm__ volatile("neg.d %0, %1" : "=f" (r) : "f" (x));
	return r;
}

static double op_add_d(double x, double y)
{
	double r;

	__asm__ volatile("add.d %0, %1, %2" : "=f" (r) : "f" (x), "f" (y));
	return r;
}

static float op_abs_s(float x)
{
	float r;

	__asm__ volatile("abs.s %0, %1" : "=f" (r) : "f" (x));
	return r;
}

static float op_neg_s(float x)
{
	float r;

	__asm__ volatile("neg.s %0, %1" : "=f" (r) : "f" (x));
	return r;
}

static float op_add_s(float x, float y)
{
	float r;

	__asm__ volatile("add.s %0, %1, %2" : "=f" (r) : "f" (x), "f" (y));
	return r;
}

static void clear_fcsr_flags(void)
{
	write_fcsr(read_fcsr() & ~0x7Cu);
}
#endif

static void print_fcsr(const char *tag, unsigned fcsr)
{
	printf("%s fcsr=0x%08x cause=0x%02x enables=0x%02x flags=0x%02x rm=%u\n",
	    tag, fcsr, (fcsr >> 12) & 0x3Fu, (fcsr >> 7) & 0x1Fu,
	    (fcsr >> 2) & 0x1Fu, fcsr & 3u);
}

/* Returns 1 when the ELF header at path carries EF_MIPS_NAN2008. */
static int elf_nan2008(const char *path, unsigned *flags_out,
    unsigned *class_out, unsigned *data_out)
{
	unsigned char eh[64];
	unsigned v;
	size_t o;
	FILE *f;

	f = fopen(path, "rb");
	if (f == NULL)
		return -1;
	if (fread(eh, 1, sizeof(eh), f) != sizeof(eh)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	if (eh[0] != 0x7Fu || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F')
		return -1;
	*class_out = eh[4];
	*data_out = eh[5];
	/* e_flags lives at offset 48 in ELF64, offset 36 in ELF32. */
	o = (*class_out == 1u) ? 36 : 48;
	if (*data_out == 1u) {	/* ELFDATA2LSB */
		v = (unsigned)eh[o] | ((unsigned)eh[o + 1] << 8) |
		    ((unsigned)eh[o + 2] << 16) | ((unsigned)eh[o + 3] << 24);
	} else if (*data_out == 2u) {	/* ELFDATA2MSB */
		v = ((unsigned)eh[o] << 24) | ((unsigned)eh[o + 1] << 16) |
		    ((unsigned)eh[o + 2] << 8) | (unsigned)eh[o + 3];
	} else {
		return -1;
	}
	*flags_out = v;
	return (v & EF_MIPS_NAN2008) != 0u ? 1 : 0;
}

static uint64_t dbits(double x)
{
	uint64_t b;

	memcpy(&b, &x, sizeof(b));
	return b;
}

static uint32_t fbits(float x)
{
	uint32_t b;

	memcpy(&b, &x, sizeof(b));
	return b;
}

static double mkd(uint64_t b)
{
	double x;

	memcpy(&x, &b, sizeof(x));
	return x;
}

static float mkf(uint32_t b)
{
	float x;

	memcpy(&x, &b, sizeof(x));
	return x;
}

static int failures;

static void check(int cond, const char *what, uint64_t got, uint64_t want)
{
	if (!cond) {
		printf("CHECK-FAIL %s got=0x%llx want=0x%llx\n", what,
		    (unsigned long long)got, (unsigned long long)want);
		failures++;
	}
}

#ifdef __mips__
static void test_double(const char *name, uint64_t bits)
{
	double x = mkd(bits);
	double r;
	unsigned f;
	uint64_t rb;

	printf("D %s bits=0x%016llx isnan=%d\n", name,
	    (unsigned long long)bits, isnan(x) != 0);

	clear_fcsr_flags();
	r = op_add_d(x, x);
	f = read_fcsr();
	rb = dbits(r);
	printf("D %s add=self bits=0x%016llx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long long)rb, (f >> 2) & 1u, (f >> 12) & 1u);

	clear_fcsr_flags();
	r = op_abs_d(x);
	f = read_fcsr();
	rb = dbits(r);
	printf("D %s abs bits=0x%016llx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long long)rb, (f >> 2) & 1u, (f >> 12) & 1u);
	/* abs of a signalling NaN raises Invalid and may quiet the
	 * result; only demand bit-exactness when nothing signalled. */
	if ((((f >> 2) & 1u) == 0u))
		check(rb == (bits & 0x7FFFFFFFFFFFFFFFuLL), name, rb,
		    bits & 0x7FFFFFFFFFFFFFFFuLL);

	clear_fcsr_flags();
	r = op_neg_d(x);
	f = read_fcsr();
	rb = dbits(r);
	printf("D %s neg bits=0x%016llx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long long)rb, (f >> 2) & 1u, (f >> 12) & 1u);
	check(rb == (bits ^ 0x8000000000000000uLL), name, rb,
	    bits ^ 0x8000000000000000uLL);
}

static void test_float(const char *name, uint32_t bits)
{
	float x = mkf(bits);
	float r;
	unsigned f;
	uint32_t rb;

	printf("S %s bits=0x%08lx isnan=%d\n", name, (unsigned long)bits,
	    isnan(x) != 0);

	clear_fcsr_flags();
	r = op_add_s(x, x);
	f = read_fcsr();
	rb = fbits(r);
	printf("S %s add=self bits=0x%08lx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long)rb, (f >> 2) & 1u, (f >> 12) & 1u);

	clear_fcsr_flags();
	r = op_abs_s(x);
	f = read_fcsr();
	rb = fbits(r);
	printf("S %s abs bits=0x%08lx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long)rb, (f >> 2) & 1u, (f >> 12) & 1u);
	if ((((f >> 2) & 1u) == 0u))
		check(rb == (bits & 0x7FFFFFFFu), name, rb,
		    bits & 0x7FFFFFFFu);

	clear_fcsr_flags();
	r = op_neg_s(x);
	f = read_fcsr();
	rb = fbits(r);
	printf("S %s neg bits=0x%08lx inv_flag=%u inv_cause=%u\n",
	    name, (unsigned long)rb, (f >> 2) & 1u, (f >> 12) & 1u);
	check(rb == (bits ^ 0x80000000u), name, rb, bits ^ 0x80000000u);
}
#endif

int main(int argc, char **argv)
{
	unsigned eflags = 0;
	unsigned eclass = 0;
	unsigned edata = 0;
	int nan2008 = -2;
	const char *self;

	printf("--- sizes ---\n");
	printf("sizeof(float)=%lu\n", (unsigned long)sizeof(float));
	printf("sizeof(double)=%lu\n", (unsigned long)sizeof(double));

	printf("--- arch macros ---\n");
#ifdef __mips__
	printf("__mips__=1\n");
#else
	printf("__mips__=0\n");
#endif
#ifdef _MIPS_SIM
	printf("_MIPS_SIM=%d\n", _MIPS_SIM);
#else
	printf("_MIPS_SIM=undef\n");
#endif
#ifdef __mips_fpr
	printf("__mips_fpr=%d\n", __mips_fpr);
#else
	printf("__mips_fpr=undef\n");
#endif
#ifdef __mips_nan2008
	printf("__mips_nan2008=1\n");
#else
	printf("__mips_nan2008=0\n");
#endif
#ifdef __mips_abs2008
	printf("__mips_abs2008=1\n");
#else
	printf("__mips_abs2008=0\n");
#endif
#ifdef __mips__
	printf("__BYTE_ORDER__=%d (4321=BE 1234=LE)\n", __BYTE_ORDER__);
#endif

#ifdef __mips__
	printf("--- FIR/FCSR ---\n");
	printf("fir=0x%08x f64=%u\n", read_fir(), (read_fir() >> 22) & 1u);
	print_fcsr("fcsr-init", read_fcsr());
#endif

	printf("--- ELF e_flags ---\n");
	self = (argc > 0 && argv[0] != NULL) ? argv[0] : "/proc/self/exe";
	nan2008 = elf_nan2008(self, &eflags, &eclass, &edata);
	if (nan2008 == -1)
		nan2008 = elf_nan2008("/proc/self/exe", &eflags, &eclass,
		    &edata);
	printf("elf_class=%u (1=32 2=64) elf_data=%u (1=LSB 2=MSB)\n",
	    eclass, edata);
	printf("elf_e_flags=0x%08x nan2008=%d\n", eflags, nan2008);
	if (nan2008 < 0) {
		printf("CHECK-FAIL elf-parse\n");
		failures++;
	}

#ifdef __mips__
	printf("--- default NaN (0.0/0.0) ---\n");
	{
		volatile double z = 0.0;
		volatile float w = 0.0f;
		double dz = z / z;
		float fz = (float)(w / w);

		printf("default-double bits=0x%016llx\n",
		    (unsigned long long)dbits(dz));
		printf("default-float bits=0x%08lx\n",
		    (unsigned long)fbits(fz));
	}

	printf("--- double patterns ---\n");
	test_double("qbit1-nopay", 0x7FF8000000000000uLL);
	test_double("qbit1-pay", 0x7FF8000000000001uLL);
	test_double("qbit0-lowpay", 0x7FF0000000000001uLL);
	test_double("qbit0-fullpay", 0x7FF7FFFFFFFFFFFFuLL);
	test_double("neg-normal", 0xC005800000000000uLL);

	printf("--- float patterns ---\n");
	test_float("qbit1-nopay", 0x7FC00000u);
	test_float("qbit1-pay", 0x7FC00001u);
	test_float("qbit0-lowpay", 0x7F800001u);
	test_float("qbit0-fullpay", 0x7FBFFFFFu);
	test_float("neg-normal", 0xC02C0000u);

	printf("--- FCSR final ---\n");
	print_fcsr("fcsr-final", read_fcsr());
#else
	printf("non-MIPS contrast: no FPU semantics probed\n");
#endif

	if (failures == 0) {
		printf("RESULT=PASS\n");
		return 0;
	}
	printf("RESULT=FAIL failures=%d\n", failures);
	return 1;
}
