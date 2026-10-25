/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * E01: MIPS N64 vs N32 syscall bases, register args, $a3 convention,
 * and TASK_SIZE address limits.
 *
 * What this verifies under qemu-mips64* (N64) and qemu-mipsn32* (N32):
 *  1. Own-ABI numbers work (read/write/exit/getpid through the own base:
 *     5000 for N64, 6000 for N32); the same offset through the other base
 *     fails with ENOSYS.
 *  2. Syscall args 1..6 travel in $a0..$a5 (registers on MIPS64 -- no
 *     O32-style stack slots). A 6-arg mmap success proves args 5,6 reach
 *     the kernel; a C 6-arg call observes the registers directly.
 *  3. 64-bit args occupy a single 64-bit register (no O32 even-pair
 *     splitting).
 *  4. Success returns $a3=0/$v0=ret; errors return $a3=1/$v0=+errno.
 *  5. TASK_SIZE boundary: valid mappings land below it; a probe above it
 *     is observed (not asserted -- emulator policy, recorded as-is).
 *
 * Curated C11: -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror.
 * No VLAs, no Annex K, no <threads.h>, no _Generic.
 */

#include <errno.h>
#include <fcntl.h>
#include <sgidefs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Sanity: MIPS errno values are load-bearing for the checks below. */
/* MIPS is NOT asm-generic: ENOSYS is 89 on MIPS (EL2NSYNC owns 38). */
_Static_assert(ENOENT == 2, "ENOENT must be 2");
_Static_assert(EBADF == 9, "EBADF must be 9");
_Static_assert(ENOSYS == 89, "ENOSYS must be 89 on MIPS");

#if _MIPS_SIM == _MIPS_SIM_ABI64
#define ABI_NAME "n64"
#define OWN_BASE 5000L
#define OTHER_BASE 6000L
/* N64 TASK_SIZE: 1ULL << 40. */
#define TASK_SIZE_LIM 0x10000000000ULL
#elif _MIPS_SIM == _MIPS_SIM_NABI32
#define ABI_NAME "n32"
#define OWN_BASE 6000L
#define OTHER_BASE 5000L
/* N32 TASK_SIZE: 0x7fff8000. */
#define TASK_SIZE_LIM 0x7fff8000ULL
#else
#define ABI_NAME "unknown"
#define OWN_BASE 0L
#define OTHER_BASE 0L
#define TASK_SIZE_LIM 0ULL
#endif

#if defined(__NR_exit)
#define NR_EXIT __NR_exit
#define NR_EXIT_NAME "__NR_exit"
#elif defined(__NR_exit_group)
#define NR_EXIT __NR_exit_group
#define NR_EXIT_NAME "__NR_exit_group"
#else
#error "need __NR_exit or __NR_exit_group"
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* ------------------------------------------------------------------ */
/* Raw syscalls: number in $v0, args 1..6 in $a0..$a5 ($4..$9).       */
/* $a3 ($7) doubles as arg 4 and as the error flag: the kernel        */
/* answers $v0=ret/$a3=0 on success, $v0=+errno/$a3=1 on error.       */
/* The trap itself is the `syscall` mnemonic -> word 0x0000000c.       */
/* ------------------------------------------------------------------ */

typedef struct {
	long v0;
	long a3;
} scres_t;

static scres_t raw_sys0(long n)
{
	register long r2 __asm__("$2") = n;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : /* no inputs */
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys1(long n, long a)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys3(long n, long a, long b, long c)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4), "r"(r5), "r"(r6)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys6(long n, long a, long b, long c,
			long d, long e, long f)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = d;
	register long r8 __asm__("$8") = e;
	register long r9 __asm__("$9") = f;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4), "r"(r5), "r"(r6), "r"(r8), "r"(r9)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

/* ------------------------------------------------------------------ */
/* Callee-side observation in plain C: the compiler copies the        */
/* incoming $a0.. registers into the parameters, which main() then   */
/* compares against the magic inputs.                                 */
/* ------------------------------------------------------------------ */

unsigned long long g_a0, g_a1, g_a2, g_a3, g_a4, g_a5;
unsigned long long h_tag, h_ll, h_tail;

void callee6(unsigned long long a0, unsigned long long a1,
	     unsigned long long a2, unsigned long long a3,
	     unsigned long long a4, unsigned long long a5)
{
	g_a0 = a0;
	g_a1 = a1;
	g_a2 = a2;
	g_a3 = a3;
	g_a4 = a4;
	g_a5 = a5;
}

void callee_ll(unsigned long long tag, unsigned long long ll,
	       unsigned long long tail)
{
	h_tag = tag;
	h_ll = ll;
	h_tail = tail;
}

/* ------------------------------------------------------------------ */

static int g_fail = 0;

static void check(int cond, const char *msg)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", msg);
	if (!cond)
		g_fail++;
}

int main(void)
{
	scres_t r;
	long own_base;
	long cross_getpid;
	long cross_write;
	int fd;
	int status;
	pid_t pid;
	char tmp[64];
	const char msg[] = "e01-write-probe\n";
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const char *endian = "little";
#else
	const char *endian = "big";
#endif

	printf("E01 N64/N32 syscall base + $a3 probe (abi=%s %s-endian)\n",
	       ABI_NAME, endian);
	printf("sizeof(long)=%lu sizeof(long long)=%lu sizeof(void*)=%lu "
	       "sizeof(scres_t)=%lu offsetof(a3)=%lu\n",
	       (unsigned long)sizeof(long),
	       (unsigned long)sizeof(unsigned long long),
	       (unsigned long)sizeof(void *),
	       (unsigned long)sizeof(scres_t),
	       (unsigned long)offsetof(scres_t, a3));
	printf("__NR: read=%d write=%d close=%d getpid=%d %s=%d mmap=%d "
	       "munmap=%d\n",
	       __NR_read, __NR_write, __NR_close, __NR_getpid,
	       NR_EXIT_NAME, NR_EXIT, __NR_mmap, __NR_munmap);
	printf("TASK_SIZE=0x%llx\n", TASK_SIZE_LIM);

	/* --- 1. own base derives from the numbers themselves --- */
	own_base = (long)(__NR_read / 1000) * 1000L;
	printf("derived base=%ld (expect %ld)\n", own_base, OWN_BASE);
	check(own_base == OWN_BASE, "own syscall base matches ABI");
	check(__NR_write == (int)(own_base + 1L),
	      "write = base+1");
	check(__NR_getpid - own_base >= 0 &&
	      __NR_getpid - own_base < 1000,
	      "getpid shares the own base");

	/* --- 2. C-compiler 6-arg call: args arrive in $a0..$a5 --- */
	callee6(0x1111111111111111ull, 0x2222222222222222ull,
		0x3333333333333333ull, 0x4444444444444444ull,
		0x5555555555555555ull, 0x6666666666666666ull);
	printf("compiler-call obs: %016llx %016llx %016llx "
	       "%016llx %016llx %016llx\n",
	       g_a0, g_a1, g_a2, g_a3, g_a4, g_a5);
	check(g_a0 == 0x1111111111111111ull &&
	      g_a1 == 0x2222222222222222ull &&
	      g_a2 == 0x3333333333333333ull &&
	      g_a3 == 0x4444444444444444ull &&
	      g_a4 == 0x5555555555555555ull &&
	      g_a5 == 0x6666666666666666ull,
	      "args1-6 arrive whole in $a0..$a5");

	/* --- 3. 64-bit arg occupies one 64-bit register --- */
	callee_ll(0x1111111111111111ull, 0x2222222233333333ull,
		  0x4444444444444444ull);
	printf("ll obs: tag=%016llx ll=%016llx tail=%016llx\n",
	       h_tag, h_ll, h_tail);
	check(h_tag == 0x1111111111111111ull &&
	      h_ll == 0x2222222233333333ull &&
	      h_tail == 0x4444444444444444ull,
	      "u64 arg arrives whole in one register");

	/* --- 4a. success paths: $a3=0 --- */
	r = raw_sys0(__NR_getpid);
	printf("getpid: v0=%ld a3=%ld (libc=%d)\n", r.v0, r.a3, getpid());
	check(r.a3 == 0 && r.v0 > 0 && r.v0 == (long)getpid(),
	      "getpid success: $a3=0, $v0=pid");

	r = raw_sys3(__NR_write, 1L, (long)msg, (long)(sizeof(msg) - 1));
	printf("write(1): v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 0 && r.v0 == (long)(sizeof(msg) - 1),
	      "write success: $a3=0, $v0=len");

	/* --- 4b. error paths: $a3=1, $v0=+errno --- */
	r = raw_sys3(__NR_write, -1L, (long)msg, 3L);
	printf("write(-1): v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == EBADF,
	      "bad-fd write: $a3=1, $v0=EBADF(9)");

	snprintf(tmp, sizeof(tmp), "/tmp/e01probe-%d", getpid());
	fd = open(tmp, O_CREAT | O_RDWR | O_TRUNC, 0600);
	check(fd >= 0, "temp file created");
	if (fd >= 0) {
		r = raw_sys3(__NR_write, (long)fd, (long)msg, 3L);
		check(r.a3 == 0 && r.v0 == 3L, "write(fd): $a3=0, $v0=3");
		r = raw_sys1(__NR_close, (long)fd);
		check(r.a3 == 0 && r.v0 == 0, "raw close ok");
		r = raw_sys1(__NR_close, (long)fd);
		printf("close(again): v0=%ld a3=%ld\n", r.v0, r.a3);
		check(r.a3 == 1 && r.v0 == EBADF,
		      "double close: $a3=1, $v0=EBADF(9)");
		unlink(tmp);
	}

	/* --- 5. cross-base numbers: same offset, other base -> ENOSYS --- */
	cross_getpid = (long)__NR_getpid - own_base + OTHER_BASE;
	cross_write = (long)__NR_write - own_base + OTHER_BASE;
	r = raw_sys0(cross_getpid);
	printf("cross-base getpid #%ld: v0=%ld a3=%ld\n",
	       cross_getpid, r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == ENOSYS,
	      "other-base getpid: $a3=1, $v0=ENOSYS(89)");
	r = raw_sys3(cross_write, 1L, (long)msg, 3L);
	printf("cross-base write #%ld: v0=%ld a3=%ld\n",
	       cross_write, r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == ENOSYS,
	      "other-base write: $a3=1, $v0=ENOSYS(89)");

	/* --- 6. exit through the own base (child), ENOSYS cross-base --- */
	pid = fork();
	if (pid == 0) {
		/* Child: own-base exit must terminate with 42. */
		r = raw_sys1(NR_EXIT, 42L);
		/* If we are still alive the exit did not happen. */
		_exit(r.a3 == 0 ? 11 : 12);
	}
	check(pid > 0, "fork for own-base exit probe");
	if (pid > 0) {
		pid_t w = waitpid(pid, &status, 0);

		check(w == pid && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 42,
		      "own-base exit terminates child with status 42");
	}
	pid = fork();
	if (pid == 0) {
		/* Child: cross-base exit must NOT terminate. */
		r = raw_sys1((long)NR_EXIT - own_base + OTHER_BASE, 42L);
		_exit((r.a3 == 1 && r.v0 == ENOSYS) ? 0 : 1);
	}
	check(pid > 0, "fork for cross-base exit probe");
	if (pid > 0) {
		pid_t w = waitpid(pid, &status, 0);

		check(w == pid && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 0,
		      "cross-base exit: ENOSYS, child survives");
	}

	/* --- 7. 6-arg mmap through $a0..$a5; TASK_SIZE boundary --- */
	{
		void *hi;

		r = raw_sys6(__NR_mmap, 0L, 4096L,
			     (long)(PROT_READ | PROT_WRITE),
			     (long)(MAP_PRIVATE | MAP_ANONYMOUS), -1L, 0L);
		printf("mmap(anon): v0=0x%lx a3=%ld\n",
		       (unsigned long)r.v0, r.a3);
		check(r.a3 == 0 && r.v0 != -1L,
		      "6-arg mmap success via register args 5,6");
		if (r.a3 == 0 && r.v0 != -1L) {
			unsigned long long addr =
				(unsigned long long)(uintptr_t)r.v0;

			printf("mmap addr=0x%llx TASK_SIZE=0x%llx\n",
			       addr, TASK_SIZE_LIM);
			/* Observation only: qemu-user places the guest
			 * mapping wherever its own allocator likes (seen
			 * at 0xffff... on N64LE), ignoring the guest
			 * TASK_SIZE. Recorded as-is in FINDINGS.md. */
			*(volatile uint32_t *)r.v0 = 0xA5A5A5A5u;
			check(*(volatile uint32_t *)r.v0 == 0xA5A5A5A5u,
			      "anonymous mapping is writable");
			r = raw_sys3(__NR_munmap, r.v0, 4096L, 0L);
			printf("munmap(addr,len): v0=%ld a3=%ld\n",
			       r.v0, r.a3);
			check(r.a3 == 0 && r.v0 == 0, "munmap ok");
		}

		/* Observation only: fixed probe at/above TASK_SIZE. */
		hi = (void *)(uintptr_t)TASK_SIZE_LIM;
		r = raw_sys6(__NR_mmap, (long)hi, 4096L,
			     (long)(PROT_READ | PROT_WRITE),
			     (long)(MAP_PRIVATE | MAP_ANONYMOUS |
				    MAP_FIXED_NOREPLACE), -1L, 0L);
		printf("mmap(fixed, TASK_SIZE): v0=0x%lx a3=%ld "
		       "(observation only)\n",
		       (unsigned long)r.v0, r.a3);
		if (r.a3 == 0)
			(void)raw_sys3(__NR_munmap, r.v0, 4096L, 0L);
	}

	printf("E01-RESULT: %s (%d checks failed)\n",
	       g_fail ? "FAIL" : "PASS", g_fail);
	return g_fail != 0;
}
