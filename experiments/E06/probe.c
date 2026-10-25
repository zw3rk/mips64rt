/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * E06: TLS (rdhwr $29 / set_thread_area) probe for MIPS64 N64 + N32.
 *
 * Build (in debian linux/arm64 container, static):
 *   mips64el-linux-gnuabi64-gcc -mabi=64 -static -O2 -o probe_n64le probe.c -pthread
 *   mips64el-linux-gnuabi64-gcc -mabi=n32 -static -O2 -o probe_n32le probe.c -pthread
 *   mips64-linux-gnuabi64-gcc   -mabi=64 -static -O2 -o probe_n64be probe.c -pthread
 *   mips64-linux-gnuabi64-gcc   -mabi=n32 -static -O2 -o probe_n32be probe.c -pthread
 * Run:
 *   qemu-mips64el  ./probe_n64le
 *   qemu-mipsn32el ./probe_n32le
 *   qemu-mips64    ./probe_n64be
 *   qemu-mipsn32   ./probe_n32be
 *
 * Verifies:
 *  (1) rdhwr $29 returns the TLS pointer (mnemonic vs fixed-encoding word);
 *  (2) set_thread_area changes the value visible via rdhwr, then restores it;
 *  (3) a pthread child gets its own TLS (rdhwr nonzero, __thread var distinct);
 *  (4) raw clone(CLONE_SETTLS) installs the given thread pointer in the child;
 *  (5) __thread variable address matches its thread's TLS area.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_set_thread_area
#error "__NR_set_thread_area is not defined by the toolchain headers"
#endif

/* rdhwr rt,$29 via mnemonic (assembler picks rt). */
static unsigned long rdhwr_ulr(void)
{
	unsigned long v;

	__asm__ volatile("rdhwr %0, $29" : "=r"(v));
	return v;
}

/* rdhwr $v1($3),$29 via its exact 32-bit encoding 0x7c03e83b.
 * $3 is saved/restored around the raw word so no compiler live value
 * in $v1 is harmed (no reliance on clobber-name spelling). */
static unsigned long rdhwr_v1_fixed(void)
{
	unsigned long v, save3;

	__asm__ volatile(
		"move %1, $3\n\t"
		".word 0x7c03e83b\n\t"
		"move %0, $3\n\t"
		"move $3, %1\n\t"
		: "=r"(v), "=&r"(save3)
		:
		: "memory");
	return v;
}

static __thread int tls_var = 42;

static unsigned long child_ulr = 0;
static void *child_tlsaddr = NULL;
static int child_tlsval = 0;

static void *tls_thread(void *arg)
{
	(void)arg;
	child_ulr = rdhwr_ulr();
	child_tlsaddr = (void *)&tls_var;
	child_tlsval = tls_var;
	return NULL;
}

/* Raw-clone child: reports rdhwr through shared memory, then exits
 * the thread via raw syscall so no libc TLS use happens under the
 * foreign TP. Uses pthread-like flags: qemu-user rejects CLONE_VM
 * without CLONE_THREAD, so the child is a real thread-group member
 * (exit signal 0, no waitpid) and the parent polls clone_done. */
static volatile unsigned long clone_seen = 0;
static volatile int clone_done = 0;

static int clone_child(void *arg)
{
	unsigned long v;

	(void)arg;
	v = rdhwr_ulr();
	clone_seen = v;
	clone_done = 1;
	syscall(SYS_exit, 0);
	for (;;) {
		__asm__ volatile("" : : : "memory");
	}
	return 1;
}

int main(void)
{
	unsigned long ulr_before, ulr_v1, ulr_test, ulr_restored;
	unsigned long set_val = (unsigned long)0x51ab0001UL;
	unsigned long clone_val = (unsigned long)0x5eed0007UL;
	long rc;
	int failures = 0;
	pthread_t th;
	char *stk = NULL;
	const size_t stksz = (size_t)65536;
	struct timespec ts;
	int spins;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("E06 TLS probe (N64/N32)\n");
	printf("__NR_set_thread_area=%d\n", __NR_set_thread_area);
	printf("sizeof void*=%lu long=%lu\n",
	    (unsigned long)sizeof(void *), (unsigned long)sizeof(long));

	/* (1) Initial ULR reads. */
	ulr_before = rdhwr_ulr();
	ulr_v1 = rdhwr_v1_fixed();
	printf("rdhwr-mnemonic ulr_before=0x%lx\n", ulr_before);
	printf("rdhwr-fixed-0x7c03e83b ulr=0x%lx\n", ulr_v1);
	printf("&tls_var=%p tls_var=%d pthread_self=%p\n",
	    (void *)&tls_var, tls_var, (void *)pthread_self());
	if (ulr_before == 0) {
		printf("FAIL: initial ULR is 0\n");
		failures++;
	} else {
		printf("ok: initial ULR nonzero\n");
	}
	if (ulr_v1 != ulr_before) {
		printf("FAIL: fixed-encoding rdhwr disagrees with mnemonic\n");
		failures++;
	} else {
		printf("ok: rdhwr $v1,$29 (0x7c03e83b) matches mnemonic read\n");
	}

	/* (2) set_thread_area round-trip. No libc calls between set and
	 * restore: libc needs the real TLS pointer, so read ULR and
	 * restore back-to-back, printing only afterwards. */
	rc = syscall(__NR_set_thread_area, set_val);
	if (rc != 0) {
		printf("FAIL: set_thread_area(0x%lx) rc=%ld errno=%d (%s)\n",
		    set_val, rc, errno, strerror(errno));
		failures++;
		ulr_test = 0;
	} else {
		ulr_test = rdhwr_ulr();
		rc = syscall(__NR_set_thread_area, ulr_before);
		printf("after set_thread_area(0x%lx): rdhwr=0x%lx\n",
		    set_val, ulr_test);
		if (ulr_test != set_val) {
			printf("FAIL: rdhwr did not return set value\n");
			failures++;
		} else {
			printf("ok: rdhwr $29 returns set_thread_area value\n");
		}
		if (rc != 0) {
			printf("FAIL: restore set_thread_area rc=%ld errno=%d\n",
			    rc, errno);
			failures++;
		}
		ulr_restored = rdhwr_ulr();
		printf("after restore: rdhwr=0x%lx (expect 0x%lx)\n",
		    ulr_restored, ulr_before);
		if (ulr_restored != ulr_before) {
			printf("FAIL: ULR restore mismatch\n");
			failures++;
		} else {
			printf("ok: ULR restored\n");
		}
	}
	if (tls_var != 42) {
		printf("FAIL: tls_var clobbered (%d)\n", tls_var);
		failures++;
	} else {
		printf("ok: __thread var intact after TLS round-trip\n");
	}
	{
		unsigned long a = (unsigned long)&tls_var;
		unsigned long d = a > ulr_before ? a - ulr_before : ulr_before - a;

		printf("tls_var-ulr distance=%lu bytes\n", d);
		if (d > 65536) {
			printf("FAIL: __thread var implausibly far from ULR\n");
			failures++;
		} else {
			printf("ok: __thread var adjacent to ULR\n");
		}
	}

	/* (3) pthread child TLS. */
	if (pthread_create(&th, NULL, tls_thread, NULL) != 0) {
		perror("pthread_create");
		return 2;
	}
	pthread_join(th, NULL);
	printf("child: ulr=0x%lx &tls_var=%p tls_var=%d\n",
	    child_ulr, child_tlsaddr, child_tlsval);
	if (child_ulr == 0) {
		printf("FAIL: child ULR is 0\n");
		failures++;
	} else {
		printf("ok: child ULR nonzero\n");
	}
	if (child_ulr == ulr_before) {
		printf("FAIL: child shares parent ULR (no private TLS)\n");
		failures++;
	} else {
		printf("ok: child has private TLS pointer\n");
	}
	if (child_tlsaddr == (void *)&tls_var) {
		printf("FAIL: child __thread var same address as parent\n");
		failures++;
	} else {
		printf("ok: child __thread var address distinct (per-thread)\n");
	}
	if (child_tlsval != 42) {
		printf("FAIL: child tls_var=%d, expect 42\n", child_tlsval);
		failures++;
	} else {
		printf("ok: child __thread var initialised to 42\n");
	}

	/* (4) raw clone(CLONE_SETTLS) propagation. */
	stk = malloc(stksz);
	if (stk == NULL) {
		perror("malloc");
		return 2;
	}
	clone_seen = 0;
	clone_done = 0;
	if (clone(clone_child, stk + stksz,
	    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS,
	    NULL, NULL, (void *)clone_val, NULL) < 0) {
		printf("FAIL: clone rc=-1 errno=%d (%s)\n",
		    errno, strerror(errno));
		failures++;
	} else {
		ts.tv_sec = 0;
		ts.tv_nsec = 10000000L;
		spins = 0;
		while (clone_done == 0 && spins < 1000) {
			nanosleep(&ts, NULL);
			spins++;
		}
		printf("clone child: rdhwr=0x%lx (expect 0x%lx)\n",
		    clone_seen, clone_val);
		if (clone_done == 0) {
			printf("FAIL: clone child never reported\n");
			failures++;
		} else if (clone_seen != clone_val) {
			printf("FAIL: CLONE_SETTLS value not visible in child\n");
			failures++;
		} else {
			printf("ok: clone(CLONE_SETTLS) propagates thread pointer\n");
		}
	}
	free(stk);

	if (failures == 0)
		printf("E06 RESULT: PASS\n");
	else
		printf("E06 RESULT: FAIL (%d)\n", failures);
	return failures != 0;
}
