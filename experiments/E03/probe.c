// Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
// SPDX-License-Identifier: Apache-2.0
//
// E03: N64 and N32 rt_sigframe layout and 128-signal UAPI probe.
//
// Compile-time: sizeof/offsetof table for sigset_t, struct sigaction,
//   ucontext_t, mcontext_t, struct sigcontext, siginfo_t, struct stat,
//   struct stat64. (glibc struct sigcontext is layout-identical to the
//   kernel arch/mips 64-bit struct sigcontext; the kernel rt_sigframe
//   is { siginfo_t + struct ucontext } + trampoline, reconstructed
//   in FINDINGS.md from the installed UAPI headers.)
// Runtime: sigaction with 16-byte mask, a REAL SIGSEGV (null store,
//   recovered via siglongjmp) plus raise(SIGILL) delivery, proving the
//   _NSIG=128 path and ucontext fill for both signals. Run under
//   qemu-mips64el / qemu-mipsn32el (LE) / qemu-mips64 / qemu-mipsn32 (BE).
//
// Cross e.g.: mips64el-linux-gnuabi64-gcc -std=c11 -Werror=vla -pedantic
//   -Wall -Wextra -Werror -march=mips64r2 -mabi=64 -static -O1 probe.c
#define _GNU_SOURCE

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#define PS(T) \
	printf("sizeof(%s)=%lu\n", #T, (unsigned long)sizeof(T))
#define PO(T, m) \
	printf("offsetof(%s,%s)=%lu\n", #T, #m, \
	    (unsigned long)offsetof(T, m))

static sigjmp_buf sj;
static volatile sig_atomic_t got_sig;
static volatile int got_code;
static volatile unsigned long long seen_addr;
static unsigned long long seen_pc;
static unsigned long long seen_sp;	/* gregs[29] */
static unsigned int seen_fpc_csr;

static void rt_handler(int sig, siginfo_t *si, void *uc)
{
#ifdef __mips__
	ucontext_t *u = (ucontext_t *)uc;
#endif

	got_sig = sig;
	got_code = si ? si->si_code : -999;
	seen_addr = (si != 0) ? (unsigned long long)(unsigned long)si->si_addr : 0ull;
#ifdef __mips__
	seen_pc = (unsigned long long)u->uc_mcontext.pc;
	seen_sp = (unsigned long long)u->uc_mcontext.gregs[29];
	seen_fpc_csr = u->uc_mcontext.fpc_csr;
#else
	seen_pc = 1;	/* non-MIPS native contrast: layout differs */
	seen_sp = 1;
	seen_fpc_csr = 0;
#endif
	siglongjmp(sj, sig);
}

static int install(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = rt_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, 64);	/* upper half of the 16-byte set */
	sigaddset(&sa.sa_mask, 120);	/* deep RT range */
	if (sigaction(sig, &sa, NULL) != 0) {
		printf("sigaction(%d) FAILED errno=%d\n", sig, errno);
		return -1;
	}
	return 0;
}

static void report(const char *tag)
{
	printf("--- delivery %s ---\n", tag);
	printf("got_sig=%d\n", (int)got_sig);
	printf("got_code=%d\n", (int)got_code);
	printf("seen_addr=0x%llx\n", seen_addr);
	printf("seen_pc=0x%llx\n", seen_pc);
	printf("seen_sp=0x%llx\n", seen_sp);
	printf("seen_fpc_csr=0x%x\n", seen_fpc_csr);
}

int main(void)
{
	struct sigaction sa;
	sigset_t full;

	/* ---- compile-time layout table ---- */
	printf("--- sizes ---\n");
	PS(sigset_t);
	PS(struct sigaction);
	PS(siginfo_t);
	PS(ucontext_t);
#ifdef __mips__
	PS(mcontext_t);
	PS(gregset_t);
	PS(fpregset_t);
	PS(greg_t);
	PS(struct sigcontext);
#endif
	PS(struct stat);
	PS(struct stat64);
	PS(stack_t);
	printf("--- sigaction offsets ---\n");
	PO(struct sigaction, sa_handler);
	PO(struct sigaction, sa_mask);
	PO(struct sigaction, sa_flags);
	PO(struct sigaction, sa_restorer);
	printf("--- ucontext offsets ---\n");
	PO(ucontext_t, uc_flags);
	PO(ucontext_t, uc_link);
	PO(ucontext_t, uc_stack);
	PO(ucontext_t, uc_mcontext);
	PO(ucontext_t, uc_sigmask);
	printf("--- stack_t offsets ---\n");
	PO(stack_t, ss_sp);
	PO(stack_t, ss_flags);
	PO(stack_t, ss_size);
	/* 64-bit (N64/N32) mcontext: { gregs, fpregs, mdhi, hi1..3,
	 * mdlo, lo1..3, pc, fpc_csr, used_math, dsp, reserved }.
	 * No regmask/status/fpc_eir/fp_owned — and no sc_cause
	 * anywhere (see FINDINGS.md header evidence). */
	printf("--- mcontext (glibc MIPS64) offsets ---\n");
#ifdef __mips__
	PO(mcontext_t, gregs);
	PO(mcontext_t, fpregs);
	PO(mcontext_t, mdhi);
	PO(mcontext_t, hi1);
	PO(mcontext_t, hi2);
	PO(mcontext_t, hi3);
	PO(mcontext_t, mdlo);
	PO(mcontext_t, lo1);
	PO(mcontext_t, lo2);
	PO(mcontext_t, lo3);
	PO(mcontext_t, pc);
	PO(mcontext_t, fpc_csr);
	PO(mcontext_t, used_math);
	PO(mcontext_t, dsp);
	printf("--- sigcontext (kernel ABI64/N32 layout) offsets ---\n");
	PO(struct sigcontext, sc_regs);
	PO(struct sigcontext, sc_fpregs);
	PO(struct sigcontext, sc_mdhi);
	PO(struct sigcontext, sc_hi1);
	PO(struct sigcontext, sc_hi2);
	PO(struct sigcontext, sc_hi3);
	PO(struct sigcontext, sc_mdlo);
	PO(struct sigcontext, sc_lo1);
	PO(struct sigcontext, sc_lo2);
	PO(struct sigcontext, sc_lo3);
	PO(struct sigcontext, sc_pc);
	PO(struct sigcontext, sc_fpc_csr);
	PO(struct sigcontext, sc_used_math);
	PO(struct sigcontext, sc_dsp);
	PO(struct sigcontext, sc_reserved);
#endif
	printf("--- siginfo offsets ---\n");
	PO(siginfo_t, si_signo);
	PO(siginfo_t, si_errno);
	PO(siginfo_t, si_code);
	printf("--- stat ---\n");
	PO(struct stat, st_dev);
	PO(struct stat, st_ino);
	PO(struct stat, st_mode);
	PO(struct stat, st_nlink);
	PO(struct stat, st_uid);
	PO(struct stat, st_gid);
	PO(struct stat, st_size);
	PO(struct stat, st_blksize);
	PO(struct stat, st_blocks);

	/* ---- UAPI constants ---- */
	printf("--- constants ---\n");
	printf("_NSIG=%d\n", _NSIG);
	printf("NSIG=%d\n", NSIG);
	printf("SIGRTMIN=%d\n", SIGRTMIN);
	printf("SIGRTMAX=%d\n", SIGRTMAX);
	printf("SI_QUEUE=%d\n", SI_QUEUE);

	/* ---- 16-byte (128-bit) sigset coverage ---- */
	sigfillset(&full);
	printf("--- sigset128 ---\n");
	printf("sigismember(1)=%d\n", sigismember(&full, 1));
	printf("sigismember(31)=%d\n", sigismember(&full, 31));
	printf("sigismember(32)=%d\n", sigismember(&full, 32));
	printf("sigismember(64)=%d\n", sigismember(&full, 64));
	printf("sigismember(120)=%d\n", sigismember(&full, 120));
	printf("sigismember(127)=%d\n", sigismember(&full, 127));

	/* ---- REAL SIGSEGV via a null store, then raise(SIGILL) ---- */
	if (install(SIGSEGV) != 0)
		return 2;
	if (sigsetjmp(sj, 1) == 0) {
		*(volatile int *)0 = 0;
		printf("null store did NOT fault\n");
		return 3;
	}
	report("SIGSEGV");
	if (got_sig != SIGSEGV) {
		printf("RESULT=FAIL expected SIGSEGV\n");
		return 4;
	}
	if (seen_pc == 0 || seen_sp == 0) {
		printf("RESULT=FAIL null context\n");
		return 5;
	}

	if (install(SIGILL) != 0)
		return 6;
	if (sigsetjmp(sj, 1) == 0) {
		if (raise(SIGILL) != 0) {
			printf("raise(SIGILL) FAILED errno=%d\n", errno);
			return 7;
		}
		printf("raise(SIGILL) did NOT deliver\n");
		return 8;
	}
	report("SIGILL");
	if (got_sig != SIGILL) {
		printf("RESULT=FAIL expected SIGILL\n");
		return 9;
	}

	/* ---- raw rt_sigprocmask: kernel sigsetsize probe ----
	 * Kernel sigset_t is _NSIG_WORDS x 8 bytes = 16 bytes on
	 * MIPS64 (_NSIG_WORDS = _NSIG/__BITS_PER_LONG = 128/64).
	 * glibc passes _NSIG/8 = 16 for every rt_*sig syscall. */
	{
		sigset_t cur;
		long r;
		int e;

		memset(&cur, 0xA5, sizeof(cur));
		errno = 0;
		r = syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &cur, 16);
		e = errno;
		printf("raw_sigprocmask_size16=%ld errno=%d\n", r, e);
		errno = 0;
		r = syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &cur, 8);
		e = errno;
		printf("raw_sigprocmask_size8=%ld errno=%d\n", r, e);
		printf("kernel_sigset_bytes=%d\n", _NSIG / 8);
	}

	(void)sa;
	printf("RESULT=PASS\n");
	return 0;
}
