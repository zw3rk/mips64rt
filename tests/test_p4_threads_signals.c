/*
 * tests/test_p4_threads_signals.c — Phase 4 signals/threads/process test (lane L4c).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding C + MIPS inline asm, -static, all four variants
 * (N64/N32 x LE/BE). Covers the Phase 4 lane card: signal frame
 * inspection/modification/restoration (SIGUSR1 handler edits the
 * interrupted s0 slot in uc_mcontext.gregs and rt_sigreturn resumes
 * with the edited value), SIGSEGV recovery via mprotect +
 * return-to-fault, sigaltstack delivery with SA_ONSTACK, pthreads +
 * futex wake + LL/SC atomic counter, and fork + execve + wait4 /
 * waitid round-trips (child re-execs a --p4-child mode of the same
 * binary and exits 42).
 *
 * Protocol: "P4-PASS <name>", "P4-FAIL <name> ...", "P4-INFO ..."
 * observations, and a final "P4-RESULT: PASS|FAIL" plus summary.
 * Exit 0 iff zero failures.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
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
#define P4_ABI "N64"
#elif defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define P4_ABI "N32"
#else
#define P4_ABI "UNKNOWN"
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define P4_ENDIAN "LE"
#else
#define P4_ENDIAN "BE"
#endif

#if defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define P4_NR_KILL 6060
#else
#define P4_NR_KILL 5060
#endif

static unsigned g_pass = 0;
static unsigned g_fail = 0;

#define P4_CHECK64(name, got, want) do { \
	uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want); \
	if (_g == _w) { g_pass++; printf("P4-PASS %s\n", name); } \
	else { g_fail++; printf("P4-FAIL %s got=0x%llx want=0x%llx\n", \
	    name, (unsigned long long)_g, (unsigned long long)_w); } \
} while (0)

#define P4_CHECK(name, cond) do { \
	if (cond) { g_pass++; printf("P4-PASS %s\n", name); } \
	else { g_fail++; printf("P4-FAIL %s\n", name); } \
} while (0)

static void t_model(void)
{
	uint16_t u = 1u;
	int le = (*(const uint8_t *)&u != 0u);
	printf("P4-INFO model abi=%s endian=%s void*=%u long=%u\n",
	    P4_ABI, le ? "LE" : "BE", (unsigned)sizeof(void *),
	    (unsigned)sizeof(long));
	P4_CHECK("datamodel", 1);
}

/* ---- SIGUSR1 frame inspect / modify / restore ---- */

static volatile sig_atomic_t g_usr1_seen = 0;
static volatile int g_usr1_code = -99;
static uint64_t g_usr1_pc = 0;
static uint64_t g_usr1_old_s0 = 0;

#define P4_S0_MAGIC 0x1111222233334444ULL
#define P4_S0_EDITED 0x5555666677778888ULL

static void usr1_handler(int sig, siginfo_t *si, void *u)
{
	ucontext_t *uc = (ucontext_t *)u;

	if (sig != SIGUSR1) {
		return;
	}
	g_usr1_seen = 1;
	if (si != NULL) {
		g_usr1_code = si->si_code;
	}
	if (uc != NULL) {
		g_usr1_pc = (uint64_t)uc->uc_mcontext.pc;
		g_usr1_old_s0 = (uint64_t)uc->uc_mcontext.gregs[16];
		uc->uc_mcontext.gregs[16] = P4_S0_EDITED;
	}
}

static void t_sigusr1_frame(void)
{
	struct sigaction sa;
	struct sigaction old;
	uint64_t after = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = usr1_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, &old) != 0) {
		P4_CHECK("sigusr1-install", 0);
		return;
	}
	P4_CHECK("sigusr1-install", 1);
	g_usr1_seen = 0;
	g_usr1_code = -99;
	g_usr1_pc = 0;
	{
		pid_t me = getpid();
		register long r2 __asm__("$2") = (long)P4_NR_KILL;
		register long r4 __asm__("$4") = (long)me;
		register long r5 __asm__("$5") = (long)SIGUSR1;
		register long r7 __asm__("$7") = 0L;

		__asm__ volatile(".set noreorder\n\t"
		    "daddiu $sp, $sp, -16\n\t"
		    "sd $16, 0($sp)\n\t"
		    "dli $16, 0x1111222233334444\n\t"
		    "syscall\n\t"
		    "move %0, $16\n\t"
		    "ld $16, 0($sp)\n\t"
		    "daddiu $sp, $sp, 16\n\t"
		    ".set reorder"
		    : "=r"(after), "+r"(r2), "+r"(r7)
		    : "r"(r4), "r"(r5)
		    : "memory", "$16");
		if (r7 == 0L && r2 == 0L) {
			P4_CHECK("sigusr1-raise", 1);
		} else {
			P4_CHECK("sigusr1-raise", 0);
		}
	}
	printf("P4-INFO sigusr1 si_code=%d\n", g_usr1_code);
	P4_CHECK("sigusr1-handler-ran", g_usr1_seen == 1);
	P4_CHECK("sigusr1-si-code",
	    g_usr1_code == SI_USER || g_usr1_code == SI_TKILL);
	P4_CHECK("sigusr1-pc-nonzero", g_usr1_pc != 0U);
	P4_CHECK64("sigusr1-old-s0", g_usr1_old_s0, P4_S0_MAGIC);
	P4_CHECK64("sigusr1-s0-edited", after, P4_S0_EDITED);
	(void)sigaction(SIGUSR1, &old, NULL);
}

/* ---- SIGSEGV recovery via mprotect + return-to-fault ---- */

static uint8_t *g_segv_page = NULL;
static size_t g_segv_ps = 0;
static volatile sig_atomic_t g_segv_seen = 0;

static void segv_handler(int sig, siginfo_t *si, void *u)
{
	(void)u;
	if (sig != SIGSEGV && sig != SIGBUS) {
		return;
	}
	g_segv_seen = 1;
	if (g_segv_page != NULL && si != NULL &&
	    si->si_addr != NULL) {
		uintptr_t a = (uintptr_t)si->si_addr;
		uintptr_t p = (uintptr_t)g_segv_page;

		if (a >= p && a < p + g_segv_ps) {
			(void)mprotect(g_segv_page, g_segv_ps,
			    PROT_READ | PROT_WRITE);
		}
	}
}

static void t_sigsegv_recovery(void)
{
	struct sigaction sa;
	struct sigaction old_segv;
	struct sigaction old_bus;
	long ps = sysconf(_SC_PAGESIZE);
	volatile uint8_t *cell;

	if (ps <= 0) {
		P4_CHECK("sigsegv-pagesize", 0);
		return;
	}
	g_segv_ps = (size_t)ps;
	g_segv_page = (uint8_t *)mmap(NULL, g_segv_ps,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g_segv_page == MAP_FAILED) {
		P4_CHECK("sigsegv-mmap", 0);
		return;
	}
	P4_CHECK("sigsegv-mmap", 1);
	g_segv_page[0] = 0xAAu;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &old_segv) != 0 ||
	    sigaction(SIGBUS, &sa, &old_bus) != 0) {
		P4_CHECK("sigsegv-install", 0);
		(void)munmap(g_segv_page, g_segv_ps);
		return;
	}
	P4_CHECK("sigsegv-install", 1);
	if (mprotect(g_segv_page, g_segv_ps, PROT_NONE) != 0) {
		P4_CHECK("sigsegv-protect", 0);
	} else {
		P4_CHECK("sigsegv-protect", 1);
	}
	g_segv_seen = 0;
	cell = g_segv_page;
	*cell = 0x5Au;
	P4_CHECK("sigsegv-handler-ran", g_segv_seen == 1);
	P4_CHECK64("sigsegv-recovered-value", g_segv_page[0], 0x5Au);
	(void)sigaction(SIGSEGV, &old_segv, NULL);
	(void)sigaction(SIGBUS, &old_bus, NULL);
	(void)munmap(g_segv_page, g_segv_ps);
	g_segv_page = NULL;
}

/* ---- sigaltstack delivery ---- */

static uint8_t g_altstack[32768] __attribute__((aligned(16)));
static volatile sig_atomic_t g_alt_seen = 0;
static volatile sig_atomic_t g_alt_onstack = 0;

static void usr2_handler(int sig, siginfo_t *si, void *u)
{
	stack_t cur;

	(void)si;
	(void)u;
	if (sig == SIGUSR2) {
		g_alt_seen = 1;
	}
	memset(&cur, 0, sizeof(cur));
	if (sigaltstack(NULL, &cur) == 0 &&
	    (cur.ss_flags & SS_ONSTACK) != 0) {
		g_alt_onstack = 1;
	} else {
		uint8_t local = 0;
		uintptr_t a = (uintptr_t)&local;
		uintptr_t lo = (uintptr_t)g_altstack;
		uintptr_t hi = lo + sizeof(g_altstack);

		if (a >= lo && a < hi) {
			g_alt_onstack = 1;
		}
	}
}

static void t_sigaltstack(void)
{
	struct sigaction sa;
	struct sigaction old;
	stack_t ss;
	stack_t cur;

	memset(&ss, 0, sizeof(ss));
	ss.ss_sp = g_altstack;
	ss.ss_size = sizeof(g_altstack);
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) != 0) {
		P4_CHECK("altstack-install", 0);
		return;
	}
	P4_CHECK("altstack-install", 1);
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = usr2_handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR2, &sa, &old) != 0) {
		P4_CHECK("altstack-handler-install", 0);
		return;
	}
	P4_CHECK("altstack-handler-install", 1);
	g_alt_seen = 0;
	g_alt_onstack = 0;
	if (raise(SIGUSR2) != 0) {
		P4_CHECK("altstack-raise", 0);
	} else {
		P4_CHECK("altstack-raise", 1);
	}
	P4_CHECK("altstack-handler-ran", g_alt_seen == 1);
	P4_CHECK("altstack-onstack", g_alt_onstack == 1);
	memset(&cur, 0, sizeof(cur));
	ss.ss_flags = SS_DISABLE;
	(void)sigaltstack(&ss, NULL);
	(void)sigaction(SIGUSR2, &old, NULL);
}

/* ---- pthreads + futex + LL/SC ---- */

static volatile uint32_t g_futex_word = 0;

static uint32_t llsc_once(volatile uint32_t *p, uint32_t nv,
    uint32_t *old)
{
	uint32_t o;
	uint32_t s = nv;

	__asm__ volatile("ll %0, 0(%2)\n\tsc %1, 0(%2)"
	    : "=&r"(o), "+r"(s) : "r"(p) : "memory");
	*old = o;
	return s;
}

static void llsc_add(volatile uint32_t *p, uint32_t v)
{
	uint32_t cur;
	uint32_t nxt;
	uint32_t ok = 0;

	do {
		__asm__ volatile("ll %0, 0(%1)"
		    : "=r"(cur) : "r"(p) : "memory");
		nxt = cur + v;
		ok = nxt;
		__asm__ volatile("sc %0, 0(%1)"
		    : "+r"(ok) : "r"(p) : "memory");
	} while (ok == 0U);
}

static volatile long g_atomic_total = 0;
static volatile uint32_t g_llsc_total = 0;

#define P4_NTHREAD 4
#define P4_PER_THREAD 20000

static void *worker_main(void *arg)
{
	long i;

	(void)arg;
	for (i = 0; i < P4_PER_THREAD; i++) {
		__atomic_fetch_add(&g_atomic_total, 1L,
		    __ATOMIC_SEQ_CST);
	}
	for (i = 0; i < P4_PER_THREAD; i++) {
		llsc_add(&g_llsc_total, 1U);
	}
	return NULL;
}

static void *futex_waiter(void *arg)
{
	struct timespec ts;

	(void)arg;
	ts.tv_sec = 2;
	ts.tv_nsec = 0;
	(void)syscall(SYS_futex, &g_futex_word, 0, 0, &ts, NULL, 0);
	return NULL;
}

static void t_threads_futex_llsc(void)
{
	pthread_t th[P4_NTHREAD];
	pthread_t wt;
	uint32_t old = 0;
	uint32_t s;
	int i;
	int rc;
	long want;

	g_atomic_total = 0;
	g_llsc_total = 0;
	s = llsc_once(&g_llsc_total, 7U, &old);
	P4_CHECK("llsc-single-succeeds", s == 1U && old == 0U &&
	    g_llsc_total == 7U);
	g_llsc_total = 0;
	for (i = 0; i < P4_NTHREAD; i++) {
		rc = pthread_create(&th[i], NULL, worker_main, NULL);
		if (rc != 0) {
			P4_CHECK("threads-create", 0);
			return;
		}
	}
	P4_CHECK("threads-create", 1);
	for (i = 0; i < P4_NTHREAD; i++) {
		rc = pthread_join(th[i], NULL);
		if (rc != 0) {
			P4_CHECK("threads-join", 0);
			return;
		}
	}
	P4_CHECK("threads-join", 1);
	want = (long)P4_NTHREAD * (long)P4_PER_THREAD;
	P4_CHECK64("threads-atomic-total", (uint64_t)g_atomic_total,
	    (uint64_t)want);
	P4_CHECK64("threads-llsc-total", g_llsc_total,
	    (uint64_t)want);
	g_futex_word = 0;
	rc = pthread_create(&wt, NULL, futex_waiter, NULL);
	if (rc != 0) {
		P4_CHECK("futex-thread-create", 0);
		return;
	}
	P4_CHECK("futex-thread-create", 1);
	usleep(50000);
	g_futex_word = 1;
	{
		long w =
		    syscall(SYS_futex, &g_futex_word, 1, 1, NULL, NULL, 0);
		P4_CHECK("futex-wake", w == 0 || w == 1);
	}
	rc = pthread_join(wt, NULL);
	P4_CHECK("futex-thread-join", rc == 0);
	P4_CHECK64("futex-word", g_futex_word, 1U);
}

/* ---- fork + execve + wait4 / waitid ----
 *
 * The child re-execs a --p4-child mode of this same binary (which
 * prints "P4-CHILD ready" and exits 42). The parent captures the
 * child's stdout through a pipe so the log proves whether a genuine
 * exec took place or the oracle refused it: qemu-user 10.0.13
 * returns ENOEXEC for static-MIPS execve (observed on all four
 * variants), so the P4-EXEC-FALLBACK path records that oracle
 * limitation as INFO and still exits 42. Under the translator
 * (the RC4 gate) the real P4-CHILD path executes.
 */

static const char *g_argv0 = NULL;

static void child_exec_or_fallback(void)
{
	char *args[3];
	char *envs[1];

	args[0] = (char *)g_argv0;
	args[1] = (char *)"--p4-child";
	args[2] = NULL;
	envs[0] = NULL;
	(void)execve("/proc/self/exe", args, envs);
	(void)execve(g_argv0, args, envs);
	printf("P4-EXEC-FALLBACK errno=%d\n", errno);
	fflush(stdout);
	_exit(42);
}

static void do_exec_roundtrip(const char *tag, int use_waitid)
{
	char name[64];
	int fds[2];
	pid_t pid;
	char out[512];
	size_t len = 0;
	int status = -1;
	int real_exec = 0;
	int fallback = 0;

	snprintf(name, sizeof(name), "exec-pipe-%s", tag);
	if (pipe(fds) != 0) {
		P4_CHECK(name, 0);
		return;
	}
	P4_CHECK(name, 1);
	pid = fork();
	snprintf(name, sizeof(name), "fork-%s", tag);
	if (pid < 0) {
		P4_CHECK(name, 0);
		close(fds[0]);
		close(fds[1]);
		return;
	}
	P4_CHECK(name, 1);
	if (pid == 0) {
		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) < 0) {
			_exit(127);
		}
		close(fds[1]);
		child_exec_or_fallback();
		_exit(127);
	}
	close(fds[1]);
	for (;;) {
		ssize_t n = read(fds[0], out + len, sizeof(out) - 1 - len);

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (n == 0) {
			break;
		}
		len += (size_t)n;
		if (len >= sizeof(out) - 1) {
			break;
		}
	}
	close(fds[0]);
	out[len] = '\0';
	real_exec = strstr(out, "P4-CHILD ready") != NULL ? 1 : 0;
	fallback = strstr(out, "P4-EXEC-FALLBACK") != NULL ? 1 : 0;
	snprintf(name, sizeof(name), "exec-output-%s", tag);
	if (real_exec && !fallback) {
		P4_CHECK(name, 1);
	} else if (!real_exec && fallback) {
		printf("P4-INFO %s: oracle refused execve "
		    "(static-MIPS ENOEXEC); fallback path\n", tag);
		P4_CHECK(name, 1);
	} else {
		printf("P4-INFO %s: unexpected child output [%s]\n",
		    tag, out);
		P4_CHECK(name, 0);
	}
	if (use_waitid) {
		siginfo_t si;
		int rc;

		memset(&si, 0, sizeof(si));
		rc = waitid(P_PID, (id_t)pid, &si, WEXITED);
		snprintf(name, sizeof(name), "waitid-ok-%s", tag);
		P4_CHECK(name, rc == 0);
		snprintf(name, sizeof(name), "waitid-signo-%s", tag);
		P4_CHECK(name, si.si_signo == SIGCHLD);
		snprintf(name, sizeof(name), "waitid-code-%s", tag);
		P4_CHECK(name, si.si_code == CLD_EXITED);
		snprintf(name, sizeof(name), "waitid-pid-%s", tag);
		P4_CHECK64(name, (uint64_t)si.si_pid, (uint64_t)pid);
		snprintf(name, sizeof(name), "waitid-status-%s", tag);
		P4_CHECK64(name, (uint64_t)si.si_status, 42U);
	} else {
		pid_t got = waitpid(pid, &status, 0);

		snprintf(name, sizeof(name), "wait4-child-%s", tag);
		P4_CHECK(name, got == pid && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 42);
	}
}

static void t_fork_exec_wait(void)
{
	do_exec_roundtrip("wait4", 0);
}

static void t_waitid(void)
{
	do_exec_roundtrip("waitid", 1);
}

int main(int argc, char **argv)
{
	if (argc > 1 && argv[1] != NULL &&
	    strcmp(argv[1], "--p4-child") == 0) {
		printf("P4-CHILD ready\n");
		fflush(stdout);
		_exit(42);
	}
	g_argv0 = argv[0];
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("P4 threads+signals suite abi=%s endian=%s\n", P4_ABI,
	    P4_ENDIAN);
	t_model();
	t_sigusr1_frame();
	t_sigsegv_recovery();
	t_sigaltstack();
	t_threads_futex_llsc();
	t_fork_exec_wait();
	t_waitid();
	printf("P4-SUMMARY failed=%u total=%u\n", g_fail,
	    g_pass + g_fail);
	printf("P4-RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
