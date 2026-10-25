/*
 * tests/test_p6_perms.c — Phase 6 lane L6b adjacent-page permissions gate.
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding-style static C11 guest (N64/N32 x LE/BE, like
 * tests/test_p1_isa.c): adjacent 4 KiB pages with distinct permissions
 * (PROT_READ|PROT_EXEC next to PROT_READ|PROT_WRITE, RELRO-style
 * RX-then-RW split plus the mirrored RW-then-RX split); guarded-page
 * faults land exactly on the faulting page with si_code SEGV_ACCERR
 * (protection) or SEGV_ACCERR (PROT_NONE is still mapped); raw PROT_NONE adjacency kills
 * unhandled children with SIGSEGV; mprotect RX->RW->RX transitions keep
 * neighbor bytes exact. Faulting probes run in forked children so the
 * suite survives; only deterministic names, offsets, and checksums reach
 * stdout (no addresses, no pids), so qemu/interp/dbt stay byte-identical.
 *
 * Protocol: "P6-PASS <name>", "P6-FAIL <name> <detail>", "P6-INFO ...",
 * plus "P6-SUMMARY failed=.. total=.." and "P6-RESULT: PASS|FAIL".
 * Exit 0 iff zero failures.
 */
#define _GNU_SOURCE
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

#if defined(_MIPS_SIM) && defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define P6_ABI "N64"
#elif defined(_MIPS_SIM) && defined(_ABIN32) && (_MIPS_SIM == _ABIN32)
#define P6_ABI "N32"
#else
#define P6_ABI "UNKNOWN"
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define P6_ENDIAN "LE"
#else
#define P6_ENDIAN "BE"
#endif

static unsigned g_pass = 0;
static unsigned g_fail = 0;

#define P6_CHECK(name, cond) do { \
	if (cond) { g_pass++; printf("P6-PASS %s\n", name); } \
	else { g_fail++; printf("P6-FAIL %s\n", name); } \
} while (0)

static size_t g_ps = 0;
static uint8_t *g_base = NULL;	/* region under test (child-inherited) */
static volatile uint8_t *g_tgt = NULL;	/* fault-target page base */
static unsigned (*g_fn)(void) = NULL;	/* exec probe entry (child use) */
static const volatile uint8_t *g_lo = NULL;	/* exec-fault range */
static const volatile uint8_t *g_hi = NULL;

static volatile sig_atomic_t g_code = 0;
static volatile sig_atomic_t g_sig = 0;
static void *g_addr = NULL;
static sigjmp_buf g_jb;

#define PROBE_OFF 256u
#define PROBE_LEN 64u

/* -pedantic forbids function<->object pointer casts, so pun through
 * memcpy (N64/N32 function and data pointers share a size). */
_Static_assert(sizeof(void *) == sizeof(unsigned (*)(void)),
    "function and object pointers must share a size");

static void *fn_to_obj(unsigned (*fn)(void))
{
	void *p = NULL;
	memcpy(&p, &fn, sizeof(p));
	return p;
}

static unsigned (*obj_to_fn(void *p))(void)
{
	unsigned (*fn)(void) = NULL;
	memcpy(&fn, &p, sizeof(fn));
	return fn;
}

/* Trivial leaf: li $2,42 / jr $ra. Position-independent, so the copied
 * bytes run identically from any RX page. */
__attribute__((noinline)) static unsigned rx_probe(void)
{
	return 42u;
}

static void cap_handler(int sig, siginfo_t *si, void *u)
{
	(void)u;
	g_sig = sig;
	g_code = si->si_code;
	g_addr = si->si_addr;
	siglongjmp(g_jb, 1);
}

static void install_cap(int sig)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = cap_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(sig, &sa, NULL);
}

static void install_both(void)
{
	install_cap(SIGSEGV);
	install_cap(SIGBUS);
}

/* Kill probes: an unhandled touch of PROT_NONE dies with SIGSEGV, but
 * qemu prints an engine-specific "uncaught target signal" note to
 * stderr on such deaths, which no byte-identical gate can carry. Like
 * test_p1_isa.c, the child therefore catches the signal and encodes
 * it: _exit(139) iff the delivered signal is SIGSEGV. */
static void kill_handler(int sig, siginfo_t *si, void *u)
{
	(void)si;
	(void)u;
	_exit(sig == SIGSEGV ? 139 : 4);
}

static void install_kill(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = kill_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
}

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

/* Child exit codes: 0 expected outcome, 2 no fault (or fault when none
 * wanted), 3 fault address off target, 4 wrong si_code/signal,
 * 5 wrong probe result, 10/11 setup failure. */
static void w_first_body(void)
{
	install_both();
	if (sigsetjmp(g_jb, 1) == 0) {
		g_tgt[0] = 0xFFu;
		_exit(2);
	}
	if (g_addr != (void *)g_tgt)
		_exit(3);
	if (g_sig != SIGSEGV || g_code != SEGV_ACCERR)
		_exit(4);
	_exit(0);
}

static void w_last_body(void)
{
	const volatile uint8_t *want;
	install_both();
	want = g_tgt + g_ps - 1u;
	if (sigsetjmp(g_jb, 1) == 0) {
		g_tgt[g_ps - 1u] = 0xFFu;
		_exit(2);
	}
	if (g_addr != (void *)want)
		_exit(3);
	if (g_sig != SIGSEGV || g_code != SEGV_ACCERR)
		_exit(4);
	_exit(0);
}

static void x_rx_body(void)
{
	unsigned r;
	unsigned (* volatile fn)(void) = g_fn;
	install_both();
	if (sigsetjmp(g_jb, 1) != 0)
		_exit(2);
	r = fn();
	_exit(r == 42u ? 0 : 5);
}

static void x_range_body(void)
{
	unsigned (* volatile fn)(void) = g_fn;
	install_both();
	if (sigsetjmp(g_jb, 1) == 0) {
		(void)fn();
		_exit(2);
	}
	if (g_sig != SIGSEGV)
		_exit(4);
	if (g_addr < (void *)g_lo || g_addr >= (void *)g_hi)
		_exit(3);
	_exit(0);
}

static void r_none_body(void)
{
	const volatile uint8_t *p;
	uint8_t v;
	install_kill();
	p = (const volatile uint8_t *)g_tgt;
	v = p[0];
	(void)v;
	_exit(2);
}

static void w_none_body(void)
{
	install_kill();
	g_tgt[0] = 0xFFu;
	_exit(2);
}

static void x_none_body(void)
{
	unsigned (* volatile fn)(void) = g_fn;
	install_kill();
	(void)fn();
	_exit(2);
}

static void c_none_body(void)
{
	install_both();
	if (sigsetjmp(g_jb, 1) == 0) {
		uint8_t v = g_tgt[0];
		(void)v;
		_exit(2);
	}
	if (g_addr != (void *)g_tgt)
		_exit(3);
	if (g_sig != SIGSEGV || g_code != SEGV_ACCERR)
		_exit(4);
	_exit(0);
}

static void expect_exit(const char *name, int st, int want)
{
	if (WIFEXITED(st) && WEXITSTATUS(st) == want) {
		g_pass++;
		printf("P6-PASS %s\n", name);
	} else {
		g_fail++;
		printf("P6-FAIL %s status=%d\n", name, st);
	}
}

static uint64_t cksum(const uint8_t *p, size_t n)
{
	uint64_t s = 0u;
	size_t i;
	for (i = 0; i < n; i++)
		s += p[i];
	return s;
}

static void t_model(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	printf("P6-INFO model abi=%s endian=%s void*=%u pagesize=%ld\n",
	    P6_ABI, P6_ENDIAN, (unsigned)sizeof(void *), ps);
	P6_CHECK("pagesize-4k", ps == 4096L);
	g_ps = (size_t)ps;
	P6_CHECK("probe-direct", rx_probe() == 42u);
}

/* RELRO-style RX-then-RW split: page 0 RX, page 1 RW. */
static void t_rx_rw_split(void)
{
	uint64_t c1;
	int st;
	g_base = mmap(NULL, 2 * g_ps, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	P6_CHECK("rxrw-map", g_base != MAP_FAILED);
	if (g_base == MAP_FAILED)
		return;
	memset(g_base, 0xA5, g_ps);
	memset(g_base + g_ps, 0x5A, g_ps);
	memcpy(g_base + PROBE_OFF, fn_to_obj(rx_probe), PROBE_LEN);
	__builtin___clear_cache((char *)(g_base + PROBE_OFF),
	    (char *)(g_base + PROBE_OFF + PROBE_LEN));
	c1 = cksum(g_base + g_ps, g_ps);
	P6_CHECK("rxrw-protect", mprotect(g_base, g_ps,
	    PROT_READ | PROT_EXEC) == 0);
	P6_CHECK("rxrw-read-rx", g_base[0] == 0xA5 &&
	    g_base[g_ps - 1u] == 0xA5);
	P6_CHECK("rxrw-read-rw", g_base[g_ps] == 0x5A &&
	    g_base[2 * g_ps - 1u] == 0x5A);
	g_base[g_ps] = 0x11u;
	g_base[2 * g_ps - 1u] = 0x22u;
	P6_CHECK("rxrw-write-rw", g_base[g_ps] == 0x11u &&
	    g_base[2 * g_ps - 1u] == 0x22u);
	g_base[g_ps] = 0x5Au;
	g_base[2 * g_ps - 1u] = 0x5Au;
	P6_CHECK("rxrw-rw-intact", cksum(g_base + g_ps, g_ps) == c1);
	g_tgt = (volatile uint8_t *)g_base;
	st = run_child(w_first_body);
	expect_exit("rxrw-write-rx-first-faults", st, 0);
	st = run_child(w_last_body);
	expect_exit("rxrw-write-rx-last-faults", st, 0);
	g_fn = obj_to_fn(g_base + PROBE_OFF);
	st = run_child(x_rx_body);
	expect_exit("rxrw-exec-rx", st, 0);
	g_fn = obj_to_fn(g_base + g_ps + PROBE_OFF);
	g_lo = (const volatile uint8_t *)(g_base + g_ps);
	g_hi = (const volatile uint8_t *)(g_base + 2 * g_ps);
	st = run_child(x_range_body);
	expect_exit("rxrw-exec-rw-faults", st, 0);
	P6_CHECK("rxrw-unmap", munmap(g_base, 2 * g_ps) == 0);
	g_base = NULL;
}

/* Mirrored RW-then-RX split: page 0 RW, page 1 RX. */
static void t_rw_rx_split(void)
{
	uint64_t c0;
	int st;
	g_base = mmap(NULL, 2 * g_ps, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	P6_CHECK("rwrx-map", g_base != MAP_FAILED);
	if (g_base == MAP_FAILED)
		return;
	memset(g_base, 0x3C, g_ps);
	memset(g_base + g_ps, 0xC3, g_ps);
	memcpy(g_base + g_ps + PROBE_OFF, fn_to_obj(rx_probe),
	    PROBE_LEN);
	__builtin___clear_cache((char *)(g_base + g_ps + PROBE_OFF),
	    (char *)(g_base + g_ps + PROBE_OFF + PROBE_LEN));
	c0 = cksum(g_base, g_ps);
	P6_CHECK("rwrx-protect", mprotect(g_base + g_ps, g_ps,
	    PROT_READ | PROT_EXEC) == 0);
	P6_CHECK("rwrx-read-both", g_base[0] == 0x3C &&
	    g_base[g_ps] == 0xC3 && g_base[2 * g_ps - 1u] == 0xC3);
	g_base[0] = 0x77u;
	P6_CHECK("rwrx-write-rw", g_base[0] == 0x77u);
	g_base[0] = 0x3Cu;
	P6_CHECK("rwrx-rw-intact", cksum(g_base, g_ps) == c0);
	g_tgt = (volatile uint8_t *)(g_base + g_ps);
	st = run_child(w_first_body);
	expect_exit("rwrx-write-rx-first-faults", st, 0);
	st = run_child(w_last_body);
	expect_exit("rwrx-write-rx-last-faults", st, 0);
	g_fn = obj_to_fn(g_base + g_ps + PROBE_OFF);
	st = run_child(x_rx_body);
	expect_exit("rwrx-exec-rx", st, 0);
	P6_CHECK("rwrx-unmap", munmap(g_base, 2 * g_ps) == 0);
	g_base = NULL;
}

/* PROT_NONE middle page: unhandled touches die with SIGSEGV, handled
 * read reports SEGV_ACCERR at the exact address, neighbors survive. */
static void t_prot_none(void)
{
	uint64_t c0, c2;
	int st;
	g_base = mmap(NULL, 3 * g_ps, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	P6_CHECK("none-map", g_base != MAP_FAILED);
	if (g_base == MAP_FAILED)
		return;
	memset(g_base, 0x11, g_ps);
	memset(g_base + 2 * g_ps, 0x33, g_ps);
	c0 = cksum(g_base, g_ps);
	c2 = cksum(g_base + 2 * g_ps, g_ps);
	P6_CHECK("none-protect", mprotect(g_base + g_ps, g_ps,
	    PROT_NONE) == 0);
	g_tgt = (volatile uint8_t *)(g_base + g_ps);
	st = run_child(r_none_body);
	expect_exit("none-read-kills", st, 139);
	st = run_child(w_none_body);
	expect_exit("none-write-kills", st, 139);
	g_fn = obj_to_fn(g_base + g_ps);
	st = run_child(x_none_body);
	expect_exit("none-exec-kills", st, 139);
	st = run_child(c_none_body);
	expect_exit("none-read-accerr-exact", st, 0);
	g_base[0] = 0x44u;
	g_base[3 * g_ps - 1u] = 0x55u;
	P6_CHECK("none-neighbors-rw", g_base[0] == 0x44u &&
	    g_base[3 * g_ps - 1u] == 0x55u);
	g_base[0] = 0x11u;
	g_base[3 * g_ps - 1u] = 0x33u;
	P6_CHECK("none-neighbors-exact", cksum(g_base, g_ps) == c0 &&
	    cksum(g_base + 2 * g_ps, g_ps) == c2);
	P6_CHECK("none-unmap", munmap(g_base, 3 * g_ps) == 0);
	g_base = NULL;
}

/* mprotect RX->RW->RX transitions keep the neighbor exact. */
static void t_transitions(void)
{
	uint64_t c1;
	int st;
	g_base = mmap(NULL, 2 * g_ps, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	P6_CHECK("trans-map", g_base != MAP_FAILED);
	if (g_base == MAP_FAILED)
		return;
	memset(g_base, 0xA5, g_ps);
	memset(g_base + g_ps, 0x5A, g_ps);
	memcpy(g_base + PROBE_OFF, fn_to_obj(rx_probe), PROBE_LEN);
	__builtin___clear_cache((char *)(g_base + PROBE_OFF),
	    (char *)(g_base + PROBE_OFF + PROBE_LEN));
	c1 = cksum(g_base + g_ps, g_ps);
	P6_CHECK("trans-to-rx", mprotect(g_base, g_ps,
	    PROT_READ | PROT_EXEC) == 0);
	g_tgt = (volatile uint8_t *)g_base;
	st = run_child(w_first_body);
	expect_exit("trans-rx-write-faults", st, 0);
	P6_CHECK("trans-to-rw", mprotect(g_base, g_ps,
	    PROT_READ | PROT_WRITE) == 0);
	g_base[0] = 0x11u;
	g_base[g_ps - 1u] = 0x22u;
	P6_CHECK("trans-rw-write-ok", g_base[0] == 0x11u &&
	    g_base[g_ps - 1u] == 0x22u);
	P6_CHECK("trans-neighbor-exact-rw", cksum(g_base + g_ps,
	    g_ps) == c1);
	g_base[0] = 0xA5u;
	g_base[g_ps - 1u] = 0xA5u;
	P6_CHECK("trans-back-to-rx", mprotect(g_base, g_ps,
	    PROT_READ | PROT_EXEC) == 0);
	st = run_child(w_first_body);
	expect_exit("trans-rx-again-faults", st, 0);
	g_fn = obj_to_fn(g_base + PROBE_OFF);
	st = run_child(x_rx_body);
	expect_exit("trans-rx-exec-again", st, 0);
	g_base[g_ps] = 0x77u;
	P6_CHECK("trans-neighbor-still-rw", g_base[g_ps] == 0x77u);
	g_base[g_ps] = 0x5Au;
	P6_CHECK("trans-neighbor-exact-rx", cksum(g_base + g_ps,
	    g_ps) == c1);
	P6_CHECK("trans-unmap", munmap(g_base, 2 * g_ps) == 0);
	g_base = NULL;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("P6-PERMS suite abi=%s endian=%s\n", P6_ABI, P6_ENDIAN);
	t_model();
	if (g_ps == 4096u) {
		t_rx_rw_split();
		t_rw_rx_split();
		t_prot_none();
		t_transitions();
	} else {
		printf("P6-INFO skip: pagesize is not 4 KiB\n");
	}
	printf("P6-SUMMARY failed=%u total=%u\n", g_fail,
	    g_pass + g_fail);
	printf("P6-RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
