/*
 * src/os/backend_darwin.c — Darwin OS backend (MAP_JIT + fallback W^X).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared U0 slot registry, TIF_FIXADE, delay-slot NPC target, and
 * Soft-TLB live in src/os/backend_state.c.
 */

#define _DARWIN_C_SOURCE 1

#include "os/backend.h"

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_JIT
#define MAP_JIT 0x0800
#endif

const char *mips_backend_name(void)
{
    return "darwin";
}

/* MAP_JIT usability probe: unentitled processes take SIGBUS on the
 * first toggled write, so the mode is decided once with a guarded
 * probe write (mirroring the host-fault guard pattern). Entitled
 * processes use MAP_JIT end to end; everyone else falls back to
 * the RW-staging + mprotect flip, which ad-hoc binaries honor. */
static _Thread_local sigjmp_buf jit_probe_jb;
static _Thread_local volatile sig_atomic_t jit_probe_armed = 0;
static pthread_mutex_t jit_probe_mu = PTHREAD_MUTEX_INITIALIZER;
static int jit_probe_mode = 0; /* 0 unknown, 1 MAP_JIT, 2 flip */

static void jit_probe_handler(int sig)
{
    if (jit_probe_armed != 0) {
        jit_probe_armed = 0;
        siglongjmp(jit_probe_jb, 1);
    }
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

static int jit_probe_map_jit(void)
{
    struct sigaction sa;
    struct sigaction old_bus;
    struct sigaction old_segv;
    void *p;
    int ok = 0;

    p = mmap(NULL, 16384, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (p == MAP_FAILED) {
        return 0;
    }
    (void)memset(&sa, 0, sizeof sa);
    sa.sa_handler = jit_probe_handler;
    sa.sa_flags = SA_RESTART;
    (void)sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGBUS, &sa, &old_bus);
    (void)sigaction(SIGSEGV, &sa, &old_segv);
    /* pthread_jit_write_protect_np(0) disables write protection (makes
     * MAP_JIT pages writable); (1) enables write protection (seals RX). */
    (void)pthread_jit_write_protect_np(0);
    jit_probe_armed = 1;
    if (sigsetjmp(jit_probe_jb, 1) == 0) {
        *(volatile uint32_t *)p = 0xD2800540u;
        ok = 1;
    }
    jit_probe_armed = 0;
    (void)pthread_jit_write_protect_np(1);
    (void)sigaction(SIGBUS, &old_bus, NULL);
    (void)sigaction(SIGSEGV, &old_segv, NULL);
    (void)munmap(p, 16384);
    return ok;
}

static int jit_use_map_jit(void)
{
    int mode;

    (void)pthread_mutex_lock(&jit_probe_mu);
    if (jit_probe_mode == 0) {
        jit_probe_mode = jit_probe_map_jit() != 0 ? 1 : 2;
    }
    mode = jit_probe_mode;
    (void)pthread_mutex_unlock(&jit_probe_mu);
    return mode == 1;
}

void *mips_jit_alloc(size_t size)
{
    size_t ps = mips_host_page_size();
    size_t n = (size + ps - 1u) & ~(ps - 1u);
    void *p;

    if (n == 0u) {
        return NULL;
    }
    if (jit_use_map_jit()) {
        /* MAP_JIT from birth: the pages can only ever execute via
         * the write-protect toggle, never via mprotect (which
         * would break them). RWX is set at map time;
         * writability comes from pthread_jit_write_protect_np. */
        p = mmap(NULL, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
        return p == MAP_FAILED ? NULL : p;
    }
    /* Unentitled fallback: plain RW staging, sealed with mprotect
     * (ad-hoc binaries honor the flip). */
    p = mmap(NULL, n, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

void mips_jit_begin_write(void *p, size_t size)
{
    size_t ps = mips_host_page_size();
    uintptr_t lo;
    uintptr_t hi;

    if (p == NULL || size == 0u) {
        return;
    }
    if (jit_use_map_jit()) {
        /* Open the JIT write window (0 = writable, no mprotect). */
        (void)pthread_jit_write_protect_np(0);
        return;
    }
    lo = (uintptr_t)p & ~(uintptr_t)(ps - 1u);
    hi = ((uintptr_t)p + size + (ps - 1u)) & ~(uintptr_t)(ps - 1u);
    (void)mprotect((void *)lo, hi - lo, PROT_READ | PROT_WRITE);
}

int mips_jit_seal_rx(void *p, size_t size)
{
    size_t ps = mips_host_page_size();
    uintptr_t lo;
    uintptr_t hi;

    if (p == NULL || size == 0u) {
        return MIPS_FAULT;
    }
    if (!jit_use_map_jit()) {
        lo = (uintptr_t)p & ~(uintptr_t)(ps - 1u);
        hi = ((uintptr_t)p + size + (ps - 1u)) & ~(uintptr_t)(ps - 1u);
        if (mprotect((void *)lo, hi - lo, PROT_READ | PROT_EXEC) != 0) {
            return MIPS_FAULT;
        }
    } else {
        /* Close the JIT write window (1 = write-protected/RX). */
        (void)pthread_jit_write_protect_np(1);
    }
#if defined(__aarch64__) || defined(__arm64__)
    __builtin___clear_cache((char *)p, (char *)p + size);
#endif
    return 0;
}

void mips_jit_free(void *p, size_t size)
{
    size_t ps = mips_host_page_size();
    size_t n = (size + ps - 1u) & ~(ps - 1u);

    if (p != NULL && n != 0u) {
        (void)munmap(p, n);
    }
}
