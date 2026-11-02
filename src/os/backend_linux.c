/*
 * src/os/backend_linux.c — Linux OS backend (JIT W^X staging).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared U0 slot registry, TIF_FIXADE, delay-slot NPC target, and
 * Soft-TLB live in src/os/backend_state.c.
 */

#define _GNU_SOURCE 1

#include "os/backend.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

const char *mips_backend_name(void)
{
    return "linux";
}

void *mips_jit_alloc(size_t size)
{
    size_t ps = mips_host_page_size();
    size_t n = (size + ps - 1u) & ~(ps - 1u);
    void *p;

    if (n == 0u) {
        return NULL;
    }
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
    /* The staging mapping is already writable; reassert in case a
     * previous seal flipped it. */
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
    lo = (uintptr_t)p & ~(uintptr_t)(ps - 1u);
    hi = ((uintptr_t)p + size + (ps - 1u)) & ~(uintptr_t)(ps - 1u);
    if (mprotect((void *)lo, hi - lo, PROT_READ | PROT_EXEC) != 0) {
        return MIPS_FAULT;
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
