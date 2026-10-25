/*
 * tests/p5_dynlib.c — Shared-library side of the Phase 5 dynamic gate.
 *
 * Built alongside tests/test_p5_dyn.c, one ABI/endian variant per
 * directory (p5_dynlib-<variant>.so next to p5-<variant>):
 *   mips64el-linux-gnuabi64-gcc -shared -fPIC -O1 -std=c11 \
 *     -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -o p5_dynlib-n64le.so tests/p5_dynlib.c
 * (N32 adds -mabi=n32; big-endian uses mips64-linux-gnuabi64-gcc.)
 * The exe side reaches every symbol below through dlopen/dlsym only,
 * exercising cross-library calls and __thread TLS (C11 _Thread_local)
 * across the library boundary. Deterministic: no addresses are ever
 * exposed, only values the exe asserts exactly.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

_Thread_local int lib_tls = 0;

int lib_answer(void)
{
    return 41;
}

int lib_bump(void)
{
    lib_tls += 1;
    return lib_tls;
}

int lib_tls_get(void)
{
    return lib_tls;
}

void lib_tls_set(int v)
{
    lib_tls = v;
}

const char *lib_name(void)
{
    return "p5_dynlib";
}
