/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 D2 static-libc fixture: formatted output. Exercises
 * snprintf/printf conversions (integer and string only; no %p, no
 * floating point). Output is fully deterministic.
 */

#include <stdio.h>

int main(void)
{
    char buf[128];
    int n;

    n = snprintf(buf, sizeof buf, "dec=%d uns=%u hex=%x HEX=%X oct=%o",
                 -42, 42u, 0xdeadbeefu, 0xdeadbeefu, 511u);
    printf("D2-PRINTF [%s] n=%d\n", buf, n);
    printf("D2-PRINTF str=[%s] ch=[%c] pct=[%%]\n", "hello", 'Q');
    printf("D2-PRINTF ll=[%lld] llu=[%llu]\n",
           -123456789012345LL, 123456789012345ULL);
    printf("D2-PRINTF width=[%8d][%-8d][%08d] prec=[%.3s][%5.2d]\n",
           42, 42, 42, "abcdef", 7);
    return 0;
}
