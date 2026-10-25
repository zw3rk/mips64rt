/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 D2 static-libc fixture: dynamic allocation. Exercises
 * malloc/calloc/realloc/free over the brk path (small objects) and
 * the mmap path (large object). Only checksums are printed, never
 * addresses, so output is fully deterministic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checksum(const unsigned char *p, size_t n)
{
    unsigned h = 0u;
    size_t i;

    for (i = 0; i < n; i++) {
        h = h * 31u + p[i];
    }
    return h;
}

int main(void)
{
    unsigned char *a;
    int *b;
    unsigned char *c;
    char *r;
    size_t i;
    int zero_ok = 1;

    a = malloc(16);
    if (a == NULL) {
        printf("D2-MALLOC FAIL small\n");
        return 1;
    }
    for (i = 0; i < 16; i++) {
        a[i] = (unsigned char)(i & 0xffu);
    }
    printf("D2-MALLOC small=%08x\n", checksum(a, 16));
    free(a);

    b = calloc(256, sizeof *b);
    if (b == NULL) {
        printf("D2-MALLOC FAIL calloc\n");
        return 1;
    }
    for (i = 0; i < 256; i++) {
        if (b[i] != 0) {
            zero_ok = 0;
        }
    }
    printf("D2-MALLOC calloc-zero=%d\n", zero_ok);
    free(b);

    c = malloc(70000);
    if (c == NULL) {
        printf("D2-MALLOC FAIL large\n");
        return 1;
    }
    for (i = 0; i < 70000; i++) {
        c[i] = (unsigned char)((i * 7u + 3u) & 0xffu);
    }
    printf("D2-MALLOC large=%08x\n", checksum(c, 70000));
    free(c);

    r = malloc(64);
    if (r == NULL) {
        printf("D2-MALLOC FAIL realloc-src\n");
        return 1;
    }
    memset(r, 0x5a, 64);
    r = realloc(r, 200);
    if (r == NULL) {
        printf("D2-MALLOC FAIL realloc\n");
        return 1;
    }
    printf("D2-MALLOC realloc=%08x\n", checksum((unsigned char *)r, 64));
    free(r);

    printf("D2-MALLOC done\n");
    return 0;
}
