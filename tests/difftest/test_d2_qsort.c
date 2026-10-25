/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 D2 static-libc fixture: sorting and searching. Exercises
 * qsort/bsearch/strcmp over fixed inputs (pure computation, no
 * syscalls past startup). Output is fully deterministic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    return (x > y) - (x < y);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(void)
{
    int v[] = { 5, -3, 17, 0, -3, 42, 8, -100, 17, 4 };
    const char *w[] = { "pear", "apple", "fig", "banana", "apple" };
    size_t i;
    int key = 17;
    int *found;

    qsort(v, sizeof v / sizeof v[0], sizeof v[0], cmp_int);
    printf("D2-QSORT ints:");
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        printf(" %d", v[i]);
    }
    printf("\n");

    qsort((void *)w, sizeof w / sizeof w[0], sizeof w[0], cmp_str);
    printf("D2-QSORT words:");
    for (i = 0; i < sizeof w / sizeof w[0]; i++) {
        printf(" %s", w[i]);
    }
    printf("\n");

    found = bsearch(&key, v, sizeof v / sizeof v[0], sizeof v[0], cmp_int);
    printf("D2-QSORT bsearch=%d\n", found != NULL ? *found : -999);
    return 0;
}
