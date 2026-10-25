/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 D2 static-libc fixture: stdio round-trip on stdin/stdout.
 * The runner (run_d2.sh) feeds three fixed lines on stdin; the
 * guest verifies each line with fgets/strcmp, echoes it with fputs,
 * and prints a verdict. Only read/write/exit syscalls are needed,
 * so the Phase 1 engine brokers every call. Output is fully
 * deterministic (stdin bytes are fixed by the runner).
 */

#include <stdio.h>
#include <string.h>

int main(void)
{
    static const char *lines[] = {
        "D2-FILEIO alpha\n",
        "D2-FILEIO beta\n",
        "D2-FILEIO gamma\n"
    };
    char buf[64];
    int i;

    for (i = 0; i < 3; i++) {
        if (fgets(buf, (int)sizeof buf, stdin) == NULL) {
            printf("D2-FILEIO FAIL read %d\n", i);
            return 1;
        }
        if (strcmp(buf, lines[i]) != 0) {
            printf("D2-FILEIO FAIL data %d\n", i);
            return 1;
        }
        if (fputs(buf, stdout) < 0) {
            printf("D2-FILEIO FAIL write %d\n", i);
            return 1;
        }
    }
    printf("D2-FILEIO ok 3 lines\n");
    return 0;
}
