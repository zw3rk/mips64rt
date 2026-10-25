/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 D2 static-libc fixture: minimal hello. Exercises the
 * write + exit_group path only. Output is fully deterministic
 * (no addresses, no environment content).
 */

#include <stdio.h>

int main(void)
{
    printf("D2-HELLO hello from static libc\n");
    return 0;
}
