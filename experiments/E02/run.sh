#!/bin/sh
# E02 runner: cross-compile N64+N32, LE+BE, run under qemu, dump encodings.
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
set -u
cd "$(dirname "$0")"
LE_CC=${LE_CC:-mips64el-linux-gnuabi64-gcc}
BE_CC=${BE_CC:-mips64-linux-gnuabi64-gcc}
CFLAGS="-O2 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
echo "== compiler identities =="
$LE_CC --version | head -1
$BE_CC --version | head -1
echo "== qemu identities =="
qemu-mips64el --version | head -1
qemu-mipsn32el --version | head -1
qemu-mips64 --version | head -1
qemu-mipsn32 --version | head -1
echo "== build N64LE =="
$LE_CC $CFLAGS -mabi=64 -o probe-n64le probe.c || exit 1
echo "== build N32LE =="
$LE_CC $CFLAGS -mabi=n32 -o probe-n32le probe.c || exit 1
echo "== build N64BE =="
$BE_CC $CFLAGS -mabi=64 -o probe-n64be probe.c || exit 1
echo "== build N32BE =="
$BE_CC $CFLAGS -mabi=n32 -o probe-n32be probe.c || exit 1
echo "== ELF identities =="
file probe-n64le probe-n32le probe-n64be probe-n32be
run_one() {
  qemu="$1"
  bin="$2"
  echo "== run $bin under $qemu =="
  timeout --kill-after=30s 60s "$qemu" "./$bin"
  rc=$?
  echo "rc-$bin=$rc"
  if [ $rc -eq 0 ]; then
    echo "E02-RESULT: PASS $bin"
  else
    echo "E02-RESULT: FAIL $bin"
  fi
  return $rc
}
fail=0
run_one qemu-mips64el probe-n64le || fail=1
run_one qemu-mipsn32el probe-n32le || fail=1
run_one qemu-mips64 probe-n64be || fail=1
run_one qemu-mipsn32 probe-n32be || fail=1
echo "== encodings: disassembly of sign-extension + field tests (N64LE) =="
for f in t_addiu t_addu t_sll t_lw t_daddiu t_dext t_dextm t_dextu t_dins t_dinsm t_dinsu t_ldl_ldr t_sdl_sdr; do
  mips64el-linux-gnuabi64-objdump -d --disassemble=$f probe-n64le | grep -v "^$\|file format\|Disassembly of section"
done
echo "== encodings: disassembly of sign-extension + field tests (N64BE) =="
for f in t_addiu t_addu t_sll t_lw t_daddiu t_dext t_dextm t_dextu t_dins t_dinsm t_dinsu t_ldl_ldr t_sdl_sdr; do
  mips64-linux-gnuabi64-objdump -d --disassemble=$f probe-n64be | grep -v "^$\|file format\|Disassembly of section"
done
exit $fail
