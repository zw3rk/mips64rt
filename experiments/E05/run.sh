#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# E05 run script: build probe.c for N64/N32 x LE/BE (static), dump
# ll/sc/lld/scd encodings, run each under its qemu-user with timeouts.
# Usage: sh run.sh   (expects mips64 toolchains + qemu-user in PATH)
set -eu
cd "$(dirname "$0")"

CC_LE=mips64el-linux-gnuabi64-gcc
CC_BE=mips64-linux-gnuabi64-gcc
CFLAGS="-march=mips64r2 -O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"

echo "=== compiler identities ==="
$CC_LE --version | head -1
$CC_BE --version | head -1
echo "=== qemu identities ==="
qemu-mips64el --version | head -1
qemu-mipsn32el --version | head -1
qemu-mips64 --version | head -1
qemu-mipsn32 --version | head -1

echo "=== build N64LE (static) ==="
$CC_LE $CFLAGS -mabi=64 -o probe-n64le probe.c
echo "=== build N32LE (static) ==="
$CC_LE $CFLAGS -mabi=n32 -o probe-n32le probe.c
echo "=== build N64BE (static) ==="
$CC_BE $CFLAGS -mabi=64 -o probe-n64be probe.c
echo "=== build N32BE (static) ==="
$CC_BE $CFLAGS -mabi=n32 -o probe-n32be probe.c
mips64el-linux-gnuabi64-readelf -h probe-n64le | grep -E 'Class|Machine|Data'
mips64-linux-gnuabi64-readelf -h probe-n64be | grep -E 'Class|Machine|Data'

echo "=== encodings: probe's own ll/sc/lld/scd sites (from .o, all ABIs) ==="
ENCFLAGS="-march=mips64r2 -O1 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
$CC_LE $ENCFLAGS -mabi=64 -c -o enc-n64le.o probe.c
$CC_LE $ENCFLAGS -mabi=n32 -c -o enc-n32le.o probe.c
$CC_BE $ENCFLAGS -mabi=64 -c -o enc-n64be.o probe.c
$CC_BE $ENCFLAGS -mabi=n32 -c -o enc-n32be.o probe.c
for o in enc-n64le.o enc-n32le.o enc-n64be.o enc-n32be.o; do
  echo "--- $o ---"
  mips64el-linux-gnuabi64-objdump -d --show-raw-insn "$o" \
    | grep -E '[[:space:]]+(ll|sc|lld|scd)[[:space:]]'
done

run_one() {
  variant="$1"
  qemu="$2"
  bin="$3"
  out="$4"
  set +e
  timeout --kill-after=30s 60s "$qemu" "./$bin" > "$out" 2>&1
  st=$?
  set -e
  echo "$variant exit=$st"
  cat "$out"
  if grep -q '^DONE$' "$out"; then
    echo "E05-RESULT: PASS $variant"
  else
    echo "E05-RESULT: FAIL $variant"
  fi
}

echo "=== run N64LE under qemu-mips64el ==="
run_one N64LE qemu-mips64el probe-n64le out-n64le.txt
echo "=== run N32LE under qemu-mipsn32el ==="
run_one N32LE qemu-mipsn32el probe-n32le out-n32le.txt
echo "=== run N64BE under qemu-mips64 ==="
run_one N64BE qemu-mips64 probe-n64be out-n64be.txt
echo "=== run N32BE under qemu-mipsn32 ==="
run_one N32BE qemu-mipsn32 probe-n32be out-n32be.txt

echo "=== diff N64LE vs N64BE (expected: endian line only) ==="
diff out-n64le.txt out-n64be.txt && echo IDENTICAL || echo DIFFER-as-expected
echo "=== diff N64LE vs N32LE (expected: ABI line only) ==="
diff out-n64le.txt out-n32le.txt && echo IDENTICAL || echo DIFFER-as-expected

rm -f probe-n64le probe-n32le probe-n64be probe-n32be enc-n64le.o enc-n32le.o enc-n64be.o enc-n32be.o
echo "binaries removed; logs kept in out-*.txt"
