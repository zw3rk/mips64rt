#!/bin/sh
# E04 runner: cross-compile probe.c for MIPS64 N64/N32 x LE/BE (static),
# run each under its qemu-user emulator, plus ELF/ASE/disasm evidence.
# Usage: ./run.sh [outdir]   (default outdir: ./out)
#
# Toolchains (overridable):
#   N64LE: mips64el-linux-gnuabi64-gcc -mabi=64  (run: qemu-mips64el)
#   N32LE: mips64el-linux-gnuabi64-gcc -mabi=n32  (run: qemu-mipsn32el)
#   N64BE: mips64-linux-gnuabi64-gcc -mabi=64     (run: qemu-mips64)
#   N32BE: mips64-linux-gnuabi64-gcc -mabi=n32    (run: qemu-mipsn32)
set -eu
cd "$(dirname "$0")"

OUT="${1:-out}"
mkdir -p "$OUT"

LE_CC="${LE_CC:-mips64el-linux-gnuabi64-gcc}"
BE_CC="${BE_CC:-mips64-linux-gnuabi64-gcc}"
NATIVE_CC="${NATIVE_CC:-cc}"
CFLAGS="${CFLAGS:--std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -static -O1}"

{
echo "=== toolchain ==="
$LE_CC --version | head -1
$BE_CC --version | head -1
qemu-mips64el --version | head -1
qemu-mips64 --version | head -1
qemu-mipsn32el --version | head -1
qemu-mipsn32 --version | head -1
file --version | head -1
} | tee "$OUT/versions.txt"

build_variant() {
  # $1 = tag, $2 = CC, $3 = abi flag, $4 = qemu
  tag="$1"; cc="$2"; abi="$3"; qemu="$4"
  od_bin="${cc%-gcc}-objdump"
  if ! command -v "$od_bin" >/dev/null 2>&1; then od_bin="objdump"; fi
  echo "=== build $tag ==="
  # shellcheck disable=SC2086
  $cc $CFLAGS $abi probe.c -o "$OUT/probe-$tag"
  echo "=== ELF header $tag ==="
  readelf -h "$OUT/probe-$tag" | tee "$OUT/elf-h-$tag.txt"
  echo "=== arch ASE attrs $tag ==="
  readelf -A "$OUT/probe-$tag" 2>&1 | awk '/Static GOT/{exit} {print}' | tee "$OUT/elf-A-$tag.txt"
  echo "=== FP disasm $tag ($od_bin) ==="
  $od_bin -d "$OUT/probe-$tag" | grep -E 'abs\.d|abs\.s|neg\.d|neg\.s|add\.d|add\.s|cfc1|ctc1' | head -40 | tee "$OUT/disasm-$tag.txt"
  test -s "$OUT/disasm-$tag.txt"
  echo "=== run $tag ($qemu) ==="
  timeout --kill-after=30s 60s "$qemu" "$OUT/probe-$tag" | tee "$OUT/output-$tag.txt"
  test "$(grep -c '^RESULT=PASS$' "$OUT/output-$tag.txt")" = 1
  echo "E04-RESULT: PASS $tag"
}

build_variant n64le "$LE_CC" "-mabi=64" qemu-mips64el
build_variant n32le "$LE_CC" "-mabi=n32" qemu-mipsn32el
build_variant n64be "$BE_CC" "-mabi=64" qemu-mips64
build_variant n32be "$BE_CC" "-mabi=n32" qemu-mipsn32

echo "=== nan2008 contrast (LE N64, readelf only) ==="
if $LE_CC $CFLAGS -mabi=64 -mnan=2008 probe.c -o "$OUT/probe-nan2008-le" 2>"$OUT/nan2008-err.txt"; then
  readelf -h "$OUT/probe-nan2008-le" | grep -i flags | tee "$OUT/elf-h-nan2008-le.txt"
else
  echo "nan2008-build FAILED:" | tee "$OUT/elf-h-nan2008-le.txt"
  cat "$OUT/nan2008-err.txt" | tee -a "$OUT/elf-h-nan2008-le.txt"
fi
if $LE_CC $CFLAGS -mabi=64 -mnan=legacy probe.c -o "$OUT/probe-nanlegacy-le" 2>"$OUT/nanlegacy-err.txt"; then
  readelf -h "$OUT/probe-nanlegacy-le" | grep -i flags | tee "$OUT/elf-h-nanlegacy-le.txt"
else
  echo "nanlegacy-build FAILED:" | tee "$OUT/elf-h-nanlegacy-le.txt"
  cat "$OUT/nanlegacy-err.txt" | tee -a "$OUT/elf-h-nanlegacy-le.txt"
fi

if command -v "$NATIVE_CC" >/dev/null 2>&1; then
echo "=== native build+run ==="
$NATIVE_CC -std=c11 -Werror=vla -pedantic -Wall -Wextra -O1 probe.c -o "$OUT/probe-native" \
  && ./"$OUT/probe-native" | tee "$OUT/output-native.txt" || true
fi

echo "E04 run.sh: ALL DONE"
