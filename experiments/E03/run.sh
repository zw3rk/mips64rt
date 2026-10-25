#!/bin/sh
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# E03 runner: N64/N32 rt_sigframe layout + 128-signal UAPI.
#
# Host usage (macOS Apple Silicon, no local toolchain):
#   sh experiments/E03/run.sh
# which re-executes this same file with --inner inside a unique
# debian:stable-slim container (--platform linux/arm64).
# Inner usage (already inside debian):
#   sh experiments/E03/run.sh --inner
set -eu

E03=experiments/E03
IMG=debian:stable-slim

if [ "${1:-}" != "--inner" ]; then
	NAME="mips64rt-E03-probe-$$"
	docker run --rm --name "$NAME" --memory 2g --cpus 2 \
		--platform linux/arm64 -v "$PWD:/w" -w /w \
		"$IMG" sh "$E03/run.sh" --inner
	rc=$?
	docker ps | head -5
	exit $rc
fi

# ---- inner (debian) ----
echo "== toolchain setup =="
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 \
	g++-mips64el-linux-gnuabi64 g++-mips64-linux-gnuabi64 \
	libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross \
	libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross \
	libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross \
	qemu-user file

echo "== identities =="
mips64el-linux-gnuabi64-gcc --version | head -1
mips64-linux-gnuabi64-gcc --version | head -1
qemu-mips64el --version | head -2
qemu-mipsn32el --version | head -2
qemu-mips64 --version | head -2
qemu-mipsn32 --version | head -2

mkdir -p "$E03/logs" "$E03/bin"
CFLAGS="-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -march=mips64r2 -static -O1"

build_one() {
	tag="$1"   # e.g. n64le
	cc="$2"    # cross compiler
	abi="$3"   # -mabi=64 | -mabi=n32
	out="$E03/bin/probe_$tag"
	echo "== build $tag ($cc $abi) =="
	# shellcheck disable=SC2086
	if $cc $CFLAGS $abi -o "$out" "$E03/probe.c" 2>"$E03/logs/build_$tag.err"; then
		echo "$tag: ok"
		file "$out" || true
	else
		echo "$tag: FAIL"
		cat "$E03/logs/build_$tag.err"
	fi
}

build_one n64le mips64el-linux-gnuabi64-gcc "-mabi=64"
build_one n32le mips64el-linux-gnuabi64-gcc "-mabi=n32"
build_one n64be mips64-linux-gnuabi64-gcc "-mabi=64"
build_one n32be mips64-linux-gnuabi64-gcc "-mabi=n32"

echo "== header evidence: sc_cause must be absent (MIPS64) =="
SYS=/usr/mips64el-linux-gnuabi64/include
cp "$SYS/asm/sigcontext.h" "$E03/logs/asm-sigcontext.h"
cp "$SYS/bits/sigcontext.h" "$E03/logs/bits-sigcontext.h"
cp "$SYS/asm/signal.h" "$E03/logs/asm-signal.h"
cp "$SYS/asm/ucontext.h" "$E03/logs/asm-ucontext.h" 2>/dev/null || true
echo "--- grep sc_cause in kernel+glibc sigcontext headers ---"
if grep -rn "sc_cause" "$SYS/asm/sigcontext.h" "$SYS/bits/sigcontext.h" >"$E03/logs/sc_cause.grep" 2>&1; then
	echo "sc_cause PRESENT (unexpected)"
	cat "$E03/logs/sc_cause.grep"
else
	echo "sc_cause ABSENT (expected)"
fi

run_one() {
	tag="$1"
	emu="$2"
	bin="$E03/bin/probe_$tag"
	echo "--- run $tag under $emu ---"
	set +e
	timeout --kill-after=30s 60s "$emu" "$bin" >"$E03/logs/$tag.stdout" 2>"$E03/logs/$tag.stderr"
	rc=$?
	set -e
	echo "exit=$rc"
	cat "$E03/logs/$tag.stdout"
	if [ -s "$E03/logs/$tag.stderr" ]; then
		echo "[stderr]"
		cat "$E03/logs/$tag.stderr"
	fi
	if [ "$rc" = "0" ] && [ "$(grep -c '^RESULT=PASS$' "$E03/logs/$tag.stdout")" = "1" ]; then
		echo "E03-RESULT: PASS $tag"
	else
		echo "E03-RESULT: FAIL $tag"
	fi
}

run_one n64le qemu-mips64el
run_one n32le qemu-mipsn32el
run_one n64be qemu-mips64
run_one n32be qemu-mipsn32
echo "INNER-DONE"
