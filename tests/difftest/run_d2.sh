#!/bin/sh
# tests/difftest/run_d2.sh — Phase 2 lane L2d D2 gate: build the
# static-libc fixtures test_d2_{hello,printf,malloc,qsort,fileio}.c
# for N64+N32 x LE+BE with the Debian cross toolchains in one bounded
# container, capture each under its qemu oracle into
# tests/difftest/golden_*, and require stdout+exit identical under
# --interp. (The --dbt half of D2 runs at RC2 integration.)
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# The fileio fixture reads three fixed lines from stdin (seeded by the
# runner) and echoes them: the Phase 1 engine brokers read/write but
# not open/fcntl yet, so stdio runs on stdin/stdout only.
set -u
ROOT="$(cd "$(dirname "$0")/../.." || exit 1; pwd)"
D="$ROOT/tests/difftest"
IMG="debian:stable-slim"
NAME="mips64rt-l2d-d2-$$"

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== D2 step 1: rebuild translator ==="
(cd "$ROOT" && make build) || exit 1
[ -x "$ROOT/_build/mips64rt" ] || {
	echo "D2-FAIL: $ROOT/_build/mips64rt missing"
	exit 1
}

echo "=== D2 step 2: fixtures + goldens + interp parity ($NAME) ==="
timeout --kill-after=30s 590s docker run --rm \
	--name "$NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$ROOT:/w" -w /w "$IMG" sh -c '
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 \
	libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross \
	libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross \
	libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross \
	qemu-user file >/dev/null 2>&1
echo "== compiler identities =="
mips64el-linux-gnuabi64-gcc --version | head -1
mips64-linux-gnuabi64-gcc --version | head -1
echo "== qemu identities =="
qemu-mips64el --version | head -1
qemu-mipsn32el --version | head -1
qemu-mips64 --version | head -1
qemu-mipsn32 --version | head -1
mkdir -p /tmp/d2bin
printf "D2-FILEIO alpha\nD2-FILEIO beta\nD2-FILEIO gamma\n" > /tmp/d2seed
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
build_one() {
	cc="$1"
	abi="$2"
	variant="$3"
	fixture="$4"
	echo "== build $variant/$fixture =="
	$cc $CFLAGS -mabi="$abi" -o /tmp/d2bin/d2-"$variant"-"$fixture" \
		/w/tests/difftest/test_d2_"$fixture".c
}
for fixture in hello printf malloc qsort fileio; do
	build_one mips64el-linux-gnuabi64-gcc 64 n64le "$fixture"
	build_one mips64el-linux-gnuabi64-gcc n32 n32le "$fixture"
	build_one mips64-linux-gnuabi64-gcc 64 n64be "$fixture"
	build_one mips64-linux-gnuabi64-gcc n32 n32be "$fixture"
done
echo "== ELF identities =="
file /tmp/d2bin/d2-n64le-hello /tmp/d2bin/d2-n32le-hello \
	/tmp/d2bin/d2-n64be-hello /tmp/d2bin/d2-n32be-hello
pass=0
run_one() {
	qemu="$1"
	variant="$2"
	fixture="$3"
	bin=/tmp/d2bin/d2-"$variant"-"$fixture"
	body=/tmp/d2bin/body-"$variant"-"$fixture".txt
	golden=/w/tests/difftest/golden_"$variant"_"$fixture".txt
	interp_out=/tmp/d2bin/interp-"$variant"-"$fixture".txt
	echo "== run $variant/$fixture under $qemu (golden) + interp =="
	set +e
	if [ "$fixture" = "fileio" ]; then
		timeout --kill-after=30s 60s "$qemu" "$bin" \
			>"$body" 2>/tmp/d2bin/qemu.err </tmp/d2seed
		qrc=$?
		timeout --kill-after=30s 60s /w/_build/mips64rt --interp "$bin" \
			>"$interp_out" 2>/tmp/d2bin/interp.err </tmp/d2seed
		irc=$?
	else
		timeout --kill-after=30s 60s "$qemu" "$bin" \
			>"$body" 2>/tmp/d2bin/qemu.err
		qrc=$?
		timeout --kill-after=30s 60s /w/_build/mips64rt --interp "$bin" \
			>"$interp_out" 2>/tmp/d2bin/interp.err
		irc=$?
	fi
	set -e
	{ cat "$body"; echo "D2-EXIT: $qrc"; } > "$golden"
	if [ "$qrc" != "$irc" ]; then
		echo "D2-FAIL $variant/$fixture: exit qemu=$qrc interp=$irc"
		head -10 /tmp/d2bin/interp.err
		exit 1
	fi
	if ! cmp -s "$body" "$interp_out"; then
		echo "D2-FAIL $variant/$fixture: stdout differs"
		diff "$body" "$interp_out" | head -10
		head -10 /tmp/d2bin/interp.err
		exit 1
	fi
	echo "D2-PASS $variant/$fixture exit=$qrc"
	pass=$((pass + 1))
}
for fixture in hello printf malloc qsort fileio; do
	run_one qemu-mips64el n64le "$fixture"
	run_one qemu-mipsn32el n32le "$fixture"
	run_one qemu-mips64 n64be "$fixture"
	run_one qemu-mipsn32 n32be "$fixture"
done
echo "D2: $pass/20 guests match"
'
rc=$?
echo "container exit: $rc"
[ $rc -eq 0 ] || exit 1
if docker ps --format "{{.Names}}" | grep -q "^${NAME}$"; then
	echo "D2-FAIL: container $NAME still present"
	exit 1
fi
echo "D2-RESULT: PASS"
