#!/bin/sh
# tests/run_p1_isa.sh — Phase 1 lane L1d acceptance: build the
# freestanding tests/test_p1_isa.c for all four variants inside one
# bounded debian:stable-slim container, run each under its qemu
# oracle, and capture stdout+exit into tests/p1_golden_*.txt.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# The two LE goldens honestly record qemu-mips64el/qemu-mipsn32el
# output, including the documented unaligned-pair oracle divergence
# (E02 adjudication): the canonical LWL/LWR/LDL/LDR (and SWL/SWR/
# SDL/SDR) checks print P1-FAIL there while the interpreter prints
# P1-PASS. The script itself exits 0 once all four goldens exist;
# per-variant exit codes land in the P1-EXIT trailer of each golden.
set -u
cd "$(dirname "$0")/.." || exit 1

IMG="debian:stable-slim"
NAME="mips64rt-l1d-run-$$"

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

timeout --kill-after=30s 280s docker run --rm \
	--name "$NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$PWD:/w" -w /w "$IMG" sh -c '
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
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
echo "== build N64LE =="
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=64 -o /tmp/p1-n64le tests/test_p1_isa.c
echo "== build N32LE =="
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -o /tmp/p1-n32le tests/test_p1_isa.c
echo "== build N64BE =="
mips64-linux-gnuabi64-gcc $CFLAGS -mabi=64 -o /tmp/p1-n64be tests/test_p1_isa.c
echo "== build N32BE =="
mips64-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -o /tmp/p1-n32be tests/test_p1_isa.c
echo "== ELF identities =="
file /tmp/p1-n64le /tmp/p1-n32le /tmp/p1-n64be /tmp/p1-n32be
run_one() {
	qemu="$1"
	bin="$2"
	golden="$3"
	echo "== run $bin under $qemu -> $golden =="
	set +e
	timeout --kill-after=30s 60s "$qemu" "$bin" >"$golden" 2>&1
	rc=$?
	set -e
	echo "P1-EXIT: $rc" >>"$golden"
	echo "rc-$bin=$rc"
}
run_one qemu-mips64el /tmp/p1-n64le tests/p1_golden_n64le.txt
run_one qemu-mipsn32el /tmp/p1-n32le tests/p1_golden_n32le.txt
run_one qemu-mips64 /tmp/p1-n64be tests/p1_golden_n64be.txt
run_one qemu-mipsn32 /tmp/p1-n32be tests/p1_golden_n32be.txt
'
rc=$?
echo "container exit: $rc"
docker ps --format "{{.Names}}" | grep -q "^${NAME}$" && {
	echo "container $NAME still present"
	exit 1
}
exit $rc
