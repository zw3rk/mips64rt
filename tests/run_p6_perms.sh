#!/bin/sh
# tests/run_p6_perms.sh — Phase 6 lane L6b acceptance: adjacent 4 KiB
# page-permissions gate (tests/test_p6_perms.c, N64/N32 x LE/BE),
# byte-identical vs the qemu-mips* oracle on both --interp and --dbt.
#
# Toolchain recipe (exact, recorded):
#   build image:  debian:trixie-slim (linux/arm64)
#   test image:   mips64rt-qemu:10.0.13 (qemu-user 10.0.13)
#   LE compiler:  mips64el-linux-gnuabi64-gcc (Debian trixie package
#                 gcc-mips64el-linux-gnuabi64), -mabi=64 (N64) / -mabi=n32
#   BE compiler:  mips64-linux-gnuabi64-gcc (Debian trixie package
#                 gcc-mips64-linux-gnuabi64), -mabi=64 (N64) / -mabi=n32
#   dev packages: libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross
#                 libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross
#                 libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross
#   guest flags:  -O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra
#                 -Werror (curated C11, same as tests/run_p1_isa.sh)
#   oracles:      qemu-mips64el (N64LE), qemu-mipsn32el (N32LE),
#                 qemu-mips64 (N64BE), qemu-mipsn32 (N32BE)
#
# What it does, end to end (all bounds wall-clocked, unique container
# names, cleanup trap + docker ps check like tests/run_p5_busybox.sh):
#   1. make build on the host (nix aarch64-musl static-PIE translator).
#   2. Build container (debian:trixie-slim): install the compilers above,
#      build the four static guests at /x/p6-<variant>, print file(1)
#      identities plus the rx_probe disassembly shape.
#   3. Test container (mips64rt-qemu:10.0.13, stage at /x, translator at
#      /b): for each variant run the qemu golden (which must itself print
#      P6-RESULT: PASS with rc 0) plus --interp plus --dbt with identical
#      argv (no args) and a clean minimal env (env -i PATH=/usr/bin:/bin
#      HOSTNAME=mips64rt), and cmp golden vs both engines byte for byte.
#      Prints P6-PASS/P6-FAIL per check and P6-RESULT: PASS|FAIL;
#      exit 0 iff every check passes on both engines.
#
# Host requirements: docker with --platform linux/arm64, make + the
# nix aarch64-musl toolchain for `make build` (see AGENTS.md).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
set -u
cd "$(dirname "$0")/.." || exit 1

BUILD_IMG="debian:trixie-slim"
TEST_IMG="mips64rt-qemu:10.0.13"
BUILD_NAME="mips64rt-l6b-build-$$"
TEST_NAME="mips64rt-l6b-test-$$"
STAGE="$(mktemp -d /tmp/mips64rt-l6b-XXXXXX)" || exit 1

cleanup() {
	docker rm -f "$BUILD_NAME" "$TEST_NAME" >/dev/null 2>&1 || true
	rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

echo "== make build (host translator) =="
make build || exit 1
test -x _build/mips64rt || { echo "P6-FAIL no _build/mips64rt"; exit 1; }
./_build/mips64rt --version 2>/dev/null || true

echo "== build container: four static perms guests =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$BUILD_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$STAGE:/x" -v "$PWD/tests:/s:ro" "$BUILD_IMG" sh -c '
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 \
	libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross \
	libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross \
	libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross \
	binutils-mips64el-linux-gnuabi64 file >/dev/null 2>&1
echo "-- compiler identities --"
mips64el-linux-gnuabi64-gcc --version | head -1
mips64-linux-gnuabi64-gcc --version | head -1
C="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
echo "== build N64LE =="
mips64el-linux-gnuabi64-gcc $C -mabi=64 -o /x/p6-n64le /s/test_p6_perms.c
echo "== build N32LE =="
mips64el-linux-gnuabi64-gcc $C -mabi=n32 -o /x/p6-n32le /s/test_p6_perms.c
echo "== build N64BE =="
mips64-linux-gnuabi64-gcc $C -mabi=64 -o /x/p6-n64be /s/test_p6_perms.c
echo "== build N32BE =="
mips64-linux-gnuabi64-gcc $C -mabi=n32 -o /x/p6-n32be /s/test_p6_perms.c
echo "-- ELF identities --"
file /x/p6-n64le /x/p6-n32le /x/p6-n64be /x/p6-n32be
echo "-- rx_probe shape (must be a tiny li/jr leaf) --"
mips64el-linux-gnuabi64-objdump -d /x/p6-n64le | grep -A6 "<rx_probe>:" || true
'
rc=$?
if test $rc -ne 0; then
	echo "P6-FAIL build container exit $rc"
	exit 1
fi

echo "== test container: qemu goldens vs interp vs dbt =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$TEST_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$STAGE:/x" -v "$PWD/_build:/b:ro" "$TEST_IMG" sh -c '
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "P6-PASS $1"; }
bad() { fail=$((fail + 1)); echo "P6-FAIL $1"; }
echo "-- qemu identities --"
/usr/bin/qemu-mips64el --version | head -1
/usr/bin/qemu-mipsn32el --version | head -1
/usr/bin/qemu-mips64 --version | head -1
/usr/bin/qemu-mipsn32 --version | head -1
echo "-- translator identity --"
/b/mips64rt --version
E="env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt"
for spec in "n64le:qemu-mips64el" "n32le:qemu-mipsn32el" \
		"n64be:qemu-mips64" "n32be:qemu-mipsn32"; do
	V="${spec%%:*}"
	Q="/usr/bin/${spec##*:}"
	timeout --kill-after=30s 90s $E "$Q" "/x/p6-$V" \
		> "/x/$V-golden.txt" 2>&1
	qrc=$?
	if test $qrc -ne 0; then bad "$V-qemu-rc=$qrc"; continue; fi
	if grep -q "P6-RESULT: PASS" "/x/$V-golden.txt"; then
		ok "$V-qemu-PASS"
	else
		bad "$V-qemu-no-PASS"
		cat "/x/$V-golden.txt" || true
		continue
	fi
	for eng in interp dbt; do
		timeout --kill-after=30s 90s $E /b/mips64rt "--$eng" \
			"/x/p6-$V" > "/x/$V-$eng.txt" 2>&1
		erc=$?
		if test $erc -ne 0; then bad "$V-$eng-rc=$erc"; continue; fi
		if cmp -s "/x/$V-golden.txt" "/x/$V-$eng.txt"; then
			ok "$V-$eng-byte-identical"
		else
			bad "$V-$eng-differs"
			diff "/x/$V-golden.txt" "/x/$V-$eng.txt" | head -8 || true
		fi
	done
done
echo "P6-SUMMARY pass=$pass fail=$fail"
if test "$fail" -eq 0; then echo "P6-RESULT: PASS"; else echo "P6-RESULT: FAIL"; fi
exit "$fail"
'
rc=$?
docker ps --format "{{.Names}}" | grep -q "^${BUILD_NAME}$" && {
	echo "P6-FAIL container $BUILD_NAME still present"
	exit 1
}
docker ps --format "{{.Names}}" | grep -q "^${TEST_NAME}$" && {
	echo "P6-FAIL container $TEST_NAME still present"
	exit 1
}
if test $rc -ne 0; then
	echo "P6-RESULT: FAIL (container exit $rc)"
	exit 1
fi
echo "P6-RESULT: PASS"
exit 0
