#!/bin/sh
# tests/run_h1_smc.sh — Phase 7 lane H1 acceptance: self-modifying-code
# & W^X gate (tests/test_h1_smc.c, N64/N32 x LE/BE), byte-identical vs
# the qemu-mips* oracle on both --interp and --dbt.
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
#      build the four static guests at /x/h1-<variant>.
#   3. Test container (mips64rt-qemu:10.0.13, stage at /x, translator at
#      /b): for each variant run the qemu golden (which must itself print
#      H1-SMC-RESULT: PASS with rc 0) plus --interp plus --dbt with
#      identical argv (no args) and a clean minimal env (env -i
#      PATH=/usr/bin:/bin HOSTNAME=mips64rt), and cmp golden vs both
#      engines byte for byte. Prints H1-PASS/H1-FAIL per check and
#      H1-RESULT: PASS|FAIL; exit 0 iff every check passes on both
#      engines.
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
BUILD_NAME="mips64rt-h1-build-$$"
TEST_NAME="mips64rt-h1-test-$$"
STAGE="$(mktemp -d /tmp/mips64rt-h1-XXXXXX)" || exit 1

cleanup() {
	docker rm -f "$BUILD_NAME" "$TEST_NAME" >/dev/null 2>&1 || true
	rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

echo "== make build (host translator) =="
make build || exit 1
test -x _build/mips64rt || { echo "H1-FAIL no _build/mips64rt"; exit 1; }
/_build/mips64rt --version 2>/dev/null || true

echo "== build container: four static SMC guests =="
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
mips64el-linux-gnuabi64-gcc $C -mabi=64 -o /x/h1-n64le /s/test_h1_smc.c
echo "== build N32LE =="
mips64el-linux-gnuabi64-gcc $C -mabi=n32 -o /x/h1-n32le /s/test_h1_smc.c
echo "== build N64BE =="
mips64-linux-gnuabi64-gcc $C -mabi=64 -o /x/h1-n64be /s/test_h1_smc.c
echo "== build N32BE =="
mips64-linux-gnuabi64-gcc $C -mabi=n32 -o /x/h1-n32be /s/test_h1_smc.c
echo "-- ELF identities --"
file /x/h1-n64le /x/h1-n32le /x/h1-n64be /x/h1-n32be
echo "-- SYNCI shape (must lower to the SYNCI instruction) --"
mips64el-linux-gnuabi64-objdump -d /x/h1-n64le | grep -m2 "synci" || true
'
rc=$?
if test $rc -ne 0; then
	echo "H1-FAIL build container exit $rc"
	exit 1
fi

echo "== test container: qemu goldens vs interp vs dbt =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$TEST_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$STAGE:/x" -v "$PWD/_build:/b:ro" "$TEST_IMG" sh -c '
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "H1-PASS $1"; }
bad() { fail=$((fail + 1)); echo "H1-FAIL $1"; }
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
	timeout --kill-after=30s 90s $E "$Q" "/x/h1-$V" \
		> "/x/$V-golden.txt" 2>&1
	qrc=$?
	if test $qrc -ne 0; then bad "$V-qemu-rc=$qrc"; continue; fi
	if grep -q "H1-SMC-RESULT: PASS" "/x/$V-golden.txt"; then
		ok "$V-qemu-PASS"
	else
		bad "$V-qemu-no-PASS"
		cat "/x/$V-golden.txt" || true
		continue
	fi
	for eng in interp dbt; do
		timeout --kill-after=30s 90s $E /b/mips64rt "--$eng" \
			"/x/h1-$V" > "/x/$V-$eng.txt" 2>&1
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
echo "H1-SUMMARY pass=$pass fail=$fail"
if test "$fail" -eq 0; then echo "H1-RESULT: PASS"; else echo "H1-RESULT: FAIL"; fi
exit "$fail"
'
rc=$?
docker ps --format "{{.Names}}" | grep -q "^${BUILD_NAME}$" && {
	echo "H1-FAIL container $BUILD_NAME still present"
	exit 1
}
docker ps --format "{{.Names}}" | grep -q "^${TEST_NAME}$" && {
	echo "H1-FAIL container $TEST_NAME still present"
	exit 1
}
if test $rc -ne 0; then
	echo "H1-RESULT: FAIL (container exit $rc)"
	exit 1
fi
echo "H1-RESULT: PASS"
exit 0
