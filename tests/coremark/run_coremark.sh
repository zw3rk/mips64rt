#!/bin/sh
# tests/coremark/run_coremark.sh — Phase 7 lane H3 acceptance gate.
#
# What it does, end to end (all bounds wall-clocked, unique container
# names, cleanup trap + docker ps check like tests/run_p5_busybox.sh):
#   1. make build on the host (nix aarch64-musl static-PIE translator).
#   2. Build container (debian:trixie-slim): install the trixie MIPS64EL
#      cross toolchain and build the fully static N64LE CoreMark guest
#      with the recipe from tests/coremark/core_portme.h
#      (mips64el-linux-gnuabi64-gcc -O1 -static).
#   3. Test container (mips64rt-qemu:10.0.13, qemu-user 10.0.13, with
#      the guest at /x and the translator at /b): run the qemu-mips64el
#      golden plus five interleaved --interp/--dbt runs at a fixed
#      iteration count (COREMARK_ITER, default 400), all with argv
#      "0 0 0x66 ITER" (known-CRC performance seeds). The validation
#      signature ([0]crclist/crcmatrix/crcstate/crcfinal plus seedcrc)
#      must be byte-identical across the oracle and both engines, with
#      no "- should be" mismatch lines; throughput is CoreMark's own
#      Iterations/Sec (wall clock via clock_gettime). Prints
#      H3-PASS/H3-FAIL per check, per-run numbers, medians + ranges,
#      and H3-RESULT: PASS iff every signature matches and the dbt
#      median iterations/sec exceeds the interp median; exit 0 on PASS.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
set -u
cd "$(dirname "$0")/../.." || exit 1

BUILD_IMG="debian:trixie-slim"
TEST_IMG="mips64rt-qemu:10.0.13"
BUILD_NAME="mips64rt-h3-build-$$"
TEST_NAME="mips64rt-h3-test-$$"
STAGE="$(mktemp -d /tmp/mips64rt-h3-XXXXXX)" || exit 1
ITER="${COREMARK_ITER:-400}"

cleanup() {
	docker rm -f "$BUILD_NAME" "$TEST_NAME" >/dev/null 2>&1 || true
	rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

echo "== make build (host translator) =="
make build || exit 1
test -x _build/mips64rt || { echo "H3-FAIL no _build/mips64rt"; exit 1; }
./_build/mips64rt --version 2>/dev/null || true

echo "== build container: static N64LE CoreMark guest =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$BUILD_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$PWD/tests/coremark:/s:ro" -v "$STAGE:/x" "$BUILD_IMG" sh -c '
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	gcc-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross file \
	>/dev/null 2>&1
mips64el-linux-gnuabi64-gcc --version | head -1
mips64el-linux-gnuabi64-gcc -O1 -static \
	-I/s -DTOTAL_DATA_SIZE=2000 -DPERFORMANCE_RUN=1 \
	-DFLAGS_STR="\"-O1 -static\"" \
	/s/core_main.c /s/core_list_join.c /s/core_matrix.c \
	/s/core_state.c /s/core_util.c /s/cvt.c /s/core_portme.c \
	-o /x/coremark-n64le -lm
file /x/coremark-n64le
'
rc=$?
if test $rc -ne 0; then
	echo "H3-FAIL build container exit $rc"
	exit 1
fi

echo "== test container: qemu golden vs 5x interp vs 5x dbt =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$TEST_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$STAGE:/x" -v "$PWD/_build:/b:ro" "$TEST_IMG" sh -c '
ITER="'"$ITER"'"
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "H3-PASS $1"; }
bad() { fail=$((fail + 1)); echo "H3-FAIL $1"; }
sig() {
	# Correctness signature: the iteration-deterministic CRC lines
	# only. The duration-dependent banners ("Correct operation
	# validated" vs "Must execute for at least 10 secs", and the
	# "Errors detected" the short-run path implies) cannot be
	# byte-compared between a ~1000 it/s oracle and 10-30 it/s
	# engines at a fixed ITER; they are a reporting convention, not
	# a correctness signal. Real CRC mismatches print "- should be"
	# lines and are caught by hardfail() below.
	grep -E "crclist|crcmatrix|crcstate|crcfinal|seedcrc" "$1" \
		| sed "s/^\\[0\\]/[N]/" > "$2" || true
}
hardfail() {
	# True failure lines: per-algorithm CRC mismatches and datatype
	# errors. The short-run banner is duration-dependent, not a
	# failure, and is excluded here.
	grep -E "should be|not an? .*datatype|Please modify the datatypes" "$1" || true
}
its() { grep "Iterations/Sec" "$1" | sed "s/.*: //"; }
echo "-- identities --"
/usr/bin/qemu-mips64el --version | head -1
/b/mips64rt --version
timeout --kill-after=30s 120s /usr/bin/qemu-mips64el \
	/x/coremark-n64le 0 0 0x66 "$ITER" > /x/golden.log 2>&1
qrc=$?
if test $qrc -ne 0; then bad "golden-rc=$qrc"; else ok "golden-rc=0"; fi
sig /x/golden.log /x/golden.sig
if grep -q "crclist" /x/golden.log && test -z "$(hardfail /x/golden.log)"; then
	ok "golden-crc-ok"
else
	bad "golden-crc-ok"
fi
: > /x/interp-its.txt
: > /x/dbt-its.txt
# Interleaved so a slow host-throttle drift cannot favour one engine.
for i in 1 2 3 4 5; do
	for eng in interp dbt; do
		L="/x/$eng-$i.log"
		timeout --kill-after=30s 150s /b/mips64rt "--$eng" \
			/x/coremark-n64le 0 0 0x66 "$ITER" > "$L" 2>&1
		erc=$?
		if test $erc -ne 0; then
			bad "$eng-run$i-rc=$erc"
			head -3 "$L" || true
			continue
		fi
		sig "$L" "$L.sig"
		if cmp -s /x/golden.sig "$L.sig"; then
			ok "$eng-run$i-sig-identical"
		else
			bad "$eng-run$i-sig-differs"
			diff /x/golden.sig "$L.sig" | head -6 || true
		fi
		if test -n "$(hardfail "$L")"; then
			bad "$eng-run$i-crc-mismatch"
			hardfail "$L" | head -4 || true
		else
			ok "$eng-run$i-no-crc-mismatch"
		fi
		v=$(its "$L")
		if test -n "$v"; then
			echo "$v" >> "/x/$eng-its.txt"
			ok "$eng-run$i-its=$v"
		else
			bad "$eng-run$i-no-its"
		fi
	done
done
med() { sort -n "$1" | sed -n "3p"; }
rng() { echo "$(sort -n "$1" | head -1)-$(sort -n "$1" | tail -1)"; }
IM=$(med /x/interp-its.txt)
DM=$(med /x/dbt-its.txt)
IR=$(rng /x/interp-its.txt)
DR=$(rng /x/dbt-its.txt)
echo "H3-NUMBERS interp median=$IM range=$IR"
echo "H3-NUMBERS dbt median=$DM range=$DR"
if test -n "$IM" && test -n "$DM" \
	&& awk "BEGIN{exit !(($DM) > ($IM))}"; then
	ok "dbt-median-gt-interp"
else
	bad "dbt-median-gt-interp"
fi
echo "H3-SUMMARY pass=$pass fail=$fail"
if test "$fail" -eq 0; then echo "H3-RESULT: PASS"; else echo "H3-RESULT: FAIL"; fi
exit "$fail"
'
rc=$?
docker ps --format "{{.Names}}" | grep -q "^${BUILD_NAME}$" && {
	echo "H3-FAIL container $BUILD_NAME still present"
	exit 1
}
docker ps --format "{{.Names}}" | grep -q "^${TEST_NAME}$" && {
	echo "H3-FAIL container $TEST_NAME still present"
	exit 1
}
if test $rc -ne 0; then
	echo "H3-RESULT: FAIL (container exit $rc)"
	exit 1
fi
echo "H3-RESULT: PASS"
exit 0
