#!/bin/sh
# tests/run_p5_busybox.sh — Phase 5 lane L5b acceptance: dynamic
# test_p5_dyn (N64/N32 x LE/BE) + target BusyBox, byte-identical vs the
# qemu-mips* oracle on both --interp and --dbt.
#
# What it does, end to end (all bounds wall-clocked, unique container
# names, cleanup trap + docker ps check like tests/run_p1_isa.sh):
#   1. make build on the host (nix aarch64-musl static-PIE translator).
#   2. Build container (debian:trixie-slim): install the Debian trixie
#      cross compilers (mips64el-linux-gnuabi64 for LE, N64+N32 via
#      -mabi=64/-mabi=n32; mips64-linux-gnuabi64 for BE) plus the N64
#      and N32 libc dev packages, stage per-variant sysroots at
#      /x/sysroot/<variant>/lib holding ld.so.1 + libc.so.6 +
#      libm.so.6 + libdl.so.2 (when present) + libgcc_s.so.1 (via
#      $CC -print-file-name), then build, with curated C11 flags
#      (-O1 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror):
#        /x/dyn/<variant>/p5-<variant>      (dynamic, -no-pie ET_EXEC,
#          --dynamic-linker=/x/sysroot/<variant>/lib/ld.so.1,
#          -rpath=/x/sysroot/<variant>/lib, -ldl)
#        /x/dyn/<variant>/p5_dynlib-<variant>.so  (-shared -fPIC)
#      -no-pie keeps the exe an ET_EXEC so the e_entry recorded in the
#      file is the absolute entry the kernel reports in AT_ENTRY.
#   3. Still in the build container: fetch the target BusyBox. trixie
#      dropped the mips64el binary port, so the static BusyBox comes
#      from bookworm (oldstable, still carries mips64el):
#        wget http://deb.debian.org/debian/dists/bookworm/main/\
#          binary-mips64el/Packages.gz
#        FN=$(zcat Packages.gz | grep -A25 "^Package: busybox-static$" \
#          | grep Filename | head -1 | cut -d" " -f2)
#        wget http://deb.debian.org/debian/$FN -O bb.deb   # e.g.
#          pool/main/b/busybox/busybox-static_1.35.0-4+deb12u1+b1_\
#          mips64el.deb (exact file resolved at runtime)
#        dpkg-deb -x bb.deb /x/bb   # -> /x/bb/bin/busybox, static N64LE
#   4. Test container (mips64rt-qemu:10.0.13, qemu-user 10.0.13, with
#      the stage at /x and the translator at /b): for each variant
#      run the qemu golden plus --interp plus --dbt with identical
#      argv (/x/dyn/<variant>/p5-<variant> p5arg1 p5arg2) and a clean
#      minimal env (env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt
#      P5_SENTINEL=dyn-env-ok; the loader scrubs LD_* and MIPS64RT_*
#      from the guest envp) and cmp golden vs both engines; one extra
#      translator-only run per engine with poison env
#      (LD_PRELOAD=/nope MIPS64RT_POISON=1) asserting env-scrub=1
#      (the qemu oracle passes env through, so scrub is asserted only
#      on the translator); then the BusyBox gate with identical argv
#      and env on all three engines:
#        /x/bb/bin/busybox sh -c 'ls / && echo ok | wc -c'
#      cmp golden vs both engines. Prints L5B-PASS/L5B-FAIL per check
#      and L5B-RESULT: PASS|FAIL; exit 0 iff every check passes.
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
BUILD_NAME="mips64rt-l5b-build-$$"
TEST_NAME="mips64rt-l5b-test-$$"
STAGE="$(mktemp -d /tmp/mips64rt-l5b-XXXXXX)" || exit 1

cleanup() {
	docker rm -f "$BUILD_NAME" "$TEST_NAME" >/dev/null 2>&1 || true
	rm -rf "$STAGE"
}
trap cleanup EXIT INT TERM

echo "== make build (host translator) =="
make build || exit 1
test -x _build/mips64rt || { echo "L5B-FAIL no _build/mips64rt"; exit 1; }
./_build/mips64rt --version 2>/dev/null || true

echo "== build container: guests + sysroots + busybox =="
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
	wget file >/dev/null 2>&1
echo "-- compiler identities --"
mips64el-linux-gnuabi64-gcc --version | head -1
mips64-linux-gnuabi64-gcc --version | head -1
C="-O1 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
mkvariant() {
	V="$1"; CC="$2"; ABI="$3"; TRIPLET="$4"
	LDORG="$5"
	mkdir -p "/x/sysroot/$V/lib" "/x/dyn/$V"
	cp -L "$LDORG/ld.so.1" "/x/sysroot/$V/lib/" 2>/dev/null || \
		cp "$LDORG/ld.so.1" "/x/sysroot/$V/lib/"
	for lib in libc.so.6 libm.so.6 libdl.so.2; do
		if test -f "$TRIPLET/$lib"; then
			cp -L "$TRIPLET/$lib" "/x/sysroot/$V/lib/" 2>/dev/null || \
				cp "$TRIPLET/$lib" "/x/sysroot/$V/lib/"
		fi
	done
	GCCLIB=$($CC $ABI -print-file-name=libgcc_s.so.1)
	if test -f "$GCCLIB"; then cp -L "$GCCLIB" "/x/sysroot/$V/lib/"; fi
	$CC $C $ABI -shared -fPIC -o "/x/dyn/$V/p5_dynlib-$V.so" /s/p5_dynlib.c
	$CC $C $ABI -no-pie -o "/x/dyn/$V/p5-$V" /s/test_p5_dyn.c \
		-Wl,--dynamic-linker,/x/sysroot/$V/lib/ld.so.1 \
		-Wl,-rpath,/x/sysroot/$V/lib -ldl
	echo "-- $V ELF identities --"
	file "/x/dyn/$V/p5-$V" "/x/dyn/$V/p5_dynlib-$V.so"
}
mkvariant n64le mips64el-linux-gnuabi64-gcc "-mabi=64" \
	/usr/mips64el-linux-gnuabi64/lib /usr/mips64el-linux-gnuabi64/lib64
mkvariant n32le mips64el-linux-gnuabi64-gcc "-mabi=n32" \
	/usr/mips64el-linux-gnuabi64/lib32 /usr/mips64el-linux-gnuabi64/lib32
mkvariant n64be mips64-linux-gnuabi64-gcc "-mabi=64" \
	/usr/mips64-linux-gnuabi64/lib /usr/mips64-linux-gnuabi64/lib64
mkvariant n32be mips64-linux-gnuabi64-gcc "-mabi=n32" \
	/usr/mips64-linux-gnuabi64/lib32 /usr/mips64-linux-gnuabi64/lib32
echo "-- fetch target busybox (bookworm mips64el binary port) --"
cd /tmp
wget -q http://deb.debian.org/debian/dists/bookworm/main/binary-mips64el/Packages.gz
FN=$(zcat Packages.gz | grep -A25 "^Package: busybox-static$" \
	| grep Filename | head -1 | cut -d" " -f2)
echo "busybox deb: $FN"
echo "$FN" > /x/bb-filename.txt
wget -q "http://deb.debian.org/debian/$FN" -O bb.deb
dpkg-deb -x bb.deb /x/bb
file /x/bb/bin/busybox
/x/bb/bin/busybox 2>&1 | head -1 || true
'
rc=$?
if test $rc -ne 0; then
	echo "L5B-FAIL build container exit $rc"
	exit 1
fi

echo "== test container: qemu goldens vs interp vs dbt =="
timeout --kill-after=30s 280s docker run --rm \
	--name "$TEST_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$STAGE:/x" -v "$PWD/_build:/b:ro" "$TEST_IMG" sh -c '
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "L5B-PASS $1"; }
bad() { fail=$((fail + 1)); echo "L5B-FAIL $1"; }
echo "-- qemu identities --"
/usr/bin/qemu-mips64el --version | head -1
echo "-- translator identity --"
/b/mips64rt --version
E="env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt P5_SENTINEL=dyn-env-ok"
for spec in "n64le:qemu-mips64el" "n32le:qemu-mipsn32el" \
		"n64be:qemu-mips64" "n32be:qemu-mipsn32"; do
	V="${spec%%:*}"
	Q="/usr/bin/${spec##*:}"
	timeout --kill-after=30s 90s $E "$Q" "/x/dyn/$V/p5-$V" \
		p5arg1 p5arg2 > "/x/$V-golden.txt" 2>&1
	qrc=$?
	if test $qrc -ne 0; then bad "$V-qemu-rc=$qrc"; continue; fi
	ok "$V-qemu-rc=0"
	for eng in interp dbt; do
		timeout --kill-after=30s 90s $E /b/mips64rt "--$eng" \
			"/x/dyn/$V/p5-$V" p5arg1 p5arg2 \
			> "/x/$V-$eng.txt" 2>&1
		erc=$?
		if test $erc -ne 0; then bad "$V-$eng-rc=$erc"; continue; fi
		if cmp -s "/x/$V-golden.txt" "/x/$V-$eng.txt"; then
			ok "$V-$eng-byte-identical"
		else
			bad "$V-$eng-differs"
			diff "/x/$V-golden.txt" "/x/$V-$eng.txt" | head -5 || true
		fi
	done
done
for eng in interp dbt; do
	timeout --kill-after=30s 90s env -i PATH=/usr/bin:/bin \
		HOSTNAME=mips64rt P5_SENTINEL=dyn-env-ok \
		LD_PRELOAD=/nope MIPS64RT_POISON=1 \
		/b/mips64rt "--$eng" /x/dyn/n64le/p5-n64le p5arg1 p5arg2 \
		> /x/scrub-$eng.txt 2>&1
	if grep -q "P5-PASS env-scrub" /x/scrub-$eng.txt && \
		grep -q "P5-RESULT: PASS" /x/scrub-$eng.txt; then
		ok "scrub-$eng-poison-env"
	else
		bad "scrub-$eng-poison-env"
		cat /x/scrub-$eng.txt | head -5 || true
	fi
done
echo "-- busybox identity --"
cat /x/bb-filename.txt
/x/bb/bin/busybox 2>&1 | head -1
B="env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt"
timeout --kill-after=30s 90s $B /usr/bin/qemu-mips64el \
	/x/bb/bin/busybox sh -c "ls / && echo ok | wc -c" \
	> /x/bb-golden.txt 2>&1
qrc=$?
if test $qrc -ne 0; then bad "busybox-qemu-rc=$qrc"; else ok "busybox-qemu-rc=0"; fi
for eng in interp dbt; do
	timeout --kill-after=30s 150s $B /b/mips64rt "--$eng" \
		/x/bb/bin/busybox sh -c "ls / && echo ok | wc -c" \
		> "/x/bb-$eng.txt" 2>&1
	erc=$?
	if test $erc -ne 0; then
		bad "busybox-$eng-rc=$erc"
		head -3 "/x/bb-$eng.txt" || true
		continue
	fi
	if cmp -s /x/bb-golden.txt "/x/bb-$eng.txt"; then
		ok "busybox-$eng-byte-identical"
	else
		bad "busybox-$eng-differs"
		diff /x/bb-golden.txt "/x/bb-$eng.txt" | head -8 || true
	fi
done
echo "L5B-SUMMARY pass=$pass fail=$fail"
if test "$fail" -eq 0; then echo "L5B-RESULT: PASS"; else echo "L5B-RESULT: FAIL"; fi
exit "$fail"
'
rc=$?
docker ps --format "{{.Names}}" | grep -q "^${BUILD_NAME}$" && {
	echo "L5B-FAIL container $BUILD_NAME still present"
	exit 1
}
docker ps --format "{{.Names}}" | grep -q "^${TEST_NAME}$" && {
	echo "L5B-FAIL container $TEST_NAME still present"
	exit 1
}
if test $rc -ne 0; then
	echo "L5B-RESULT: FAIL (container exit $rc)"
	exit 1
fi
echo "L5B-RESULT: PASS"
exit 0
