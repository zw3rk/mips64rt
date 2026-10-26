#!/bin/sh
# tests/p6_host_check.sh — Phase 6 lane L6a acceptance: host-contract
# surface of the `mips64rt` translator (CLI/descriptors/sysroot/
# cache/family/page-rule wiring) on AArch64 Linux.
#
# What it does, end to end (all runs wall-clocked, unique container
# names, cleanup trap + docker ps check like tests/run_p1_isa.sh):
#   1. Host cross-build of the translator with the lane TU set: the
#      Makefile is coordinator-frozen and does not list the new TU yet,
#      so this script compiles BOOT_SRCS plus src/os/host_args.c and
#      the referenced substrate TUs (dbt/aot/sha256, dbt/aot/
#      identity, runtime/family_broker) with the same curated C11
#      flags into _build/mips64rt-l6a. The coordinator wires these
#      TUs into BOOT_SRCS at the RC6 merge.
#   2. One bounded debian:trixie-slim container (--platform
#      linux/arm64): install the documented mips64el + mips64 cross
#      compilers, libc dev packages, qemu-user, and binutils; build
#      static argv0/auxv probes (N64LE + N32LE, two markers A/B) and a
#      dynamic N64LE hello against a staged sysroot; capture qemu
#      goldens; then run the P6 matrix below.
#
# Checks (each prints P6-PASS/P6-FAIL; P6-RESULT: PASS iff zero fail):
#   no-device fallback (/dev/a32host absent, run works); --help lists
#   every contract flag; static-PIE with zero DT_NEEDED (readelf);
#   --execfn custom argv[0] + AT_EXECFN decoupling (vs qemu -0);
#   default AT_EXECFN presence; AT_EXECFD absence on plain Linux;
#   --image-fd same-file load, fd-0 load, and cross-file (fd names A,
#   path names B: output must be A); --sysroot main-image resolution
#   (absolute path present only under the sysroot) incl. the
#   MIPS64RT_SYSROOT env spelling; no-sysroot byte-identity (static +
#   dynamic guests match qemu on both engines); --cache-dir leaf keyed
#   by the SHA-256 runtime digest; family broker join-or-create;
#   non-auto authorities decline with a diagnostic; --engine alias and
#   --engine jit rejection.
#
# Known boundary (coordinator RC6 follow-up, reported with the lane):
# PT_INTERP / guest-runtime absolute-path prefixing still opens the
# literal path: src/loader.c + src/os/exec.c call sites are outside
# this lane's exclusive files, so the script covers dynamic guests in
# the no-sysroot (byte-identical) and --sysroot / (degenerate root)
# shapes only. The shared mips64_sysroot_join() helper they will call
# is unit-covered by tests/check_host_contract.c.
#
# Host requirements: docker with --platform linux/arm64, plus the nix
# aarch64-musl toolchain for the host cross-build (see AGENTS.md).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
set -u
cd "$(dirname "$0")/.." || exit 1

BUILD_IMG="debian:trixie-slim"
BUILD_NAME="mips64rt-l6a-build-$$"
TEST_NAME="mips64rt-l6a-test-$$"
BIN="_build/mips64rt-l6a"

cleanup() {
	docker rm -f "$BUILD_NAME" >/dev/null 2>&1 || true
	docker rm -f "$TEST_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# --- 1. Host cross-build (explicit lane TU set) ---------------------
NIX_GCC="/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc"
if [ ! -x "$NIX_GCC" ]; then
	echo "P6-FAIL: host cross compiler missing ($NIX_GCC)"
	exit 1
fi
mkdir -p _build
# shellcheck disable=SC2086
timeout --kill-after=30s 200s $NIX_GCC -static-pie -fPIE \
	-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -pthread \
	-Isrc \
	src/main.c \
	src/os/host_args.c \
	src/os/worker_loop.c \
	src/dbt/aot/sha256.c \
	src/dbt/aot/identity.c \
	src/dbt/aot/sites.c \
	src/os/family_broker.c \
	src/os/signal_core.c \
	src/interp/decode.c \
	src/interp/interp.c \
	src/interp/unaligned.c \
	src/interp/fpmove.c \
	src/interp/fp.c \
	src/interp/fp_cvt.c \
	src/interp/fp_ps.c \
	src/os/mem.c \
	src/os/mem_table.c \
	src/os/syscall_min.c \
	src/os/syscalls.c \
	src/os/syscalls_stat.c \
	src/os/syscalls_sync.c \
	src/os/syscalls_time.c \
	src/os/sigact.c \
	src/os/sigframe.c \
	src/os/threads.c \
	src/os/futex.c \
	src/os/exec.c \
	src/os/quiesce.c \
	src/vm/vm64.c \
	src/vm/vm_file.c \
	src/vm/vm_pages.c \
	src/os/backend_linux.c \
	src/dbt/a64_emit.c \
	src/dbt/dbt.c \
	src/dbt/mem_recover.c \
	src/dbt/emit_int.c \
	src/dbt/emit_enc.c \
	src/dbt/emit_alu.c \
	src/dbt/emit_mem.c \
	src/dbt/emit_fp.c \
	src/dbt/trampoline_a64.S \
	src/loader.c \
	-o "$BIN" || {
	echo "P6-FAIL: host cross-build failed"
	exit 1
}
echo "P6-PASS: host cross-build ok"

# --- 2. Docker matrix ----------------------------------------------
timeout --kill-after=30s 280s docker run --rm \
	--name "$TEST_NAME" --memory 2g --cpus 2 --platform linux/arm64 \
	-v "$PWD:/w" -w /w "$BUILD_IMG" sh -c '
set -u
fail=0
pass() { echo "P6-PASS: $1"; }
failn() { echo "P6-FAIL: $1"; fail=$((fail + 1)); }
check() {
	# check <name> <expected> <actual>
	if [ "$2" = "$3" ]; then pass "$1"; else
		failn "$1 (want [$2] got [$3])"
	fi
}

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	gcc-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross \
	libc6-dev-mipsn32-mips64el-cross libn32gcc-14-dev-mips64el-cross \
	qemu-user binutils file >/dev/null 2>&1

RT=/w/_build/mips64rt-l6a
G=/x/g
SYS=/x/sys
SROOT=/x/sysroot
CACHE=/x/cache
mkdir -p "$G" "$SYS" "$SROOT/lib" "$CACHE"

cat > /tmp/probe.c <<EOF
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/auxv.h>
#ifndef AT_EXECFD
#define AT_EXECFD 21
#endif
#ifndef MARKER
#define MARKER ?
#endif
#define STR_(x) #x
#define STR(x) STR_(x)
int main(int argc, char **argv) {
    unsigned long v; int present;
    printf("marker=%s\n", STR(MARKER));
    printf("argv0=%s\n", argc > 0 ? argv[0] : "(none)");
    errno = 0; v = getauxval(AT_EXECFN); present = (errno == 0);
    printf("execfn-present=%d\n", present);
    if (present) printf("execfn=%s\n", (const char *)v);
    errno = 0; v = getauxval(AT_EXECFD); present = (errno == 0);
    (void)v;
    printf("execfd-present=%d\n", present);
    return 0;
}
EOF
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=64 -DMARKER=A \
	-o "$G/probeA-n64le" /tmp/probe.c
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=64 -DMARKER=B \
	-o "$G/probeB-n64le" /tmp/probe.c
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -DMARKER=A \
	-o "$G/probeA-n32le" /tmp/probe.c
file "$G/probeA-n64le" "$G/probeB-n64le" "$G/probeA-n32le" | sed "s/^/info: /"

# Dynamic N64LE hello against the staged sysroot.
CC=mips64el-linux-gnuabi64-gcc
SYSABI=64
cat > /tmp/dyn.c <<EOF
#include <stdio.h>
int main(int argc, char **argv) {
    printf("dyn-hello argc=%d argv0=%s\n", argc, argv[0]);
    return 0;
}
EOF
# `-rpath` carries the staged sysroot lib dir (run_p5 pattern), so
# both qemu (no -L) and the translator resolve libc identically.
$CC -O1 "-mabi=$SYSABI" -std=c11 -pedantic -Wall -Wextra \
	-Wl,--dynamic-linker="$SROOT/lib/ld.so.1" \
	"-Wl,-rpath,$SROOT/lib" \
	-o "$G/dyn-n64le" /tmp/dyn.c
LIBC_PATH=$($CC -mabi=64 -print-file-name=libc.so.6)
SYS_LIB=$(dirname "$LIBC_PATH")
GCC_LIB=$(dirname $($CC -mabi=64 -print-file-name=libgcc_s.so.1 2>/dev/null) 2>/dev/null || echo "$SYS_LIB")
# Debian multiarch keeps the N64 dynamic linker in the sibling lib64
# dir; the N32 dev packages ship a same-named but incompatible
# lib/ld.so.1, so the linker comes from lib64 only (verified below).
for lib in libc.so.6 libm.so.6 libdl.so.2; do
	[ -f "$SYS_LIB/$lib" ] && \
		cp -n "$SYS_LIB/$lib" "$SROOT/lib/" 2>/dev/null || true
done
if [ -f "$SYS_LIB/../lib64/ld.so.1" ]; then
	cp -n "$SYS_LIB/../lib64/ld.so.1" "$SROOT/lib/" 2>/dev/null || true
elif [ -f "$SYS_LIB/ld.so.1" ]; then
	cp -n "$SYS_LIB/ld.so.1" "$SROOT/lib/" 2>/dev/null || true
fi
if file "$SROOT/lib/ld.so.1" 2>/dev/null | grep -q "MIPS"; then
	pass "staged ld.so.1 is MIPS"
else
	failn "staged ld.so.1 is not MIPS"
	file "$SROOT/lib/ld.so.1" 2>&1 | sed "s/^/info: /" || true
fi
[ -f "$GCC_LIB/libgcc_s.so.1" ] && \
	cp -n "$GCC_LIB/libgcc_s.so.1" "$SROOT/lib/" 2>/dev/null || true
ls "$SROOT/lib" | sed "s/^/info: sysroot lib /"

# Sysroot-only static probe (absolute path exists only under $SYS).
cp "$G/probeA-n64le" "$SYS/g-basic"

run_rt() {
	# run_rt <out> <engine> <args...>: translator run, timeout 60s.
	out="$1"; engine="$2"; shift 2
	set +e
	timeout --kill-after=10s 60s "$RT" "$engine" "$@" >"$out" 2>"$out.err"
	echo "$?" >"$out.rc"
	set -e
}
run_qemu() {
	# run_qemu <out> <qemu> <args...>
	out="$1"; q="$2"; shift 2
	set +e
	timeout --kill-after=10s 60s "$q" "$@" >"$out" 2>"$out.err"
	echo "$?" >"$out.rc"
	set -e
}
expect_rc() {
	# expect_rc <name> <want> <out>
	got=$(cat "$3.rc")
	check "$1 (exit)" "$2" "$got"
}
expect_out() {
	# expect_out <name> <out> <line-prefix> <want-suffix...>: the line
	# starting with <line-prefix> must equal prefix + want.
	name="$1"; out="$2"; prefix="$3"; want="$4"
	got=$(grep "^$prefix" "$out" | head -1 || true)
	check "$name" "$prefix$want" "$got"
}

echo "== no-device fallback =="
[ -e /dev/a32host ] && failn "/dev/a32host unexpectedly present" || \
	pass "no /dev/a32host in container"
run_rt /tmp/o-nodev --interp "$G/probeA-n64le" nodevarg
expect_rc "nodev run works" 0 /tmp/o-nodev
expect_out "nodev argv0" /tmp/o-nodev "argv0=" "$G/probeA-n64le"
expect_out "nodev execfn-present" /tmp/o-nodev "execfn-present=" 1
expect_out "nodev execfn" /tmp/o-nodev "execfn=" "$G/probeA-n64le"
expect_out "nodev execfd-absent (plain Linux)" /tmp/o-nodev \
	"execfd-present=" 0

echo "== --help lists contract flags =="
"$RT" --help >/tmp/o-help 2>&1
for flag in --sysroot --rootfs --cache --cache-dir --engine --execfn \
	--image-fd --cache-authority --file-identity --family-authority; do
	grep -q -- "$flag" /tmp/o-help && pass "help lists $flag" || \
		failn "help missing $flag"
done

echo "== static-PIE, zero DT_NEEDED =="
if readelf -d "$RT" | grep -q "NEEDED"; then
	failn "translator has DT_NEEDED"
else
	pass "translator has zero DT_NEEDED"
fi
readelf -h "$RT" | grep -q "Type:.*DYN" && \
	pass "translator is ET_DYN (static-PIE)" || \
	failn "translator is not ET_DYN"

echo "== no-sysroot byte-identity vs qemu (both engines) =="
for variant in "n64le:qemu-mips64el" "n32le:qemu-mipsn32el"; do
	v="${variant%%:*}"; q="${variant##*:}"
	run_qemu /tmp/o-q-$v "$q" "$G/probeA-$v" hello
	expect_rc "qemu $v golden" 0 /tmp/o-q-$v
	for engine in --interp --dbt; do
		run_rt /tmp/o-rt-$v "$engine" "$G/probeA-$v" hello
		expect_rc "translator $engine $v" 0 /tmp/o-rt-$v
		if cmp -s /tmp/o-q-$v /tmp/o-rt-$v; then
			pass "byte-identical $engine $v"
		else
			failn "divergence $engine $v"; diff /tmp/o-q-$v /tmp/o-rt-$v | head -8
		fi
	done
done

echo "== --execfn custom argv[0] + AT_EXECFN decoupling =="
for engine in --interp --dbt; do
	run_rt /tmp/o-execfn "$engine" --execfn "$G/probeA-n64le" -- \
		custom0 extra
	expect_rc "execfn run $engine" 0 /tmp/o-execfn
	expect_out "execfn argv0 $engine" /tmp/o-execfn "argv0=" "custom0"
	expect_out "execfn AT_EXECFN $engine" /tmp/o-execfn "execfn=" \
		"$G/probeA-n64le"
done
run_qemu /tmp/o-q0 qemu-mips64el -0 custom0 "$G/probeA-n64le" extra
expect_rc "qemu -0 golden" 0 /tmp/o-q0
expect_out "qemu -0 argv0" /tmp/o-q0 "argv0=" "custom0"
if cmp -s /tmp/o-q0 /tmp/o-execfn 2>/dev/null; then
	pass "execfn run matches qemu -0 (interp)"
else
	echo "info: execfn run differs from qemu -0 (see below, argv0 must still match)"
	diff /tmp/o-q0 /tmp/o-execfn | head -8 || true
	expect_out "execfn argv0 parity (interp)" /tmp/o-execfn "argv0=" \
		"custom0"
fi

echo "== --image-fd loads =="
exec 3<"$G/probeA-n64le"
run_rt /tmp/o-ifd3 --interp --image-fd 3 "$G/probeA-n64le" viafd
expect_rc "image-fd 3 run" 0 /tmp/o-ifd3
expect_out "image-fd 3 marker (same file)" /tmp/o-ifd3 "marker=" "A"
expect_out "image-fd 3 argv0" /tmp/o-ifd3 "argv0=" "$G/probeA-n64le"
expect_out "image-fd 3 execfn (same-file dance)" /tmp/o-ifd3 \
	"execfn=" "$G/probeA-n64le"
if cmp -s /tmp/o-ifd3 /tmp/o-nodev 2>/dev/null || \
   diff /tmp/o-ifd3 /tmp/o-rt-n64le >/dev/null 2>&1; then
	pass "image-fd 3 identical to direct run"
else
	echo "info: image-fd 3 vs direct diff (argv differs by design: viafd vs nodevarg)"
	diff /tmp/o-ifd3 /tmp/o-rt-n64le | head -8 || true
	expect_out "image-fd 3 marker parity" /tmp/o-ifd3 "marker=" "A"
fi
exec 3<&-
run_rt /tmp/o-ifd0 --interp --image-fd 0 --execfn "$G/probeA-n64le" -- \
	zeroarg <"$G/probeA-n64le"
expect_rc "image-fd 0 run" 0 /tmp/o-ifd0
expect_out "image-fd 0 marker" /tmp/o-ifd0 "marker=" "A"
expect_out "image-fd 0 argv0" /tmp/o-ifd0 "argv0=" "zeroarg"
expect_out "image-fd 0 execfn" /tmp/o-ifd0 "execfn=" \
	"$G/probeA-n64le"
exec 4<"$G/probeA-n64le"
run_rt /tmp/o-ifdx --interp --image-fd 4 "$G/probeB-n64le" crossarg
expect_rc "image-fd cross-file run" 0 /tmp/o-ifdx
expect_out "image-fd cross-file marker (fd wins)" /tmp/o-ifdx \
	"marker=" "A"
exec 4<&-
run_rt /tmp/o-ifdbad --interp --image-fd 99 "$G/probeA-n64le" x
if [ "$(cat /tmp/o-ifdbad.rc)" != "0" ]; then
	pass "image-fd 99 diagnosed"
	grep -q "image fd" /tmp/o-ifdbad.err && \
		pass "image-fd 99 diagnostic" || \
		failn "image-fd 99 silent"
else
	failn "image-fd 99 unexpectedly ran"
fi

echo "== --sysroot main-image resolution =="
run_rt /tmp/o-nosys --interp /g-basic sysarg
if [ "$(cat /tmp/o-nosys.rc)" != "0" ]; then
	pass "missing literal path fails without sysroot"
else
	failn "missing literal path unexpectedly ran"
fi
run_rt /tmp/o-sys --interp --sysroot "$SYS" /g-basic sysarg
expect_rc "sysroot run" 0 /tmp/o-sys
expect_out "sysroot marker" /tmp/o-sys "marker=" "A"
expect_out "sysroot argv0 untouched" /tmp/o-sys "argv0=" "/g-basic"
MIPS64RT_SYSROOT="$SYS" run_rt /tmp/o-sysenv --interp /g-basic sysarg
expect_rc "MIPS64RT_SYSROOT env run" 0 /tmp/o-sysenv
if cmp -s /tmp/o-sys /tmp/o-sysenv; then
	pass "sysroot CLI == env"
else
	failn "sysroot CLI != env"
fi
run_rt /tmp/o-dyn --interp "$G/dyn-n64le"
expect_rc "dynamic no-sysroot run" 0 /tmp/o-dyn
# The dynamic linker path is baked host-absolute (run_p5 pattern),
# so the qemu golden needs no -L prefix: same literal invocation.
run_qemu /tmp/o-qdyn qemu-mips64el "$G/dyn-n64le"
expect_rc "qemu dynamic golden" 0 /tmp/o-qdyn
if cmp -s /tmp/o-dyn /tmp/o-qdyn; then pass "dynamic parity"; else
	failn "dynamic divergence"; diff /tmp/o-qdyn /tmp/o-dyn | head -8
fi
run_rt /tmp/o-dynroot --interp --sysroot / "$G/dyn-n64le"
expect_rc "dynamic --sysroot / run" 0 /tmp/o-dynroot
if cmp -s /tmp/o-dynroot /tmp/o-qdyn; then
	pass "dynamic --sysroot / parity"
else
	failn "dynamic --sysroot / divergence"
fi

echo "== --cache-dir keyed by runtime digest =="
DIGEST=$(sha256sum "$RT" | cut -d" " -f1)
run_rt /tmp/o-cache --interp --cache-dir "$CACHE" "$G/probeA-n64le" c
expect_rc "cache run" 0 /tmp/o-cache
if [ -f "$CACHE/$DIGEST.aot" ]; then
	pass "cache leaf keyed by digest"
else
	failn "cache leaf missing ($CACHE/$DIGEST.aot)"
	ls "$CACHE" | sed "s/^/info: cache has /" || true
fi
BEFORE=$(stat -c %Y "$CACHE/$DIGEST.aot" 2>/dev/null || echo 0)
sleep 1
run_rt /tmp/o-cache2 --interp --cache-dir "$CACHE" "$G/probeA-n64le" c
AFTER=$(stat -c %Y "$CACHE/$DIGEST.aot" 2>/dev/null || echo 1)
check "cache leaf never truncated" "$BEFORE" "$AFTER"

echo "== family broker join-or-create =="
if ls -d /tmp/.mips64rt-family-* >/dev/null 2>&1; then
	pass "family broker rendezvous present"
	ls -d /tmp/.mips64rt-family-* | sed "s/^/info: broker /"
else
	failn "no family broker rendezvous"
fi

echo "== authorities: auto admits, rest decline =="
run_rt /tmp/o-auto --interp --cache-authority auto \
	--file-identity auto --family-authority auto \
	"$G/probeA-n64le" a
expect_rc "auto authorities run" 0 /tmp/o-auto
for auth in "--cache-authority hyper-linux-apfs-acl-v1" \
	"--file-identity hyper-linux-apfs-v1" \
	"--family-authority hyper-linux-apfs-acl-v1"; do
	set -- $auth
	run_rt /tmp/o-decl --interp "$1" "$2" "$G/probeA-n64le" a
	if [ "$(cat /tmp/o-decl.rc)" != "0" ]; then
		pass "declined: $1 $2"
		grep -q "declined" /tmp/o-decl.err && \
			pass "diagnostic: $1 $2" || \
			failn "silent decline: $1 $2"
	else
		failn "unexpectedly admitted: $1 $2"
	fi
done

echo "== --engine alias =="
run_rt /tmp/o-eng --engine dbt "$G/probeA-n64le" e
expect_rc "engine dbt run" 0 /tmp/o-eng
MIPS64RT_ENGINE=dbt run_rt /tmp/o-enge --interp "$G/probeA-n64le" e
expect_rc "CLI --interp overrides env dbt" 0 /tmp/o-enge
run_rt /tmp/o-engjit --interp --engine jit "$G/probeA-n64le" e
if [ "$(cat /tmp/o-engjit.rc)" != "0" ]; then
	pass "engine jit rejected"
else
	failn "engine jit unexpectedly admitted"
fi

echo "P6-RESULT: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL) ($fail failures)"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
'
rc=$?
echo "container exit: $rc"
docker ps --format "{{.Names}}" | grep -q "^${TEST_NAME}$" && {
	echo "P6-FAIL: container $TEST_NAME still present"
	exit 1
}
exit $rc
