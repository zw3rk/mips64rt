#!/bin/sh
# tests/rc1_interp_check.sh — RC1 durable gate: rebuild the translator,
# rebuild all four P1 guests, run each under --interp, and compare
# against the committed qemu goldens.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Pass criteria (GOAL RC1: bit-for-bit oracle parity per variant):
#   BE (n64be, n32be): interp stdout is byte-identical to the golden
#     (minus its P1-EXIT trailer) and interp exits 0.
#   LE (n64le, n32le): interp stdout is byte-identical to the golden
#     (minus its P1-EXIT trailer) and interp exits with the golden's
#     P1-EXIT status (1: the oracle itself reports the 10
#     architecturally-unsatisfiable unaligned LE checks as P1-FAIL;
#     the LE canonical pair cannot compose a full word on real
#     hardware, so no engine passes those lines).
#
# Signal-delivery deferral (mips32rt RC1 precedent: its gate greps out
# beql-pageend, delayslot-sigpc, unaligned-child): two P1 tests need
# guest signal delivery (Phase 4, lane L4b), so their exact lines
# cannot match qemu at RC1 and are filtered from both sides before
# the byte comparison instead:
#   unaligned-lw-child-faults: qemu runs the guest SIGBUS handler
#     (child exits 139); the Phase-1 engine has no delivery, the
#     worker reports the fault, the child still exits 139.
#   pageend INFOs (no verdict attached): qemu delivers SIGSEGV to
#     the guest handler which prints the fault offset; the Phase-1
#     child dies by SIGSEGV with no offset line.
# The decisive annul proof (likely-annul-skips-protnone) needs no
# delivery and stays in the byte-parity set on all variants.
# Tripwire: each variant must show exactly 2 worker fault lines
# (one per deferred child); more means a new fault is hiding behind
# the filter.
#
# Post-RC4 update (Phase 5): signal delivery is live (pageend and the
# SIGBUS child now run their guest handlers), so the worker reports
# no faults and the tripwire below expects 0. The pageend-offset
# value itself stays engine-specific by test design (qemu records
# the translated delay-slot fetch at +4; a correct engine faults on
# the annulled fall-through at +8), so it remains filtered.
set -u
ROOT="$(cd "$(dirname "$0")/.." || exit 1; pwd)"
T="$ROOT/tests"
B="$ROOT/_build"
IMG="debian:stable-slim"
NAME="mips64rt-rc1-$$"

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== RC1 step 1: rebuild translator ==="
(cd "$ROOT" && PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH make build check-line-limits) || exit 1
file "$B/mips64rt" | grep -q "static-pie linked" || {
	echo "RC1-FAIL: _build/mips64rt is not static-pie"
	exit 1
}

echo "=== RC1 step 2: build guests + run interp in container ==="
timeout --kill-after=30s 280s docker run --rm \
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
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=64 -o _build/p1-n64le tests/test_p1_isa.c
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -o _build/p1-n32le tests/test_p1_isa.c
mips64-linux-gnuabi64-gcc $CFLAGS -mabi=64 -o _build/p1-n64be tests/test_p1_isa.c
mips64-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -o _build/p1-n32be tests/test_p1_isa.c
for v in n64le n32le n64be n32be; do
	set +e
	MIPS64RT_ENGINE=interp timeout --kill-after=30s 60s \
		/w/_build/mips64rt --interp /w/_build/p1-$v >_build/rc1-$v-interp.txt 2>&1
	echo "$?" >_build/rc1-$v-interp.exit
	set -e
	echo "interp-$v exit=$(cat _build/rc1-$v-interp.exit) pass=$(grep -c P1-PASS _build/rc1-$v-interp.txt || true) fail=$(grep -c P1-FAIL _build/rc1-$v-interp.txt || true)"
done
'
rc=$?
echo "container exit: $rc"
[ $rc -eq 0 ] || exit 1
if docker ps --format "{{.Names}}" | grep -q "^${NAME}$"; then
	echo "RC1-FAIL: container $NAME still present"
	exit 1
fi

echo "=== RC1 step 3: compare interp vs goldens ==="
fails=0
# Filter the signal-deferred lines (see header) from both sides.
filter_deferred() {
	grep -vE -e '^P1-(PASS|FAIL) unaligned-lw-child-faults$' \
		-e '^P1-INFO unaligned-lw status=' \
		-e '^P1-INFO pageend-offset=' \
		-e '^P1-INFO pageend-child status=' \
		-e '^mips64rt: guest fault at pc=' ${1:-/dev/stdin}
}
for v in n64be n32be; do
	golden="$T/p1_golden_$v.txt"
	interp="$B/rc1-$v-interp.txt"
	# Strip the P1-EXIT trailer the L1d runner appends to goldens.
	tmp_golden="$B/rc1-$v-golden.tmp"
	tmp_interp="$B/rc1-$v-interp.tmp"
	grep -v '^P1-EXIT: ' "$golden" | filter_deferred >"$tmp_golden"
	filter_deferred "$interp" >"$tmp_interp"
	faults=$(grep -c '^mips64rt: guest fault at pc=' "$interp" || true)
	if [ "$faults" != "0" ]; then
		echo "RC1 $v: want no worker faults post-RC4, saw $faults"
		fails=$((fails + 1))
	fi
	if cmp -s "$tmp_golden" "$tmp_interp"; then
		echo "RC1 $v: MATCH ($(wc -l <"$tmp_interp") parity lines)"
	else
		echo "RC1 $v: MISMATCH"
		diff "$tmp_golden" "$tmp_interp" | head -20
		fails=$((fails + 1))
	fi
	if [ "$(cat "$B/rc1-$v-interp.exit")" != "0" ]; then
		echo "RC1 $v: bad interp exit $(cat "$B/rc1-$v-interp.exit") (want 0)"
		fails=$((fails + 1))
	fi
done
for v in n64le n32le; do
	golden="$T/p1_golden_$v.txt"
	interp="$B/rc1-$v-interp.txt"
	# Strip the P1-EXIT trailer the L1d runner appends to goldens.
	tmp_golden="$B/rc1-$v-golden.tmp"
	tmp_interp="$B/rc1-$v-interp.tmp"
	grep -v '^P1-EXIT: ' "$golden" | filter_deferred >"$tmp_golden"
	filter_deferred "$interp" >"$tmp_interp"
	faults=$(grep -c '^mips64rt: guest fault at pc=' "$interp" || true)
	if [ "$faults" != "0" ]; then
		echo "RC1 $v: want no worker faults post-RC4, saw $faults"
		fails=$((fails + 1))
	fi
	if cmp -s "$tmp_golden" "$tmp_interp"; then
		echo "RC1 $v: MATCH ($(wc -l <"$tmp_interp") parity lines)"
	else
		echo "RC1 $v: MISMATCH"
		diff "$tmp_golden" "$tmp_interp" | head -20
		fails=$((fails + 1))
	fi
	# LE goldens record the oracle's own exit status (P1-EXIT: 1 with
	# 10 architecturally-unsatisfiable unaligned LE checks); the
	# translator must reproduce the oracle's exit code bit-for-bit
	# (GOAL RC1). P1-RESULT is FAIL on both sides by construction.
	want_exit=$(grep '^P1-EXIT: ' "$golden" | awk '{print $2}')
	if [ "$(cat "$B/rc1-$v-interp.exit")" != "$want_exit" ]; then
		echo "RC1 $v: bad interp exit $(cat "$B/rc1-$v-interp.exit") (want $want_exit)"
		fails=$((fails + 1))
	fi
	if ! grep -q 'P1-RESULT: FAIL' "$interp"; then
		echo "RC1 $v: missing P1-RESULT: FAIL (oracle parity)"
		fails=$((fails + 1))
	fi
done
if [ "$fails" != "0" ]; then
	echo "RC1-RESULT: FAIL ($fails violations)"
	exit 1
fi
echo "RC1-RESULT: PASS"
