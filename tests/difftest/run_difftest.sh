#!/bin/sh
# tests/difftest/run_difftest.sh — Phase 2 lane L2d difftest: run one
# guest under two engines with --trace plus MIPS64RT_DUMPSTATE=1 exit
# dumps (frozen mips_dump_regs), diff the "I <pc> <word>" streams and
# the "REGS ..." dumps, and print "DIFFTEST: 0 divergences" or the
# first divergence.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: run_difftest.sh GUEST [ENGINE_A [ENGINE_B]]
# (engines: interp|dbt; default interp interp for self-consistency;
# interp-vs-dbt goes live at the RC2 integration). On a Linux/aarch64
# host the translator runs directly; elsewhere it runs inside one
# bounded debian:stable-slim container per engine.
set -u
ROOT="$(cd "$(dirname "$0")/../.." || exit 1; pwd)"
RT="$ROOT/_build/mips64rt"
IMG="debian:stable-slim"
NAME="mips64rt-l2d-diff-$$"
TDIR="/tmp/d2t-$$"
: "${MIPS64RT_DUMPSTATE:=1}"
export MIPS64RT_DUMPSTATE

usage() {
	echo "Usage: $0 GUEST [ENGINE_A [ENGINE_B]] (engines: interp|dbt)" >&2
}
[ $# -ge 1 ] || { usage; exit 2; }
GUEST="$1"
ENGA="${2:-interp}"
ENGB="${3:-interp}"
case "$ENGA" in interp|dbt) ;; *) usage; exit 2 ;; esac
case "$ENGB" in interp|dbt) ;; *) usage; exit 2 ;; esac
[ -f "$GUEST" ] || {
	echo "run_difftest: guest '$GUEST' not found" >&2
	exit 2
}
[ -x "$RT" ] || {
	echo "run_difftest: translator '$RT' missing; run make build first" >&2
	exit 2
}

NATIVE=0
if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "aarch64" ]; then
	NATIVE=1
fi

cleanup() {
	rm -rf "$TDIR"
	docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
mkdir -p "$TDIR"

# run_engine SIDE ENG: run $GUEST, capture stdout/stderr/rc into
# $TDIR/$SIDE.{out,err,rc}. SIDE separates the two runs even when both
# engines are the same (interp-vs-interp self-consistency).
run_engine() {
	side="$1"
	eng="$2"
	out="$TDIR/$side.out"
	err="$TDIR/$side.err"
	rcfile="$TDIR/$side.rc"
	if [ "$NATIVE" = "1" ]; then
		set +e
		timeout --kill-after=30s 120s "$RT" --"$eng" --trace \
			"$GUEST" >"$out" 2>"$err"
		echo "$?" >"$rcfile"
		set -e
	else
		GDIR="$(cd "$(dirname "$GUEST")" && pwd)"
		set +e
		timeout --kill-after=30s 280s docker run --rm \
			--name "$NAME" --memory 2g --cpus 2 \
			--platform linux/arm64 \
			-e MIPS64RT_DUMPSTATE \
			-e DIFTEST_SIDE="$side" -e DIFTEST_ENG="$eng" \
			-e DIFTEST_GUEST="$(basename "$GUEST")" \
			-v "$ROOT:/w" -v "$GDIR:/g" -v "$TDIR:/t" -w /w "$IMG" \
			sh -c 'timeout --kill-after=30s 120s /w/_build/mips64rt \
				--"$DIFTEST_ENG" --trace "/g/$DIFTEST_GUEST" \
				>"/t/$DIFTEST_SIDE.out" 2>"/t/$DIFTEST_SIDE.err"'
		echo "$?" >"$rcfile"
		set -e
		if docker ps --format "{{.Names}}" | grep -q "^${NAME}$"; then
			echo "run_difftest: container $NAME still present" >&2
			exit 1
		fi
	fi
}

# compare_stream A B LABEL: count line pairs that differ; print the
# count on stdout line 1 followed by the first divergence detail.
compare_stream() {
	paste -d'|' "$1" "$2" | awk -F'|' '
		{ n++
		  if ($1 != $2) {
			c++
			if (c == 1) { ln = n; la = $1; lb = $2 }
		  } }
		END {
			print c + 0
			if (c > 0) {
				print ln
				print la
				print lb
			} }'
}

echo "== difftest $GUEST: $ENGA vs $ENGB =="
run_engine a "$ENGA"
run_engine b "$ENGB"
rca=$(cat "$TDIR/a.rc")
rcb=$(cat "$TDIR/b.rc")
echo "exits: $ENGA=$rca $ENGB=$rcb"
if [ "$rca" != "$rcb" ]; then
	echo "DIFFTEST: 1 divergences"
	echo "first divergence: exit $ENGA=$rca $ENGB=$rcb"
	echo "--- $ENGA stderr tail ---"
	tail -5 "$TDIR/a.err"
	echo "--- $ENGB stderr tail ---"
	tail -5 "$TDIR/b.err"
	exit 1
fi
grep '^I ' "$TDIR/a.err" >"$TDIR/a.trace" || true
grep '^I ' "$TDIR/b.err" >"$TDIR/b.trace" || true
grep '^REGS ' "$TDIR/a.err" >"$TDIR/a.regs" || true
grep '^REGS ' "$TDIR/b.err" >"$TDIR/b.regs" || true
echo "trace lines: $ENGA=$(wc -l <"$TDIR/a.trace") $ENGB=$(wc -l <"$TDIR/b.trace")"
echo "regs lines: $ENGA=$(wc -l <"$TDIR/a.regs") $ENGB=$(wc -l <"$TDIR/b.regs")"
t_res=$(compare_stream "$TDIR/a.trace" "$TDIR/b.trace")
g_res=$(compare_stream "$TDIR/a.regs" "$TDIR/b.regs")
t_cnt=$(echo "$t_res" | sed -n '1p')
g_cnt=$(echo "$g_res" | sed -n '1p')
total=$((t_cnt + g_cnt))
if [ "$total" = "0" ]; then
	echo "DIFFTEST: 0 divergences"
	exit 0
fi
echo "DIFFTEST: $total divergences"
if [ "$t_cnt" != "0" ]; then
	echo "first divergence (trace line $(echo "$t_res" | sed -n '2p')):"
	echo "  $ENGA: $(echo "$t_res" | sed -n '3p')"
	echo "  $ENGB: $(echo "$t_res" | sed -n '4p')"
else
	echo "first divergence (regs line $(echo "$g_res" | sed -n '2p')):"
	echo "  $ENGA: $(echo "$g_res" | sed -n '3p')"
	echo "  $ENGB: $(echo "$g_res" | sed -n '4p')"
fi
exit 1
