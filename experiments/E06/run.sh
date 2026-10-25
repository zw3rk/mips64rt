#!/bin/sh
# E06 run script: cross-compile probe.c for MIPS64 N64+N32, LE+BE, run under qemu.
# Usage: ./run.sh [n64le|n32le|n64be|n32be|all]   (default: all)
set -eu
cd "$(dirname "$0")"

CFLAGS="-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"

one() {
	VARIANT="$1"; CC="$2"; ABI="$3"; QEMU="$4"
	BIN="probe_${VARIANT}"
	OBJ="/tmp/e06_probe_${VARIANT}.o"
	echo "== variant ${VARIANT}: CC='${CC} -mabi=${ABI}' QEMU=${QEMU}"
	${CC} -mabi="${ABI}" ${CFLAGS} -static -O2 -o "${BIN}" probe.c -pthread
	file "${BIN}"
	${CC} -mabi="${ABI}" ${CFLAGS} -O2 -c -o "${OBJ}" probe.c
	echo "== rdhwr/encodings disassembly (${VARIANT}):"
	"${CC%-gcc}-objdump" -d "${OBJ}" 2>/dev/null | grep -E 'rdhwr' | head -10 || true
	echo "== fixed-encoding word check (expect 7c03e83b):"
	"${CC%-gcc}-objdump" -d "${OBJ}" 2>/dev/null | grep -i '7c03e83b' | head -5 || true
	echo "== run under ${QEMU}:"
	if timeout --kill-after=30s 90s "${QEMU}" "./${BIN}"; then
		echo "E06-RESULT: PASS (${VARIANT})"
	else
		echo "E06-RESULT: FAIL (${VARIANT}) exit=$?"
		FAIL=1
	fi
}

FAIL=0
do_all() {
	one n64le mips64el-linux-gnuabi64-gcc 64 qemu-mips64el
	one n32le mips64el-linux-gnuabi64-gcc n32 qemu-mipsn32el
	one n64be mips64-linux-gnuabi64-gcc 64 qemu-mips64
	one n32be mips64-linux-gnuabi64-gcc n32 qemu-mipsn32
	echo "E06-RESULT: overall FAIL=${FAIL}"
	exit "$FAIL"
}

case "${1:-all}" in
n64le) one n64le mips64el-linux-gnuabi64-gcc 64 qemu-mips64el ;;
n32le) one n32le mips64el-linux-gnuabi64-gcc n32 qemu-mipsn32el ;;
n64be) one n64be mips64-linux-gnuabi64-gcc 64 qemu-mips64 ;;
n32be) one n32be mips64-linux-gnuabi64-gcc n32 qemu-mipsn32 ;;
all) do_all ;;
*) echo "unknown variant: $1" >&2; exit 2 ;;
esac
exit "$FAIL"
