#!/bin/sh
# E01 build + run driver: MIPS64 N64 (base 5000) and N32 (base 6000),
# little- and big-endian where the toolchains exist.
# Runs where a MIPS64 cross toolchain and qemu-user exist
# (Debian container per lane instructions). Variants whose toolchain
# or oracle is absent are skipped gracefully as UNVERIFIED.
set -eu
cd "$(dirname "$0")"

LE_CC=${LE_CC:-mips64el-linux-gnuabi64-gcc}
BE_CC=${BE_CC:-mips64-linux-gnuabi64-gcc}

build_one() {
	# $1 = cc, $2 = abi flag, $3 = output
	"$1" -static "$2" -std=c11 -Werror=vla -pedantic -Wall -Wextra \
		-Werror -O1 -o "$3" probe.c
	ls -l "$3"
}

run_variant() {
	# $1 = label, $2 = cc, $3 = abi flag, $4 = binary, $5 = qemu
	if command -v "$2" >/dev/null 2>&1 && \
	   command -v "$5" >/dev/null 2>&1; then
		echo "== $1 build ($2 $3) =="
		build_one "$2" "$3" "$4"
		echo "== $1 versions =="
		"$2" -dumpversion
		"$5" --version | head -1
		echo "== $1 readelf =="
		"${2%-gcc}-readelf" -h "$4" | grep -E 'Class|Machine|Flags'
		echo "== $1 disasm: every 'syscall' site and its encoding =="
		"${2%-gcc}-objdump" -d "$4" | grep -B2 'syscall' | head -30
		echo "count of 0000000c words in disassembly:"
		"${2%-gcc}-objdump" -d "$4" | grep -c '0000000c'
		echo "== $1 run ($5 ./$4) =="
		if timeout --kill-after=30s 60s "$5" ./"$4"; then
			echo "E01-RESULT: PASS ($1)"
		else
			echo "E01-RESULT: FAIL ($1)"
			return 1
		fi
	else
		echo "$1 toolchain/oracle absent: $1 UNVERIFIED"
	fi
}

run_variant "N64LE" "$LE_CC" "-mabi=64" "probe-n64le" "qemu-mips64el"
run_variant "N32LE" "$LE_CC" "-mabi=n32" "probe-n32le" "qemu-mipsn32el"
run_variant "N64BE" "$BE_CC" "-mabi=64" "probe-n64be" "qemu-mips64"
run_variant "N32BE" "$BE_CC" "-mabi=n32" "probe-n32be" "qemu-mipsn32"
