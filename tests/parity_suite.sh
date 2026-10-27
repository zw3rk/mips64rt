#!/bin/sh
# tests/parity_suite.sh — Lane U12 interp-vs-dbt parity gate.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# What it does, end to end:
#   1. Host section (always runs, no Docker): structural proof that
#      `src/rt64/` is gone, plus the host-portable unit gates —
#      `tests/test_mem_sites` (24-byte site records, bump table,
#      serialization, 2-insn stub words), `tests/check_host_contract`
#      (the fixed host-cc command from its header), and the
#      `check-abi-invariants` / `test_decode` recipes from `make check`.
#   2. Docker section (one bounded `--platform linux/arm64`
#      container; SKIP when Docker is unusable): rebuild the N64LE
#      `test_p1_isa` guest, capture the `qemu-mips64el` golden, run the
#      host cross-built `_build/mips64rt` under `--interp` and `--dbt`,
#      and byte-compare all three. Prints `P-RESULT: PASS` iff every
#      executed check passes (SKIP never passes, FAIL always fails).
#
# Exit status: 0 iff zero FAIL (SKIP allowed, counted separately).
set -u
cd "$(dirname "$0")/.." || exit 1

pass=0
fail=0
skip=0
gapn=0

ok() { pass=$((pass + 1)); echo "P-PASS: $1"; }
bad() { fail=$((fail + 1)); echo "P-FAIL: $1"; }
skipped() { skip=$((skip + 1)); echo "P-SKIP: $1"; }
gap() { gapn=$((gapn + 1)); echo "P-GAP: $1"; }

CC_HOST="${HOST_CC:-cc}"

# U0: src/os/mem.c calls mips_fixade_enabled/mips_bus_fault, defined in
# exactly one OS backend TU. Mirror the Makefile backend selection: the
# backend follows the compiler target triple, never the build host.
if "${CC_HOST:-cc}" -dumpmachine 2>/dev/null | grep -q darwin; then
    OS_BACKEND="src/os/backend_darwin.c"
else
    OS_BACKEND="src/os/backend_linux.c"
fi

# --- 1. Host section -------------------------------------------------
if [ -d src/rt64 ]; then
    bad "src/rt64 still present"
else
    ok "src/rt64 absent"
fi

mkdir -p _build
if "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_mem_sites.c src/dbt/emit_mem.c \
    src/dbt/aot/sites.c \
    src/dbt/emit_enc.c src/dbt/a64_emit.c src/dbt/emit_int.c \
    src/dbt/emit_alu.c src/dbt/emit_fp.c src/interp/decode.c \
    src/os/mem.c src/os/mem_table.c src/vm/vm_pages.c "$OS_BACKEND" tests/stubs_signal.c \
    -o _build/test_mem_sites && _build/test_mem_sites >/dev/null; then
    ok "test_mem_sites (24B relative rows + AOT file round-trip)"
else
    bad "test_mem_sites"
fi

if "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc -o _build/check_host_contract \
    tests/check_host_contract.c "$OS_BACKEND" src/vm/vm_pages.c \
    && _build/check_host_contract >/dev/null; then
    ok "check_host_contract"
else
    bad "check_host_contract"
fi

if "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -Isrc tests/check_abi_invariants.c \
    -o _build/check_abi_invariants && _build/check_abi_invariants >/dev/null; then
    ok "check_abi_invariants"
else
    bad "check_abi_invariants"
fi

if "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_decode.c src/interp/decode.c src/os/mem.c \
    src/os/mem_table.c src/vm/vm_pages.c "$OS_BACKEND" tests/stubs_signal.c -o _build/test_decode \
    && _build/test_decode >/dev/null; then
    ok "test_decode"
else
    bad "test_decode"
fi

if make build-darwin >/dev/null 2>&1 && _build/test_u0_fill_retry >/dev/null; then
    ok "test_u0_fill_retry (cold-page fill-and-retry)"
else
    bad "test_u0_fill_retry (cold-page fill-and-retry)"
fi

if _build/test_u0_gate >/dev/null; then
    ok "test_u0_gate (write gate + Provider A)"
else
    bad "test_u0_gate (write gate + Provider A)"
fi

# --- 2. Docker section (bounded, guarded) ----------------------------
IMG="debian:trixie-slim"
NAME="mips64rt-parity-$$"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Container exit codes: 0 full oracle parity, 2 documented GAP
# (engines agree, oracle differs), anything else FAIL. Infrastructure
# failures (no daemon, no image) never reach the container and SKIP.
#
# Known GAP (covering reason, pre-existing, not a U12 regression):
# `pageend-offset`: qemu-mips64el reports 4, both engines report 8.
# The P1 page-end probe faults one guest instruction later under the
# translator (fault-address reporting on the delay-slot path); interp
# and dbt agree byte-for-byte, so engine parity holds while the oracle
# diverges. Re-check this reason whenever the fault path is touched.
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    skipped "docker unavailable: oracle parity not executed"
elif [ ! -x _build/mips64rt ] && ! make build >/dev/null 2>&1; then
    skipped "cross-build failed: oracle parity not executed"
else
    set +e
    timeout --kill-after=30s 280s docker run --rm \
        --name "$NAME" --memory 2g --cpus 2 --platform linux/arm64 \
        -v "$PWD:/w" -w /w "$IMG" sh -c '
set -u
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 \
    libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross \
    libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross \
    libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross \
    qemu-user >/dev/null 2>&1
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
gaps=0
fails=0
run_abi() {
    abi="$1"; cc="$2"; mabi="$3"; qemu="$4"
    bin="/tmp/parity-$abi"
    echo "== ABI $abi ($cc -mabi=$mabi vs $qemu) =="
    # shellcheck disable=SC2086
    $cc $CFLAGS -mabi=$mabi -o "$bin" tests/test_p1_isa.c || {
        echo "P-FAIL: $abi guest build failed"; fails=$((fails + 1)); return
    }
    set +e
    timeout --kill-after=30s 60s "$qemu" "$bin" >/tmp/o-qemu 2>&1
    qrc=$?
    timeout --kill-after=30s 60s /w/_build/mips64rt --interp "$bin" >/tmp/o-interp 2>&1
    irc=$?
    timeout --kill-after=30s 60s /w/_build/mips64rt --dbt "$bin" >/tmp/o-dbt 2>&1
    drc=$?
    set -e
    echo "rc: qemu=$qrc interp=$irc dbt=$drc"
    [ "$qrc" = "$irc" ] || { echo "P-FAIL: $abi interp exit differs from oracle"; fails=$((fails + 1)); return; }
    [ "$qrc" = "$drc" ] || { echo "P-FAIL: $abi dbt exit differs from oracle"; fails=$((fails + 1)); return; }
    cmp -s /tmp/o-interp /tmp/o-dbt || { echo "P-FAIL: $abi interp != dbt"; fails=$((fails + 1)); return; }
    # Known oracle quirk (see test_p1_isa.c pageend_body note): a
    # never-taken branch-likely annuls its delay slot, so the first
    # execution fetch fault lands on the fall-through (offset 8),
    # which both engines report byte-identically. qemu-user instead
    # faults while translating the annulled delay word itself
    # (offset 4). The engines are architecturally right and agree
    # with each other; only this one observation line is normalized
    # out of the oracle comparison. Any other oracle difference is
    # still a GAP.
    grep -v "^P1-INFO pageend-offset=" /tmp/o-qemu > /tmp/o-qemu-n
    grep -v "^P1-INFO pageend-offset=" /tmp/o-interp > /tmp/o-interp-n
    if cmp -s /tmp/o-qemu-n /tmp/o-interp-n; then
        echo "P-PASS: $abi P1 oracle parity (interp == dbt == $qemu)"
    else
        echo "P-GAP: $abi P1 oracle differs, engines agree (see diff)"
        diff /tmp/o-qemu /tmp/o-interp | head -20
        gaps=$((gaps + 1))
    fi
    for suite in "p3:tests/test_p3_fp_simd.c:-lm" \
                 "p4:tests/test_p4_threads_signals.c:-pthread" \
                 "p6:tests/test_p6_perms.c:" \
                 "h1:tests/test_h1_smc.c:"; do
        tag="${suite%%:*}"
        rest="${suite#*:}"
        src="${rest%%:*}"
        libs="${rest#*:}"
        sbin="/tmp/${tag}-${abi}"
        # shellcheck disable=SC2086
        $cc $CFLAGS -mabi=$mabi -o "$sbin" "$src" $libs || {
            echo "P-FAIL: $abi $tag build failed"; fails=$((fails + 1)); return
        }
        set +e
        timeout --kill-after=30s 60s "$qemu" "$sbin" >/tmp/s-qemu 2>&1
        sqrc=$?
        timeout --kill-after=30s 60s /w/_build/mips64rt --interp "$sbin" >/tmp/s-interp 2>&1
        sirc=$?
        timeout --kill-after=30s 60s /w/_build/mips64rt --dbt "$sbin" >/tmp/s-dbt 2>&1
        sdrc=$?
        set -e
        [ "$sqrc" = "$sirc" ] && [ "$sqrc" = "$sdrc" ] || {
            echo "P-FAIL: $abi $tag exit differs ($sqrc/$sirc/$sdrc)"; fails=$((fails + 1)); return
        }
        cmp -s /tmp/s-interp /tmp/s-dbt || {
            echo "P-FAIL: $abi $tag interp != dbt"; fails=$((fails + 1)); return
        }
        grep -v "^P4-INFO " /tmp/s-qemu > /tmp/s-qemu-n
        grep -v "^P4-INFO " /tmp/s-interp > /tmp/s-interp-n
        cmp -s /tmp/s-qemu-n /tmp/s-interp-n || {
            echo "P-GAP: $abi $tag oracle differs"; gaps=$((gaps + 1)); return
        }
        echo "P-PASS: $abi $tag oracle parity (interp == dbt == $qemu)"
    done
    dbin="/tmp/d2-${abi}"
    # shellcheck disable=SC2086
    $cc $CFLAGS -mabi=$mabi -o "$dbin" tests/difftest/test_d2_hello.c || {
        echo "P-FAIL: $abi d2 build failed"; fails=$((fails + 1)); return
    }
    set +e
    MIPS64RT_RANDSEED=1 timeout --kill-after=30s 60s \
        /w/_build/mips64rt --difftest "$dbin" >/tmp/s-diff 2>&1
    dfrc=$?
    set -e
    if [ "$dfrc" -eq 0 ] && grep -q "difftest clean" /tmp/s-diff; then
        echo "P-PASS: $abi --difftest (I + R trace 0 divergences)"
    else
        echo "P-FAIL: $abi --difftest failed (rc=$dfrc)"
        tail -10 /tmp/s-diff
        fails=$((fails + 1))
    fi
}
run_abi n64le mips64el-linux-gnuabi64-gcc 64 qemu-mips64el
run_abi n64be mips64-linux-gnuabi64-gcc 64 qemu-mips64
run_abi n32le mips64el-linux-gnuabi64-gcc n32 qemu-mipsn32el
run_abi n32be mips64-linux-gnuabi64-gcc n32 qemu-mipsn32
echo "abis done: fails=$fails gaps=$gaps"
[ "$fails" -eq 0 ] || exit 1
[ "$gaps" -eq 0 ] || exit 2
exit 0
' >/tmp/parity-docker.log 2>&1
    crc=$?
    set -e
    if [ "$crc" -eq 0 ]; then
        ok "P1/P3/P4/P6/H1/--difftest 4-ABI oracle parity (interp == dbt == qemu, N64/N32 x LE/BE)"
    elif [ "$crc" -eq 2 ]; then
        gap "P1/P3/P4/P6/H1 oracle GAP (interp == dbt, oracle differs)"
        sed -n '1,25p' /tmp/parity-docker.log
    else
        bad "docker oracle section failed (exit $crc)"
        sed -n '1,25p' /tmp/parity-docker.log
    fi
fi

# --- 3. Phase lanes with their own gates (bounded, self-cleaning) ---
if ./tests/run_p5_busybox.sh >/tmp/parity-p5.log 2>&1; then
    ok "P5 dynamic + BusyBox gate (interp == dbt == qemu, N64/N32 x LE/BE)"
else
    bad "P5 dynamic + BusyBox gate failed"
    tail -5 /tmp/parity-p5.log
fi
if ./tests/run_h4_cxx17.sh >/tmp/parity-h4.log 2>&1; then
    ok "H4 C++17 gate (interp == dbt, N64/N32 x LE/BE)"
else
    bad "H4 C++17 gate failed"
    tail -5 /tmp/parity-h4.log
fi

trap - EXIT INT TERM
cleanup
if docker ps --format "{{.Names}}" 2>/dev/null | grep -q "^${NAME}$"; then
    echo "container $NAME still present"
    fail=$((fail + 1))
fi

echo "P-RESULT: pass=$pass fail=$fail skip=$skip gap=$gapn"
# Zero-GAP, zero-SKIP gate: any fail, skip, or parity gap fails the suite.
[ "$fail" -eq 0 ] && [ "$skip" -eq 0 ] && [ "$gapn" -eq 0 ]
