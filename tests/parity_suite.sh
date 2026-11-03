#!/bin/sh
# tests/parity_suite.sh — mips64rt cross-engine parity gate.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Two tiers, one script (environment-selected):
#
#   smoke (default): `sh tests/parity_suite.sh`
#     Hermetic, <30s, no Docker, no network, no qemu. Runs on Darwin and
#     Linux with identical goldens:
#       T0 host unit checks: test_mem_sites, check_host_contract,
#          check_abi_invariants, test_decode, test_r3_defects,
#          test_u0_fill_retry, test_u0_gate.
#       T1 static guests: test_p1_isa and test_p3_fp_simd for all 4 ABI
#          variants (n64le, n64be, n32le, n32be) under --interp and --dbt,
#          compared byte-for-bit against tests/golden/ (guest argv[0] is
#          always absolute: the static glibc startup aborts on a relative
#          AT_EXECFN path); plus n64le-only p4_threads, h1_smc, h4_cxx,
#          p3_torture, and tcg_smoke under both engines.
#       T1d dynamic guests: p5_dyn (P5_SENTINEL=dyn-env-ok, argv
#          p5arg1 p5arg2) and h4_cxx-dyn under both engines with the
#          committed tests/sysroot/ (--sysroot, guest path absolute
#          under the sysroot), compared against tests/golden/.
#       T2 --difftest legs: hello, printf, qsort, and fileio fixtures
#          for all 4 ABI variants with MIPS64RT_RANDSEED=1 (fixed
#          AT_RANDOM so the two lockstep engines agree), compared
#          against tests/golden/.
#       T3 bench smoke: ../rt-series/_build/bench/bench-mips64el --smoke
#          under --interp and --dbt with us=/ops_sec= timings normalized.
#       T4 AOT round-trip: real guest ELF (tcg-n64le) cold-emit into a
#          fresh --cache dir then warm-reload in a fresh process; stdout
#          must be identical and match the tcg golden, with exactly one
#          <hex>.aot leaf left behind.
#     Guest legs run in parallel background jobs (at most MAXJOBS at a
#     time; rows are still emitted in fixed order from the parent, so
#     output is deterministic). Every row is PASS or the suite fails
#     closed (never SKIP, never GAP in smoke; a missing
#     translator/guest/golden is a GAP row and fails the gate via
#     parity_summary).
#
#   qualify: `PARITY_TIER=qualify sh tests/parity_suite.sh`
#     (alias PARITY_DOCKER=1). Runs the smoke tiers above, then one
#     bounded `--platform linux/arm64` container rebuilds every guest
#     from source, captures the live qemu-mips64el/qemu-mips64/
#     qemu-mipsn32el/qemu-mipsn32 oracles, and checks interp == dbt ==
#     oracle (plus --difftest, dynamic P5, and BusyBox). Inner exit 0 =
#     full oracle parity, 2 = documented oracle GAP (engines agree,
#     oracle differs), anything else = FAIL.
#
# Golden regeneration (review the diff before committing):
#   PARITY_UPDATE_GOLDEN=1 sh tests/parity_suite.sh
# regenerates tests/golden/ from the current engines.
#
# Coverage notes (grounded, not worked around):
#   P1 guest self-verdict is FAIL (11 unaligned LWL/LWR/SWL/SWR/LDL/SDL
#   canonical-pair checks; exit 1): both engines agree byte-for-bit, so
#   the rows pin engine parity, not oracle truth. Oracle truth is the
#   qualify tier's job.
#   P6 and BusyBox have no committed Darwin-runnable guests and are
#   qualify-tier-only. P4 (threads/signals), H1, H4 (static and
#   dynamic), dynamic P5, p3_torture, and tcg_smoke run in smoke on
#   n64le via committed tests/guests/ + tests/sysroot/ guests.
#   d2-malloc is qualify-tier-only: each --difftest leg takes 20-30s
#   (brk-heavy soak under lockstep), which alone exceeds the smoke
#   budget; the qualify container runs it under --difftest on all 4
#   ABIs.
#
# Environment:
#   TRANSLATOR  translator binary (default _build/mips64rt-darwin on
#               Darwin, _build/mips64rt elsewhere).
#   BENCH_BIN   bench guest (default
#               ../rt-series/_build/bench/bench-mips64el).
#   PARITY_TIER smoke|qualify (default smoke; contract default).
#   PARITY_DOCKER=1  alias for the qualify Docker leg.
#   PARITY_UPDATE_GOLDEN=1  refresh tests/golden/ from current engines.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="$ROOT/../rt-series/tools/parity_contract.sh"
if [ ! -f "$CONTRACT" ]; then
    echo "parity_suite: missing frozen contract $CONTRACT" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$CONTRACT"
parity_init "mips64rt"

HOST_OS="$(uname -s | tr 'A-Z' 'a-z')"
HOST_M="$(uname -m)"
HOST_TAG="${HOST_OS}-${HOST_M}"
GOLDEN_DIR="$ROOT/tests/golden"
GUEST_DIR="$ROOT/tests/guests"
SYSROOT_DIR="$ROOT/tests/sysroot"
OUT_DIR="${OUTDIR:-/tmp/mips64rt-parity}"
mkdir -p "$OUT_DIR"
CC_HOST="${HOST_CC:-cc}"

if [ -n "${TRANSLATOR:-}" ]; then
    RT="$TRANSLATOR"
elif [ "$HOST_OS" = "darwin" ]; then
    RT="$ROOT/_build/mips64rt-darwin"
else
    RT="$ROOT/_build/mips64rt"
fi
BENCH_BIN="${BENCH_BIN:-$ROOT/../rt-series/_build/bench/bench-mips64el}"

if [ ! -x "$RT" ]; then
    parity_row "host" "$HOST_TAG" "translator-present" "host" "GAP" 0 "no executable $RT (run make build / build-darwin)"
    parity_summary
    exit $?
fi

# --- T0: host unit checks (always run, no Docker) --------------------
case "$HOST_OS" in
    darwin) OS_BACKEND="src/os/backend_darwin.c" ;;
    *) OS_BACKEND="src/os/backend_linux.c" ;;
esac
cd "$ROOT" || exit 1

run_unit() {
    # run_unit <case> <cmd...>
    _ru_case="$1"; shift
    _t0=$(parity_now_ms)
    if "$@" >"$OUT_DIR/u-$_ru_case.log" 2>&1; then
        _st="PASS"; _det="exit 0"
    else
        _st="FAIL"; _det="exit $?"
    fi
    parity_row "host" "$HOST_TAG" "$_ru_case" "host" "$_st" "$(( $(parity_now_ms) - _t0 ))" "$_det"
}

if [ -x _build/test_mem_sites ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_mem_sites.c src/dbt/emit_mem.c src/dbt/emit_fpmem.c src/dbt/aot/sites.c \
    src/dbt/emit_enc.c src/dbt/a64_emit.c src/dbt/emit_int.c src/dbt/emit_alu.c \
    src/dbt/emit_fp.c src/interp/decode.c src/os/mem.c src/os/mem_table.c \
    src/os/backend_state.c src/vm/vm_pages.c "$OS_BACKEND" tests/stubs_signal.c \
    -o _build/test_mem_sites >/dev/null 2>&1; then
    run_unit "test_mem_sites" ./_build/test_mem_sites
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_mem_sites" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/check_host_contract ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc -o _build/check_host_contract \
    tests/check_host_contract.c src/os/host_args.c src/os/mem.c \
    src/os/mem_table.c src/os/backend_state.c src/dbt/aot/sha256.c \
    src/dbt/aot/identity.c src/os/family_broker.c src/os/page_rules.c \
    "$OS_BACKEND" src/vm/vm_pages.c >/dev/null 2>&1; then
    run_unit "check_host_contract" ./_build/check_host_contract
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "check_host_contract" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/check_abi_invariants ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -Isrc tests/check_abi_invariants.c \
    -o _build/check_abi_invariants >/dev/null 2>&1; then
    run_unit "check_abi_invariants" ./_build/check_abi_invariants
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "check_abi_invariants" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/test_decode ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_decode.c src/interp/decode.c src/os/mem.c \
    src/os/mem_table.c src/os/backend_state.c src/vm/vm_pages.c \
    "$OS_BACKEND" tests/stubs_signal.c \
    -o _build/test_decode >/dev/null 2>&1; then
    run_unit "test_decode" ./_build/test_decode
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_decode" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/test_r3_defects ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_r3_defects.c src/interp/decode.c src/interp/interp.c \
    src/interp/unaligned.c src/interp/fpmove.c src/interp/fp.c src/interp/fp_cvt.c \
    src/interp/fp_ps.c src/interp/fp_round.c src/os/mem.c src/os/mem_table.c \
    src/os/backend_state.c \
    src/os/proc.c src/os/syscalls.c src/os/syscalls_extra.c src/os/syscalls_sync.c \
    src/os/syscalls_time.c src/os/syscalls_stat.c src/os/host_args.c src/os/quiesce.c \
    src/os/signal_core.c src/vm/vm64.c src/vm/vm_file.c src/vm/vm_file_sync.c src/vm/vm_pages.c \
    src/dbt/aot/sites.c src/dbt/a64_emit.c src/dbt/emit_enc.c src/dbt/emit_alu.c \
    src/dbt/emit_mem.c src/dbt/emit_fpmem.c src/dbt/emit_int.c src/dbt/emit_fp.c \
    src/dbt/arena.c src/dbt/dbt.c src/dbt/mem_recover.c src/dbt/trampoline_a64.S \
    "$OS_BACKEND" tests/stubs_signal.c \
    -o _build/test_r3_defects >/dev/null 2>&1; then
    run_unit "test_r3_defects" ./_build/test_r3_defects
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_r3_defects" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/test_r7_defects ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_r7_defects.c src/loader.c src/interp/decode.c \
    src/interp/interp.c src/interp/unaligned.c src/interp/fpmove.c src/interp/fp.c \
    src/interp/fp_cvt.c src/interp/fp_ps.c src/interp/fp_round.c src/os/mem.c \
    src/os/mem_table.c src/os/backend_state.c \
    src/os/proc.c src/os/syscalls.c src/os/syscalls_extra.c src/os/syscalls_sync.c \
    src/os/syscalls_time.c src/os/syscalls_stat.c src/os/host_args.c src/os/quiesce.c \
    src/os/signal_core.c src/vm/vm64.c src/vm/vm_file.c src/vm/vm_file_sync.c src/vm/vm_pages.c \
    src/dbt/aot/sites.c src/dbt/a64_emit.c src/dbt/emit_enc.c src/dbt/emit_alu.c \
    src/dbt/emit_mem.c src/dbt/emit_fpmem.c src/dbt/emit_int.c src/dbt/emit_fp.c \
    src/dbt/arena.c src/dbt/dbt.c src/dbt/mem_recover.c src/dbt/trampoline_a64.S \
    "$OS_BACKEND" \
    -o _build/test_r7_defects >/dev/null 2>&1; then
    run_unit "test_r7_defects" ./_build/test_r7_defects
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_r7_defects" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/test_r7_fp ] || "$CC_HOST" -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
    -pthread -Isrc tests/test_r7_fp.c src/interp/decode.c \
    src/interp/interp.c src/interp/unaligned.c src/interp/fpmove.c src/interp/fp.c \
    src/interp/fp_cvt.c src/interp/fp_ps.c src/interp/fp_round.c src/os/mem.c \
    src/os/mem_table.c src/os/backend_state.c \
    src/os/proc.c src/os/syscalls.c src/os/syscalls_extra.c src/os/syscalls_sync.c \
    src/os/syscalls_time.c src/os/syscalls_stat.c src/os/host_args.c src/os/quiesce.c \
    src/os/signal_core.c src/vm/vm64.c src/vm/vm_file.c src/vm/vm_file_sync.c src/vm/vm_pages.c \
    src/dbt/aot/sites.c src/dbt/a64_emit.c src/dbt/emit_enc.c src/dbt/emit_alu.c \
    src/dbt/emit_mem.c src/dbt/emit_fpmem.c src/dbt/emit_int.c src/dbt/emit_fp.c \
    src/dbt/arena.c src/dbt/dbt.c src/dbt/mem_recover.c src/dbt/trampoline_a64.S \
    "$OS_BACKEND" \
    -o _build/test_r7_fp >/dev/null 2>&1; then
    run_unit "test_r7_fp" ./_build/test_r7_fp
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_r7_fp" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "build failed"
fi

if [ -x _build/test_u0_fill_retry ] && [ -x _build/test_u0_gate ]; then
    run_unit "test_u0_fill_retry" ./_build/test_u0_fill_retry
    run_unit "test_u0_gate" ./_build/test_u0_gate
elif [ "$HOST_OS" = "darwin" ] && make build-darwin >/dev/null 2>&1 \
    && [ -x _build/test_u0_fill_retry ] && [ -x _build/test_u0_gate ]; then
    run_unit "test_u0_fill_retry" ./_build/test_u0_fill_retry
    run_unit "test_u0_gate" ./_build/test_u0_gate
else
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_u0_fill_retry" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "binary missing and build-darwin failed"
    _t0=$(parity_now_ms)
    parity_row "host" "$HOST_TAG" "test_u0_gate" "host" "FAIL" "$(( $(parity_now_ms) - _t0 ))" "binary missing and build-darwin failed"
fi

# --- parallel smoke lanes (one background job per ABI) ---------------
# do_stdout/do_difftest execute the engine and record raw output, exit
# code, and timing into $OUT_DIR/job-<tag>.*; emit_* runs in the parent
# afterwards and turns those records into contract rows in fixed order.
do_stdout() {
    # do_stdout <tag> <guest> <engine>
    _d_tag="$1"; _d_guest="$2"; _d_eng="$3"
    _t0=$(parity_now_ms)
    "$RT" "--$_d_eng" "$_d_guest" >"$OUT_DIR/job-$_d_tag.raw" 2>&1
    printf '%s\n' "$?" >"$OUT_DIR/job-$_d_tag.rc"
    printf '%s %s\n' "$_t0" "$(parity_now_ms)" >"$OUT_DIR/job-$_d_tag.ms"
}

do_difftest() {
    # do_difftest <tag> <guest> [stdin-file]
    _d_tag="$1"; _d_guest="$2"
    _t0=$(parity_now_ms)
    if [ $# -ge 3 ]; then
        MIPS64RT_RANDSEED=1 "$RT" --difftest "$_d_guest" <"$3" >"$OUT_DIR/job-$_d_tag.raw" 2>&1
    else
        MIPS64RT_RANDSEED=1 "$RT" --difftest "$_d_guest" >"$OUT_DIR/job-$_d_tag.raw" 2>&1
    fi
    printf '%s\n' "$?" >"$OUT_DIR/job-$_d_tag.rc"
    printf '%s %s\n' "$_t0" "$(parity_now_ms)" >"$OUT_DIR/job-$_d_tag.ms"
}

do_dyn() {
    # do_dyn <tag> <engine> <sysroot-guest-path> <sentinel|-> [guest args...]
    # Dynamic leg: minimal scrubbed env, committed tests/sysroot, guest
    # path absolute under the sysroot (argv[0] dir locates bundled .so).
    _d_tag="$1"; _d_eng="$2"; _d_guest="$3"; _d_sentinel="$4"; shift 4
    _t0=$(parity_now_ms)
    if [ "$_d_sentinel" = "-" ]; then
        env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt \
            "$RT" "--$_d_eng" --sysroot "$SYSROOT_DIR" "$_d_guest" "$@" \
            >"$OUT_DIR/job-$_d_tag.raw" 2>&1
    else
        # shellcheck disable=SC2086
        env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt $_d_sentinel \
            "$RT" "--$_d_eng" --sysroot "$SYSROOT_DIR" "$_d_guest" "$@" \
            >"$OUT_DIR/job-$_d_tag.raw" 2>&1
    fi
    printf '%s\n' "$?" >"$OUT_DIR/job-$_d_tag.rc"
    printf '%s %s\n' "$_t0" "$(parity_now_ms)" >"$OUT_DIR/job-$_d_tag.ms"
}

job_ms() {
    # job_ms <tag>: elapsed ms recorded by the background job.
    if [ -f "$OUT_DIR/job-$1.ms" ]; then
        # shellcheck disable=SC2086
        set -- $(cat "$OUT_DIR/job-$1.ms")
        echo "$(($2 - $1))"
    else
        echo "0"
    fi
}

job_rc() {
    if [ -f "$OUT_DIR/job-$1.rc" ]; then
        cat "$OUT_DIR/job-$1.rc"
    else
        echo "127"
    fi
}

# emit_stdout <abi> <case> <engine> <norm:0|1> [guest-override]
emit_stdout() {
    _abi="$1"; _case="$2"; _eng="$3"; _norm="$4"
    _tag="$_case-$_eng"
    if [ -n "${5:-}" ]; then
        _guest="$5"
    elif [ "$_case" = "bench-smoke" ]; then
        _guest="$BENCH_BIN"
    else
        _guest="$GUEST_DIR/$_case"
    fi
    if [ ! -f "$_guest" ] && [ ! -x "$_guest" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "GAP" 0 "missing guest $_guest"
        return
    fi
    if [ ! -f "$OUT_DIR/job-$_tag.raw" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "FAIL" 0 "background job produced no output"
        return
    fi
    if [ "$_norm" = "1" ]; then
        sed -E 's/(us|ops_sec)=[0-9]+/\1=N/g; s/[0-9][0-9]* I-lines/N I-lines/' \
            "$OUT_DIR/job-$_tag.raw" >"$OUT_DIR/$_tag.out"
    else
        cp "$OUT_DIR/job-$_tag.raw" "$OUT_DIR/$_tag.out"
    fi
    _rc=$(job_rc "$_tag")
    _ms=$(job_ms "$_tag")
    if [ "$PARITY_UPDATE_GOLDEN" = "1" ]; then
        mkdir -p "$GOLDEN_DIR"
        cp "$OUT_DIR/$_tag.out" "$GOLDEN_DIR/$_case.out"
        printf '%s\n' "$_rc" >"$GOLDEN_DIR/$_case.exit"
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "PASS" "$_ms" "exit $_rc, golden recorded"
        return
    fi
    if [ ! -f "$GOLDEN_DIR/$_case.out" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "GAP" "$_ms" "missing golden tests/golden/$_case.out"
        return
    fi
    if [ -f "$GOLDEN_DIR/$_case.exit" ]; then
        _exprc="$(cat "$GOLDEN_DIR/$_case.exit")"
    else
        _exprc="$_rc"
    fi
    if [ "$_rc" != "$_exprc" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "FAIL" "$_ms" "exit $_rc, golden wants $_exprc"
    elif parity_check_golden "$GOLDEN_DIR/$_case.out" "$OUT_DIR/$_tag.out"; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "PASS" "$_ms" "exit $_rc, matches golden"
    else
        parity_row "$_abi" "$HOST_TAG" "$_tag" "$_eng" "FAIL" "$_ms" "exit $_rc, output differs from golden"
    fi
}

# emit_difftest <abi> <case>
emit_difftest() {
    _abi="$1"; _case="$2"
    _tag="$_case-difftest"
    if [ ! -f "$GUEST_DIR/$D2_SUB/$_case" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "GAP" 0 "missing guest $GUEST_DIR/$D2_SUB/$_case"
        return
    fi
    if [ ! -f "$OUT_DIR/job-$_tag.raw" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "FAIL" 0 "background job produced no output"
        return
    fi
    sed -E 's/[0-9][0-9]* I-lines/N I-lines/' \
        "$OUT_DIR/job-$_tag.raw" >"$OUT_DIR/$_tag.out"
    _rc=$(job_rc "$_tag")
    _ms=$(job_ms "$_tag")
    if [ "$PARITY_UPDATE_GOLDEN" = "1" ]; then
        mkdir -p "$GOLDEN_DIR"
        cp "$OUT_DIR/$_tag.out" "$GOLDEN_DIR/$_tag.out"
        printf '%s\n' "$_rc" >"$GOLDEN_DIR/$_tag.exit"
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "PASS" "$_ms" "exit $_rc, golden recorded"
        return
    fi
    if [ ! -f "$GOLDEN_DIR/$_tag.out" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "GAP" "$_ms" "missing golden tests/golden/$_tag.out"
        return
    fi
    if [ -f "$GOLDEN_DIR/$_tag.exit" ]; then
        _exprc="$(cat "$GOLDEN_DIR/$_tag.exit")"
    else
        _exprc="$_rc"
    fi
    if [ "$_rc" != "$_exprc" ]; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, golden wants $_exprc"
    elif ! grep -q "difftest clean" "$OUT_DIR/$_tag.out"; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, no 'difftest clean' marker"
    elif parity_check_golden "$GOLDEN_DIR/$_tag.out" "$OUT_DIR/$_tag.out"; then
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "PASS" "$_ms" "exit $_rc, 0 divergences, matches golden"
    else
        parity_row "$_abi" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, output differs from golden"
    fi
}

D2_SUB="d2"
printf 'D2-FILEIO alpha\nD2-FILEIO beta\nD2-FILEIO gamma\n' >"$OUT_DIR/d2seed.txt"

# Launch one background job per (abi, leg); at most MAXJOBS concurrent.
# Rows are emitted afterwards in fixed order, so output is deterministic
# regardless of completion order.
MAXJOBS=8
_njobs=0
launch() {
    "$@" &
    _njobs=$((_njobs + 1))
    if [ "$_njobs" -ge "$MAXJOBS" ]; then
        wait
        _njobs=0
    fi
}

for _abi in n64le n64be n32le n32be; do
    for _t in p1 p3; do
        launch do_stdout "$_t-$_abi-interp" "$GUEST_DIR/$_t-$_abi" "interp"
        launch do_stdout "$_t-$_abi-dbt" "$GUEST_DIR/$_t-$_abi" "dbt"
    done
    for _fix in hello printf qsort fileio; do
        if [ "$_fix" = "fileio" ]; then
            launch do_difftest "d2-$_abi-$_fix-difftest" "$GUEST_DIR/$D2_SUB/d2-$_abi-$_fix" "$OUT_DIR/d2seed.txt"
        else
            launch do_difftest "d2-$_abi-$_fix-difftest" "$GUEST_DIR/$D2_SUB/d2-$_abi-$_fix"
        fi
    done
done
launch do_stdout "bench-smoke-interp" "$BENCH_BIN" "interp"
launch do_stdout "bench-smoke-dbt" "$BENCH_BIN" "dbt"
for _t in p4 h1 h4 p3torture tcg; do
    launch do_stdout "$_t-n64le-interp" "$GUEST_DIR/$_t-n64le" "interp"
    launch do_stdout "$_t-n64le-dbt" "$GUEST_DIR/$_t-n64le" "dbt"
done
launch do_dyn "p5-dyn-n64le-interp" "interp" "/p5-n64le" "P5_SENTINEL=dyn-env-ok" "p5arg1" "p5arg2"
launch do_dyn "p5-dyn-n64le-dbt" "dbt" "/p5-n64le" "P5_SENTINEL=dyn-env-ok" "p5arg1" "p5arg2"
launch do_dyn "h4-dyn-n64le-interp" "interp" "/h4-dyn-n64le" "-"
launch do_dyn "h4-dyn-n64le-dbt" "dbt" "/h4-dyn-n64le" "-"
wait

# --- emit rows in fixed order -----------------------------------------
for _abi in n64le n64be n32le n32be; do
    for _t in p1 p3; do
        emit_stdout "$_abi" "$_t-$_abi" "interp" 0
        emit_stdout "$_abi" "$_t-$_abi" "dbt" 0
    done
done
for _abi in n64le n64be n32le n32be; do
    for _fix in hello printf qsort fileio; do
        emit_difftest "$_abi" "d2-$_abi-$_fix"
    done
done
emit_stdout "n64le" "bench-smoke" "interp" 1
emit_stdout "n64le" "bench-smoke" "dbt" 1
for _t in p4 h1 h4 p3torture tcg; do
    emit_stdout "n64le" "$_t-n64le" "interp" 0
    emit_stdout "n64le" "$_t-n64le" "dbt" 0
done
emit_stdout "n64le" "p5-dyn-n64le" "interp" 0 "$SYSROOT_DIR/p5-n64le"
emit_stdout "n64le" "p5-dyn-n64le" "dbt" 0 "$SYSROOT_DIR/p5-n64le"
emit_stdout "n64le" "h4-dyn-n64le" "interp" 0 "$SYSROOT_DIR/h4-dyn-n64le"
emit_stdout "n64le" "h4-dyn-n64le" "dbt" 0 "$SYSROOT_DIR/h4-dyn-n64le"

# --- T4 AOT round-trip: cold emit -> warm reload (real guest ELF) --------
# Cold run emits into a fresh cache dir, warm run reloads in a fresh
# process; stdout must be identical (and equal the tcg dbt leg output),
# both exits 0 with silent stderr, and exactly one `<hex>.aot` leaf must
# exist afterwards (cold created it, warm reused it).
AOT_DIR="$OUT_DIR/aot-roundtrip"
rm -rf "$AOT_DIR"
mkdir -p "$AOT_DIR"
if [ -f "$GUEST_DIR/tcg-n64le" ]; then
    _t0=$(parity_now_ms)
    "$RT" --dbt --cache "$AOT_DIR" "$GUEST_DIR/tcg-n64le" \
        >"$OUT_DIR/aot-cold.out" 2>"$OUT_DIR/aot-cold.err"
    _crc=$?
    "$RT" --dbt --cache "$AOT_DIR" "$GUEST_DIR/tcg-n64le" \
        >"$OUT_DIR/aot-warm.out" 2>"$OUT_DIR/aot-warm.err"
    _wrc=$?
    _ams=$(( $(parity_now_ms) - _t0 ))
    if [ "$PARITY_UPDATE_GOLDEN" = "1" ]; then
        _aot_want="$OUT_DIR/tcg-n64le-dbt.out"
    else
        _aot_want="$GOLDEN_DIR/tcg-n64le.out"
    fi
    if [ "$PARITY_UPDATE_GOLDEN" != "1" ] && [ ! -f "$_aot_want" ]; then
        parity_row "n64le" "$HOST_TAG" "aot-roundtrip-output" "dbt" "GAP" "$_ams" "missing golden tests/golden/tcg-n64le.out"
    elif [ "$_crc" = "0" ] && [ "$_wrc" = "0" ] \
        && [ ! -s "$OUT_DIR/aot-cold.err" ] && [ ! -s "$OUT_DIR/aot-warm.err" ] \
        && cmp -s "$OUT_DIR/aot-cold.out" "$OUT_DIR/aot-warm.out" \
        && parity_check_golden "$_aot_want" "$OUT_DIR/aot-cold.out"; then
        parity_row "n64le" "$HOST_TAG" "aot-roundtrip-output" "dbt" "PASS" "$_ams" "cold==warm rc=0, matches tcg golden"
    else
        parity_row "n64le" "$HOST_TAG" "aot-roundtrip-output" "dbt" "FAIL" "$_ams" "cold rc=$_crc warm rc=$_wrc"
    fi
    _nleaf=$(find "$AOT_DIR" -name '*.aot' | grep -c .)
    if [ "$_nleaf" = "1" ]; then
        parity_row "n64le" "$HOST_TAG" "aot-roundtrip-cache" "dbt" "PASS" 0 "single leaf reused cold->warm"
    else
        parity_row "n64le" "$HOST_TAG" "aot-roundtrip-cache" "dbt" "FAIL" 0 "leaves=$_nleaf, want 1"
    fi
else
    parity_row "n64le" "$HOST_TAG" "aot-roundtrip-output" "dbt" "GAP" 0 "missing guest $GUEST_DIR/tcg-n64le"
    parity_row "n64le" "$HOST_TAG" "aot-roundtrip-cache" "dbt" "GAP" 0 "missing guest $GUEST_DIR/tcg-n64le"
fi

# --- qualify tier: full Docker live-QEMU rebuild ----------------------
if [ "${PARITY_DOCKER:-0}" = "1" ] || [ "${PARITY_TIER:-smoke}" = "qualify" ]; then
    if [ "$(docker image inspect mips64rt-parity-env:trixie >/dev/null 2>&1; echo $?)" = "0" ]; then
        IMG="mips64rt-parity-env:trixie"
    else
        IMG="debian:trixie-slim"
    fi
    NAME="mips64rt-parity-$$"
    cleanup() {
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT INT TERM
    # Container exit codes: 0 full oracle parity, 2 documented oracle GAP
    # (engines agree, oracle differs), anything else = FAIL.
    _t0=$(parity_now_ms)
    set +e
    timeout --kill-after=30s 480s docker run --rm \
        --name "$NAME" --memory 2g --cpus 4 --platform linux/arm64 \
        -v "$ROOT:/w" -w /w "$IMG" sh -c '
set -u
if ! command -v mips64el-linux-gnuabi64-g++ >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 \
        g++-mips64el-linux-gnuabi64 g++-mips64-linux-gnuabi64 \
        libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross \
        libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross \
        libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross \
        libn32stdc++-14-dev-mips64el-cross libn32stdc++-14-dev-mips64-cross \
        wget qemu-user >/dev/null 2>&1
fi
CFLAGS="-O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
CXXFLAGS="-O1 -static -pthread -std=c++17 -Wall -Wextra"
DCFLAGS="-O1 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror"
gaps=0
fails=0
run_abi() {
    abi="$1"; cc="$2"; cxx="$3"; mabi="$4"; qemu="$5"; triplet="$6"; ldorg="$7"
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
        [ "$sqrc" -eq 0 ] && [ "$sirc" -eq 0 ] && [ "$sdrc" -eq 0 ] || {
            echo "P-FAIL: $abi $tag nonzero exit ($sqrc/$sirc/$sdrc)"; fails=$((fails + 1)); return
        }
        grep -q "RESULT: PASS" /tmp/s-interp || {
            echo "P-FAIL: $abi $tag missing RESULT: PASS"; fails=$((fails + 1)); return
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
    h4bin="/tmp/h4-${abi}"
    # shellcheck disable=SC2086
    $cxx $CXXFLAGS -mabi=$mabi -o "$h4bin" tests/test_h4_cxx17.cc || {
        echo "P-FAIL: $abi h4 build failed"; fails=$((fails + 1)); return
    }
    set +e
    timeout --kill-after=30s 60s "$qemu" "$h4bin" >/tmp/s-qemu 2>&1
    sqrc=$?
    timeout --kill-after=30s 60s /w/_build/mips64rt --interp "$h4bin" >/tmp/s-interp 2>&1
    sirc=$?
    timeout --kill-after=30s 60s /w/_build/mips64rt --dbt "$h4bin" >/tmp/s-dbt 2>&1
    sdrc=$?
    set -e
    [ "$sqrc" -eq 0 ] && [ "$sirc" -eq 0 ] && [ "$sdrc" -eq 0 ] && \
        grep -q "H4-RESULT: PASS" /tmp/s-interp && \
        cmp -s /tmp/s-interp /tmp/s-dbt && \
        cmp -s /tmp/s-qemu /tmp/s-interp || {
        echo "P-FAIL: $abi h4 failed ($sqrc/$sirc/$sdrc)"; fails=$((fails + 1)); return
    }
    echo "P-PASS: $abi h4 oracle parity (interp == dbt == $qemu)"
    mkdir -p "/x/sysroot/$abi/lib" "/x/dyn/$abi"
    cp -L "$ldorg/ld.so.1" "/x/sysroot/$abi/lib/" 2>/dev/null || cp "$ldorg/ld.so.1" "/x/sysroot/$abi/lib/"
    for lib in libc.so.6 libm.so.6 libdl.so.2; do
        if [ -f "$triplet/$lib" ]; then
            cp -L "$triplet/$lib" "/x/sysroot/$abi/lib/" 2>/dev/null || cp "$triplet/$lib" "/x/sysroot/$abi/lib/"
        fi
    done
    gcclib=$($cc -mabi=$mabi -print-file-name=libgcc_s.so.1)
    [ -f "$gcclib" ] && cp -L "$gcclib" "/x/sysroot/$abi/lib/"
    # shellcheck disable=SC2086
    $cc $DCFLAGS -mabi=$mabi -shared -fPIC -o "/x/dyn/$abi/p5_dynlib-$abi.so" tests/p5_dynlib.c && \
    cp "/x/dyn/$abi/p5_dynlib-$abi.so" "/x/dyn/$abi/p5_dynlib-$(echo "$abi" | tr n N).so" && \
    $cc $DCFLAGS -mabi=$mabi -no-pie -o "/x/dyn/$abi/p5-$abi" tests/test_p5_dyn.c \
        -Wl,--dynamic-linker,"/x/sysroot/$abi/lib/ld.so.1" \
        -Wl,-rpath,"/x/sysroot/$abi/lib" -ldl || {
        echo "P-FAIL: $abi p5 build failed"; fails=$((fails + 1)); return
    }
    set +e
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt P5_SENTINEL=dyn-env-ok \
        timeout --kill-after=30s 60s "$qemu" "/x/dyn/$abi/p5-$abi" p5arg1 p5arg2 >/tmp/s-qemu 2>&1
    sqrc=$?
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt P5_SENTINEL=dyn-env-ok \
        timeout --kill-after=30s 60s /w/_build/mips64rt --interp "/x/dyn/$abi/p5-$abi" p5arg1 p5arg2 >/tmp/s-interp 2>&1
    sirc=$?
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt P5_SENTINEL=dyn-env-ok \
        timeout --kill-after=30s 60s /w/_build/mips64rt --dbt "/x/dyn/$abi/p5-$abi" p5arg1 p5arg2 >/tmp/s-dbt 2>&1
    sdrc=$?
    set -e
    [ "$sqrc" -eq 0 ] && [ "$sirc" -eq 0 ] && [ "$sdrc" -eq 0 ] && \
        grep -q "P5-RESULT: PASS" /tmp/s-interp && \
        cmp -s /tmp/s-interp /tmp/s-dbt && \
        cmp -s /tmp/s-qemu /tmp/s-interp || {
        echo "P-FAIL: $abi p5 failed ($sqrc/$sirc/$sdrc)"; fails=$((fails + 1)); return
    }
    echo "P-PASS: $abi p5 dynamic oracle parity (interp == dbt == $qemu)"
    printf "D2-FILEIO alpha\nD2-FILEIO beta\nD2-FILEIO gamma\n" > /tmp/d2seed
    for dfix in hello printf malloc qsort fileio; do
        dbin="/tmp/d2-${dfix}-${abi}"
        # shellcheck disable=SC2086
        $cc $CFLAGS -mabi=$mabi -o "$dbin" "tests/difftest/test_d2_${dfix}.c" || {
            echo "P-FAIL: $abi d2-$dfix build failed"; fails=$((fails + 1)); return
        }
        set +e
        if [ "$dfix" = "fileio" ]; then
            MIPS64RT_RANDSEED=1 timeout --kill-after=30s 60s \
                /w/_build/mips64rt --difftest "$dbin" </tmp/d2seed >/tmp/s-diff 2>&1
        else
            MIPS64RT_RANDSEED=1 timeout --kill-after=30s 60s \
                /w/_build/mips64rt --difftest "$dbin" >/tmp/s-diff 2>&1
        fi
        dfrc=$?
        set -e
        if [ "$dfrc" -eq 0 ] && grep -q "difftest clean" /tmp/s-diff; then
            echo "P-PASS: $abi --difftest $dfix (I + R trace 0 divergences)"
        else
            echo "P-FAIL: $abi --difftest $dfix failed (rc=$dfrc)"
            tail -10 /tmp/s-diff
            fails=$((fails + 1))
        fi
    done
}
run_abi n64le mips64el-linux-gnuabi64-gcc mips64el-linux-gnuabi64-g++ 64 qemu-mips64el /usr/mips64el-linux-gnuabi64/lib /usr/mips64el-linux-gnuabi64/lib64
run_abi n64be mips64-linux-gnuabi64-gcc mips64-linux-gnuabi64-g++ 64 qemu-mips64 /usr/mips64-linux-gnuabi64/lib /usr/mips64-linux-gnuabi64/lib64
run_abi n32le mips64el-linux-gnuabi64-gcc mips64el-linux-gnuabi64-g++ n32 qemu-mipsn32el /usr/mips64el-linux-gnuabi64/lib32 /usr/mips64el-linux-gnuabi64/lib32
run_abi n32be mips64-linux-gnuabi64-gcc mips64-linux-gnuabi64-g++ n32 qemu-mipsn32 /usr/mips64-linux-gnuabi64/lib32 /usr/mips64-linux-gnuabi64/lib32
if [ ! -x /x/bb/bin/busybox ]; then
    cd /tmp
    wget -q http://deb.debian.org/debian/dists/bookworm/main/binary-mips64el/Packages.gz && \
    FN=$(zcat Packages.gz | grep -A25 "^Package: busybox-static$" | grep "^Filename:" | head -1 | cut -d" " -f2) && \
    wget -q "http://deb.debian.org/debian/$FN" -o /tmp/bb.deb && \
    mkdir -p /x/bb && dpkg-deb -x /tmp/bb.deb /x/bb || {
        echo "P-FAIL: busybox fetch failed"; fails=$((fails + 1))
    }
fi
if [ -x /x/bb/bin/busybox ]; then
    set +e
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt timeout --kill-after=30s 60s \
        qemu-mips64el /x/bb/bin/busybox sh -c "ls / && echo ok | wc -c" >/tmp/bb-q 2>&1
    bqrc=$?
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt timeout --kill-after=30s 60s \
        /w/_build/mips64rt --interp /x/bb/bin/busybox sh -c "ls / && echo ok | wc -c" >/tmp/bb-i 2>&1
    birc=$?
    env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt timeout --kill-after=30s 60s \
        /w/_build/mips64rt --dbt /x/bb/bin/busybox sh -c "ls / && echo ok | wc -c" >/tmp/bb-d 2>&1
    bdrc=$?
    set -e
    if [ "$bqrc" -eq 0 ] && [ "$birc" -eq 0 ] && [ "$bdrc" -eq 0 ] && \
       cmp -s /tmp/bb-q /tmp/bb-i && cmp -s /tmp/bb-i /tmp/bb-d; then
        echo "P-PASS: n64le BusyBox oracle parity"
    else
        echo "P-FAIL: n64le BusyBox parity failed ($bqrc/$birc/$bdrc)"
        fails=$((fails + 1))
    fi
fi
echo "abis done: fails=$fails gaps=$gaps"
[ "$fails" -eq 0 ] || exit 1
[ "$gaps" -eq 0 ] || exit 2
exit 0
' >"$OUT_DIR/qualify-docker.log" 2>&1
    crc=$?
    set -e
    _t1=$(parity_now_ms)
    if [ "$crc" -eq 0 ]; then
        parity_row "all" "$HOST_TAG" "qualify-docker-oracle" "oracle" "PASS" "$((_t1 - _t0))" "P1/P3/P4/P5/P6/H1/H4/--difftest/BusyBox oracle parity"
    elif [ "$crc" -eq 2 ]; then
        parity_row "all" "$HOST_TAG" "qualify-docker-oracle" "oracle" "GAP" "$((_t1 - _t0))" "engines agree, oracle differs (see $OUT_DIR/qualify-docker.log)"
    else
        parity_row "all" "$HOST_TAG" "qualify-docker-oracle" "oracle" "FAIL" "$((_t1 - _t0))" "docker leg exit $crc (see $OUT_DIR/qualify-docker.log)"
        tail -30 "$OUT_DIR/qualify-docker.log" >&2 || true
    fi
    trap - EXIT INT TERM
    cleanup
    if docker ps --format "{{.Names}}" 2>/dev/null | grep -q "^${NAME}$"; then
        parity_row "all" "$HOST_TAG" "qualify-docker-cleanup" "host" "FAIL" 0 "container $NAME still present"
    else
        parity_row "all" "$HOST_TAG" "qualify-docker-cleanup" "host" "PASS" 0 "container removed"
    fi
fi

parity_summary
