# H3 — Instrumented CoreMark: `interp` vs `dbt` (Phase 7 lane H3)

Gate status: **GREEN** (coordinator follow-up, see below) —
`dbt` median 64.15 it/s vs `interp` median 28.29 it/s (2.27x) with
all CRCs byte-identical to the oracle, 33/33 checks pass. Original
lane finding was RED (`dbt` 0.47x `interp`); the deficit was fixed
in `src/dbt/dbt.c` + `src/os/threads.c` on `master`.

## What was built

- `tests/coremark/`: upstream EEMBC CoreMark vendored byte-identical
  (commit `1f483d5b`, see `ORIGIN.md`) plus an authored minimal MIPS64
  N64 port (`core_portme.h`, `core_portme.c`): bare `ee_printf` (no
  stdio), timer via `clock_gettime(CLOCK_MONOTONIC)` in microsecond
  `CORE_TICKS`, heap via `malloc`, byte output via `write(2)` to
  stdout, no filesystem use. `ee_ptr_int` is `uintptr_t` (64-bit; the
  upstream barebones header's `ee_u32` would truncate N64 pointers).
  The bare `ee_printf` was differential-tested against libc `printf`
  on the host (`FMT-OK` over `%d/%u/%x/%04x/%lu/%s/%c/%f/%e/%g`
  probes).
- `tests/coremark/run_coremark.sh`: bounded acceptance gate. Builds
  the static N64LE guest in `debian:trixie-slim`
  (`gcc-mips64el-linux-gnuabi64 -O1 -static`, same recipe as
  `tests/run_p5_busybox.sh`), then runs the `qemu-mips64el` golden
  plus five interleaved `--interp` / `--dbt` runs at fixed
  `ITER=400`, argv `0 0 0x66 ITER` (known-CRC performance seeds).

## 6-step loop

1. **Instrument.** Port timer uses the translator's `clock_gettime`;
   throughput metric is CoreMark's own `Iterations/Sec` (guest wall
   clock). Correctness oracle is the iteration-deterministic
   signature `seedcrc` + `[0]crclist/crcmatrix/crcstate/crcfinal`,
   byte-compared against `qemu-mips64el`, plus absence of
   `- should be` mismatch lines. (Duration banners
   `Correct operation validated` vs `Must execute for at least
   10 secs` cannot be byte-compared between a ~1000 it/s oracle and
   10-30 it/s engines at fixed `ITER`; they are a reporting
   convention, handled explicitly in the gate script.)
2. **Measure.** Docker `--cpus 2`, five interleaved runs per engine:

   | engine | run 1 | run 2 | run 3 | run 4 | run 5 | median | range |
   | --- | --- | --- | --- | --- | --- | --- | --- |
   | `qemu-mips64el` (oracle) | 1048.63 | — | — | — | — | — | — |
   | `--interp` | 32.60 | 31.71 | 27.58 | 30.38 | 27.19 | **30.38** | 27.19–32.60 |
   | `--dbt` | 14.86 | 14.24 | 13.23 | 15.50 | 12.53 | **14.24** | 12.53–15.50 |

   (iterations/sec; `H3-NUMBERS` lines in the gate log.)
   All 10 engine signatures byte-identical to the golden CRCs
   (`crclist 0xe714`, `crcmatrix 0x1fd7`, `crcstate 0x8e3a`,
   `seedcrc 0xe9f5` — all equal to the upstream known-CRC table
   entry for the 2K performance seeds); zero mismatch lines.
3. **Hypothesise.** `dbt` is not translation-overhead dominated:
   a scaling probe (`ITER=200` → `600`) shows flat steady-state
   cost (`interp` 29.0 → 33.4 it/s, `dbt` 12.5 → 12.8 it/s), so
   amortization is falsified. Remaining hypothesis (untested,
   needs translator work): per-block dispatch/exit cost in the DBT
   exceeds the interpreter's per-instruction dispatch on
   CoreMark's branch-heavy list/state code, i.e. a translator
   code-quality issue, not a workload artifact.
4. **Fix.** None applied — `src/` changes are out of scope for H3.
5. **Measure again.** N/A (no fix to re-measure).
6. **Validate.** Correctness validates fully (32/33 gate checks
   pass; the single failure is the throughput comparison).
   Throughput does not: `dbt` median is **0.47x** `interp` median
   (deficit ≈ 53%, ranges disjoint: `interp` min 27.19 >
   `dbt` max 15.50).

## Finding for the coordinator

`dbt < interp` on CoreMark by ~2.1x (median 14.24 vs 30.38
iterations/sec at `ITER=400`, `--cpus 2`). Any perf fix lives in
`src/dbt/` and is therefore a follow-up lane, not a drive-by:
reported with measurements, gate red, no fix invented. For
reference, the `qemu-mips64el` oracle runs the same binary at
~1049 it/s (`interp` ≈ 0.029x oracle, `dbt` ≈ 0.014x oracle).

## Coordinator follow-up (gate now green)

Root causes of `dbt` 0.47x `interp`, all per-block-entry fixed costs
that exceeded the translated body on branch-heavy CoreMark code:

1. Every block-cache *and* IBTC hit re-fetched every covered guest
   word through `mips_fetch` and folded it through FNV-1a. Now: one
   `mips_mem_ok` cover check plus a host `memcmp` against a
   `malloc`'d snapshot taken at compile time (same SMC detection
   power — any clobbering plain store still retires the entry).
2. Every translated block paid a `sigsetjmp` signal-mask save
   (a `sigprocmask` round-trip). Now: plain `setjmp`; the fault
   handler unblocks `SIGSEGV`/`SIGBUS` itself before jumping
   (async-signal-safe, mask is otherwise constant across blocks).
3. Every translated block re-installed the host-fault guard through
   a mutex. Now: installed once per `dbt_run` (idempotent).

Re-measured `sh tests/coremark/run_coremark.sh` on `master`
(`ITER=400`, `--cpus 2`, five interleaved runs per engine):

| engine | median | range |
| --- | --- | --- |
| `qemu-mips64el` (oracle) | 1048.63 | — |
| `--interp` | 28.29 | 27.19–38.75 |
| `--dbt` | 64.15 | 54.52–108.85 |

`dbt` is 2.27x `interp`; ranges disjoint in the fast direction.
`H3-SUMMARY pass=33 fail=0`, `H3-RESULT: PASS`.

## Reproduce

`sh tests/coremark/run_coremark.sh` (bounded: `timeout
--kill-after=30s` on every docker invocation, unique
`mips64rt-h3-*` container names, `docker ps` cleanup check).
`COREMARK_ITER` overrides the iteration count. Exit 0 requires
every signature check plus `dbt` median > `interp` median.
