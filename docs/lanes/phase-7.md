# Phase 7 Task Cards — Hardening (`SMC`, `libc-test`, LTP Subset, CoreMark, C++17) (`mips64rt`)

Run after `RC6` (`c654c9d`) is committed on `master`. Frozen contracts:
`src/core/cpu.h`, `src/os/syscall_nr.h`, `Makefile`, SPEC 1.1 (window) +
[`../rt-series/docs/HOST-CONTRACT.md`](../rt-series/docs/HOST-CONTRACT.md).
The DBT already keys every block on the SMC epoch
(`dbt_smc_epoch`, `dbt_invalidate_all/range` in `src/dbt/dbt.c`), but
nothing triggers invalidation yet: `mips_mem_map/protect/unmap` do not
call it, `cacheflush` (N64 5197 / N32 6197) has no dispatch arm, and
`SYNCI` is a `NOP` in both engines. `SYNCI` + `cacheflush` are the
flush primitives `gcc` lowers `__builtin___clear_cache` to — the H1
hooks close exactly these paths. W^X is probed functionally (guest RX
executes and rejects stores; guest RW data rejects execution), never
by inspecting host mappings.

Shared rules: curated C11, every file <= 900 lines, no `x18`, W^X +
I-cache discipline kept, no AI/agent names, never `git push`. RC-H
integration by the coordinator after all lanes merge; P1/P3/P4/P5/P6
suites are re-run against the final binary on both engines. Reference
`../mips32rt/docs/lanes/phase-7.md` (completed `RC-H`) and
`../loongarch64rt/docs/lanes/phase-7.md` (Class-B specifics).

---

### Lane `H1` — Self-Modifying Code & W^X (`tests/test_h1_smc.c`, `tests/run_h1_smc.sh`)
- **Worktree**: `../mips64rt-h1` on branch `lane/phase-7-h1`
- **Exclusive Files**: `tests/test_h1_smc.c` (new),
  `tests/run_h1_smc.sh` (new), additive invalidation hooks in
  `src/os/mem.c` (`mips_mem_map/protect/unmap` call
  `dbt_invalidate_range`), one `cacheflush` dispatch arm in
  `src/os/syscall_min.c` (range-invalidate, success return), and
  `src/dbt/dbt.c` only if the `SYNCI` path needs it (prefer: DBT
  `SYNCI` exits the block with an invalidation; never slow the
  common no-`SMC` path — hooks fire only on map/protect/unmap/
  flush/`SYNCI`)
- **Task**:
  1. `tests/test_h1_smc.c` (freestanding, musl-static style):
     copy a small function into (a) stack, (b) heap, (c) anonymous
     `mmap` (`RW`), flush with an explicit `SYNCI` sweep plus
     `__builtin___clear_cache`, call it; rewrite the copy in place
     (different return constant), flush again, call again — assert
     the new behavior each time; plus a `PROT_EXEC`-flip variant
     (`mprotect` `RW` → write → `RX` → call) and a `munmap`
     invalidation variant. Functional W^X section: RX page executes
     and rejects stores (`SIGSEGV` with `SEGV_ACCERR`); RW data
     rejects execution (`SIGSEGV`). Deterministic `H1-PASS` lines +
     summary, exit 0 iff zero failures; LE+BE.
  2. `tests/run_h1_smc.sh` (mirrors `run_p6_perms.sh`): build all
     four variants in Docker, capture `qemu-mips64el/qemu-mips64/
     qemu-mipsn32el/qemu-mipsn32` goldens (image
     `mips64rt-qemu:10.0.13`), run `--interp` + `--dbt`,
     byte-compare; `H1-RESULT: PASS` exit 0 iff every check passes
     on both engines.
- **Acceptance Command** (bounded, in worktree):
  `sh tests/run_h1_smc.sh` exit 0.

---

### Lane `H2` — `libc-test` + LTP Syscall Subset (`docs/h2-report.md`)
- **Worktree**: `../mips64rt-h2` on branch `lane/phase-7-h2`
- **Exclusive Files**: `docs/h2-report.md` (new), additive syscall
  arms in `src/os/syscalls.c` ONLY (new `case` handling, no reshaping
  of existing paths)
- **Task**:
  1. Build static glibc probes for `mips64el`/`mips64` N64
     (`gcc-mips64el-linux-gnuabi64`, `-O1 -static`, same recipe as
     `run_p5_busybox.sh`): math (trig/exp/pow/NaN/Inf), string
     (`memcpy`/`memmove`/`strcmp`/`strstr`), pthread
     (join/mutex/cond/TLS/`once`), signal, functional — plus an LTP
     syscall-subset probe (the syscalls the P-suites already cover
     plus `pipe2`/`dup3`/`truncate`/`clock_nanosleep` family where
     implemented).
  2. Run each probe under the `qemu-mips*` oracle and both engines;
     record per-probe assertions in four classes: `GOLDEN` (oracle
     passes), `GREEN` (translator byte-identical), `GAP`
     (documented failure signature reproduced exactly — names the
     unimplemented syscall or known approximation), `PARITY`
     (`interp` output == `dbt` output). Anything out of scope stays
     `-ENOSYS`.
  3. Implement missing syscalls the suites need (additive arms in
     `src/os/syscalls.c` only); if an arm needs another file: STOP
     and report back (two-failure escalation rule).
  4. Commit `docs/h2-report.md` with machine-enforced per-probe
     assertions (`0` unexpected failures: every red entry names its
     covering reason).
- **Acceptance Command** (bounded, in worktree): the report's own
  container gate exit 0 with `docs/h2-report.md` committed (state
  the pass/skip/fail totals in the lane report).

---

### Lane `H3` — Instrumented CoreMark (`tests/coremark/*`, `docs/h3-coremark.md`)
- **Worktree**: `../mips64rt-h3` on branch `lane/phase-7-h3`
- **Exclusive Files**: `tests/coremark/*` (new port),
  `docs/h3-coremark.md` (new) only — NO `src/` changes (a perf fix
  that needs translator changes is a finding, not a drive-by: report
  it with measurements and STOP)
- **Task**:
  1. Vendor CoreMark under `tests/coremark/` (upstream EEMBC mirror)
     with a minimal MIPS64 port (bare `ee_printf`, timer via
     `clock_gettime`, no filesystem) and the musl-static N64 build
     recipe in the port header; keep the port minimal and Upstream
     diff-free where possible.
  2. Follow the mandatory 6-step loop (Instrument → Measure →
     Hypothesise → Fix → Measure again → Validate): record
     `interp` vs `dbt` iterations/sec (fixed iteration count, wall
     clock, Docker `--cpus 2`, five runs, median + range).
  3. Commit `docs/h3-coremark.md` demonstrating measured
     `dbt > interp` throughput with numbers; if `dbt` is not faster,
     the doc reports the measured deficit as the finding (gate red).
- **Acceptance Command** (bounded, in worktree): bounded container
  CoreMark run exit 0 with `docs/h3-coremark.md` committed showing
  `dbt > interp`.

---

### Lane `H4` — C++17 Exceptions/RTTI/TLS (`tests/test_h4_cxx17.cc`)
- **Worktree**: `../mips64rt-h4` on branch `lane/phase-7-h4`
- **Exclusive Files**: `tests/test_h4_cxx17.cc` (new),
  `tests/run_h4_cxx17.sh` (new) only — NO `src/` changes (a
  translator bug is a finding: document it precisely and STOP)
- **Task**:
  1. `tests/test_h4_cxx17.cc`: `try`/`catch` unwinding across call
     frames (throw through three frames, catch by const-ref,
     rethrow), `dynamic_cast` across a small hierarchy (success +
     null + `bad_cast`), `std::thread` (launch/join/detach +
     `thread_local` with non-trivial destructor ordering), and
     `thread_local` errno-style isolation. Deterministic
     `H4-PASS` protocol + `H4-RESULT`, exit 0 iff zero failures.
  2. `tests/run_h4_cxx17.sh`: build with the trixie cross C++
     toolchain (`g++-mips64el-linux-gnuabi64` /
     `g++-mips64-linux-gnuabi64`, `-O1 -static -std=c++17`), LE+BE,
     capture `qemu-mips*` goldens, run `--interp` + `--dbt`,
     byte-compare; `H4-RESULT: PASS` exit 0.
- **Acceptance Command** (bounded, in worktree):
  `sh tests/run_h4_cxx17.sh` exit 0.

---

## RC-H gate (coordinator, after all lanes merge)

1. Merge H1..H4 (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/run_h1_smc.sh`, `tests/run_h4_cxx17.sh`, the H2
   report gate, plus P1 (`rc1_interp_check.sh`), P3, P4, P5
   (`run_p5_busybox.sh`), P6 (`run_p6_perms.sh`,
   `p6_host_check.sh`) on both engines × LE+BE.
3. `docs/h2-report.md` shows `0` unexpected failures;
   `docs/h3-coremark.md` shows measured `dbt > interp`.
4. `make check`, `make check-line-limits` pass with a clean git tree;
   tick `GOAL.md` Phase 7 + `RC-H`.
