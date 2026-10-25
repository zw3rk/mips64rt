<!--
Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
SPDX-License-Identifier: Apache-2.0
-->

# H2 Report — `libc-test` Categories + LTP Syscall Subset (`interp` + `dbt`, N64/N32 × LE/BE)

**Verdict: gate green — 0 unexpected failures.**
Machine-enforced container summary (gate exit 0):

```text
H2-SUMMARY: pass=78 xfail=18 fail=0 total=96 (want pass=78 xfail=18 fail=0 total=96)
H2: gate green — no unexpected failures
```

Assertion classes: `GOLDEN` 24 (qemu oracle exits 0 with no
`FAIL`/`GAP` line on every probe × variant), `GREEN` 30 (translator
stdout+exit byte-identical to golden), `GAP` 18 (stdout byte-identical
to the pinned `want/<probe>-<variant>.gap` signature — the documented
failure reproduced exactly), `PARITY` 24 (`interp` stdout+exit ==
`dbt` stdout+exit on all 24 pairs, including the gap guests). The gate
fails on any deviation: a new failure, a fixed gap, or a drifted line
or exit code class all break it (gap stdout is pinned; gap exit codes
are recorded in the matrix below).

## Environment

- Lane worktree `../mips64rt-h2`, branch `lane/phase-7-h2`, base
  `66b463c` (tree carries only this report + the `src/os/syscalls.c`
  helpers below).
- Translator `_build/mips64rt` (static-PIE AArch64, host cross-build:
  `PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH
  make build`).
- Build container `debian:trixie-slim`, `--platform linux/arm64`,
  `--name mips64rt-h2-build-$$`, `--memory 2g --cpus 2`, per-command
  `timeout --kill-after=30s 280s`; toolchains
  `gcc-mips64el-linux-gnuabi64` / `gcc-mips64-linux-gnuabi64`
  (Debian 14.2.0-13) + N64/N32 libc dev packages, trixie static
  glibc; guests `-O1 -static -std=c11 -Werror=vla -pedantic -Wall
  -Wextra -Werror -mabi=64/-mabi=n32 -lm -lpthread`.
- Test container `mips64rt-qemu:10.0.13` (qemu-user 10.0.13,
  `qemu-mips64el version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)`),
  `--name mips64rt-h2-test-$$`, same bounds; oracle
  `qemu-mips64el/qemu-mipsn32el/qemu-mips64/qemu-mipsn32` per variant,
  translator `env -i PATH=/usr/bin:/bin HOSTNAME=mips64rt
  /b/mips64rt --interp|--dbt <guest>`; stage `/x` holds the 24 guests
  plus fixed dirs `/x/h2dir` (`a/b/c.txt`) and `/x/h2ltpdir`
  (`f1/f2.txt`).
- 6 static probes × 4 variants (N64/N32 × LE/BE); sources, gate
  (`h2gate.sh`) and `want/*.gap` live in gitignored `_build/h2src/`
  (never committed — exclusive-files rule); this report is the lane's
  committed artifact. Containers `--rm` with a cleanup trap;
  `docker ps` empty afterwards.

## Results matrix (qemu golden / interp / dbt)

| Probe (category) | N64LE | N64BE | N32LE | N32BE | Class |
|---|---|---|---|---|---|
| `h2math` (trig/exp/pow/NaN/Inf, 14 boolean checks) | PASS | PASS | PASS | PASS | GREEN ×8 |
| `h2str` (memcpy/memmove/strcmp/strstr, 13 checks) | PASS | PASS | PASS | PASS | GREEN ×8 |
| `h2thr` (pthread join/mutex/cond/TLS/once) | PASS | PASS | PASS | PASS | GREEN ×8 |
| `h2sig` (handler/raise/mask/pending) | GREEN ×2 | GREEN ×2 | GREEN ×2 | exact gap G7 ×2 | GAP ×2 |
| `h2fun` (stdio/file/dir/proc/ids, 16 checks) | exact gap G2 ×2 | exact gap G2 ×2 | exact gap G2 ×2 | exact gap G2 ×2 | GAP ×8 |
| `h2ltp` N64 (12 groups: pipe/pipe2/dup/truncate/sleep/random/symlink/dir/access/fcntl/time/wait) | exact gaps G1+G3+G4+G5 ×2 | exact gaps G1+G3+G4+G5 ×2 | — | — | GAP ×4 |
| `h2ltp` N32 (same 12 groups) | — | — | exact gaps G1+G3+G4+G5′+G6 ×2 | exact gaps G1+G3+G4+G5′+G6 ×2 | GAP ×4 |

Each cell covers both engines (`×2` = interp + dbt). `PARITY`: all 24
`interp`-vs-`dbt` pairs byte-identical in stdout and exit code.

Notable passes (gaps in the `mips32rt` H2 lineage, working here):
`kill`/`raise` delivery + `rt_sigprocmask`/`sigpending` (Phase 4),
BE `getdents64` (`readdir` counts/names identical LE+BE), `pipe2`,
`dup`/`dup2`/`dup3`, `getrandom`, `clock_gettime`, `fork`+`wait4`,
`readlink` legacy + `/proc/self/exe`. glibc lowers `pipe()` to
`pipe2(fd, 0)` and `nanosleep()` to `clock_nanosleep` on both ABIs
(`qemu -strace`-observed), so no legacy-`pipe` arm is needed.

## Documented gaps (expected; each breaks the gate if fixed or drifted)

- **G1 — `clock_nanosleep` 3-arg dispatch shift (N64 5224 / N32 6228 /
  N32 time64 6407): every sleep fails `-EFAULT`.** The dispatch arm
  calls `mips_sc_nanosleep(ctx, a0, a1, a2, …)` for `(clk, req, rem)`,
  but the ABI is `(clk, flags, req, rem)` in `a0..a3`: the flags word
  (`0`) is read as the request pointer, address 0 is unmapped, and
  the suite prints `LTP-GAP nanosleep rc=-1 errno=14` on all variants
  × both engines (oracle `LTP-OK sleep`). Helper
  `mips_sc_clock_nanosleep` (true `(clk, flags, req, rem)` order,
  `TIMER_ABSTIME` passed through, `EINVAL` on reserved flag bits,
  `EINTR` remainder writeback mirroring `mips_sc_nanosleep`) is added
  in `src/os/syscalls.c`; RC-H rewires the three dispatch arms to it.
  No header change needed.
- **G2 — legacy `unlink` undispatched (N64 5085 / N32 6085).**
  glibc `unlink()` emits the legacy number (`qemu -strace`-observed);
  the suites print `H2FUN-GAP unlink rc=-1 errno=89` /
  matching `LTP-GAP symlink`-group context on all variants × both
  engines (oracle passes). Helper `mips_sc_unlink`
  (`unlinkat(AT_FDCWD)`) added in `src/os/syscalls.c`; RC-H adds the
  dispatch arm. Numbers already frozen.
- **G3 — `truncate`/`ftruncate` undispatched (N64 5074/5075, N32
  6074/6075).** Suite prints `LTP-GAP truncate rc=-1 errno=89` on all
  variants × both engines (oracle `LTP-OK truncate`). Helpers
  `mips_sc_truncate` / `mips_sc_ftruncate` added in
  `src/os/syscalls.c`; RC-H adds the dispatch arms. Numbers frozen.
- **G4 — legacy `symlink` undispatched (N64 5086 / N32 6086).**
  glibc `symlink()` emits the 2-arg legacy number, **not**
  `symlinkat` (`qemu -strace`-observed on both ABIs); the suite prints
  `LTP-GAP symlink rc=-1 errno=89` on all variants × both engines
  (oracle `LTP-OK symlink`). Helper `mips_sc_symlinkat` added in
  `src/os/syscalls.c` (target stored verbatim per Linux creation
  semantics — never resolved at creation; only the link path joins
  the sysroot; also serves `symlinkat` 5256/6260). **STOP item:**
  5086/6086 have no `src/os/syscall_nr.h` entry (frozen) — RC-H adds
  the numbers plus dispatch (legacy pair routes to the helper with
  `AT_FDCWD`).
- **G5 — `clock_getres` undispatched (N64 5223 / N32 6227); N32 emits
  `clock_getres_time64`.** Suite prints `LTP-GAP time-res rc=-1
  errno=89` on all variants × both engines (oracle `LTP-OK time`;
  `clock_gettime` itself passes). Helper `mips_sc_clock_getres`
  added in `src/os/syscalls.c` (N64/time64 16-byte and N32 8-byte
  `{s32,s32}` layouts, mirroring `syscalls_time.c`). **STOP item:**
  N32's `clock_getres_time64` (6406) has no frozen number — RC-H adds
  it plus dispatch; 5223/6227 need dispatch only.
- **G6 — N32 `fcntl64` undispatched (N32 6212; N64 unaffected).**
  N32 glibc `fcntl()` lowers to `fcntl64` (`qemu -strace`-observed);
  the N32 suites print `LTP-GAP pipe2-fcntl rc=-1 errno=89` and
  `LTP-GAP fcntl rc=-1 errno=89` on both engines (N64 `LTP-OK
  pipe2`/`LTP-OK fcntl`; oracle passes everywhere). **STOP item:**
  6212 has no frozen number and no dispatch — RC-H adds both (the
  `F_GETFD/F_GETFL/F_SETFL` subset reuses the `mips_sc_fcntl` MIPS→host
  mapping; `F_*` command values are ABI-identical).
- **G7 — N32BE `rt_sigprocmask` word-size mismatch (`h2sig-n32be`
  only, exit 1).** `SIG_BLOCK` returns 0 but the block bit mislands:
  the handler reads the set as 2×u64 while the N32 guest lays out
  32-bit words, so `SIGUSR1` delivers while blocked
  (`H2SIG-FAIL still-blocked`, `H2SIG-FAIL pending`; everything else
  passes; N64BE passes with identical handler code — the differential
  proves a guest-layout, not handler-logic, difference). **STOP /
  finding:** the fix belongs to `src/os/sigact.c` (outside H2
  exclusive files) — reported, not touched. Pinned want output keeps
  the exact bytes; any fix or drift breaks the gate.

Anything else out of scope stays `-ENOSYS`; no existing path was
reshaped (`src/os/syscalls.c` diff is purely additive + one
`<time.h>` include; helpers compile clean under the frozen
`-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror` build and the
file stays ≤900 lines at 837).

## Probe-side corrections (oracle-caught, fixed before gating)

Three failures reproduced identically under qemu and both engines and
traced to probe bugs, not the translator: `h2fun` wrote 12 of the 13
bytes of `"h2fun-line-1\n"` (`strcmp=-10` on correct bytes proved the
truncation); `h2str` expected `'o'` where the overlap leaves `'\0'`;
`h2sig` printed libc-startup `errno` residue (89) — now reset at
`main` entry so only in-probe behavior shows. The oracle is green on
all 24 runs after the fixes.

## Reproduction

In the lane worktree with the lane helpers compiled: `make build`
(nix musl `PATH` per `AGENTS.md`), then
`sh _build/h2src/h2gate.sh` — unique `--name mips64rt-h2-…`
containers, `--memory 2g --cpus 2`, bounded `timeout
--kill-after=30s` on every step, `docker ps` cleanup check. Exit 0
iff `H2-SUMMARY: pass=78 xfail=18 fail=0 total=96`. Per-variant gap
bodies pinned by the gate (translator stdout, byte-exact):

```text
--- want/h2ltp-n64{le,be}.gap (interp+dbt) ---
LTP-OK pipe / pipe2 / dup, LTP-GAP truncate rc=-1 errno=89,
LTP-GAP nanosleep rc=-1 errno=14, LTP-OK random,
LTP-GAP symlink rc=-1 errno=89, LTP-OK dir / access / fcntl,
LTP-GAP time-res rc=-1 errno=89, LTP-OK wait, LTP-RESULT: PASS
--- want/h2ltp-n32{le,be}.gap: as above, but ---
LTP-GAP pipe2-fcntl rc=-1 errno=89 (not LTP-OK pipe2),
LTP-GAP fcntl rc=-1 errno=89 (not LTP-OK fcntl)
--- want/h2fun-{n64le,n64be,n32le,n32be}.gap: all H2FUN-PASS except ---
H2FUN-GAP unlink rc=-1 errno=89
--- want/h2sig-n32be.gap: all H2SIG-PASS except ---
H2SIG-FAIL still-blocked, H2SIG-FAIL pending,
H2SIG-RESULT: FAIL errno=0 (exit 1)
```

After RC-H wires the G1–G6 arms (and the G4/G5′/G6 frozen numbers),
these bodies change by design: the gate goes red until the report's
want set is re-pinned — that redness is the wiring diff, reviewed
then.
