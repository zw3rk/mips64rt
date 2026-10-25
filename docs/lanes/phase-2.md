# Phase 2 Task Cards — Static Libc Syscalls & Base Integer AArch64 DBT

Run after `RC1` is merged to `master`. Frozen contracts: `src/core/cpu.h`
(`mips64_ctx_t` incl. `ibtc_ptr` at `0x150`, `MIPS64_DBT_MAX_INSNS 64`,
`dbt_block_t`, `dbt_lookup`/`dbt_compile`, `dbt_emit_int`,
`mips_dump_regs`, the N64/N32 syscall `$a3` convention, SPEC §§2–3) and
the Phase 1 contracts. The host register map for translated code is
defined by lane L2b in `src/dbt/dbt.h` and frozen for L2c: `x19` = ctx,
`x20` = guest window base, `$0` reads as `wzr` (writes dropped), all
other guest state spilled to `[x19, #off]`; **never read or write
`x18`**.

Shared rules: curated C11 (`-std=c11 -Werror=vla -pedantic -Wall
-Wextra -Werror`), every file ≤ 900 lines, W^X + I-cache discipline for
emitted code (`PROT_READ|PROT_WRITE` during emission, flip to
`PROT_READ|PROT_EXEC` + `__builtin___clear_cache` before execution),
Apache-2.0 header on new files, no AI/agent names, never `git push`.
Bound every build/container run with `timeout --kill-after=30s`, unique
`--name mips64rt-<lane>-...`, `docker ps` cleanup check. A lane stops
and reports back if its acceptance command fails twice, if it needs a
frozen-header edit, or if a spec detail is ambiguous.

RC2 integration (by the coordinator after all lanes merge): wire
`Makefile` (`BOOT_SRCS` gains `src/dbt/*.c` + `src/os/syscalls.c` +
trampoline), route `--dbt` to the L2b engine, build, run `--difftest`.

---

### Lane `L2a` — Complete Static-Libc Syscall & Struct Layer
- **Worktree**: `../mips64rt-l2a` on branch `lane/p2-l2a`
- **Exclusive Files**: `src/os/syscalls.c` (new), `src/os/syscall_nr.h`
  (extend), `src/os/syscall_min.c` (extend the `mips_syscall` dispatch
  only; no other edits)
- **Task**:
  1. Extend `src/os/syscall_nr.h` with the N64/N32 numbers L1c omitted
     (verify each against the UAPI headers in the Debian container and
     cite the header in a comment): `openat`, `fcntl`, `clock_gettime`,
     `getrandom`, `futex` (single-threaded `FUTEX_WAIT`/`FUTEX_WAKE`
     minimum), `rt_sigprocmask` (record mask, no delivery until Phase 4),
     `ioctl`, `lseek`, `stat` family + `statx`, `getdents64`,
     `readlinkat`, `access`/`faccessat`, `pipe2`, `dup`/`dup3`,
     `nanosleep`, `getpid`/`getppid`/`getuid`/`getgid` family,
     `set_robust_list`/`get_robust_list`, `unlinkat`, `close_range`.
     Keep the `MIPS64_NR_`/`MIPS64_NR32_` naming and base-5000/6000
     grouping.
  2. New `src/os/syscalls.c`: struct conversions with MIPS layouts
     (`stat`/`stat64`, `statx`, `iovec`, open flags per E01 `O_*`) +
     handlers wired through the extended dispatch. Unknown syscalls keep
     `-ENOSYS` with `$a3=1`. No `sprintf`/`strcpy`/`strcat`, no VLAs.
- **Acceptance Command** (cross compile check, no link; execution is the
  RC2 gate — report it deferred):
  ```sh
  PATH=/nix/store/82ac69jwkpj68v4mx22yxnwqzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/syscalls.c -o /tmp/syscalls.o && PATH=/nix/store/82ac69jwkpj68v4mx22yxnwqzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/syscall_min.c -o /tmp/syscall_min.o
  ```

---

### Lane `L2b` — AArch64 DBT Core (dispatcher, block cache, IBTC, trampoline, encoder)
- **Worktree**: `../mips64rt-l2b` on branch `lane/p2-l2b`
- **Exclusive Files**: `src/dbt/a64_emit.c`, `src/dbt/a64_emit.h`,
  `src/dbt/dbt.c`, `src/dbt/dbt.h`, `src/dbt/trampoline_a64.S`
- **Task**:
  1. `src/dbt/a64_emit.[ch]`: direct 32-bit AArch64 instruction encoder
     (integer only for RC2; FP/NEON arrives in Phase 3). May adapt the
     structure of `../loongarch64rt/src/dbt/a64_emit.[ch]` (32-GPR
     host map); do not copy A32-specific (`a32rt`) Thumb/ARM pieces.
     Every emitted instruction needs a unit assertion in the file's
     `#ifdef` self-test or in `tests/test_dbt_emit.c` (new, lane-owned
     if created — keep it native-compilable).
  2. `src/dbt/dbt.h`: the frozen-for-L2c host register map (`x19` =
     ctx, `x20` = guest window base, `$0` = `wzr`, spills to
     `[x19, #off]`, `x21..x24` scratch, never `x18`) + lane-internal
     cache/RAS/trampoline declarations + `MIPS64_IBTC_SIZE 4096`.
  3. `src/dbt/dbt.c`: engine loop behind the frozen `dbt_lookup` /
     `dbt_compile` contracts, direct chaining + 4096-entry IBTC keyed
     by guest PC + RAS, `dbt_compile` fetches via `mips_fetch`,
     decodes via `mips_decode`, stops at control transfers / 64-insn
     cap / page crossing per SPEC 2.2, delegates emission to frozen
     `dbt_emit_int`, publishes W^X + `__builtin___clear_cache`,
     `EXIT_UNDEF`/`EXIT_SINGLE_STEP` fall back to `interp_step` then
     resume, FP/COP1 blocks fall back to `interp_step` until Phase 3.
     `ctx->ibtc_ptr` owns the table; `smc_version` from page
     versioning (bump on `mprotect`/`munmap`/guest writes to
     translated pages; invalidate on mismatch). When
     `ctx->trace_enabled`, emit interp-compatible `I <pc> <word>`
     lines so the L2d difftest can compare trace streams.
  4. `src/dbt/trampoline_a64.S`: host entry/exit (save/restore
     callee-saved, set `x19`/`x20`, dispatch to block code,
     exit-reason return). Never read/write `x18`.
- **Acceptance Command**: same cross `-c` check as L2a for
  `src/dbt/dbt.c`, `src/dbt/a64_emit.c`, and `as` for
  `src/dbt/trampoline_a64.S` (execution is the RC2 gate).

---

### Lane `L2c` — AArch64 Integer Instruction Emitter
- **Worktree**: `../mips64rt-l2c` on branch `lane/p2-l2c`
- **Exclusive Files**: `src/dbt/emit_int.c`
- **Task**: Implement frozen `dbt_emit_int` using the L2b `dbt.h`
  register map and `a64_emit.h` only: ALU (32-bit forms with `SXTW`,
  `D`-forms full 64-bit, `LUI`, `SLTI*`), shifts (`SLL[V]`/`SRL[V]`/
  `SRA[V]`/`DSLL[V/32]`/`DSRL[V/32]`/`DSRA[V/32]`/`DROTR[V/32]`/`ROTR`
  with the RC1 `DINSM`/`DINSU`/`DINS` + `DEXT[M/U]` + `DSBH`/`DSHD`
  semantics), `MULT[U]`/`DMULT[U]`/`DIV[U]`/`DDIV[U]` +
  `MFHI`/`MFLO`/`MTHI`/`MTLO` (HI/LO spill to ctx), branches/jumps +
  likely-annul (delay slot emitted inline; link `ra = pc + 8`;
  not-taken likely skips the slot with no fetch), loads/stores
  (aligned fast path via `x20` + guest-base; `LWL`/`LWR`/`SWL`/`SWR`
  and `LDL`/`LDR`/`SDL`/`SDR` with the RC1 span semantics;
  `LL`/`SC`/`LLD`/`SCD` via `LDXR`/`STXR` with `llbit` semantics),
  `J`/`JAL`/`JALR` direct-chaining hooks, `SYSCALL`/`BREAK`/traps as
  exits to the dispatcher, `RDHWR`/`ulr`, cache/pref as NOPs,
  unknown/FP/COP1 ops as `EXIT_UNDEF` (never abort: the dispatcher
  falls back to `interp_step`). `$0` writes dropped.
- **Acceptance Command**: same cross `-c` check as L2a for
  `src/dbt/emit_int.c` (execution is the RC2 gate).

---

### Lane `L2d` — Difftest Harness + Static Libc Test Suite
- **Worktree**: `../mips64rt-l2d` on branch `lane/p2-l2d`
- **Exclusive Files**: `tests/difftest/**` (new directory)
- **Task**:
  1. `tests/difftest/run_d2.sh`: builds fixtures
     `test_d2_{hello,printf,malloc,qsort,fileio}.c` (static, N64+N32 ×
     LE+BE = 8 binaries) with the Debian cross toolchains in a bounded
     container (unique `--name`, `--memory 2g --cpus 2`,
     `timeout --kill-after=30s`, `docker ps` cleanup check); runs each
     under its qemu capturing stdout+exit into
     `tests/difftest/golden_*`; runs each under `--interp` and requires
     stdout+exit identical to golden (the dbt half runs at RC2).
  2. `tests/difftest/run_difftest.sh`: runs a guest under `--interp
     --trace` and `--dbt --trace` (plus `MIPS64RT_DUMPSTATE=1` exit
     dumps via frozen `mips_dump_regs`), diffs the `pc+word` streams
     and the `REGS` dumps, prints `DIFFTEST: 0 divergences` or the
     first divergence. Must already work interp-vs-interp
     (self-consistency); interp-vs-dbt goes live at RC2.
- **Acceptance Command**:
  ```sh
  sh tests/difftest/run_d2.sh && test -s tests/difftest/golden_n64le_hello.txt
  ```

---

## RC2 outcome (coordinator integration)

`tests/difftest/run_difftest.sh GUEST interp dbt` reports `0
divergences` on all guests (`test_p1_isa` + fixtures × LE/BE ×
N64/N32); D2 (`run_d2.sh`) matches every qemu golden on both engines;
RC1 still green after the integration. Container cleaned.
