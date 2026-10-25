# Phase 4 Task Cards — Signals, Threads & Process Lifecycle (`RC4`)

Run after `RC3` is merged to `master`. Frozen contracts: `src/core/cpu.h`
(`mips64_ctx_t` incl. the appended signal state `sigactions[129]` /
`sig_blocked[2]` / `pend_queue[16]` + the Phase 4 seam declarations —
`mips_raise_guest`, `mips_rt_sigreturn`, `mips_signal_has_handler`,
`mips_trap`, `mips_sc_rt_sigaction`, `mips_l4a_rt_sigprocmask`,
`mips_sc_sigaltstack`, `mips64_signals_reset_for_exec`,
`mips_thread_exit`, `mips_hostfault_install/run/disarm`),
`src/os/syscall_nr.h`, `src/os/sigframe_mips64rt.h` (frozen N64/N32
`rt_sigframe` types), `src/rt64/linux/signal_core.h` (trampoline
placement, `mips64_ctx_clear_ll`), `src/dbt/dbt.h` (host-register map
`x19` = ctx, `x20` = guest base, `x21..x24` scratch, `x25` JR/JALR
spill, **never read or write `x18`**), SPEC §§2–4, and the Phase 1/2/3
contracts (RC1 span semantics, E05 LL/SC reservation, difftest
`I`/`REGS` stream parity, legacy pre-nan2008 SNaN rule).

Shared rules: curated C11 (`-std=c11 -Werror=vla -pedantic -Wall
-Wextra -Werror`), every file ≤ 900 lines (`make check-line-limits`),
W^X + I-cache discipline, Apache-2.0 header on new files
(`Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.`),
no AI/agent names in commits, never `git push`. Bound every build,
Docker, and `qemu-mips64el` / `qemu-mips64` / `qemu-mipsn32el` /
`qemu-mipsn32` run with an explicit wall-clock
`timeout --kill-after=30s`, name every container uniquely
(`--name mips64rt-l4x-...`), remove containers on exit or error.
Reference implementation: `../rvrt/src/linux/{signal_frame,signal,
signal_exec,thread,futex,futex_key,wait,file_exec,pipe}.c` (+ headers)
and `../rvrt/src/runtime/{exec_state,exec_launch,exec_tid}.c`.

RC4 integration (by the coordinator after all lanes merge): wire
`BOOT_SRCS` (the three new files), `syscall_min.c` dispatch to the
lane seams, pending-signal checks at the interp loop and DBT block
boundaries, and `mips_trap` at fault sites; then run
`test_p4_threads_signals` under `qemu` (golden), `interp`, and `dbt`
on all four ABI/endian variants with `0` difftest divergences.

Escalation rule: a lane stops and reports back if its acceptance
command fails twice, if it needs an edit to a frozen header, or if a
spec detail is ambiguous. Lanes never merge: the coordinator merges
each lane `--no-ff` and removes its worktree.

---

### Lane `L4a` — Signal Actions, Masks & `rt_sigframe` Delivery
- **Worktree**: `../mips64rt-l4a` on branch `lane/p4-l4a`
- **Exclusive Files**: `src/os/sigact.c` (new), `src/os/sigframe.c` (new)
- **Task**:
  1. `src/os/sigact.c`: define every signal seam declared in frozen
     `cpu.h` (`mips_sc_rt_sigaction`, `mips_l4a_rt_sigprocmask`,
     `mips_sc_sigaltstack`, `mips_signal_has_handler`,
     `mips64_signals_reset_for_exec`) plus one dispatch seam
     `int64_t mips_sc_sig_syscall(mips64_ctx_t *ctx, uint64_t nr,
     uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)` covering
     `rt_sigpending`, `rt_sigsuspend`, `rt_sigqueueinfo`, `kill`,
     `tkill`, `tgkill` (N64+N32 numbers from frozen `syscall_nr.h`).
     128-entry action table + 128-bit blocked/pending masks live in
     the frozen `ctx` tail; `SIGKILL`/`SIGSTOP` are never caught.
  2. `src/os/sigframe.c`: define `mips_raise_guest` (build the
     `rt_sigframe` from frozen `sigframe_mips64rt.h` on the guest
     stack — or `sigalt_sp` when enabled — redirect `pc` to the
     handler with `ra` at the frozen trampoline page, block the
     handled signal plus the action mask), `mips_rt_sigreturn`
     (restore, return `-ENOSYS` on a bogus frame), and `mips_trap`
     (record `signo`/`code`/`addr` into `pend_queue`, deliver if
     unhandled-unblocked else keep pending). Synchronous mapping:
     guest fetch/mem fault → `SIGSEGV`, undefined word → `SIGILL`,
     FP `V` cause → `SIGFPE`, `BREAK` → `SIGTRAP`, misaligned →
     `SIGBUS`. Delay-slot faults record `sc_pc = branch_pc`.
  3. Mirror `../rvrt/src/linux/signal_frame.c` + `signal.c` semantics;
     read them before coding.
- **Acceptance Command** (cross compile check; execution is the RC4
  gate — report it deferred):
  ```sh
  PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/sigact.c -o /tmp/sigact.o && PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/sigframe.c -o /tmp/sigframe.o
  ```

---

### Lane `L4b` — Threads: `clone`, TLS, `futex`, LL/SC Invalidation
- **Worktree**: `../mips64rt-l4b` on branch `lane/p4-l4b`
- **Exclusive Files**: `src/os/threads.c` (new), `src/os/futex.c` (new)
- **Task**:
  1. `src/os/threads.c`: define `mips_thread_exit`,
     `mips_hostfault_install/run/disarm`, plus one dispatch seam
     `int64_t mips_clone_full(mips64_ctx_t *ctx, uint64_t flags,
     uint64_t stack_va, uint64_t parent_tid_va, uint64_t tls_va,
     uint64_t child_tid_va)` for the full `clone(2)` flag set:
     thread-group clones (`CLONE_VM|CLONE_THREAD|CLONE_SIGHAND`)
     spawn a host thread sharing the guest reservation with
     `tls_va` installed as the child's `ulr`, `CLONE_CHILD_CLEARTID`
     recorded in frozen `ctx.clear_child_tid`, robust list recorded;
     process clones fall back to `fork(2)`. `musl` `fork`/`vfork`
     lowering (already in `syscall_min.c`) keeps working untouched.
     Invalidate the LL/SC reservation (`mips64_ctx_clear_ll`) across
     every clone and every signal delivery. Mirror
     `../rvrt/src/linux/thread.c` + `../rvrt/src/runtime/exec_tid.c`.
  2. `src/os/futex.c`: define `int64_t mips_futex_op(mips64_ctx_t
     *ctx, uint64_t uaddr, uint64_t op, uint64_t val, uint64_t
     timeout_va, uint64_t uaddr2, uint64_t val3)` implementing
     `FUTEX_WAIT/WAKE/BITSET/REQUEUE_CMP` (+ `_PRIVATE` variants) on
     guest-shared memory via host `futex(2)`; `FUTEX_WAKE_OP` and
     `TID`-addressed ops return `-ENOSYS`. N32 32-bit `uaddr`
     truncation follows the frozen N32 pointer rule.
- **Acceptance Command**: same cross `-c` check shape as L4a for
  `src/os/threads.c` and `src/os/futex.c` (execution is the RC4 gate).

---

### Lane `L4c` — `execve`, `waitid` & `tests/test_p4_threads_signals.c`
- **Worktree**: `../mips64rt-l4c` on branch `lane/p4-l4c`
- **Exclusive Files**: `src/os/exec.c` (new),
  `tests/test_p4_threads_signals.c` (new)
- **Task**:
  1. `src/os/exec.c`: define `int64_t mips_sc_exec(mips64_ctx_t *ctx,
     uint64_t nr, uint64_t path_va, uint64_t argv_va, uint64_t envp_va,
     uint64_t a3, uint64_t a4)` for `execve`/`execveat` (N64+N32):
     reload the image through the existing loader + file-capability
     path, rebuild stack/auxv via `exec_args`, reset all signal
     actions to `SIG_DFL` (`mips64_signals_reset_for_exec`), clear
     `sig_blocked`/`pend_queue`/altstack/`clear_child_tid`, refuse
     with `-EPERM` under `CLONE_THREAD`. `waitid` (plus `WEXITED`
     status decoding into guest `siginfo_t`) joins extended `wait4`
     coverage; `vfork` stays "clone lowering" (frozen `syscall_nr.h`
     note), `pipe2`/`dup2`/`dup3` already exist and are out of scope.
  2. New `tests/test_p4_threads_signals.c` (freestanding, musl-static
     style like `tests/test_p1_isa.c`, `P4_CHECK` macros, summary +
     `P4-RESULT` line, exit `0` iff zero failures): signal frame
     inspection/modification/restoration (`SIGUSR1` handler edits
     `sc_regs`, `rt_sigreturn` resumes), `SIGSEGV` recovery via
     `mmap` + return-to-fault, `sigaltstack` delivery,
     `pthread_create` + `futex` wake + LL/SC atomic counter,
     `fork`+`execve`+`wait4` round-trip (child re-execs a
     `--p4-child` mode of the same binary).
  3. Build all four variants with the D2 container toolchains
     (`-mabi=64`/`-mabi=n32` × `mips64el`/`mips64` cross compilers,
     `-O1 -static`, same `CFLAGS` as `run_d2.sh`) into the worktree's
     `_build/` (git-ignored, never committed). Run each under its
     `qemu-` oracle; all four must exit `0` with zero `FAIL` lines.
     Record the qemu versions in the commit message.
- **Acceptance Command**: the four `qemu-mips*` runs described above
  (translator execution is the RC4 gate — report it deferred).
