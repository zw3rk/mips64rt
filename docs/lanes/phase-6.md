# Phase 6 Task Cards — `hyper-linux` Host Contract & Dual-Host Parity (`mips64rt`)

Run after `RC5` (`2c3c824`) is committed on `master`. Frozen contracts:
`src/core/cpu.h`, `src/os/syscall_nr.h`, `Makefile`, SPEC 1.1 (window) +
[`../rt-series/docs/HOST-CONTRACT.md`](../rt-series/docs/HOST-CONTRACT.md)
(Class-B: `HL_MEMORY_POLICY_RVRT`, family broker
`.mips64rt-family-<pid>-<seq>`, AOT cache identity via SHA-256 runtime
digest, separate `--cache-authority`/`--file-identity`/
`--family-authority`). Current state: `src/rt64/` carries the `rvrt`
substrate (`aot/` incl. `sha256`+`identity`, `linux/` incl.
`page_rules`, `memory/`, `runtime/` incl. `family_broker`,
`scheduler_*`, `safe_syscall_a64.S`) partially wired into the worker
loop; CLI has `--interp/--dbt/--difftest/--trace` + `MIPS64RT_ENGINE`
(no `--window` — correctly Class-B N/A — no `--sysroot/--rootfs`,
`--cache/--cache-dir`, `--engine`, `--execfn`, `--image-fd` yet);
`AT_EXECFN` names the guest path; no `AT_EXECFD` detection, no
`--image-fd` load, no guest-sysroot prefixing for `PT_INTERP`/
absolute paths; `getauxval` is guest-side only.

Shared rules: curated C11, every file <= 900 lines, no `x18`, W^X +
I-cache discipline kept, no AI/agent names, never `git push`. The
`--engine <interp|dbt>` spelling is an alias of `--interp`/`--dbt`
(explicit CLI overrides `MIPS64RT_ENGINE`). RC6 integration by the
coordinator after all lanes merge; P1/P3/P4/P5 suites are re-run
against the final binary.

Reference: [`../loongarch64rt/docs/lanes/phase-6.md`](../loongarch64rt/docs/lanes/phase-6.md)
(Class-B, same substrate; its RC6 close-out notes record the
LL-atomicity, `CHILD_SETTID`, fork-difftest-mute, and virtual-pid
fixes to re-check here) and `../mips32rt/docs/lanes/phase-6.md`
(CLI/execfn/image-fd/host-check shape).

---

### Lane `L6a` — Host-Contract Surface: CLI, Descriptors, Sysroot, Cache/Family, Page Rules (Wave 1)
- **Worktree**: `../mips64rt-l6a` on branch `lane/phase-6-l6a`
- **Exclusive Files**: `src/main.c` (CLI parsing only), new
  `src/os/host_args.c` + `src/os/host_args.h` (arg/env parsing only),
  `src/os/mem.c` (page-rule compliance only), additive `src/rt64/`
  wiring (family join/create, AOT digest), `tests/check_host_contract.c`
  (new, host-native like `check_abi_invariants.c`),
  `tests/p6_host_check.sh` (new). Do NOT touch frozen headers or the
  `Makefile` (the coordinator wires the new TU + `--help` text after
  the merge).
- **Task**:
  1. Read `../rt-series/docs/HOST-CONTRACT.md` §3 (CLI/env/descriptor
     rules), §5 (Class-B authorities/broker), §2.1 (4 KiB page rules)
     first; inventory which `src/rt64/*` pieces are already live vs
     stub (aot digest, family broker, page_rules).
  2. `src/os/host_args.[ch]`: parse `--sysroot/--rootfs DIR`
     (`MIPS64RT_SYSROOT`/`MIPS64RT_ROOTFS`), `--cache/--cache-dir DIR`
     (`MIPS64RT_CACHE`/`MIPS64RT_CACHE_DIR`), `--engine interp|dbt`
     (`MIPS64RT_ENGINE`), `--execfn PATH` (`MIPS64RT_EXECFN`),
     `--image-fd FD`, `--cache-authority/--file-identity/
     --family-authority auto|...` (parse; `auto` admits local Linux,
     anything else declines with a clear diagnostic); validate
     ranges; expose one struct + parse function `main.c` calls.
     `--execfn` decouples the guest path/`AT_EXECFN` from
     `argv[0]` (remaining args verbatim); without it, `argv[i]`
     stays both path and `argv[0]` (backward compatible).
  3. Descriptor hygiene (contract §3.1): `AT_EXECFD` presence via
     `errno`-checked `getauxval` (0 with `errno == 0` is a valid fd)
     or raw auxv scan; `--image-fd FD`/`AT_EXECFD` supplies the main
     ELF image (`pread`-position-independent load, `close()` after
     mapping; never touch fds `0,1,2` or other caller fds).
  4. Guest sysroot prefix (path translation only, not sandboxing):
     resolve the `PT_INTERP` pathname and absolute guest paths
     against `--sysroot` when set (loader + `mips_sc_exec` follow
     the same helper; keep the no-sysroot behavior byte-identical).
  5. Wire the AOT cache identity + family broker: SHA-256 runtime
     digest at startup (existing `src/rt64/aot/*`), `--cache-dir`
     entries keyed by it, join-or-create
     `.mips64rt-family-<pid>-<seq>` per contract §5 (never conflate
     the three authorities).
  6. `src/os/mem.c`: verify contract §2.1 page rules (`mmap`
     misaligned `MAP_FIXED`/bad offset/`len == 0` → `EINVAL`;
     `mprotect`/`munmap` alignment, `munmap len == 0` → `EINVAL`
     vs `mprotect len == 0` no-op; `mremap` alignment/zero-size;
     `brk` byte-exact with 4 KiB backing) and fix gaps found.
  7. `tests/check_host_contract.c` (host-native `cc` build, no
     Docker): static-PIE with zero `DT_NEEDED`, `--help` lists the
     contract flags, cache entries key by the runtime digest,
     page-rule unit probes. `tests/p6_host_check.sh`: no-device
     fallback, `--execfn` custom `argv[0]`, `--image-fd` load,
     `AT_EXECFN` presence, `--sysroot` interp resolution; all PASS.
- **Acceptance Command** (bounded, in worktree):
  `sh tests/p6_host_check.sh` exit 0 AND the host-native contract
  check builds + passes.

---

### Lane `L6b` — Adjacent 4 KiB Page Permissions + Perms Gate (Wave 1, parallel-safe)
- **Worktree**: `../mips64rt-l6b` on branch `lane/phase-6-l6b`
- **Exclusive Files**: `tests/test_p6_perms.c` (new),
  `tests/run_p6_perms.sh` (new) only. No `src/` edits (page-rule
  *fixes* belong to L6a; report gaps instead of touching `src/`).
- **Task**:
  1. `tests/test_p6_perms.c` (freestanding, musl-static style like
     `test_p1_isa.c`; N64 + N32 variants via `-mabi=64/-mabi=n32`):
     adjacent 4 KiB pages with distinct permissions
     (`PROT_READ|PROT_EXEC` next to `PROT_READ|PROT_WRITE`,
     `PT_GNU_RELRO`-style RX-then-RW split); guest faults land
     exactly on the guarded page with the right `si_code`;
     `PROT_NONE` adjacency kills with `SIGSEGV`; `mprotect`
     transitions RX→RW→RX keep neighbors exact. Deterministic
     P6-PASS/P6-FAIL protocol + `P6-RESULT`, exit 0 iff zero
     failures; LE+BE.
  2. `tests/run_p6_perms.sh` (mirrors `run_p5_busybox.sh` structure):
     build all four variants in Docker, capture qemu goldens, run
     `--interp` + `--dbt`, byte-compare; `P6-RESULT: PASS` exit 0
     iff every check passes on both engines. Record the exact
     toolchain recipe in the script header.
- **Acceptance Command** (bounded, in worktree):
  `sh tests/run_p6_perms.sh` exit 0 (perms PASS on both engines).

---

## RC6 gate (coordinator, after all lanes merge)

1. Merge L6a/L6b (`--no-ff`); wire the new `host_args` TU into the
   `Makefile` + `--help` text (coordinator-owned, lane-frozen).
2. Re-run `tests/p6_host_check.sh`, `tests/run_p6_perms.sh`, the
   host-native `check_host_contract`, plus P1 (`rc1_interp_check.sh`),
   P3, P4, P5 (`run_p5_busybox.sh`) gates on both engines × LE+BE
   with `0` divergences.
3. `make check`, `make check-line-limits` pass; tick `GOAL.md`.
