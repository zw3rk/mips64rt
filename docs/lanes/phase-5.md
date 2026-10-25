# Phase 5 Task Cards — Dynamic Linking (`PT_INTERP`), `BusyBox` (`mips64rt`)

Run after `RC4` (`dee416c`) is committed on `master`. Frozen contracts:
`src/core/cpu.h`, `src/os/syscall_nr.h`, `Makefile`, SPEC 1.1 (window) +
dynamic-linkage section. Loader maps `ET_EXEC`/`ET_DYN` static guests
(`src/loader.c`, 691 lines) with auxv (`AT_PHDR/AT_ENTRY`,
`AT_UID/AT_EUID/AT_GID/AT_EGID`, `AT_RANDOM`, `AT_EXECFN`, ...) and a
guest-visible auxv copy already staged in `ctx->auxv_data`/`auxv_bytes`
for the `/proc/self` layer. No `PT_INTERP`, no `AT_BASE`/`AT_HWCAP2`,
no `/proc/self/*` interception yet.

Shared rules: curated C11, every file <= 900 lines, no `x18`, W^X +
I-cache discipline kept, no AI/agent names, never `git push`. RC5
integration by the coordinator after all lanes merge; P1/P3/P4 suites
are re-run against the final binary.

Reference: `../loongarch64rt/docs/lanes/phase-5.md` (Class-B 64-bit,
same substrate layout; its RC5 close-out notes record environment
repairs worth re-checking here: `O_*` guest<->host flag translation,
`getdents64` passthrough, host-env scrubbing for `ld.so`, `execve`
fallthrough to host for non-guest binaries and `#!` scripts).
`qemu-mips64el / qemu-mips64 / qemu-mipsn32el / qemu-mipsn32`
(qemu-user 10.0.13, image `mips64rt-qemu:10.0.13`) is the oracle.

---

### Lane `L5a` — `PT_INTERP` Loader, Full auxv, `/proc/self/*`
- **Worktree**: `../mips64rt-l5a` on branch `lane/phase-5-l5a`
- **Exclusive Files**: `src/loader.c` (additive: `PT_INTERP`, `AT_BASE`,
  `AT_HWCAP2` only), `src/os/proc.c` (new: `/proc/self/*` interception)
  + minimal dispatch glue in `src/os/syscalls.c` only
- **Task**:
  1. Read `src/loader.c` fully first (ELF parse, `ET_DYN` bias, auxv
     block, `build_stack` argv/envp layout — honor the L4a/L4c argv
     fix, do not regress it).
  2. `PT_INTERP`: when the guest has one, map the named interpreter
     at its own load bias (a second fixed bias distinct from the exe
     bias; document both), set `AT_ENTRY` to the exe entry, add
     `AT_BASE` (interp base) and `AT_HWCAP2`, keep `AT_PHDR/PHENT/PHNUM`
     describing the *exe* (as the kernel does), and transfer control
     to the *interpreter* entry instead of the exe entry. No
     `DT_NEEDED`/relocation engine in the translator: `ld.so` does
     that work itself.
  3. `src/os/proc.c` (new, `<= 900 LOC`): intercept `open`/`openat` of
     `/proc/self/{exe,maps,cmdline,stat,auxv}` and serve
     guest-accurate content from translator state (`exe` -> guest path,
     `maps` -> guest mappings from the region table, `cmdline` ->
     guest argv, `stat` -> guest pid/comm/state, `auxv` -> the
     `ctx->auxv_data` block). Reads/lseek on these synthetic fds behave
     like small read-only files.
  4. Watch-items from the sibling Class-B bring-up (verify, do not
     assume): guest<->host `O_*` flag values in `openat`, `getdents64`
     passthrough, scrub host-only env (`LD_*`, `MIPS64RT_*`) from the
     guest envp so `ld.so` never sees it.
- **Acceptance Command** (bounded, in worktree): dynamic hello +
  `dlopen`/`dlsym` + `__thread` TLS guest (lane-built, recipe in a
  header comment) matches the `qemu-mips64el` golden byte-for-byte
  under `--interp`.

---

### Lane `L5b` — Dynamic `test_p5_dyn` + Target `BusyBox` Suite (Wave 2)
- **Worktree**: `../mips64rt-l5b` on branch `lane/phase-5-l5b`
- **Exclusive Files**: `tests/test_p5_dyn.c` (new), `tests/p5_dynlib.c`
  (new, the `.so` side), `tests/run_p5_busybox.sh` (new) only
- **Task**:
  1. First: `git fetch origin lane/phase-5-l5a` + merge; STOP and
     report back if L5a is incomplete (two-failure escalation rule).
  2. `tests/test_p5_dyn.c`: dynamic `dlopen`/`dlsym` of `p5_dynlib.so`
     (built `-shared -fPIC` alongside), `__thread` TLS access across
     the library boundary, shared-library calls (`printf`/`qsort` via
     target libc), `argv`/`envp`/`auxv` self-check
     (`getauxval(AT_ENTRY)` == main entry, `AT_BASE` != 0,
     `AT_PAGESZ`/`AT_CLKTCK` assertions), `/proc/self/{maps,cmdline}`
     content checks (guest mappings + argv[0] present, never host
     paths). Deterministic output (no pointers/ASLR-dependent bytes;
     sort before printing). N64 + N32 variants like the P4 gate.
  3. `tests/run_p5_busybox.sh`: target `BusyBox` (static or dynamic
     build for `mips64el`, fetched/built in Docker; record the exact
     recipe in the script header): `sh -c 'ls / && echo ok | wc -c'`
     byte-identical vs qemu on both engines.
- **Acceptance Command** (bounded, in worktree):
  `sh tests/run_p5_busybox.sh` exit 0 (BusyBox PASS on both engines).

---

## RC5 gate (coordinator, after all lanes merge)

1. Merge L5a/L5b (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/test_p1_isa`, `tests/test_p3_fp_simd`,
   `tests/test_p4_threads_signals` under `--interp` and `--dbt`
   (all four ABI/endian variants; dynamic libc now live).
3. New `tests/test_p5_dyn` + BusyBox match the `qemu-mips*` goldens
   on both `interp` and `dbt` with `0` difftest divergences
   (single-threaded portions; P4-style spin-count nondeterminism
   stays excluded per the RC4 note).
4. `make check`, `make check-line-limits` pass; tick `GOAL.md`.
