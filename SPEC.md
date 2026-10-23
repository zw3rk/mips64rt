# `mips64rt` — Technical Specification & Execution Plan

**Target Architecture**: MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)
**Target Host**: AArch64 Linux (`aarch64-unknown-linux-musl` static-PIE) & macOS on Apple Silicon via `hyper-linux` (`hl`)
**Series Tier**: Tier 2 (Wave 4b — Class-B 64-Bit Full Address Space, N64 & N32 ABIs)

---

## 0. Execution Protocol (Muse Spark Coordinator + Parallel Worker-Lane DAG)

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` on `master`) owns frozen headers (`src/core/cpu.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Concurrent Subagents & Workflows**:
     - For every phase (`Phase E`, `Phase 0` .. `Phase 7`), spawn **multiple concurrent `subagent` worker lanes in parallel** using isolated git worktrees (`../mips64rt-<lane>` on branch `lane/<phase>-<lane>`) and use `run_workflow` / `list_workflows` where helpful.
     - Each worker lane has **exclusive file ownership**, codes against **frozen headers**, and runs **one bounded acceptance check** (`timeout --kill-after=30s ...`).
2. **Dual-Oracle Verification**:
   - Every phase validates `src/interp/` against the independent **`qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` ground-truth oracle** first, and then validates `src/dbt/` against `src/interp/` via `--difftest` (`0` register/PC mismatches).

---

## 1. Target Profile, ELF Admission & Substrate Architecture

### 1.1 Target CPUs & ELF Admission
- **Target CPUs**: Loongson 3A3000 (`mips64el` LSB) and Cavium Octeon III (`CN78XX`/`CN73XX`, `mips64` MSB)
- **ELF Admission**: `e_machine == EM_MIPS (8)`, both `ELFCLASS64` (`N64`, `(e_flags & EF_MIPS_ABI) == 0`, syscall base `5000`) and `ELFCLASS32` (`N32`, `(e_flags & EF_MIPS_ABI2) == 0x20`, syscall base `6000`)
- **Guest `TASK_SIZE`**: `N64: 1ULL << 40 (1 TiB xuseg); N32: 0x7fff8000ULL (2 GiB useg so all pointers fit in signed 32-bit)`
- **Ground-Truth Oracle**: `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)`
- **Cross Toolchains**: `pkgsCross.mips64el-linux-gnuabi64 (N64) and pkgsCross.mips64el-linux-gnuabin32 (N32)`

### 1.2 Class-B 64-Bit Full Address Space & `src/rt64/` Copy-First Substrate
- `mips64rt` preserves strict separation between Guest VA (`uint64_t`), Translator VA, and Host GPA. Never truncate 64-bit guest addresses or force a 64-bit guest into a 4 GiB window.
- **Phase 0 Lane `L0a`** copies the proven `rt64` substrate from `../rvrt/src/` into `src/rt64/` and splits any large files so every `.c`/`.h` file is `<= 900` lines (`make check-line-limits`):
  1. `../rvrt/src/memory/{space.c,space.h}` -> `src/rt64/memory/{space.c,space.h}` (parameterized on `N64: 1ULL << 40 (1 TiB xuseg); N32: 0x7fff8000ULL (2 GiB useg so all pointers fit in signed 32-bit)`).
  2. `../rvrt/src/runtime/{family.c,family_mm.c,mm_view.c,file_caps.c,mm_join.c,family_wait.c,family_file_index.c,guest_memory.c,scheduler.c,native_signal.c,safe_syscall_a64.S,exec_state.c}` (+ `.h`) -> `src/rt64/runtime/` (parameterized on `.mips64rt-family-<pid>-<seq>` and `mips64_ctx_t`).
  3. `../rvrt/src/linux/{memory.c,file.c,io.c,poll.c,socket.c,metadata.c,exec_args.c}` (+ `.h`) -> `src/rt64/linux/` plus modular `src/main.c`, `src/rt64/runtime/worker_loop.c`, `src/rt64/linux/signal_core.c`, and `src/linux/signal_frame_mips64rt.c` (all `< 900 LOC`, with signal trampoline placed below the profile's `TASK_SIZE`).
  4. `../rvrt/src/aot/{format.c,reader.c,writer.c}` (+ `.h`) -> `src/rt64/aot/` (parameterized on `mips64rt` `e_machine`, `e_flags`, and endianness).

---

## 2. CPU Context, ISA Semantics & Linux ABI

### 2.1 Profile-Specific `TASK_SIZE` & Address Layout (`N64` vs `N32`)
- **N64 ABI**: `ELFCLASS64`, `e_machine == EM_MIPS (8)`, `(e_flags & EF_MIPS_ABI) == 0`, syscall base `5000`, `TASK_SIZE = 1ULL << 40` (`0x0000010000000000`, 40-bit `xuseg`). Profile placements below `1ULL << 40`: stack top `0x000000ffffff0000`, unhinted `mmap` base `0x0000005500000000`, `PT_INTERP` bias `0x0000007f00000000`, signal return trampoline page **`0x000000fffffe0000`**.
- **N32 ABI**: `ELFCLASS32`, `e_machine == EM_MIPS (8)`, `(e_flags & EF_MIPS_ABI2) == EF_MIPS_ABI2 (0x20)`, 64-bit GPRs/FPRs with **32-bit user pointers**, syscall base `6000`, **`TASK_SIZE = 0x7fff8000ULL` (2 GiB `useg`)** so every `mmap`/`brk`/stack address fits in a signed 32-bit pointer! Profile placements below `0x7fff8000`: stack top `0x7fff0000`, unhinted `mmap` base `0x3f000000`, `PT_INTERP` bias `0x3f800000`, signal return trampoline page **`0x7fff1000`**.

### 2.2 Canonical 32-Bit Sign-Extension, Delay Slots, & NaN Modes
- **Canonical 32-Bit Sign-Extension Rule**: Every 32-bit MIPS64 operation (`ADDIU`, `ADDU`, `SUBU`, `SLL`, `SRL`, `SRA`, `LW`, `MULT`, `DIV`, `ROTR`, `EXT`, `INS`) writes `(uint64_t)(int64_t)(int32_t)res32` (`SXTW Xd, Wd` in A64 DBT).
- **64-Bit Operations**: `DADDIU`, `DADDU`, `DSUBU`, `DSLL[V/32]`, `DSRL[V/32]`, `DSRA[V/32]`, `DROTR[V/32]`, `DMULT[U]`, `DDIV[U]`, `DEXT[M/U]`, `DINS[M/U]`, `DSBH`, `DSHD`, `DCLO`, `DCLZ`, `LD`/`SD`, `LDL`/`LDR`/`SDL`/`SDR`, `LWU`, `LLD`/`SCD`.
- **N64 & N32 Syscall & 128-Signal Subsystem**:
  - 6 register arguments in `$a0..$a5` (`$4..$9`); `$a3 = 0, $v0 = res` on success (`$v0/$v1` for `pipe`); `$a3 = 1, $v0 = +mips_errno` on error.
  - Shares the guest-owned 1..128 MIPS signal subsystem (`SIGEMT=7`, 128-entry action table, 128-bit masks, RT queue for `32..128`). N64/N32 `sigcontext` has no `sc_cause` field; delay-slot faults record `sc_pc = branch_pc` using internal `ctx->in_delay_slot`.

---

## 3. Dual-Engine Design (`src/interp/` + `src/dbt/`)

1. **Reference Interpreter (`src/interp/`)**:
   - Pure Curated C11 step-by-step and chunked interpreter (`interp_step(mips64_ctx_t *ctx)` and `interp_run(mips64_ctx_t *ctx)`).
   - Serves as:
     - Ground-truth reference engine (`MIPS64RT_ENGINE=interp` or `--interp`),
     - Instruction-by-instruction differential oracle (`--difftest`),
     - Single-instruction fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP` -> `interp_step(ctx)` -> resume DBT) for rare system/unaligned/cross-page delay-slot instructions so valid instructions never abort execution.
2. **AArch64 Dynamic Binary Translator (`src/dbt/`)**:
   - Translates guest basic blocks (up to 64 guest instructions, terminating at control transfers or page boundaries) into AArch64 machine code using `a64_emit.[ch]`.
   - Direct block chaining + 4096-entry per-thread Indirect Branch Target Cache (`IBTC`) + Return Address Stack (`RAS`).
   - Enforces W^X (`PROT_READ | PROT_WRITE` during emission -> `PROT_READ | PROT_EXEC` before execution + `__builtin___clear_cache` / `A32H_CAP_ICACHE_TRAP_IALLU`) and self-modifying code (`SMC`) page-version invalidation on `mprotect` / `munmap` / `clear_cache` / guest writes to translated pages.
   - **Never touches `x18`**.

---

## 4. Nine-Phase Implementation Pipeline & Review Checkpoints (`RC`)

| Phase / Gate | Lanes (Run in Parallel Worktrees) | Required Independent Oracle & Acceptance Gate |
|---|---|---|
| **Phase E (`RC-E`)** | `E01` .. `E06` (`experiments/E01..E06/FINDINGS.md`) | All 6 empirical probes compiled with target cross-CC, executed under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)`, and committed with `FINDINGS.md` (`sizeof`/`offsetof` verified). |
| **Phase 0 (`RC0`)** | `L0a` (Substrate copy + build), `L0b` (`tests/check_abi_invariants.c` + CLI smoke) | `aarch64-unknown-linux-musl-gcc -static-pie` builds `_build/mips64rt`; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass; `--version` / `--help` pass in AArch64 Docker container. |
| **Phase 1 (`RC1`)** | `L1a` (Decoder), `L1b` (Integer `src/interp/`), `L1c` (Minimal syscalls `exit`, `write`, `brk`, `mmap`), `L1d` (`test_p1_isa`) | `test_p1_isa` (covering ALU, shifts, branches, delay slots/annul at `page_end - 4` before `PROT_NONE` page, atomics, unaligned accesses) matches `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` exit code and stdout bit-for-bit under `MIPS64RT_ENGINE=interp`. |
| **Phase 2 (`RC2`)** | `L2a` (`src/os/` static libc syscalls + struct translation), `L2b` (`src/dbt/` dispatcher + block cache + IBTC), `L2c` (`src/dbt/emit_int.c`), `L2d` (`difftest` + static libc tests) | `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa`; static `hello`, `printf`, `qsort`, `malloc`, and file I/O match `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` on both `interp` and `dbt`. |
| **Phase 3 (`RC3`)** | `L3a` (`src/interp/fp.c` FPU/SIMD), `L3b` (`src/dbt/emit_fp.c` NEON/FP lowering), `L3c` (`test_p3_fp_simd`) | `test_p3_fp_simd` (NaN modes, rounding, FPU/SIMD corner cases) matches `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` bit-for-bit on both `interp` and `dbt` with `0` difftest divergences. |
| **Phase 4 (`RC4`)** | `L4a` (`rt_sigframe` + `rt_sigaction`/`rt_sigreturn`/altstack), `L4b` (`clone`/TLS/`futex`/reservation invalidation), `L4c` (`fork`/`vfork`/`execve`/`wait4` + `test_p4_threads_signals`) | `test_p4_threads_signals` (signal frame inspection/modification/restoration, `SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`) matches `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` on both `interp` and `dbt`. |
| **Phase 5 (`RC5`)** | `L5a` (`PT_INTERP` dynamic linker loading + auxv + `/proc/self/*`), `L5b` (Dynamic `glibc`/`musl` + `BusyBox` suite) | Dynamic `test_p5_dyn` and `BusyBox` (`sh -c 'ls / && echo ok | wc -c'`) match `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` on both `interp` and `dbt`. |
| **Phase 6 (`RC6`)** | `L6a` (`hyper-linux` host contract & packaging), `L6b` (Both-host parity test suite) | `test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, and `BusyBox` pass on both AArch64 Linux container and `hl` (`hyper-linux`). |
| **Phase 7 (`RC-H`)** | `H1` (`test_h1_smc`), `H2` (`libc-test` + LTP syscall subset -> `docs/h2-report.md`), `H3` (6-step instrumented CoreMark -> `docs/h3-coremark.md`), `H4` (C++17 exceptions/RTTI/TLS smoke) | All 4 hardening gates committed with machine-verified pass counts (`0` unexpected failures) and measured `dbt > interp` speedup in `docs/h3-coremark.md`. |
