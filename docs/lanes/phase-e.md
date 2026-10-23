# Phase E Task Cards — Empirical Pre-Implementation Experiments (`mips64rt`)

Spawn **concurrent `subagent` worker lanes** for `E01..E06` in isolated worktrees (`../mips64rt-e01` .. `../mips64rt-e06`), merge each into `master`, and verify `RC-E`.

---

### Lane `E01` — N64 (Base 5000) vs N32 (Base 6000) Syscalls & `TASK_SIZE` Bounds
- **Worktree**: `../mips64rt-e01` on branch `lane/pe-e01`
- **Exclusive Files**: `experiments/E01/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E01/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E01/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E01/FINDINGS.md
  ```

### Lane `E02` — Canonical 32-Bit Sign-Extension & `DEXT*`/`DINS*`/`LDL`/`LDR`
- **Worktree**: `../mips64rt-e02` on branch `lane/pe-e02`
- **Exclusive Files**: `experiments/E02/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E02/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E02/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E02/FINDINGS.md
  ```

### Lane `E03` — N64 & N32 `rt_sigframe` Layout & 128-Signal (`sigsetsize=16`) UAPI
- **Worktree**: `../mips64rt-e03` on branch `lane/pe-e03`
- **Exclusive Files**: `experiments/E03/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E03/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E03/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E03/FINDINGS.md
  ```

### Lane `E04` — Legacy vs IEEE-2008 NaN/ABS FPU Semantics in 64-Bit `FR=1` Mode
- **Worktree**: `../mips64rt-e04` on branch `lane/pe-e04`
- **Exclusive Files**: `experiments/E04/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E04/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E04/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E04/FINDINGS.md
  ```

### Lane `E05` — `LL`/`SC` & `LLD`/`SCD` Reservation Semantics
- **Worktree**: `../mips64rt-e05` on branch `lane/pe-e05`
- **Exclusive Files**: `experiments/E05/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E05/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E05/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E05/FINDINGS.md
  ```

### Lane `E06` — TLS (`rdhwr $29` / `set_thread_area`) in N64 and N32
- **Worktree**: `../mips64rt-e06` on branch `lane/pe-e06`
- **Exclusive Files**: `experiments/E06/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E06/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)` and run under `qemu-mips64el (and qemu-mips64 / qemu-mipsn32el)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E06/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E06/FINDINGS.md
  ```

