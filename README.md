# `mips64rt` — MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs) User-Mode Binary Translator for AArch64

`mips64rt` is a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **MIPS64r2 (`mips64el` LE & `mips64` BE, N64 & N32 ABIs)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (via [`hyper-linux`](../hyper-linux)).

- **Series Tier**: Tier 2 (Wave 4b — Class-B 64-Bit Full Address Space, N64 & N32 ABIs)
- **Target CPUs**: Loongson 3A3000 (`mips64el` LSB) and Cavium Octeon III (`CN78XX`/`CN73XX`, `mips64` MSB)
- **ELF Admission**: `e_machine == EM_MIPS (8)`, both `ELFCLASS64` (`N64`, `(e_flags & EF_MIPS_ABI) == 0`, syscall base `5000`) and `ELFCLASS32` (`N32`, `(e_flags & EF_MIPS_ABI2) == 0x20`, syscall base `6000`)
- **Guest `TASK_SIZE`**: `N64: 1ULL << 40 (1 TiB xuseg); N32: 0x7fff8000ULL (2 GiB useg so all pointers fit in signed 32-bit)`
- **Dual Execution Engines**:
  1. `src/interp/` — Portable Curated C11 reference interpreter and differential oracle (`MIPS64RT_ENGINE=interp`)
  2. `src/dbt/` — Direct-mapped + IBTC AArch64 dynamic binary translator (`MIPS64RT_ENGINE=dbt`, default) with single-instruction interpreter fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP`)

---

## Key Documents

| Document | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Repository ground rules, Curated C11 & AArch64 ABI invariants, Muse Spark Coordinator + Parallel Worker-Lane worktree protocol, and host environment notes. |
| [`SPEC.md`](SPEC.md) | Complete technical specification for `mips64rt` (CPU context, ISA semantics, syscall/signal/thread ABI, host contract, and 9-phase verification pipeline). |
| [`GOAL.md`](GOAL.md) | Executable `/goal` specification for autonomous Muse Spark implementation (`Phase E` -> `Phase 0..Phase 7`). |
| [`docs/lanes/`](docs/lanes/) | Phase task cards (`phase-e.md`, `phase-0.md`, and subsequent phase lane cards). |
| [`../rt-series/`](../rt-series/) | Series-wide architecture (`../rt-series/SPEC.md`), master plan (`../rt-series/PLAN.md`), and host contract (`../rt-series/docs/HOST-CONTRACT.md`). |
