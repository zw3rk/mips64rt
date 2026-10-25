# Phase 3 Task Cards — Floating-Point & SIMD (`RC3`)

Run after `RC2` is merged to `master`. Frozen contracts: `src/core/cpu.h`
(`fpr[32]` at `0x160`, `fcsr`/`FCR31` at `0x128`, FR=1 64-bit lanes,
`MIPS64_EXIT_*`, `MIPS64_CTX_FCSR_OFFSET`), `src/dbt/dbt.h` (host
register map `x19` = ctx, `x20` = guest base, `x21..x24` scratch,
`x25` JR/JALR spill, **never read or write `x18`**), `src/interp/decode.h`,
SPEC §§2–3, and the Phase 1/2 contracts (RC1 span semantics, E05
LL/SC reservation, difftest `I`/`REGS` stream parity).

Shared rules: curated C11 (`-std=c11 -Werror=vla -pedantic -Wall
-Wextra -Werror`), every file ≤ 900 lines (`make check-line-limits`),
W^X + I-cache discipline, Apache-2.0 header on new files
(`Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.`),
no AI/agent names in commits, never `git push`. Bound every build,
Docker, and `qemu-mips64el` / `qemu-mips64` / `qemu-mipsn32el` /
`qemu-mipsn32` oracle run with an explicit wall-clock
`timeout --kill-after=30s`, name every container uniquely
(`--name mips64rt-<lane>-...`), remove containers on exit. A lane stops
and reports back if its acceptance command fails twice, if it needs a
frozen-header edit, or if a spec detail is ambiguous.

Verified cross wrapper (use exactly; other hashes in old cards are
stale): `/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin`.
Lane-local builds append new files to the `make build` command line;
the coordinator alone edits `Makefile`/`GOAL.md` at merge.

RC3 integration (by the coordinator after all lanes merge): wire
`Makefile` (`BOOT_SRCS` gains `src/interp/fp.c` + `src/dbt/emit_fp.c`),
build, run `test_p3_fp_simd` under `qemu` (golden), `interp`, and `dbt`
on all four ABI/endian variants with `0` difftest divergences.

First, every lane reads `SPEC.md` §2 FP/SIMD, `src/interp/fpmove.c`
(existing COP1/COP0 moves), and the qemu oracle before coding: SIMD
scope (paired-single COP1X vs MSA) is adjudicated by experiment —
probe what `qemu-mips64el` / `qemu-mips64` implement for our target
CPUs, record the finding in the lane's commit message, and implement
exactly that (scalar S/D + conversions + compares + `BC1T`/`BC1F` +
likely are mandatory in all cases).

---

### Lane `L3a` — FPU Reference Interpreter (`src/interp/fp.c`)
- **Worktree**: `../mips64rt-l3a` on branch `lane/p3-l3a`
- **Exclusive Files**: `src/interp/fp.c` (new), `src/interp/fpmove.c`
  (extend the `fpmove_cop1` tail only: route arithmetic/branch words to
  `fp.c`, keep all moves bit-identical)
- **Task**:
  1. New `src/interp/fp.c`: COP1 arithmetic in the frozen `fpr`/`fcsr`
     state — `ADD`/`SUB`/`MUL`/`DIV`/`SQRT`/`ABS`/`NEG`/`MOV` (S/D),
     `CVT` family (`S`/`D`/`W`/`L`, `TRUNC`/`CEIL`/`FLOOR`/`ROUND`),
     `C.cond` comparisons + condition bit, `BC1T`/`BC1F` +
     `BC1TL`/`BC1FL` with RC1 delay-slot/annul rules. NaN/rounding per
     SPEC §2 (quiet-NaN propagation, `FCSR` cause/flag sticky bits,
     round-to-nearest default). No host FP control-word changes; do the
     rounding in software or save/restore the host state around the op.
  2. Extend `src/interp/fpmove.c`: arithmetic/branch COP1 words (the
     ones that currently return nonzero) call into `fp.c`; moves,
     `LWC1`/`SWC1`/`LDC1`/`SDC1`, `MFC1`/`MTC1`/`DMFC1`/`DMTC1`,
     `CFC1`/`CTC1` stay exactly as-is.
- **Acceptance Command** (cross compile check; execution is the RC3
  gate — report it deferred):
  ```sh
  PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/fp.c -o /tmp/fp.o && PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/fpmove.c -o /tmp/fpmove.o
  ```

---

### Lane `L3b` — AArch64 FP & NEON Emitter (`src/dbt/emit_fp.c`)
- **Worktree**: `../mips64rt-l3b` on branch `lane/p3-l3b`
- **Exclusive Files**: `src/dbt/emit_fp.c` (new), `src/dbt/emit_int.c`
  (COP1 hook only: route COP1 words to `emit_fp.c` instead of
  `EXIT_UNDEF`; `BC1T`/`BC1F`/likely via the existing `ei_branch`
  shape with an FPU condition source)
- **Task**:
  1. New `src/dbt/emit_fp.c`: NEON/FP lowering of the L3a COP1 set
     using the L2b register map (`x19` ctx, `x20` base, `x21..x24`
     scratch, `x25` spill, never `x18`; FP ctx fields via
     `MIPS64_CTX_FPR_OFFSET`-style offsets already in `cpu.h`).
     FPRs live in ctx memory (spill/fill per word; no pinned host
     FP registers). Match L3a NaN/rounding bit-for-bit (same software
     rounding or host-state discipline). Unknown/phase-gated words
     return nonzero so the dispatcher falls back to `interp_step`.
  2. Hook `src/dbt/emit_int.c`: the COP1 case (currently
     `EXIT_UNDEF`) calls the `emit_fp.c` entry point; keep every other
     opcode byte-identical.
- **Acceptance Command**: same cross `-c` check as L3a for
  `src/dbt/emit_fp.c` and `src/dbt/emit_int.c` (execution is the RC3
  gate).

---

### Lane `L3c` — `tests/test_p3_fp_simd.c` + Guest Fixtures
- **Worktree**: `../mips64rt-l3c` on branch `lane/p3-l3c`
- **Exclusive Files**: `tests/test_p3_fp_simd.c` (new)
- **Task**:
  1. New `tests/test_p3_fp_simd.c` (freestanding, musl-static style
     like `tests/test_p1_isa.c`): scalar S/D arithmetic, conversions
     (incl. `TRUNC`/`CEIL`/`FLOOR`/`ROUND`), NaN propagation, all
     `C.cond` comparisons, `BC1T`/`BC1F`/likely taken+not-taken,
     rounding-mode coverage, plus the adjudicated SIMD scope.
     `P1_CHECK`-style macros renamed `P3_CHECK`; summary +
     `P3-RESULT` line; exit `0` iff zero failures.
  2. Build all four variants with the D2 container toolchains
     (`-mabi=64`/`-mabi=n32` × `mips64el`/`mips64` cross compilers,
     `-O1 -static`, same `CFLAGS` as `run_d2.sh`) into the worktree's
     `_build/` (git-ignored build products, never committed).
  3. Run each variant under its `qemu-` oracle; all four must exit `0`
     with zero `FAIL` lines. Record the qemu versions in the commit
     message.
- **Acceptance Command**: the four `qemu-mips*` runs described above
  (interp/dbt execution is the RC3 gate).
