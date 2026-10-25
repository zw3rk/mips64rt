# Phase 1 Task Cards — Base Integer Decoder, Reference Interpreter & Minimal Syscalls (`mips64rt`)

Run after `RC0` is merged to `master`. Frozen contract: `src/core/cpu.h`
(`mips_dec_t`, `mips_decode`/`mips_fetch`, `interp_step`/`interp_run`,
`guest_*`, `mips_fault`, `mips_syscall`, `mips64_guest_ptr`, `MIPS_FAULT`,
`mips_is_be`/`mips_is_n32`) + `src/os/syscall_nr.h` (N64/N32 numbers).
Code against the headers, not each other.

Shared rules: curated C11 (`-std=c11 -Werror=vla -pedantic -Wall -Wextra
-Werror`), every file <= 900 lines, never touch `x18`, no AI/agent names.
`$0` stays 0: any write to `gpr[0]` is discarded by the writer.
Canonical 32-bit sign-extension (E02): every 32-bit op writes
`(uint64_t)(int64_t)(int32_t)res32`. Delay slots: every branch/jump
executes `pc+4` then transfers control, `ra = pc+8` on links;
branch-likely annuls `pc+4` when not taken (no fetch, no fault);
cross-page branch at `(pc & 0xfff) == 0xffc` steps one instruction at a
time (no block formation in Phase 1). `LL`/`SC`/`LLD`/`SCD`: `llbit`/
`lladdr`/`llval` per SPEC 2.2 and E05; any helper/syscall clears `llbit`.
Unaligned `LW`/`SW`/`LD`/`SD` fault (`mips_fault`); `LWL`/`LWR`/`SWL`/`SWR`
and `LDL`/`LDR`/`SDL`/`SDR` compose bytes via `guest_ld8`/`guest_st8`
per the E02 tables as corrected at RC1 — the MIPS IV pseudocode with
endian-swapped spans and fixed placement (see `experiments/E02/FINDINGS.md`).
On BE the canonical pair round-trips; on LE it architecturally cannot
compose a full word, and both oracle and interpreter record the same
`P1-FAIL`s (LE parity holds including the FAILs). N64/N32 syscall convention per SPEC 2.2
and E01 (6 register args in `$a0..$a5`, `$a3` error flag, bases
5000/6000). COP1 data movement (`LWC1`/`SWC1`/`LDC1`/`SDC1`/`MFC1`/`MTC1`/
`CFC1`/`CTC1`, no arithmetic) is integer-adjacent and required for static
binaries — implement in Phase 1; all other COP1/COP2 goes to `mips_fault`
(Phase 3 owns arithmetic). Faults in Phase 1: `mips_fault` records
`EXIT_FAULT`; `interp_run` returns and the process exits 139.

Guest memory model (lane L1c): single host-VA reservation of `task_size`
bytes (`PROT_NONE`, `MAP_NORESERVE`) at `ctx->guest_base`; guest mappings
placed `MAP_FIXED` inside it; `mips64_guest_ptr` translates. Tracked in
`ctx->regions` for maps-gap queries. The rt64 family-broker integration
lands with Phase 4/6 and keeps `guest_base` as the process window base.

---

### Lane `L1a` — Instruction Decoder + Self-Test
- **Worktree**: `../mips64rt-l1a` on branch `lane/p1-l1a`
- **Exclusive Files**: `src/interp/decode.c`, `src/interp/decode.h`, `tests/test_decode.c`
- **Task**:
  1. Implement `mips_decode` (pure field splitter, fills every `mips_dec_t`
     field) and `mips_fetch` (endianness-aware via `mips_is_be`, fault on
     bad `pc`) in `src/interp/decode.c`; `decode.h` re-exports the contract
     from `src/core/cpu.h` plus pure classifiers (branch/jump/load/store/
     trap) as needed. Cover all SPEC 2 integer/FP-trap major opcodes
     (SPECIAL, SPECIAL2, SPECIAL3, REGIMM, COP0/COP1, LB..SD, LWL..SDR,
     CACHE/PREF, SYSCALL/BREAK/TEQ-TLT families).
  2. Write `tests/test_decode.c`: table-driven host-native self-test
     (fixed instruction words → expected fields, LE+BE fetch via a scratch
     `guest_base` window).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc tests/test_decode.c src/interp/decode.c src/os/mem.c -o /tmp/test_decode && /tmp/test_decode
  ```
  (If `src/os/mem.c` is not on master yet, stub `guest_mem_init` locally in
  the test and note it; do not create `src/os/mem.c`.)

---

### Lane `L1b` — Base Integer Reference Interpreter
- **Worktree**: `../mips64rt-l1b` on branch `lane/p1-l1b`
- **Exclusive Files**: `src/interp/interp.c`, `src/interp/interp.h`, `src/interp/unaligned.c`, `src/interp/fpmove.c`
- **Task**: Implement `interp_step`/`interp_run` for the full SPEC 2
  integer subset: 32-bit ALU with sign-extension (ADD/ADDU/SUB/SUBU/AND/
  OR/XOR/NOR/SLT/SLTI*/LUI/ADDIU), 64-bit ALU (DADD/DADDU/DSUB/DSUBU/
  DADDIU), shifts (SLL/SRL/SRA/SLLV/SRLV/SRAV + DSLL[V/32]/DSRL[V/32]/
  DSRA[V/32]/DROTR[V/32]/ROTR), DEXT*/DINS*/DSBH/DSHD/DCLO/DCLZ per E02,
  multiply/divide (MULT/MULTU/DIV/DIVU/DMULT/DMULTU/DDIV/DDIVU via `hi`/
  `lo`, MFHI/MFLO/MTHI/MTLO), branches/jumps (BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ/
  BLTZAL/BGEZAL + likely variants with annul, J/JAL/JR/JALR, SYSCALL/
  BREAK → dispatcher/fault), loads/stores (LB/LBU/LH/LHU/LW/LWU/LD/SB/SH/
  SW/SD with alignment faults, LWL/LWR/SWL/SWR + LDL/LDR/SDL/SDR per the
  E02 manual-correct tables, LWU zero-extends), LL/SC/LLD/SCD per E05,
  `RDHWR $29` (returns `ulr`; other selectors → fault), traps
  (TEQ/TNE/TGE/TLT + immediates → `mips_fault` when the condition fires),
  CACHE/PREF (NOP), MFC0/DMFC0 only for the wired `ulr` alias (others →
  `mips_fault`), COP1 data movement in `fpmove.c` (LWC1/SWC1/LDC1/SDC1/
  MFC1/MTC1/CFC1/CTC1; arithmetic → fault). `interp.h` holds
  lane-internal helpers only. No FP arithmetic (Phase 3 → fault).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/interp.c -o /tmp/interp.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/unaligned.c -o /tmp/unaligned.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/fpmove.c -o /tmp/fpmove.o
  ```
  (Full execution is the RC1 gate after all lanes merge; report it deferred.)

---

### Lane `L1c` — Guest Memory + Minimal Syscalls + ELF Loader
- **Worktree**: `../mips64rt-l1c` on branch `lane/p1-l1c`
- **Exclusive Files**: `src/os/mem.c`, `src/os/syscall_min.c`, `src/loader.c`, `src/loader.h`
- **Task**:
  1. `src/os/mem.c`: `guest_mem_init` (reserve `task_size` host VA via
     `mmap(PROT_NONE, MAP_NORESERVE)` at any host address, record
     `guest_base`; N64 `1ULL<<40`, N32 `0x7fff8000`), endianness-aware
     `guest_ld/st8/16/32/64` with alignment faults for 16/32/64-bit
     accesses and `MIPS_FAULT` on unmapped pages; `mips_fault` (record
     `EXIT_FAULT`, stash fault addr in `exit_info`). Never truncate a
     64-bit guest VA.
  2. `src/os/syscall_min.c`: `mips_syscall` for `exit`, `exit_group`,
     `write`, `read`, `brk`, `mmap`, `munmap`, `mprotect`, `uname`,
     `set_tid_address` (dual numbers from `src/os/syscall_nr.h` selected
     by `ctx->is_n32`); 6 register args `$a0..$a5`; `$a3` convention;
     unknown syscall → `-ENOSYS` with `$a3=1`.
  3. `src/loader.c` + `src/loader.h`: `mips_load_elf` — admit
     `e_machine == EM_MIPS` with `ELFCLASS64`/N64
     (`(e_flags & EF_MIPS_ABI) == 0`) vs `ELFCLASS32`/N32
     (`(e_flags & EF_MIPS_ABI2) == 0x20`); reject others; map `PT_LOAD`s
     `MAP_FIXED` into the reservation with `PROT_EXEC` stripped from host
     data pages (W^X: interp fetches via `mips64_guest_ptr`, never executes
     host-side); build the initial stack (argc/argv/envp/auxv incl.
     `AT_PHDR`/`AT_ENTRY`, `AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID`,
     `AT_CLKTCK=100`) at the per-ABI stack top; set `is_be`/`is_n32`/
     `task_size`/`mmap_base`; entry → `ctx->pc`. Expose
     `int mips_load_elf(mips64_ctx_t *ctx, const char *path, char **argv,
     char **envp)` and `void mips_loader_init_ctx(mips64_ctx_t *ctx)` in
     `src/loader.h` for the RC1 main.c wiring (coordinator-owned).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/mem.c -o /tmp/mem.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/syscall_min.c -o /tmp/syscall_min.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/loader.c -o /tmp/loader.o
  ```
  (Execution is the RC1 gate; report it deferred.)

---

### Lane `L1d` — Freestanding ISA Test Suite + QEMU Goldens
- **Worktree**: `../mips64rt-l1d` on branch `lane/p1-l1d`
- **Exclusive Files**: `tests/test_p1_isa.c`, `tests/run_p1_isa.sh`, `tests/p1_golden_*.txt`
- **Task**:
  1. Write `tests/test_p1_isa.c`: freestanding C + MIPS inline asm,
     `-static`, covering 32-bit ALU sign-extension, 64-bit ALU, shifts,
     DEXT/DINS (E02 values), MULT/DIV (+ hi/lo), all branch types with
     delay slots (taken + not-taken), branch-likely annul at
     `page_end - 4` before a `PROT_NONE` page, `JALR`/`JR`, `LL`/`SC` and
     `LLD`/`SCD` (success + interference-failure), `LWL`/`LWR`/`SWL`/`SWR`
     all alignments, `LDL`/`LDR`/`SDL`/`SDR` pairs checked against the
     MANUAL-correct values (E02 adjudication), `RDHWR`, `LWU`, a deliberate
     unaligned-`LW` fault case in a child process (expect 139 without
     killing the suite), and a raw `write`+`exit` path. Prints
     `P1-RESULT: PASS` + per-check lines.
  2. Write `tests/run_p1_isa.sh`: cross-compiles all four variants
     (`mips64el-linux-gnuabi64-gcc -mabi=64/-mabi=n32`,
     `mips64-linux-gnuabi64-gcc -mabi=64/-mabi=n32`, all `-static`),
     runs each under its qemu (`qemu-mips64el`/`qemu-mipsn32el`/
     `qemu-mips64`/`qemu-mipsn32`) with `timeout --kill-after=30s 60s`,
     captures stdout+exit into `tests/p1_golden_{n64le,n32le,n64be,n32be}.txt`.
     KNOWN: the ten LE unaligned-pair check lines FAIL under
     `qemu-mips64el`/`qemu-mipsn32el` — RC1 verified this architectural
     (the interpreter reproduces qemu-LE byte-identically), not an
     oracle defect. The goldens record qemu's actual output honestly
     and the RC1 gate requires the interpreter to reproduce the same
     FAILs (parity holds including the FAILs).
- **Acceptance Command**:
  ```sh
  sh tests/run_p1_isa.sh && test -s tests/p1_golden_n64le.txt && test -s tests/p1_golden_n32le.txt && test -s tests/p1_golden_n64be.txt && test -s tests/p1_golden_n32be.txt
  ```

---

## RC1 outcome (coordinator integration)

`tests/rc1_interp_check.sh` is the durable gate: rebuilds the translator,
builds all four guests, runs each under `--interp`, and compares against
the committed qemu goldens. BE variants must be byte-identical with exit
0 (`P1-RESULT: PASS`, 134/134). LE variants must be byte-identical with
the golden's own exit (1: the oracle itself records the 10
architecturally-unsatisfiable unaligned LE checks as `P1-FAIL`, and so
does the interpreter — LE parity holds including the FAILs).
Two signal-dependent tests are filtered from the byte comparison with a
tripwire (exactly 2 worker fault lines per variant), deferred to Phase 4
per the mips32rt RC1 precedent: `unaligned-lw-child-faults` (qemu runs
the guest handler, exit 139; the Phase-1 engine has no delivery) and the
`pageend` INFOs (no verdict). The decisive annul proof
(`likely-annul-skips-protnone`) needs no delivery and stays in parity.
RC1 integration fixes on master: `ANDI` zero-extends while
`ORI`/`XORI` preserve high bits; SPECIAL3 `DSBH`/`DSHD` funct `0x24`;
`DINSM` pos `= sa`; LE `LDL`/`LDR`/`SDL`/`SDR` rewritten per the MIPS IV
pseudocode (verified against qemu on a 64-cell table); `llbit` cleared by
every ordinary store; fork plus the fork-equivalent `clone` subset
(MIPS `SIGCHLD` is 18, not 17) plus `wait4` with endian-correct status
for the child-test harness; instruction fetch requires `PROT_EXEC`
(PROT_NONE fetch faults cleanly instead of trapping the host).
Container cleaned afterwards.
