# E02 FINDINGS — canonical 32-bit sign-extension, `DEXT*`/`DINS*`, `LDL`/`LDR`/`SDL`/`SDR`

## Verdict summary (all qemu-observed ground truth)

- Sign-extension (`ADDIU`/`ADDU`/`SLL`/`LW`/`LB` vs `LWU`/`LBU`,
  contrasted with `DADDIU`/`DADDU`): **MATCH on all 4 variants**.
- Field ops (`DEXT`/`DEXTM`/`DEXTU`/`DINS`/`DINSM`/`DINSU`):
  **MATCH on all 4 variants**.
- Unaligned pairs, canonical `(0,7)` idiom
  (`LDL Rt,0(X)` + `LDR Rt,7(X)`, `SDL`/`SDR` likewise, `Y = X+7`):
  **BE: MATCH (both ABIs); LE: MISMATCH (both ABIs)** —
  qemu-user LE does not implement the documented pair semantics
  (details below). Whether real silicon matches either behavior is
  **UNVERIFIED** (no hardware available).
- N64 vs N32 outputs are identical within each endianness; only the
  data-model line differs.

## Toolchain (exact, qemu-verified)

| Role | Identity |
|---|---|
| Cross compiler LE | `mips64el-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| Cross compiler BE | `mips64-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| Oracle LE | `qemu-mips64el version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| Oracle LE32 | `qemu-mipsn32el version 10.0.13 (same build)` |
| Oracle BE | `qemu-mips64 version 10.0.13 (same build)` |
| Oracle BE32 | `qemu-mipsn32 version 10.0.13 (same build)` |
| ELF N64LE | `ELF 64-bit LSB executable, MIPS, MIPS64 rel2, statically linked` |
| ELF N32LE | `ELF 32-bit LSB executable, MIPS, N32 MIPS64 rel2, statically linked` |
| ELF N64BE | `ELF 64-bit MSB executable, MIPS, MIPS64 rel2, statically linked` |
| ELF N32BE | `ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2, statically linked` |

## Build / run commands (exact)

```sh
mips64el-linux-gnuabi64-gcc -O2 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -mabi=64 -o probe-n64le probe.c
mips64el-linux-gnuabi64-gcc -O2 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -mabi=n32 -o probe-n32le probe.c
mips64-linux-gnuabi64-gcc  -O2 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -mabi=64 -o probe-n64be probe.c
mips64-linux-gnuabi64-gcc  -O2 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -mabi=n32 -o probe-n32be probe.c
timeout --kill-after=30s 60s qemu-mips64el  ./probe-n64le  # rc=1 (LE unaligned pair, see T12/T13)
timeout --kill-after=30s 60s qemu-mipsn32el ./probe-n32le  # rc=1 (same)
timeout --kill-after=30s 60s qemu-mips64    ./probe-n64be  # rc=0 E02-RESULT: PASS
timeout --kill-after=30s 60s qemu-mipsn32   ./probe-n32be  # rc=0 E02-RESULT: PASS
```

Full script: [run.sh](./run.sh); probe source: [probe.c](./probe.c).
All result lines below are identical across N64/N32 unless noted.

## Data model (observed at runtime)

| Variant | `sizeof(void*)` | `sizeof(long)` | `sizeof(int)` | `sizeof(long long)` | endian |
|---|---|---|---|---|---|
| N64LE | 8 | 8 | 4 | 8 | LE |
| N32LE | 4 | 4 | 4 | 8 | LE |
| N64BE | 8 | 8 | 4 | 8 | BE |
| N32BE | 4 | 4 | 4 | 8 | BE |

## Observed results T1–T11 (MATCH on all 4 variants)

```text
T1a addiu +1:                0x123456789abcdef0 +1      -> 0xffffffff9abcdef1 MATCH
T1b addiu -1:                0x0 + (-1)                 -> 0xffffffffffffffff MATCH
T2a addu wrap-to-zero:       low32(1 + 0xffffffff)=0    -> 0x0000000000000000 MATCH
T2b addu sign-bit:           low32 0x80000000           -> 0xffffffff80000000 MATCH
T3a sll into sign:           0x40000000 << 1            -> 0xffffffff80000000 MATCH
T3b sll sa=0 sext:           0x80000001 << 0            -> 0xffffffff80000001 MATCH
T4a lw sext:                 mem32 0x80000001           -> 0xffffffff80000001 MATCH
T4b lwu zext:                mem32 0x80000001           -> 0x0000000080000001 MATCH
T4c lb sext:                 mem8 0x80                  -> 0xffffffffffffff80 MATCH
T4d lbu zext:                mem8 0x80                  -> 0x0000000000000080 MATCH
T5a daddiu 64-bit:           0x123456789abcdef0 +1      -> 0x123456789abcdef1 MATCH
T5b daddu 64-bit:            same +1                    -> 0x123456789abcdef1 MATCH
T6a dext 8,8     (V):        bits[15:8]                 -> 0x0000000000000032 MATCH
T6b dext 0,32    (V):        bits[31:0]                 -> 0x0000000076543210 MATCH
T7  dextm 16,48  (V):        bits[63:16]                -> 0x0000fedcba987654 MATCH
T8a dextu 48,16  (V):        bits[63:48]                -> 0x000000000000fedc MATCH
T8b dextu 32,32  (V):        bits[63:32]                -> 0x00000000fedcba98 MATCH
T9  dins 8,8:  rd=all1 rs=0xab   -> 0xffffffffffffabff MATCH
T10 dinsm 16,32: rd=0 rs=0xdeadbeef -> 0x0000deadbeef0000 MATCH
T11 dinsu 48,16: rd=0 rs=0x1234    -> 0x1234000000000000 MATCH
```

with `V = 0xFEDCBA9876543210`
(`bits[63:48]=FEDC [47:32]=BA98 [31:16]=7654 [15:0]=3210`).
So 32-bit ops ignore the upper halves of their inputs and
sign-extend bit 31; `LW`/`LB` sign-extend while `LWU`/`LBU`
zero-extend; 64-bit `D*` ops preserve all 64 bits.

## Observed results T12/T13 (endian-split)

Setup: 8-byte-aligned static window, `A = wbuf+8` (`Amod8 = 0`),
`X = wbuf+11` (`Xmod8 = 3`), `Y = X+7 = wbuf+18` (`Ymod8 = 2`),
pattern byte `wbuf[k] = 0xA0+k`, so
`wbuf[11..18] = ab ac ad ae af b0 b1 b2`.
Store value `V = 0xA1B2C3D4E5F60718`.

```text
LE: T12 ldl-only X: rt0=0xabaaa9a800000000 rtFF=0xabaaa9a8ffffffff
LE: T12 ldr-only X: rt0=0x000000afaeadacab rtFF=0xffffffafaeadacab
LE: T12 pair ldl(X)+ldr(X+7): got=0xabaab7b6b5b4b3b2 want=0xb2b1b0afaeadacab MISMATCH
LE: T13 sdl+sdr: guards wbuf[10]=0xb2 wbuf[19]=0x07 MISMATCH (want aa/b3)
LE: T13 footprint wbuf[10:20]: b2 a1 ac ad ae af b0 b1 18 07
BE: T12 ldl-only X: rt0=0xabacadaeaf000000 rtFF=0xabacadaeafffffff
BE: T12 ldr-only X: rt0=0x00000000a8a9aaab rtFF=0xffffffffa8a9aaab
BE: T12 pair ldl(X)+ldr(X+7): got=0xabacadaeafb0b1b2 want=0xabacadaeafb0b1b2 MATCH
BE: T13 sdl+sdr: guards wbuf[10]=0xaa wbuf[19]=0xb3 MATCH
BE: T13 footprint wbuf[10:20]: aa a1 b2 c3 d4 e5 f6 07 18 b3
```

The BE store deposits exactly `V` in BE memory order at
`wbuf[11..18]` with both guards intact — the canonical idiom works.
The LE store writes `V[0]=a1` at `wbuf[11]`, `V[7..6]=18 07` at
`wbuf[18..19]`, leaves the middle untouched, and clobbers both
guards: it does not deposit `V` anywhere.

## Analysis: per-op spans under qemu-user 10.0.13

Decomposing single ops at `X` (`Xmod8 = 3`, word `A`, bytes
`m8..m15 = a8..af`) gives, on **both** endians, with the natural
endian word placement:

| Op | qemu span (observed) | Architectural span (MIPS IV manual) |
|---|---|---|
| `LDL X` | `mem[X..A+7]` (right span) to far end | same: `mem[X..A+7]` to far end |
| `LDR X` | `mem[A..X]` (left span) to near end | same: `mem[A..X]` to near end |
| `SDL X` | `mem[X..A+7]` from `V`-high | same |
| `SDR X` | `mem[A..X]` from `V`-low | same |

i.e. on BE every decomposed span matches the architecture, and the
canonical `(0,7)` pair round-trips both directions. The manual's own
example is exactly this shape: for a doubleword at byte 2, `LDL`
loads the six bytes `mem[2..7]` and the complementary `LDR $24,9`
loads the remainder `mem[8..9]`
(`MIPS IV Instruction Set`, unaligned-doubleword figure; note
`9 = 2+7`). On LE the same-address spans likewise mirror correctly,
but the `(0,7)` pair and both stores diverge as recorded above
(load pair returns a rotated mix, the store scatters outside
`[X..X+7]`). Whether this is a qemu-LE-only defect or also true of
silicon is **UNVERIFIED**. Consequence for DBT work: do not treat
qemu-LE as the oracle for `LDL`/`LDR`/`SDL`/`SDR` codegen; verify
against the BE oracle or the interpreter's byte-order model, and
re-check on hardware when available.

## Instruction encodings (confirmed in objdump, identical LE/BE words)

| Mnemonic (as written) | Word | objdump renders |
|---|---|---|
| `addiu rt,rs,1` | `0x24420001` | `addiu v0,v0,1` |
| `addiu rt,rs,-1` | `0x24c6ffff` | `addiu a2,a2,-1` |
| `addu rd,rs,rt` | `0x00c23021` | `addu a2,a2,v0` |
| `sll rd,rt,1` | `0x00063040` | `sll a2,a2,0x1` |
| `sll rd,rt,0` | `0x00063000` | `sll a2,a2,0x0` |
| `lw rt,0(rs)` | `0x8fa60000` | `lw a2,0(sp)` |
| `lwu rt,0(rs)` | `0x9fa60000` | `lwu a2,0(sp)` |
| `lb rt,0(rs)` | `0x82060000` | `lb a2,0(s0)` |
| `lbu rt,0(rs)` | `0x92060000` | `lbu a2,0(s0)` |
| `daddiu rt,rs,1` | `0x64460001` | `daddiu a2,v0,1` |
| `daddu rd,rs,rt` | `0x0206302d` | `daddu a2,s0,a2` |
| `dext rd,rs,8,8` | `0x7cc63a03` | `dext a2,a2,0x8,0x8` |
| `dext rd,rs,0,32` | `0x7cc6f803` | `dext a2,a2,0x0,0x20` |
| `dextm rd,rs,16,48` | `0x7cc67c01` | `dext a2,a2,0x10,0x30` (func 1) |
| `dextu rd,rs,48,16` | `0x7cc67c02` | `dext a2,a2,0x30,0x10` (func 2) |
| `dextu rd,rs,32,32` | `0x7cc6f802` | `dext a2,a2,0x20,0x20` (func 2) |
| `dins rd,rs,8,8` | `0x7c467a07` | `dins a2,v0,0x8,0x8` |
| `dinsm rd,rs,16,32` | `0x7c467c05` | `dins a2,v0,0x10,0x20` |
| `dinsu rd,rs,48,16` | `0x7c46fc06` | `dins a2,v0,0x30,0x10` |
| `ldl rt,0(rs)` | `0x6a140000` | `ldl s4,0(s0)` |
| `ldr rt,0(rs)` | `0x6e130000` | `ldr s3,0(s0)` |
| `sdl rs,0(rb)` | `0xb0850000` | `sdl a1,0(a0)` |
| `sdr rs,0(rb)` | `0xb4450000` | `sdr a1,0(v0)` |

Formulae used: `ADDIU = 0x24000000|rs<<21|rt<<16|imm`;
`DE/ DINS family = SPECIAL3 (0x1F)`, func `DEXT=3 DEXTM=1 DEXTU=2
DINS=7 DINSM=5 DINSU=6`, `pos` in sa-field, size control in
rd-field; `LDL/LDR/SDL/SDR` major opcodes `0x1A/0x1B/0x2C/0x2D`.

## Assembler note (verified by execution, all 4 toolchain combos)

This GAS (binutils 2.44) spells `DEXTM` as
`dextm rd,rs,pos,POS_PLUS_SIZE`: the 4th operand is `pos+size`
(valid range `33..64`), not `size`. `dextm rd,rs,16,32` is rejected
(`operand 4 out of range`) while `dextm rd,rs,16,48` assembles and
extracts `bits[63:16]`. The sibling `DINSM` keeps the plain
`(pos,size)` spelling (`dinsm rd,rs,16,32` assembles fine).
`DEXTU`/`DINSU` also use plain `(pos,size)`.

## Repro

```sh
cd experiments/E02 && ./run.sh   # needs mips64el/mips64 gcc + qemu-mips64el/qemu-mipsn32el/qemu-mips64/qemu-mipsn32
```

`E02-RESULT: PASS` lines print per binary for BE (`rc=0`); LE
binaries print `E02-RESULT: FAIL` with the exact divergent values
above — that FAIL is the recorded qemu-LE finding, not a probe bug.
Nothing else in this lane is UNVERIFIED except silicon behavior.
