# E04 — Legacy vs IEEE-2008 NaN/ABS FPU semantics (MIPS64, FR=1): FINDINGS

Probe: [probe.c](probe.c) · Runner: [run.sh](run.sh)

All claims below are observed output from the container runs. Anything not
directly observed is marked UNVERIFIED. Raw per-variant logs were verified
(`RESULT=PASS` × 4) and then removed from the tree; every value in §4–§7 is
copied verbatim from those logs.

## 1. Toolchain / oracle identities (exact)

| Tool | Identity |
|---|---|
| LE cross compiler | `mips64el-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| BE cross compiler | `mips64-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| LE N64 emulator | `qemu-mips64el version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| BE N64 emulator | `qemu-mips64 version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| LE N32 emulator | `qemu-mipsn32el version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| BE N32 emulator | `qemu-mipsn32 version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| glibc (cross sysroot) | 2.40 (`/usr/mips64el-linux-gnuabi64`, `/usr/mips64-linux-gnuabi64`) |
| binutils | 2.44 (host `readelf`/`objdump`, cross `-objdump` for disasm) |

Host: macOS Apple Silicon; all builds/runs inside one
`debian:stable-slim` container (`--platform linux/arm64`), repo at `/w`.

## 2. Exact build / run commands

```sh
mips64el-linux-gnuabi64-gcc -mabi=64 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -static -O1 probe.c -o out/probe-n64le
mips64el-linux-gnuabi64-gcc -mabi=n32 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -static -O1 probe.c -o out/probe-n32le
mips64-linux-gnuabi64-gcc -mabi=64 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -static -O1 probe.c -o out/probe-n64be
mips64-linux-gnuabi64-gcc -mabi=n32 -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -static -O1 probe.c -o out/probe-n32be
timeout --kill-after=30s 60s qemu-mips64el out/probe-n64le    # E04-RESULT: PASS n64le
timeout --kill-after=30s 60s qemu-mipsn32el out/probe-n32le   # E04-RESULT: PASS n32le
timeout --kill-after=30s 60s qemu-mips64 out/probe-n64be      # E04-RESULT: PASS n64be
timeout --kill-after=30s 60s qemu-mipsn32 out/probe-n32be     # E04-RESULT: PASS n32be
```

All four cross builds are warning-free. Full command is `run.sh`
(`sh experiments/E04/run.sh out`), which additionally records
`readelf -h`, `readelf -A`, and cross-`objdump -d` FP excerpts per
variant plus a `-mnan=2008`/`-mnan=legacy` contrast (§6).
A native contrast build was skipped (no host `cc` for MIPS asm in the
container); the probe guards all MIPS asm with `#ifdef __mips__`.

## 3. `sizeof` / arch-macro table (qemu-verified, all 4 variants)

| Item | n64le | n32le | n64be | n32be |
|---|---|---|---|---|
| `sizeof(float)` | 4 | 4 | 4 | 4 |
| `sizeof(double)` | 8 | 8 | 8 | 8 |
| `_MIPS_SIM` | 3 (N64) | 2 (N32) | 3 (N64) | 2 (N32) |
| `__mips_fpr` | 64 | 64 | 64 | 64 |
| `__mips_nan2008` | 0 | 0 | 0 | 0 |
| `__mips_abs2008` | 0 | 0 | 0 | 0 |
| `__BYTE_ORDER__` | 1234 (LE) | 1234 (LE) | 4321 (BE) | 4321 (BE) |
| ELF class / data | 64 / LSB | 32 / LSB | 64 / MSB | 32 / MSB |

N32 uses ELFCLASS32 (not ELF64); the probe parses `e_flags` at offset 36
for ELF32 vs 48 for ELF64 (an offset-48-only parse misreads N32 flags).

## 4. ELF `e_flags` / EF_MIPS_NAN2008 (probe self-parse == `readelf -h`)

| Variant | `e_flags` (probe) | `readelf -h Flags` | `nan2008` bit (0x400) |
|---|---|---|---|
| n64le | `0x80000007` | `0x80000007, noreorder, pic, cpic, mips64r2` | 0 |
| n64be | `0x80000007` | `0x80000007, noreorder, pic, cpic, mips64r2` | 0 |
| n32le | `0x80000025` | `0x80000025, noreorder, cpic, abi2, mips64r2` | 0 |
| n32be | `0x80000025` | `0x80000025, noreorder, cpic, abi2, mips64r2` | 0 |

No `nan2008` token in any `readelf -h` output: the Debian GCC 14 default
is **legacy NaN** (`__mips_nan2008=0`, §3).

`readelf -A` (all variants): `ISA: MIPS64r2`, `GPR size: 64`,
`CPR1 size: 64`, `FP ABI: Hard float (double precision)`,
`ISA Extension: None`, `ASEs: None` — i.e. scalar FPU only,
**MSA-free by construction and confirmed** (`FLAGS 1: 00000001`).

## 5. FIR / FCSR observations (identical on all 4 variants)

- `fir=0x007f0000`, `f64=1` (FIR bit 22 = F64: 64-bit FPRs present).
- `fcsr-init=0x00000000` (`cause=0x00 enables=0x00 flags=0x00 rm=0`,
  rounding = round-to-nearest).
- `fcsr-final=0x00000000`: no sticky Cause/Flag bit was ever set during
  the whole run, including all sNaN-shaped inputs (§7).
- FR=1 mode itself (CP0 Status.FR) is **UNVERIFIED** — not user-readable;
  evidence is indirect only: N64 ABI requires FR=1, `__mips_fpr=64`,
  FIR.F64=1, and all scalar double ops executed correctly.

## 6. `-mnan=2008` vs `-mnan=legacy` contrast (LE N64, compile only)

- `-mnan=2008`: **build fails** — the Debian cross sysroot ships
  legacy-NaN multilibs only:
  `fatal error: gnu/stubs-n64_hard_2008.h: No such file or directory`.
- `-mnan=legacy`: builds fine, `readelf -h` flags `0x80000007`
  (identical to the default build) — default == legacy confirmed.
- A 2008-encoding binary could therefore not be executed in this
  container; every 2008-vs-legacy behavioural comparison on real
  encoding-selected binaries is **UNVERIFIED**.

## 7. Observed NaN / abs / neg values (identical on all 4 variants)

Default NaN from `0.0/0.0` at runtime: double `0x7ff7ffffffffffff`,
float `0x7fbfffff` — the legacy quiet-NaN shapes (quiet bit clear).

`add=D+` means `add.fmt x,x`; `inv_flag`/`inv_cause` are the FCSR Invalid
flag (bit 2) / cause (bit 12) right after the op:

| Input bits | `isnan` | `add=self` result | `inv` | `abs` result | `inv` | `neg` result | `inv` |
|---|---|---|---|---|---|---|---|
| D `0x7ff8000000000000` (qbit1-nopay) | 1 | `0x7ff7ffffffffffff` | 0/0 | `0x7ff8000000000000` | 0/0 | `0xfff8000000000000` | 0/0 |
| D `0x7ff8000000000001` (qbit1-pay) | 1 | `0x7ff7ffffffffffff` | 0/0 | `0x7ff8000000000001` | 0/0 | `0xfff8000000000001` | 0/0 |
| D `0x7ff0000000000001` (qbit0-lowpay) | 1 | `0x7ff7ffffffffffff` | 0/0 | `0x7ff0000000000001` | 0/0 | `0xfff0000000000001` | 0/0 |
| D `0x7ff7ffffffffffff` (qbit0-fullpay) | 1 | `0x7ff7ffffffffffff` | 0/0 | `0x7ff7ffffffffffff` | 0/0 | `0xfff7ffffffffffff` | 0/0 |
| S `0x7fc00000` (qbit1-nopay) | 1 | `0x7fbfffff` | 0/0 | `0x7fc00000` | 0/0 | `0xffc00000` | 0/0 |
| S `0x7fc00001` (qbit1-pay) | 1 | `0x7fbfffff` | 0/0 | `0x7fc00001` | 0/0 | `0xffc00001` | 0/0 |
| S `0x7f800001` (qbit0-lowpay) | 1 | `0x7fbfffff` | 0/0 | `0x7f800001` | 0/0 | `0xff800001` | 0/0 |
| S `0x7fbfffff` (qbit0-fullpay) | 1 | `0x7fbfffff` | 0/0 | `0x7fbfffff` | 0/0 | `0xffbfffff` | 0/0 |

Sanity rows: `abs`/`neg` on `D -1.5`-shaped `0xc005800000000000`
give `0x4005800000000000` both ways; `S -2.75`-shaped `0xc02c0000`
gives `0x402c0000` both ways (`inv` 0/0 everywhere).

QEMU model finding: **any** NaN input to `add.fmt` yields the default
NaN (`D 0x7ff7ffffffffffff` / `S 0x7fbfffff`) with no Invalid flag or
cause; `abs.fmt` clears only the sign bit and `neg.fmt` flips only the
sign bit, bit-exact, never signalling — even for the legacy-sNaN shapes
(`D 0x7ff8…`, `S 0x7fc0…`). The sNaN-vs-qNaN FCSR distinction is
**not observable under qemu-user 10.0.13**; hardware Invalid behaviour
for sNaN inputs is **UNVERIFIED**.

## 8. Instruction encodings (cross-`objdump -d`, all variants)

| Mnemonic | Encoding | Decode (op `010001`=COP1) |
|---|---|---|
| `cfc1 rt,c1_fcsr` | `0x4442f800` (v0) | rs `00100`=cfc1, rd `11111`=$31 |
| `ctc1 rt,c1_fcsr` | `0x44c2f800` (v0) | rs `00110`=ctc1, rd `11111`=$31 |
| `cfc1 rt,c1_fir` | `0x44450000` (a1) | rd `00000`=$0 (FIR) |
| `add.s` | `0x46000000` | fmt `00000`=s, funct `000000` |
| `abs.s` | `0x46000005` | fmt `00000`=s, funct `000101` |
| `neg.s` | `0x46000007` | fmt `00000`=s, funct `000111` |
| `add.d` | `0x46200000` | fmt `10001`=d, funct `000000` |
| `abs.d` | `0x46200005` | fmt `10001`=d, funct `000101` |
| `neg.d` | `0x46200007` | fmt `10001`=d, funct `000111` |

LE and BE disassemblies agree on encodings (modulo load addresses).

## 9. Phase 0 header inputs (precision summary)

- Default toolchain NaN mode is **legacy** (`e_flags` without 0x400,
  `__mips_nan2008=0`); Debian sysroot cannot build `-mnan=2008`
  (missing `stubs-n64_hard_2008.h`). Headers must assume legacy quiet
  bit polarity unless the translator targets a 2008-capable sysroot.
- FCSR layout confirmed by construction: Cause bits 17:12, Enables
  bits 11:7, Flags bits 6:2 (Invalid = flag bit 2 / cause bit 12),
  RM bits 1:0; qemu-user leaves all of them zero (§5, §7).
- FIR `0x007f0000` (F64=1); FP ABI hard-float double; no MSA ASE.
- N32 is ELFCLASS32 with `e_flags=0x80000025` (`abi2`); N64 is ELFCLASS64
  with `0x80000007`.
- UNVERIFIED (needs 2008-capable toolchain and/or real HW or full-system
  qemu): sNaN Invalid Cause/Flag behaviour of `abs`/`add`, Status.FR
  direct readout, 2008-mode default-NaN shapes.
