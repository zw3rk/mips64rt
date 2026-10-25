# E03 Findings — N64 & N32 `rt_sigframe` Layout and 128-Signal UAPI

All values below are qemu-verified ground truth unless marked otherwise.
Reproduce: `sh experiments/E03/run.sh` (host; delegates to a unique
`debian:stable-slim --platform linux/arm64` container, `--memory 2g
--cpus 2`, apt-installs the toolchain, builds all four ABI/endian
variants, runs each under its qemu with `timeout --kill-after=30s`).
Raw outputs: `experiments/E03/logs/` (per-variant `.stdout`/`.stderr`,
build errors, copied UAPI headers). Binaries: `experiments/E03/bin/`.

Reference method: `mips32rt` E04 (O32 `rt_sigframe`); this lane is its
MIPS64 (N64+N32, LE+BE) analogue. (The `mips32rt` E03 card covers FPU
NaN semantics, not signals; the topical reference is E04.)

## 1. Toolchain / oracle identity (exact)

| Item | Identity |
|---|---|
| LE cross-CC | `mips64el-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| BE cross-CC | `mips64-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| LE oracles | `qemu-mips64el version 10.0.13`, `qemu-mipsn32el version 10.0.13` (both `Debian 1:10.0.13+ds-0+deb13u1`) |
| BE oracles | `qemu-mips64 version 10.0.13`, `qemu-mipsn32 version 10.0.13` (same build) |
| Host container | `debian:stable-slim` on linux/arm64, packages: `gcc/g++-mips64el-linux-gnuabi64`, `gcc/g++-mips64-linux-gnuabi64`, `libc6-dev-mips64el-cross`, `libc6-dev-mipsn32-mips64el-cross`, `libc6-dev-mips64-cross`, `libc6-dev-mipsn32-mips64-cross`, `libn32gcc-14-dev-mips64{el-,}cross`, `qemu-user`, `file` |
| Containers used | `mips64rt-E03-probe-*` (build+run), `mips64rt-E03-rerun-*` (PASS-line confirmation), `mips64rt-E03-versions-*` (identity), all `--rm` |

## 2. Exact build / run commands

```sh
CFLAGS="-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -march=mips64r2 -static -O1"
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=64 -o bin/probe_n64le probe.c  # run: qemu-mips64el
mips64el-linux-gnuabi64-gcc $CFLAGS -mabi=n32 -o bin/probe_n32le probe.c  # run: qemu-mipsn32el
mips64-linux-gnuabi64-gcc  $CFLAGS -mabi=64 -o bin/probe_n64be probe.c  # run: qemu-mips64
mips64-linux-gnuabi64-gcc  $CFLAGS -mabi=n32 -o bin/probe_n32be probe.c  # run: qemu-mipsn32
timeout --kill-after=30s 60s qemu-mips64el  bin/probe_n64le   # exit 0, E03-RESULT: PASS n64le
timeout --kill-after=30s 60s qemu-mipsn32el bin/probe_n32le   # exit 0, E03-RESULT: PASS n32le
timeout --kill-after=30s 60s qemu-mips64    bin/probe_n64be   # exit 0, E03-RESULT: PASS n64be
timeout --kill-after=30s 60s qemu-mipsn32   bin/probe_n32be   # exit 0, E03-RESULT: PASS n32be
```

All four builds warning-free; all four runs exit `0` with empty
stderr. LE vs BE outputs are byte-identical except runtime
`seen_pc`/`seen_sp` (and the SIGILL `si_addr` overlap quirk, §5).

## 3. `sizeof` table (qemu-verified; N64 vs N32)

| Type | N64 | N32 |
|---|---|---|
| `sigset_t` (glibc) | 128 | 128 |
| `struct sigaction` (glibc) | 152 | 144 |
| `siginfo_t` | 128 | 128 |
| `ucontext_t` (glibc) | 768 | 752 |
| `mcontext_t` (glibc) | 600 | 600 |
| `gregset_t` | 256 (32 × 8) | 256 (32 × 8) |
| `fpregset_t` | 256 (32 × 8) | 256 (32 × 8) |
| `greg_t` | 8 | 8 |
| `struct sigcontext` (glibc = kernel ABI64/N32 layout) | 600 | 600 |
| `struct stat` (glibc) | 216 | 160 |
| `struct stat64` (glibc) | 216 | 176 |
| `stack_t` (glibc) | 24 | 12 |

`greg_t` is 64-bit on **both** ABIs (glibc comment: "Even in o32 we
assume 64-bit registers, like the kernel"); same 600-byte context on
N64 and N32. Only pointer/word-sized wrappers differ (sigaction,
ucontext header, stack, stat).

## 4. Offsets (qemu-verified)

Shared on N64 and N32 (`mcontext_t` ≡ `struct sigcontext` field for field):

| Field (`mcontext` / `sigcontext`) | Offset | Size |
|---|---|---|
| `gregs` / `sc_regs[32]` | 0 | 256 (32 × u64) |
| `fpregs` / `sc_fpregs[32]` | 256 | 256 (32 × u64) |
| `mdhi` / `sc_mdhi` | 512 | 8 |
| `hi1` / `sc_hi1` | 520 | 8 |
| `hi2` / `sc_hi2` | 528 | 8 |
| `hi3` / `sc_hi3` | 536 | 8 |
| `mdlo` / `sc_mdlo` | 544 | 8 |
| `lo1` / `sc_lo1` | 552 | 8 |
| `lo2` / `sc_lo2` | 560 | 8 |
| `lo3` / `sc_lo3` | 568 | 8 |
| `pc` / `sc_pc` | 576 | 8 |
| `fpc_csr` / `sc_fpc_csr` | 584 | 4 |
| `used_math` / `sc_used_math` | 588 | 4 |
| `dsp` / `sc_dsp` | 592 | 4 |
| `__glibc_reserved1` / `sc_reserved` | 596 | 4 |
| total | — | **600** |

ABI-dependent wrappers:

| Field | N64 | N32 |
|---|---|---|
| `sigaction.sa_flags` | 0 | 0 |
| `sigaction.sa_handler` | 8 | 4 |
| `sigaction.sa_mask` | 16 (128 B) | 8 (128 B) |
| `sigaction.sa_restorer` | 144 | 136 |
| `ucontext.uc_flags` | 0 | 0 |
| `ucontext.uc_link` | 8 | 4 |
| `ucontext.uc_stack` | 16 | 8 |
| `ucontext.uc_mcontext` | 40 | 24 |
| `ucontext.uc_sigmask` | 640 (128 B) | 624 (128 B) |
| `stack_t.ss_sp` / `.ss_size` / `.ss_flags` | 0 / 8 / 16 | 0 / 4 / 8 |
| `siginfo.si_signo` / `.si_code` / `.si_errno` | 0 / 4 / 8 | 0 / 4 / 8 |

## 5. Runtime observations (all four variants)

- Real `SIGSEGV` (null store, `siglongjmp` recovery) → handler ran:
  `got_sig=11`, `got_code=1` (`SEGV_MAPERR`), `seen_addr=0x0`,
  `seen_pc`/`seen_sp` nonzero code/stack addresses,
  `seen_fpc_csr=0x0`. Exit path continues to the SIGILL stage.
- `raise(SIGILL)` → handler ran: `got_sig=4`, `got_code=-6`
  (`SI_TKILL`, the `raise()` path). `seen_addr` holds the kill-union
  pid/uid overlap, not a fault address: `0x458` (N64LE), `0x45d`
  (N32LE), `0x467` (N32BE), `0x46200000000` (N64BE, pid in high word —
  qemu-user BE packing quirk in the reused field; the signal/code
  delivery itself is correct on all four).
- `sa_mask` spans both halves of the 16-byte kernel set (signals 64
  and 120 blocked during handler) on every variant.
- Raw `rt_sigprocmask` sigsetsize probe: `size=16 → 0, errno=0`;
  `size=8 → -1, errno=22 (EINVAL)` — all four variants. qemu enforces
  the 16-byte kernel set size for N64 and N32 alike.
- Constants (glibc): `_NSIG=128`, `NSIG=128`, `SIGRTMIN=34`,
  `SIGRTMAX=127`, `SI_QUEUE=-1`.
- `sigfillset` coverage: members 1, 31, 64, 120, 127 present;
  **member 32 absent (0)** — signals 32/33 are NPTL-reserved, hence
  glibc `SIGRTMIN=34` (kernel `asm/signal.h` says `SIGRTMIN=32`).
- No inline assembly in the probe (pure C11 + libc), so there are no
  instruction encodings to record for this lane.

## 6. `sc_cause` is absent on MIPS64 (header evidence + compile proof)

- `grep -rn sc_cause` over the installed `asm/sigcontext.h` and
  glibc `bits/sigcontext.h` (`logs/sc_cause.grep`) finds only two
  **comments**: kernel `sc_hi1; /* Was sc_cause */` inside the
  `#if _MIPS_SIM == _MIPS_SIM_ABI32` (O32-only) struct, and glibc's
  `sc_cause -> sc_hi1` rename note. No `sc_cause` field exists.
- The ABI64/N32 `struct sigcontext` (kernel and glibc agree exactly)
  is `{ sc_regs, sc_fpregs, sc_mdhi, sc_hi1..3, sc_mdlo, sc_lo1..3,
  sc_pc, sc_fpc_csr, sc_used_math, sc_dsp, sc_reserved }` — 600 bytes,
  no `regmask`/`status`/`fpc_eir`/`ownedfp` either (those are O32-only).
- Compile proof: `probe.c` takes `offsetof` of every field above and
  builds `-Werror` clean on all four variants; a `sc_cause` member
  would not compile.

## 7. Kernel `rt_sigframe` reconstruction (header-derived, UNVERIFIED by execution)

qemu-user cannot execute kernel `signal.c`; this frame is derived from
the installed UAPI headers (`asm/signal.h`, `asm/ucontext.h`,
`asm/sigcontext.h`, copies in `logs/`), not observed at runtime:

- Kernel `sigset_t` = `_NSIG_WORDS × word`: N64 `2 × 8` = **16 B**,
  N32 `4 × 4` = **16 B** (`_NSIG_WORDS = _NSIG/_NSIG_BPW`).
- Kernel `struct sigaction` = `{ u32 sa_flags; handler; sigset(16 B) }`:
  N64 `4+pad+8+16` = **32 B**, N32 `4+4+16` = **24 B** (no restorer).
- Kernel `struct ucontext` = `{ ulong uc_flags; uc_link*; stack_t;
  struct sigcontext(600 B); sigset_t(16 B) }`: N64 `8+8+24+600+16` =
  **656 B**, N32 `4+4+12+600+16` = **640 B** (aligned).
- Kernel `rt_sigframe` ≈ `{ siginfo_t(128 B) + struct ucontext }`
  plus the trampoline: ≈784 B (N64) / ≈768 B (N32) before the stub.
  Exact final size/alignment comes from `arch/mips/kernel/signal.c`
  (`setup_rt_frame`) — left to Phase 0 against real-kernel sources.

## 8. UNVERIFIED / limits (honest)

- §7 is header arithmetic, not a runtime observation (same caveat as
  O32 E04 §8).
- qemu 10.0.13 is the oracle here, not silicon; the N64BE SIGILL
  `si_addr` packing (§5) is a qemu reporting quirk.
- Kernel `stat` layouts (vs glibc `stat`/`stat64` in §3) are not
  resolved in this lane; recorded sizes are glibc-side only.
