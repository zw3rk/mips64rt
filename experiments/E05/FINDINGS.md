# E05 FINDINGS — LL/SC and LLD/SCD reservation semantics (N64+N32, LE+BE)

qemu-verified ground truth for all four ABI/endianness combinations.
Every value below was executed under qemu-user; no UNVERIFIED items
except ERET (cannot be executed from user mode — stated explicitly).

## Toolchain identities

| Component | Identity |
|---|---|
| LE compiler | `mips64el-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| BE compiler | `mips64-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0` |
| QEMU (all four) | `qemu-mips64el / qemu-mipsn32el / qemu-mips64 / qemu-mipsn32 version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| Container | `debian:stable-slim` (`--platform linux/arm64`), packages `gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 g++-... libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross qemu-user file` |

## Exact build / run commands

Host (worktree root `../mips64rt-e05`); containers `--rm`, names
`mips64rt-E05-probe-<pid>` / `mips64rt-E05-probe2-<pid>` /
`mips64rt-E05-final-<pid>`, `docker ps` confirms no stray container:

```sh
timeout --kill-after=30s 280s docker run --rm --platform linux/arm64 \
  --name mips64rt-E05-final-<pid> -v "$PWD:/w" -w /w debian:stable-slim \
  sh -c 'apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 ... qemu-user file >/dev/null 2>&1; \
  cd /w/experiments/E05 && sh run.sh'
```

Inside container (`experiments/E05/run.sh`):

```sh
mips64el-linux-gnuabi64-gcc -march=mips64r2 -O1 -static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -mabi=64 -o probe-n64le probe.c
mips64el-linux-gnuabi64-gcc ... -mabi=n32 -o probe-n32le probe.c
mips64-linux-gnuabi64-gcc  ... -mabi=64 -o probe-n64be probe.c
mips64-linux-gnuabi64-gcc  ... -mabi=n32 -o probe-n32be probe.c
timeout --kill-after=30s 60s qemu-mips64el  ./probe-n64le   # exit 0
timeout --kill-after=30s 60s qemu-mipsn32el ./probe-n32le   # exit 0
timeout --kill-after=30s 60s qemu-mips64    ./probe-n64be   # exit 0
timeout --kill-after=30s 60s qemu-mipsn32   ./probe-n32be   # exit 0
```

Notes: `-static` is required (qemu-user has no dynamic-loader sysroot).
`-march=mips64r2` accepted; LL/SC (MIPS II) and LLD/SCD (MIPS III) all
assemble. `readelf -h` reports `ELF64`, `MIPS R3000`, LE/BE as expected.
Probe binaries are deleted by `run.sh`; full logs kept in `out-*.txt`.

Result: `E05-RESULT: PASS` for N64LE, N32LE, N64BE, N32BE (all exit 0,
all printed `DONE`, `FAILURES=0`, 10/10 `E05-PASS` checks each).
Cross-variant diffs touch only the `ABI=`/`SIZEOF` header lines and the
`getpid()` values — every semantic observation is identical on all four.

## sizeof table (observed)

| Type | N64 (n64le, n64be) | N32 (n32le, n32be) |
|---|---|---|
| `int` | 4 | 4 |
| `long` | 8 | 4 |
| `void *` | 8 | 4 |
| `long long` / `uint64_t` | 8 | 8 |
| `uint32_t` | 4 | 4 |

## Observed values table (identical on all four variants)

SC success code: `1` = store committed, `0` = reservation lost, memory
unchanged. Initial `w0 = AAAAAAAA`, `d0 = AAAAAAAAAAAAAAAA` unless noted.

| Sequence | sc | Memory after |
|---|---|---|
| SC32, no prior LL (`w0=AAAAAAAA`, store `55555555`) | 0 | `AAAAAAAA` (kept) |
| SCD64, no prior LL (`d0=AA..AA`, store `55..55`) | 0 | `AAAAAAAAAAAAAAAA` (kept) |
| LL32 (`w0=11112222`) returns | — | `val=11112222` |
| LLD64 (`d0=1111222233334444`) returns | — | `val=1111222233334444` |
| Tight LL/SC32 (`w0=AABBCCDD`, store `12345678`; ll=`AABBCCDD`) | 1 | `12345678` |
| Tight LLD/SCD64 (`d0=AABBCCDD11223344`, store `123456789ABCDEF0`) | 1 | `123456789ABCDEF0` |
| Repeat SC32, no new LL (store `DEADBEEF`) | 0 | `12345678` (kept) |
| Repeat SCD64, no new LL (store `DEADBEEFDEADBEEF`) | 0 | `123456789ABCDEF0` (kept) |
| Ordinary SW to same addr between LL/SC32 (`BBBBBBBB`) | 0 | `BBBBBBBB` (SC store lost) |
| Ordinary SD to same addr between LLD/SCD64 (`BB..BB`) | 0 | `BBBBBBBBBBBBBBBB` (SCD store lost) |
| Ordinary SW to same 32 B line (`w1=DDDDDDDD`) between LL/SC32 | 1 | `w0=CCCCCCCC` (committed!) |
| Ordinary SD to same 32 B line (`d1=DD..DD`) between LLD/SCD64 | 1 | `d0=CCCCCCCCCCCCCCCC` (committed!) |
| `getpid()` syscall between LL/SC32 | 1 | `w0=CCCCCCCC` (committed) |
| `getpid()` syscall between LLD/SCD64 | 1 | `d0=CCCCCCCCCCCCCCCC` (committed) |

## qemu granularity limits (honest divergences from hardware)

- **Reservation granule is exact-address, not a cache line.** A store to
  `w1`/`d1` (offset +4/+8, same 32-byte line as the reservation) does NOT
  clear qemu-user's reservation: SC/SCD still return 1. Real MIPS hardware
  tracks reservations at cache-line (or larger) granularity and such a
  store clears the reservation. A DBT must model line-granularity
  invalidation even though qemu-user does not exhibit it.
- **Syscalls do not clear the reservation under qemu-user.**
  `getpid()` between LL and SC leaves SC succeeding (sc=1) on all four
  variants. Real kernels may clear reservations on trap/context switch, so
  a DBT must not assume a reservation survives a syscall just because
  qemu-user preserves it.
- **ERET: UNVERIFIED.** ERET is privileged and cannot be executed from a
  user-mode probe; its reservation-clearing effect was not measured.

## Instruction encodings (objdump `--show-raw-insn` on probe `.o`)

Opcodes: LL `0x30`, SC `0x38`, LLD `0x34`, SCD `0x3C` (upper 6 bits).
Probe's own `main` sites, identical across N64/N32 and LE/BE:

```text
c0850000  ll   a1,0(a0)      e0860000  sc   a2,0(a0)
d0850000  lld  a1,0(a0)      f0820000  scd  v0,0(a0)
```

32-bit and 64-bit forms coexist in every build, including `-mabi=n32`
(N32 keeps 64-bit GPRs, so `lld`/`scd` assemble and run there too).
LL/SC behavior is endian-neutral: LE and BE logs agree on all values.
