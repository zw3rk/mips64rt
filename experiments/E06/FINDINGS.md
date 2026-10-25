# E06 FINDINGS — TLS (`rdhwr $29` / `set_thread_area`) in N64 and N32

All results below are qemu-verified ground truth (nothing UNVERIFIED:
all four ABI/endian variants were executed).

## Toolchain identities

- Cross-compilers: `mips64el-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0`
  and `mips64-linux-gnuabi64-gcc (Debian 14.2.0-13) 14.2.0`
  (Debian `gcc-mips64el-linux-gnuabi64` / `gcc-mips64-linux-gnuabi64`
  packages, `libc6-dev-mips64el-cross`, `libc6-dev-mipsn32-mips64el-cross`,
  `libc6-dev-mips64-cross`, `libc6-dev-mipsn32-mips64-cross`,
  `libn32gcc-14-dev-mips64el-cross`, `libn32gcc-14-dev-mips64-cross`)
- Oracles: `qemu-mips64el`, `qemu-mipsn32el`, `qemu-mips64`, `qemu-mipsn32`,
  all `version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)`
- Container: `--platform linux/arm64 debian:stable-slim`
  (`docker run --rm --name mips64rt-E06-probe ...`, removed after)

## Exact build / run commands

```sh
cd experiments/E06
./run.sh all
# n64le: mips64el-linux-gnuabi64-gcc -mabi=64 -static -O2 -o probe_n64le probe.c -pthread
#        timeout --kill-after=30s 90s qemu-mips64el ./probe_n64le
# n32le: mips64el-linux-gnuabi64-gcc -mabi=n32 -static -O2 -o probe_n32le probe.c -pthread
#        timeout --kill-after=30s 90s qemu-mipsn32el ./probe_n32le
# n64be: mips64-linux-gnuabi64-gcc  -mabi=64 -static -O2 -o probe_n64be probe.c -pthread
#        timeout --kill-after=30s 90s qemu-mips64 ./probe_n64be
# n32be: mips64-linux-gnuabi64-gcc  -mabi=n32 -static -O2 -o probe_n32be probe.c -pthread
#        timeout --kill-after=30s 90s qemu-mipsn32 ./probe_n32be
```

CFLAGS add `-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror`.
Binaries: `ELF 64-bit {LSB,MSB} executable, MIPS, MIPS64 rel2 ...,
statically linked, for GNU/Linux 3.2.0` (N64) and `ELF 32-bit {LSB,MSB}
executable, MIPS, N32 MIPS64 rel2 ..., statically linked` (N32).
All four runs: `E06 RESULT: PASS`, run.sh prints
`E06-RESULT: PASS (n64le|n32le|n64be|n32be)` plus
`E06-RESULT: overall FAIL=0`.

## (1) `set_thread_area` numbers and `rdhwr $29` encoding

- `__NR_set_thread_area` from toolchain headers (used via
  `syscall(__NR_set_thread_area, addr)`, rc 0): **5242 (N64)**,
  **6246 (N32)**. Same value LE and BE.
- `rdhwr $v1,$29` encoding verified in objdump output of all four
  `.o` files: **`0x7c03e83b`** (7 occurrences each; objdump
  disassembles it as `rdhwr v1,$29`). The probe executes this exact
  word (saving/restoring `$3` around it) and cross-checks it against
  the `rdhwr %0,$29` mnemonic form; both reads agree in every run.

## sizeof / offsetof shape

| ABI | `sizeof(void*)` | `sizeof(long)` |
|---|---|---|
| N64 (LE+BE) | 8 | 8 |
| N32 (LE+BE) | 4 | 4 |

## Observed values (representative run; absolute addresses vary with ASLR, relationships stable)

| quantity | n64le | n32le | n64be | n32be |
|---|---|---|---|---|
| `rdhwr` before (both forms) | `0x1200ce760` | `0x100c3500` | `0x1200cd760` | `0x100c2500` |
| `&tls_var` (`__thread int = 42`) | `0x1200c7760` | `0x100bc500` | `0x1200c6760` | `0x100bb500` |
| tls–ULR distance | 28672 | 28672 | 28672 | 28672 |
| `pthread_self()` | `0x1200c7000` | `0x100bc000` | `0x1200c6000` | `0x100bb000` |
| `set_thread_area(0x51ab0001)` rc | 0 | 0 | 0 | 0 |
| `rdhwr` after set | `0x51ab0001` | `0x51ab0001` | `0x51ab0001` | `0x51ab0001` |
| `rdhwr` after restore | matches before | matches before | matches before | matches before |
| `tls_var` after round-trip | 42 (intact) | 42 (intact) | 42 (intact) | 42 (intact) |

## pthread propagation

| quantity | n64le | n32le | n64be | n32be |
|---|---|---|---|---|
| child `rdhwr` | `0xffff94006c60` | `0x2bab4ca0` | `0xffffa3805c60` | `0x2bab4ca0` |
| child `&tls_var` | `0xffff93fffc60` | `0x2baadca0` | `0xffffa37fec60` | `0x2baadca0` |
| child `tls_var` | 42 | 42 | 42 | 42 |

Child ULR is nonzero and differs from the parent's (private TLS);
child `__thread` address is distinct from the parent's (per-thread
instance) yet initialised to 42.

## clone(`CLONE_SETTLS`) propagation

Child created with pthread-like flags
(`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS`,
exit signal 0) and TLS `0x5eed0007`; child reads `rdhwr` and reports
it through shared memory, then exits the thread via raw `SYS_exit`.
Parent polls a shared flag (10 ms nanosleep, up to 10 s).

| run | child `rdhwr` | verdict |
|---|---|---|
| n64le | `0x5eed0007` | exact match |
| n32le | `0x5eed0007` | exact match |
| n64be | `0x5eed0007` | exact match |
| n32be | `0x5eed0007` | exact match |

Notes:

- Plain `clone` with `CLONE_VM` but without `CLONE_THREAD` fails with
  `EINVAL` under qemu-user (verified with a scratch probe, all flag
  combinations); the thread-group form above is the supported shape.
- No libc call is made between the test `set_thread_area` and the
  restore (libc needs the real TLS pointer); output is unbuffered
  (`setvbuf(stdout, NULL, _IONBF, 0)`).

## Raw program output (n32le)

```text
E06 TLS probe (N64/N32)
__NR_set_thread_area=6246
sizeof void*=4 long=4
rdhwr-mnemonic ulr_before=0x100c3500
rdhwr-fixed-0x7c03e83b ulr=0x100c3500
&tls_var=0x100bc500 tls_var=42 pthread_self=0x100bc000
ok: initial ULR nonzero
ok: rdhwr $v1,$29 (0x7c03e83b) matches mnemonic read
after set_thread_area(0x51ab0001): rdhwr=0x51ab0001
ok: rdhwr $29 returns set_thread_area value
after restore: rdhwr=0x100c3500 (expect 0x100c3500)
ok: ULR restored
ok: __thread var intact after TLS round-trip
tls_var-ulr distance=28672 bytes
ok: __thread var adjacent to ULR
child: ulr=0x2bab4ca0 &tls_var=0x2baadca0 tls_var=42
ok: child ULR nonzero
ok: child has private TLS pointer
ok: child __thread var address distinct (per-thread)
ok: child __thread var initialised to 42
clone child: rdhwr=0x5eed0007 (expect 0x5eed0007)
ok: clone(CLONE_SETTLS) propagates thread pointer
E06 RESULT: PASS
```

(N64 runs identical except `__NR_set_thread_area=5242`,
`sizeof void*=8 long=8`, and wider addresses; BE runs identical
except endianness and addresses.)
