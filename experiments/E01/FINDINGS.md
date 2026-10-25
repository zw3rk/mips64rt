# E01 Findings — N64 (Base 5000) vs N32 (Base 6000) Syscalls & Address Limits

All results below are qemu-verified ground truth (N64LE, N32LE, N64BE,
N32BE all executed, `E01-RESULT: PASS (0 checks failed)` on each).
Nothing in this file is UNVERIFIED except where explicitly marked.

## 1. Toolchain & Oracle Identity

| Item | Identity |
|---|---|
| N64LE cross-CC | `mips64el-linux-gnuabi64-gcc 14` (`-mabi=64`), target `mips64el-linux-gnuabi64` |
| N32LE cross-CC | same driver, `-mabi=n32` |
| N64BE cross-CC | `mips64-linux-gnuabi64-gcc 14` (`-mabi=64`) |
| N32BE cross-CC | same driver, `-mabi=n32` |
| N64LE oracle | `qemu-mips64el version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| N32LE oracle | `qemu-mipsn32el version 10.0.13` (same build) |
| N64BE oracle | `qemu-mips64 version 10.0.13` (same build) |
| N32BE oracle | `qemu-mipsn32 version 10.0.13` (same build) |
| Host container | `debian:stable-slim` on linux/arm64, `apt-get install gcc-mips64el-linux-gnuabi64 gcc-mips64-linux-gnuabi64 libc6-dev-mips64el-cross libc6-dev-mipsn32-mips64el-cross libc6-dev-mips64-cross libc6-dev-mipsn32-mips64-cross libn32gcc-14-dev-mips64el-cross libn32gcc-14-dev-mips64-cross qemu-user` |

## 2. Exact Build / Run Commands

```sh
C="-static -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -O1"
mips64el-linux-gnuabi64-gcc $C -mabi=64  -o probe-n64le probe.c  # N64 LE
mips64el-linux-gnuabi64-gcc $C -mabi=n32 -o probe-n32le probe.c  # N32 LE
mips64-linux-gnuabi64-gcc   $C -mabi=64  -o probe-n64be probe.c  # N64 BE
mips64-linux-gnuabi64-gcc   $C -mabi=n32 -o probe-n32be probe.c  # N32 BE
timeout --kill-after=30s 60s qemu-mips64el  ./probe-n64le
timeout --kill-after=30s 60s qemu-mipsn32el ./probe-n32le
timeout --kill-after=30s 60s qemu-mips64    ./probe-n64be
timeout --kill-after=30s 60s qemu-mipsn32   ./probe-n32be
```

ELF identities (`readelf -h`): N64 = `ELF64, MIPS R3000,
Flags 0x80000007 (noreorder, pic, cpic, mips64r2)`; N32 = `ELF32,
MIPS R3000, Flags 0x80000025 (noreorder, cpic, abi2, mips64r2)`.
`run.sh` performs all four builds and runs; exit code `0`,
`E01-RESULT: PASS (N64LE/N32LE/N64BE/N32BE)` for every variant.

## 3. `sizeof` / `offsetof`

| Expression | N64 (LE+BE) | N32 (LE+BE) |
|---|---|---|
| `sizeof(long)` | 8 | 4 |
| `sizeof(long long)` | 8 | 8 |
| `sizeof(void *)` | 8 | 4 |
| `sizeof(scres_t)` (`{long v0, a3}`) | 16 | 8 |
| `offsetof(scres_t, a3)` | 8 | 4 |

## 4. `__NR` Numbers: Own Base Works, Other Base Is ENOSYS

Probe-startup print (identical LE and BE within each ABI):

| Call | N64 (`__NR`) | N32 (`__NR`) |
|---|---|---|
| read | 5000 | 6000 |
| write | 5001 | 6001 |
| close | 5003 | 6003 |
| getpid | 5038 | 6038 |
| exit (`__NR_exit`) | 5058 | 6058 |
| mmap | 5009 | 6009 |
| munmap | 5011 | 6011 |

So N64 = base 5000, N32 = base 6000, with shared offsets
(read +0, write +1, mmap +9, munmap +11, getpid +38, exit +58).
Derived at runtime as `(__NR_read / 1000) * 1000` = 5000 (n64) /
6000 (n32): PASS on all four variants.

Cross-base invocation (same offset, foreign base), observed:

| Call | Observed `$v0` | Observed `$a3` | Verdict |
|---|---|---|---|
| N64 guest, `getpid #6038` | 89 (`ENOSYS`) | 1 | foreign base rejected |
| N64 guest, `write #6001` | 89 (`ENOSYS`) | 1 | foreign base rejected |
| N32 guest, `getpid #5038` | 89 (`ENOSYS`) | 1 | foreign base rejected |
| N32 guest, `write #5001` | 89 (`ENOSYS`) | 1 | foreign base rejected |

Exit via forked children: own-base `exit(42)` terminates the child
with status 42 (PASS); foreign-base `exit(42)` returns
`$a3=1/$v0=ENOSYS(89)` and the child survives (PASS). Same on LE+BE.

## 5. Syscall Args 1..6 in `$a0`..`$a5` (No O32 Stack Slots)

Compiler-generated call
`callee6(0x1111… … 0x6666…)` (full 64-bit magics), all variants:

```text
compiler-call obs: 1111111111111111 2222222222222222 3333333333333333
                   4444444444444444 5555555555555555 6666666666666666
```

All six arrive whole — no splitting, no stack spill. Kernel-side
proof (raw `syscall`, args straight into `$4..$9`):

| Raw call | Observed `$v0` | Observed `$a3` | Verdict |
|---|---|---|---|
| `mmap(NULL,4096,RW,PRIVATE\|ANON,-1,0)` (6 args) | `0xffffb8b00000` (N64LE) / `0x2b2ad000` (N32) | 0 | mapping live, writable, `munmap` ok |
| `munmap(addr,4096)` | 0 | 0 | ok |

6-arg register passing works; there is no MIPS64 analogue of the O32
`16/20/24/28($sp)` stack-arg frame.

## 6. 64-bit Args Occupy One Register (No Even-Pair Rule)

Compiler-generated call
`callee_ll(0x1111…, 0x2222222233333333, 0x4444…)`, all variants:

```text
ll obs: tag=1111111111111111 ll=2222222233333333 tail=4444444444444444
```

The `u64` lands whole in a single `$a*` register on N64 and N32,
LE and BE — unlike O32, where it must align to an even pair.

## 7. `$a3` Error Flag (`$v0` = ret / +errno)

| Call | `$v0` | `$a3` |
|---|---|---|
| `getpid` (raw own `__NR`; matches libc `getpid()`, e.g. 964/988/1012) | pid | 0 |
| `write(1, msg, 16)` | 16 | 0 |
| `write(-1, msg, 3)` | 9 (`EBADF`) | 1 |
| `write(fd, msg, 3)` then `close(fd)` | 3 then 0 | 0 then 0 |
| `close(fd)` again | 9 (`EBADF`) | 1 |

Rule confirmed on both ABIs and endians: success → `$a3=0,
$v0=ret`; error → `$a3=1, $v0` = positive MIPS errno
(`ENOSYS = 89`, compile-time `_Static_assert`ed in `probe.c`).

## 8. TASK_SIZE Address Limits vs qemu-user (Observed Divergence)

Reference limits compiled into the probe: N64 `TASK_SIZE =
0x10000000000` (1ULL<<40), N32 `TASK_SIZE = 0x7fff8000`.

| Probe | N64 observed | N32 observed |
|---|---|---|
| anonymous `mmap` address | `0xffffb8b00000` (LE) / `0xffff9cb0f000` (BE) — **above** `TASK_SIZE` | `0x2b2ad000` — below `TASK_SIZE` |
| `mmap(MAP_FIXED_NOREPLACE)` exactly at `TASK_SIZE` | succeeds (`$a3=0`, addr = `0x10000000000`) | succeeds (`$a3=0`, addr = `0x7fff8000`) |

qemu-user does **not** enforce the guest `TASK_SIZE`: it places
N64 mappings at the top of the host VA (`0xffff…`) and grants fixed
mappings at/above the architectural limit. Enforcement of
`TASK_SIZE` on real kernels is UNVERIFIED by this experiment (no
hardware kernel available in the container); a translator must
implement the limit itself rather than rely on the host.

## 9. Instruction Encoding

Every trap assembles to the word `0x0000000c`. `objdump -d` sample
(N64LE; `li v0,6038` = 0x1796 is the cross-base getpid constant):

```text
1200044e0: 240213ae  li   v0,5038
1200044e4: 00003825  move a3,zero
1200044e8: 0000000c  syscall
...
1200047b0: 24021796  li   v0,6038
1200047b4: 00003825  move a3,zero
1200047b8: 0000000c  syscall
```

`129` occurrences of the `0000000c` word in `probe-n64le`/`probe-n64be`
(7 probe wrappers + libc startup), `143` in the N32 binaries.

## 10. Reproduction

From the worktree root (`../mips64rt-e01`): the probe lives in
`experiments/E01/` (`probe.c`, `run.sh`, this file). Inside the lane
container (`debian:stable-slim`, toolchain per §1):

```sh
cd experiments/E01 && ./run.sh   # builds N64LE/N32LE/N64BE/N32BE, runs all under qemu
test -s experiments/E01/FINDINGS.md   # lane acceptance command
```
