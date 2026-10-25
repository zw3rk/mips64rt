# CoreMark provenance (`tests/coremark/`)

Upstream: EEMBC CoreMark mirror, <https://github.com/eembc/coremark>,
commit `1f483d5b8316753a742cbf5590caf5bd0a4e4777`.

Vendored byte-identical (verified with `cmp` against the upstream
checkout; `md5sum` below matches `coremark.md5` from upstream where
that file covers the source):

| file | md5 | upstream path |
| --- | --- | --- |
| `core_list_join.c` | 9007fe7861b60ee6f210d156b62974c8 | `core_list_join.c` |
| `core_main.c` | 4a9e6dadce1ac3866381021fbe843fc9 | `core_main.c` |
| `core_matrix.c` | 5fa21a0f7c3964167c9691db531ca652 | `core_matrix.c` |
| `core_state.c` | fb49e7605c125306575a83f14f5798ac | `core_state.c` |
| `core_util.c` | 45540ba2145adea1ec7ea2c72a1fbbcb | `core_util.c` |
| `coremark.h` | b0ec69b6c8e75853d06accb3b1bcf534 | `coremark.h` |
| `cvt.c` | 29044e67a7c3e695d355bdca63568aa7 | `barebones/cvt.c` |
| `LICENSE.upstream.md` | (EEMBC license text) | `LICENSE.md` |

No `ee_printf.c` is vendored: the upstream `barebones/ee_printf.c`
carries a hard `#error` in `uart_send_char` (it cannot compile as-is),
so the bare `ee_printf` is authored here instead (see below).

Authored for the MIPS64 N64 port (Apache-2.0, this repo's license):

- `core_portme.h` — port configuration plus the musl-static N64 build
  recipe in its header comment. Key choices: `HAS_FLOAT=1`,
  `HAS_TIME_H=1`, `USE_CLOCK=0`, `HAS_STDIO=0`, `HAS_PRINTF=0`,
  `SEED_ARG`, `MEM_MALLOC`, `MULTITHREAD=1`, and `ee_ptr_int` as
  `uintptr_t` (64-bit: the upstream barebones header's `ee_u32` would
  truncate guest pointers on N64).
- `core_portme.c` — `portable_malloc/free` (libc heap),
  `start/stop/get_time` over `clock_gettime(CLOCK_MONOTONIC)` with
  microsecond `CORE_TICKS`, byte output via `write(2)` to stdout, and
  the bare `ee_printf`/`ee_vsprintf` (integer, string, char, pointer
  and `%f`/`%e`/`%g` float formats; differential-tested against libc
  `printf` on the host).
- `run_coremark.sh` — the bounded Phase 7 H3 acceptance gate.
