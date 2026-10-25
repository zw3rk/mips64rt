/* CoreMark MIPS64 N64 port for mips64rt (Phase 7 lane H3).
 *
 * Minimal bare-metal-style port: bare ee_printf (no stdio/printf), timer
 * via clock_gettime(CLOCK_MONOTONIC) (implemented by this translator),
 * heap via malloc/free, no filesystem use (output goes to stdout only).
 *
 * Build recipe (musl-static N64 moral equivalent: fully static N64LE;
 * same Docker recipe as tests/run_p5_busybox.sh):
 *
 *   docker run --rm --platform linux/arm64 \
 *     -v "$PWD:/w" -w /w debian:trixie-slim sh -c '
 *       apt-get update -qq &&
 *       DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
 *         gcc-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross &&
 *       mips64el-linux-gnuabi64-gcc -O1 -static \
 *         -Itests/coremark -DTOTAL_DATA_SIZE=2000 \
 *         -DPERFORMANCE_RUN=1 -DFLAGS_STR='"'"'"-O1 -static"'"'"' \
 *         tests/coremark/core_main.c tests/coremark/core_list_join.c \
 *         tests/coremark/core_matrix.c tests/coremark/core_state.c \
 *         tests/coremark/core_util.c tests/coremark/cvt.c \
 *         tests/coremark/core_portme.c \
 *         -o /w/coremark-n64le -lm'
 *
 * Run under the translator (both engines take the same guest argv):
 *
 *   _build/mips64rt --interp /w/coremark-n64le 0 0 0x66 <ITER> 0x0
 *   _build/mips64rt --dbt    /w/coremark-n64le 0 0 0x66 <ITER> 0x0
 *
 * argv: seed1 seed2 seed3 iterations execs(multialg mask, 0 = all).
 * Seeds 0/0/0x66 select the known-CRC performance run, so the
 * "Correct operation validated" line plus the [n]crc* lines are the
 * byte-compare oracle across qemu-mips64el, --interp and --dbt.
 *
 * Upstream sources (EEMBC CoreMark, Apache-2.0) are vendored diff-free
 * beside this file; see ORIGIN.md. Only core_portme.{h,c} are authored
 * for this port. ee_printf itself lives in core_portme.c and formats
 * %d/%i/%u/%x/%X/%o/%c/%s/%p/%f/%e/%E/%g/%G with width, precision,
 * flags and the l length modifier; %f-family uses the vendored
 * ecvtbuf/fcvtbuf helpers from cvt.c.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef COREMARK_MIPS64_PORTME_H
#define COREMARK_MIPS64_PORTME_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Data types and settings */
#ifndef HAS_FLOAT
#define HAS_FLOAT 1
#endif
#ifndef HAS_TIME_H
#define HAS_TIME_H 1
#endif
#ifndef USE_CLOCK
#define USE_CLOCK 0
#endif
#ifndef HAS_STDIO
#define HAS_STDIO 0
#endif
#ifndef HAS_PRINTF
#define HAS_PRINTF 0
#endif

/* Ticks are microseconds from clock_gettime(CLOCK_MONOTONIC); 64 bits
 * so even multi-minute runs cannot overflow. */
typedef unsigned long long mips64_core_ticks_t;
typedef mips64_core_ticks_t CORE_TICKS;

/* Compiler / memory location strings reported in the results banner. */
#ifndef COMPILER_VERSION
#ifdef __GNUC__
#define COMPILER_VERSION "GCC" __VERSION__
#else
#define COMPILER_VERSION "mips64el-unknown (non-gcc)"
#endif
#endif
#ifndef COMPILER_FLAGS
#define COMPILER_FLAGS FLAGS_STR
#endif
#ifndef MEM_LOCATION
#define MEM_LOCATION "HEAP"
#endif

/* CoreMark data types. ee_ptr_int MUST hold a pointer: the N64 guest
 * is 64-bit, so this is uintptr_t ( NOT ee_u32 as in the upstream
 * barebones 32-bit port). */
typedef signed short   ee_s16;
typedef unsigned short ee_u16;
typedef signed int     ee_s32;
typedef unsigned int   ee_u32;
typedef double         ee_f32;
typedef unsigned char  ee_u8;
typedef uintptr_t      ee_ptr_int;
typedef size_t         ee_size_t;
#define align_mem(x) (void *)(4 + (((ee_ptr_int)(x)-1) & ~3))

#ifndef SEED_METHOD
#define SEED_METHOD SEED_ARG
#endif
#ifndef MEM_METHOD
#define MEM_METHOD MEM_MALLOC
#endif
#ifndef MULTITHREAD
#define MULTITHREAD 1
#define USE_PTHREAD 0
#define USE_FORK    0
#define USE_SOCKET  0
#endif
#ifndef MAIN_HAS_NOARGC
#define MAIN_HAS_NOARGC 0
#endif
#ifndef MAIN_HAS_NORETURN
#define MAIN_HAS_NORETURN 0
#endif

extern ee_u32 default_num_contexts;

typedef struct CORE_PORTABLE_S
{
    ee_u8 portable_id;
} core_portable;

void portable_init(core_portable *p, int *argc, char *argv[]);
void portable_fini(core_portable *p);

/* Bare output primitive: format into the caller's buffer (ee_vsprintf)
 * or straight to stdout fd 1 (ee_printf). Declared here (not via
 * stdio) because HAS_STDIO is 0. */
int ee_printf(const char *fmt, ...);
int ee_vsprintf(char *buf, const char *fmt, va_list args);

#if !defined(PROFILE_RUN) && !defined(PERFORMANCE_RUN) \
    && !defined(VALIDATION_RUN)
#if (TOTAL_DATA_SIZE == 1200)
#define PROFILE_RUN 1
#elif (TOTAL_DATA_SIZE == 2000)
#define PERFORMANCE_RUN 1
#else
#define VALIDATION_RUN 1
#endif
#endif

#endif /* COREMARK_MIPS64_PORTME_H */
