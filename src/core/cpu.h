/*
 * src/core/cpu.h — Core context, constants, and module interfaces for mips64rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze: the layout of the first 0x260 bytes of mips64_ctx_t is
 * ABI-locked for the future DBT trampoline (Phase 2) and the a64 emitter.
 * Fields after the fpr array are C-only and may be extended at the tail
 * between phases; never inside the locked prefix. Offsets verified by
 * tests/check_abi_invariants.c (lane L0b).
 */

#ifndef MIPS64RT_CORE_CPU_H
#define MIPS64RT_CORE_CPU_H

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* MIPS64 GPR indices in architectural numbering (N64: $8..$11 are
 * A4..A7, $12..$15 are T0..T3). */
#define MIPS64_REG_ZERO 0U
#define MIPS64_REG_AT   1U
#define MIPS64_REG_V0   2U
#define MIPS64_REG_V1   3U
#define MIPS64_REG_A0   4U
#define MIPS64_REG_A1   5U
#define MIPS64_REG_A2   6U
#define MIPS64_REG_A3   7U
#define MIPS64_REG_A4   8U
#define MIPS64_REG_A5   9U
#define MIPS64_REG_A6   10U
#define MIPS64_REG_A7   11U
#define MIPS64_REG_T0   12U
#define MIPS64_REG_T1   13U
#define MIPS64_REG_T2   14U
#define MIPS64_REG_T3   15U
#define MIPS64_REG_S0   16U
#define MIPS64_REG_S1   17U
#define MIPS64_REG_S2   18U
#define MIPS64_REG_S3   19U
#define MIPS64_REG_S4   20U
#define MIPS64_REG_S5   21U
#define MIPS64_REG_S6   22U
#define MIPS64_REG_S7   23U
#define MIPS64_REG_T8   24U
#define MIPS64_REG_T9   25U
#define MIPS64_REG_K0   26U
#define MIPS64_REG_K1   27U
#define MIPS64_REG_GP   28U
#define MIPS64_REG_SP   29U
#define MIPS64_REG_FP   30U
#define MIPS64_REG_RA   31U

/* CP0 UserLocal register number read by RDHWR (E06: rdhwr word 0x7c03e83b). */
#define MIPS64_RDHWR_ULR 29U

/* Guest ABI selection. */
#define MIPS64_ABI_N64 0U
#define MIPS64_ABI_N32 1U

/* Engine exit reasons (engines return to the dispatcher via exit_reason). */
#define MIPS64_EXIT_NONE        0U
#define MIPS64_EXIT_BRANCH     1U
#define MIPS64_EXIT_SYSCALL    2U
#define MIPS64_EXIT_UNDEF      3U
#define MIPS64_EXIT_FAULT      4U
#define MIPS64_EXIT_TRAP       5U
#define MIPS64_EXIT_SINGLE_STEP 6U

/* Architectural limits, page/window constants (SPEC 1.1, 1.2, 2.1). */
#define MIPS64_MAX_REGIONS 512U
#define MIPS64_RAS_SIZE      64U
#define MIPS64_IBTC_SIZE     4096U
#define MIPS64_PAGE_SIZE     4096U
/* N64 xuseg: 1 TiB. N32 useg: 2 GiB (all pointers fit in signed 32-bit). */
#define MIPS64_N64_TASK_SIZE (UINT64_C(1) << 40)
#define MIPS64_N32_TASK_SIZE UINT64_C(0x7fff8000)
/* N64 placements below 1ULL<<40; N32 placements below 0x7fff8000 (SPEC 2.1). */
#define MIPS64_N64_STACK_TOP  UINT64_C(0x000000ffffff0000)
#define MIPS64_N64_MMAP_BASE  UINT64_C(0x0000005500000000)
#define MIPS64_N64_INTERP_BIAS UINT64_C(0x0000007f00000000)
#define MIPS64_N64_SIGTRAMP   UINT64_C(0x000000fffffe0000)
#define MIPS64_N32_STACK_TOP  UINT64_C(0x7fff0000)
#define MIPS64_N32_MMAP_BASE  UINT64_C(0x3f000000)
#define MIPS64_N32_INTERP_BIAS UINT64_C(0x3f800000)
#define MIPS64_N32_SIGTRAMP   UINT64_C(0x7fff1000)
#define MIPS64_LOW_GUARD_SIZE UINT64_C(0x00010000)

/* Region descriptor for /proc/self/maps + gap tracking. */
typedef struct mips64_region {
    uint64_t start;
    uint64_t end;
    uint32_t prot;
    uint32_t flags;
    char     name[64];
} mips64_region_t;

/* Engine selection (MIPS64RT_ENGINE, --interp/--dbt). */
enum {
    MIPS64_ENGINE_INTERP = 0, /* portable C interpreter: oracle (Phase 1) */
    MIPS64_ENGINE_DBT    = 1  /* MIPS64r2 -> A64 translator (Phase 2) */
};

/*
 * Architectural + runtime state for a MIPS64r2 guest thread
 * (N64 ELFCLASS64 or N32 ELFCLASS32).
 *
 * ABI-locked prefix (offsets 0..0x25f, SPEC 2.1):
 *   0x000 gpr[32]        u64 ($0 hardwired 0 by engines on writeback)
 *   0x100 pc, 0x108 next_pc, 0x110 hi, 0x118 lo
 *   0x120 ulr (CP0 UserLocal), 0x128 fcsr (FCR31)
 *   0x12c in_delay_slot, 0x12d fr_mode, 0x12e llbit, 0x12f nan2008
 *   0x130 lladdr, 0x138 llval
 *   0x140 is_be, 0x144 is_n32, 0x148 exit_reason, 0x14c exit_info
 *   0x150 ibtc_ptr, 0x158 pad
 *   0x160 fpr[32]        256 B of u64 slots, 16-byte aligned (FR=1)
 */
typedef struct mips64_ctx {
    uint64_t gpr[32];           /* 0x000 */
    uint64_t pc;                /* 0x100 */
    uint64_t next_pc;           /* 0x108 */
    uint64_t hi;                /* 0x110 */
    uint64_t lo;                /* 0x118 */
    uint64_t ulr;               /* 0x120 */
    uint32_t fcsr;              /* 0x128 */
    uint8_t  in_delay_slot;     /* 0x12c */
    uint8_t  fr_mode;           /* 0x12d (always 1 after Phase 3) */
    uint8_t  llbit;             /* 0x12e */
    uint8_t  nan2008;           /* 0x12f */
    uint64_t lladdr;            /* 0x130 */
    uint64_t llval;             /* 0x138 */
    uint32_t is_be;             /* 0x140 */
    uint32_t is_n32;            /* 0x144 */
    uint32_t exit_reason;       /* 0x148 */
    uint32_t exit_info;         /* 0x14c */
    uint64_t ibtc_ptr;          /* 0x150 (host pointer, Phase 2) */
    uint64_t pad150;            /* 0x158 (keeps fpr 16-byte aligned) */
    uint64_t fpr[32];           /* 0x160 */

    /* ---- C-only tail (no asm offset dependencies; extend at end only) ---- */

    /* Guest memory layout inside TASK_SIZE. Phase 1 reservation model: a
     * single host-VA reservation of task_size bytes (PROT_NONE,
     * MAP_NORESERVE); guest mappings are placed MAP_FIXED inside it so
     * guest_base + va is the host address. The rt64 family broker
     * integration (Phase 4/6) keeps this field as the process window base. */
    uint64_t task_size;
    uint64_t guest_base;        /* host base of the TASK_SIZE reservation */
    uint64_t brk_base;
    uint64_t brk_curr;
    uint64_t mmap_cursor;
    uint64_t mmap_base;         /* unhinted-mmap search base (per ABI) */
    uint64_t interp_base;
    uint64_t elf_base;
    uint64_t elf_entry;
    uint64_t stack_top;
    uint64_t stack_base;

    /* Tracked guest regions (sorted by start) for /proc/self/maps + gaps. */
    mips64_region_t regions[MIPS64_MAX_REGIONS];
    size_t          region_count;

    /* Thread, futex, and signal state (wired in Phase 4). */
    uint64_t clear_child_tid;
    uint64_t robust_list_head;
    uint64_t robust_list_len;
    int      host_tid;
    bool     is_thread_clone;
    /* Alternate signal stack (sigaltstack(2); 0 == disabled). */
    uint64_t sigalt_sp;
    uint64_t sigalt_size;
    uint64_t sigalt_flags;

    /* Guest startup metadata for /proc/self/{cmdline,auxv,exe} (Phase 5). */
    int      guest_argc;
    char   **guest_argv;
    char   **host_envp;
    uint64_t auxv_data[64];
    size_t   auxv_bytes;

    /* Configuration & engine selection. */
    const char *sysroot;
    const char *exec_path;
    const char *cache_dir;
    int         engine;         /* MIPS64_ENGINE_* */
    bool        trace_enabled;
    bool        difftest_enabled;

    /* Instrumentation counters. */
    uint64_t blocks_executed;
    uint64_t syscalls_executed;
    uint64_t blocks_compiled;
    uint64_t icache_flushes;
    uint64_t wx_transitions;
} mips64_ctx_t;

/* ABI-locked offsets (SPEC 2.1, verified by tests/check_abi_invariants). */
#define MIPS64_CTX_GPR_OFFSET            0x000U
#define MIPS64_CTX_PC_OFFSET             0x100U
#define MIPS64_CTX_NEXT_PC_OFFSET        0x108U
#define MIPS64_CTX_HI_OFFSET             0x110U
#define MIPS64_CTX_LO_OFFSET             0x118U
#define MIPS64_CTX_ULR_OFFSET            0x120U
#define MIPS64_CTX_FCSR_OFFSET           0x128U
#define MIPS64_CTX_IN_DELAY_SLOT_OFFSET  0x12cU
#define MIPS64_CTX_FR_MODE_OFFSET        0x12dU
#define MIPS64_CTX_LLBIT_OFFSET          0x12eU
#define MIPS64_CTX_NAN2008_OFFSET        0x12fU
#define MIPS64_CTX_LLADDR_OFFSET         0x130U
#define MIPS64_CTX_LLVAL_OFFSET          0x138U
#define MIPS64_CTX_IS_BE_OFFSET          0x140U
#define MIPS64_CTX_IS_N32_OFFSET         0x144U
#define MIPS64_CTX_EXIT_REASON_OFFSET    0x148U
#define MIPS64_CTX_EXIT_INFO_OFFSET      0x14cU
#define MIPS64_CTX_IBTC_PTR_OFFSET       0x150U
#define MIPS64_CTX_FPR_OFFSET            0x160U

_Static_assert(offsetof(mips64_ctx_t, gpr) == 0, "gpr must be at offset 0");
_Static_assert(offsetof(mips64_ctx_t, pc) == 0x100, "pc at 0x100");
_Static_assert(offsetof(mips64_ctx_t, next_pc) == 0x108, "next_pc at 0x108");
_Static_assert(offsetof(mips64_ctx_t, hi) == 0x110, "hi at 0x110");
_Static_assert(offsetof(mips64_ctx_t, lo) == 0x118, "lo at 0x118");
_Static_assert(offsetof(mips64_ctx_t, ulr) == 0x120, "ulr at 0x120");
_Static_assert(offsetof(mips64_ctx_t, fcsr) == 0x128, "fcsr at 0x128");
_Static_assert(offsetof(mips64_ctx_t, in_delay_slot) == 0x12c, "ids at 0x12c");
_Static_assert(offsetof(mips64_ctx_t, fr_mode) == 0x12d, "fr_mode at 0x12d");
_Static_assert(offsetof(mips64_ctx_t, llbit) == 0x12e, "llbit at 0x12e");
_Static_assert(offsetof(mips64_ctx_t, nan2008) == 0x12f, "nan2008 at 0x12f");
_Static_assert(offsetof(mips64_ctx_t, lladdr) == 0x130, "lladdr at 0x130");
_Static_assert(offsetof(mips64_ctx_t, llval) == 0x138, "llval at 0x138");
_Static_assert(offsetof(mips64_ctx_t, is_be) == 0x140, "is_be at 0x140");
_Static_assert(offsetof(mips64_ctx_t, is_n32) == 0x144, "is_n32 at 0x144");
_Static_assert(offsetof(mips64_ctx_t, exit_reason) == 0x148, "exit at 0x148");
_Static_assert(offsetof(mips64_ctx_t, exit_info) == 0x14c, "info at 0x14c");
_Static_assert(offsetof(mips64_ctx_t, ibtc_ptr) == 0x150, "ibtc at 0x150");
_Static_assert(offsetof(mips64_ctx_t, fpr) == 0x160, "fpr at 0x160");
_Static_assert(sizeof(((mips64_ctx_t *)0)->fpr) == 256, "fpr is 256 bytes");

static inline void mips64_spin_lock(_Atomic uint32_t *lock)
{
    while (atomic_exchange_explicit(lock, 1U, memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static inline void mips64_spin_unlock(_Atomic uint32_t *lock)
{
    atomic_store_explicit(lock, 0U, memory_order_release);
}

/* Fault sentinel for guest memory helpers (Phase 1, lane L1c). */
#define MIPS_FAULT (-1)

/*
 * Guest protection flags (POSIX numbering: READ=1, WRITE=2, EXEC=4) used
 * in mips64_region_t.prot and every mips_mem_* entry point. ELF p_flags
 * use the opposite corner numbering (PF_X=1, PF_W=2, PF_R=4); the loader
 * translates with MIPS_PF_* (src/loader.c), never by masking p_flags
 * directly (RC1 integration fix).
 */
#define MIPS_PROT_READ  1U
#define MIPS_PROT_WRITE 2U
#define MIPS_PROT_EXEC  4U

/*
 * 64-bit page mask (RC1 integration fix): ~(4096U - 1U) alone is a
 * 32-bit constant (0xFFFFF000) that zero-extends and clears the high
 * 32 address bits. Every page-rounding site must use this mask so N64
 * addresses above 4 GiB survive (brk_base was truncated to 0x200B6000
 * before this fix).
 */
#define MIPS64_PAGE_MASK (~(UINT64_C(4096) - UINT64_C(1)))

/* Guest VA -> host pointer under the Phase 1 reservation model:
 * guest_base + va. va is never truncated: N64 VAs use the full 64 bits,
 * N32 VAs fit in 32 bits but are still carried in uint64_t. */
static inline void *mips64_guest_ptr(const mips64_ctx_t *ctx, uint64_t guest_va)
{
    return (void *)(uintptr_t)(ctx->guest_base + guest_va);
}

static inline int mips_is_be(const mips64_ctx_t *ctx)
{
    return ctx->is_be != 0U;
}

static inline int mips_is_n32(const mips64_ctx_t *ctx)
{
    return ctx->is_n32 != 0U;
}

static inline uint64_t mips_task_size(const mips64_ctx_t *ctx)
{
    return ctx->is_n32 != 0U ? MIPS64_N32_TASK_SIZE : MIPS64_N64_TASK_SIZE;
}

static inline uint64_t mips64_page_down(uint64_t x)
{
    return x & MIPS64_PAGE_MASK;
}

static inline uint64_t mips64_page_up(uint64_t x)
{
    return (x + (MIPS64_PAGE_SIZE - 1U)) & MIPS64_PAGE_MASK;
}

/* Decoded MIPS64r2 instruction (word already in host byte order). */
typedef struct mips_dec {
    uint32_t word;              /* raw 32-bit instruction word */
    uint8_t  op;                /* major opcode (bits 31..26) */
    uint8_t  rs;                /* bits 25..21 */
    uint8_t  rt;                /* bits 20..16 */
    uint8_t  rd;                /* bits 15..11 */
    uint8_t  sa;                /* bits 10..6 */
    uint8_t  funct;             /* bits 5..0 (SPECIAL) */
    uint16_t imm;               /* bits 15..0 */
    uint32_t target;            /* bits 25..0 (J/JAL) */
    int32_t  simm;              /* sign-extended imm */
    uint32_t uimm;              /* zero-extended imm */
} mips_dec_t;

/* Pure decoder (src/interp/decode.c, lane L1a). */
void mips_decode(uint32_t word, mips_dec_t *d);
/* Endianness-aware fetch from guest pc (0 ok, MIPS_FAULT on fault). */
int mips_fetch(mips64_ctx_t *ctx, uint64_t pc, uint32_t *word);

/* Reference interpreter (src/interp/interp.c, lane L1b). */
int interp_step(mips64_ctx_t *ctx);
int interp_run(mips64_ctx_t *ctx);

/* Guest memory window + accessors (src/os/mem.c, lane L1c). */
int guest_mem_init(mips64_ctx_t *ctx);
int guest_ld8(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
int guest_ld16(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
int guest_ld32(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
int guest_ld64(mips64_ctx_t *ctx, uint64_t va, uint64_t *out);
int guest_st8(mips64_ctx_t *ctx, uint64_t va, uint64_t val);
int guest_st16(mips64_ctx_t *ctx, uint64_t va, uint64_t val);
int guest_st32(mips64_ctx_t *ctx, uint64_t va, uint64_t val);
int guest_st64(mips64_ctx_t *ctx, uint64_t va, uint64_t val);
/* Synchronous fault: records EXIT_FAULT (lane L1c; signals in Phase 4). */
void mips_fault(mips64_ctx_t *ctx, uint64_t addr);

/* Minimal N64/N32 syscall dispatcher (src/os/syscall_min.c, lane L1c). */
int64_t mips_syscall(mips64_ctx_t *ctx);

/*
 * ---- Phase 2 frozen DBT contracts (dispatcher/cache L2b, emitter L2c) ----
 */
#define MIPS64_DBT_MAX_INSNS 64U

typedef struct dbt_block {
    uint64_t guest_pc;    /* block entry guest VA */
    uint64_t guest_end;   /* first VA past the block (delay slot included) */
    void    *code;        /* host RX entry, NULL until published */
    size_t   code_len;    /* host bytes */
    uint32_t smc_version; /* page-version cookie captured at compile time */
} dbt_block_t;

/* Direct block chaining + 4096-entry IBTC + RAS (src/dbt/dbt.c, L2b). */
void *dbt_lookup(mips64_ctx_t *ctx, uint64_t pc);
int   dbt_compile(mips64_ctx_t *ctx, uint64_t pc);
/* Integer emitter (src/dbt/emit_int.c, L2c). */
int   dbt_emit_int(mips64_ctx_t *ctx, uint64_t pc, const mips_dec_t *insns,
                   unsigned count, uint8_t *out, size_t cap,
                   size_t *out_len, uint64_t *out_end);
/* Exit-state dump for the RC2 difftest (src/main.c; both engines share it). */
void  mips_dump_regs(const mips64_ctx_t *ctx, FILE *out);

/*
 * ---- Phase 4 frozen contracts (signals L4a, threads L4b, procs L4c) ----
 */
int mips_raise_guest(mips64_ctx_t *ctx, int signo, uint64_t fault_addr);
int64_t mips_rt_sigreturn(mips64_ctx_t *ctx);
int mips_signal_has_handler(int signo);
void mips_trap(mips64_ctx_t *ctx, int signo, uint64_t addr);
int64_t mips_sc_rt_sigaction(mips64_ctx_t *ctx, uint64_t sp);
int64_t mips_l4a_rt_sigprocmask(mips64_ctx_t *ctx, uint64_t sp);
int64_t mips_sc_sigaltstack(mips64_ctx_t *ctx, uint64_t sp);
void mips64_signals_reset_for_exec(mips64_ctx_t *ctx);
void mips_thread_exit(mips64_ctx_t *ctx, int status);
void mips_hostfault_install(const void *pool, size_t len);
int mips_hostfault_run(mips64_ctx_t *ctx, void *code, uint32_t *reasonp);
void mips_hostfault_disarm(void);

#endif /* MIPS64RT_CORE_CPU_H */
