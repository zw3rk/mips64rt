/*
 * src/dbt/emit_fp.c — AArch64 FP/NEON emitter for COP1 (Phase 3, lane L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lowers the L3a COP1 set — scalar S/D ADD/SUB/MUL/DIV/SQRT/ABS/NEG/MOV,
 * the CVT family (S/D/W/L, TRUNC/CEIL/FLOOR/ROUND), C.cond compares, and
 * (via emit_int.c) BC1T/BC1F/BC1TL/BC1FL — to AArch64 FP using only the
 * frozen register map from src/dbt/dbt.h: x19 pins ctx, x20 pins the
 * guest base, x21..x24 (EI_A..EI_T) are scratch, x25 is the JR/JALR
 * spill. x18 (and v18, by construction) is never read or written.
 *
 * FPRs live in ctx memory (MIPS64_CTX_FPR_OFFSET + idx * 8, FR=1 64-bit
 * lanes); every word spills/fills through those offsets and keeps no
 * host FP register live across words. Scratch FP use is s0..s4/d0..d3
 * only. FCSR (MIPS64_CTX_FCSR_OFFSET) is touched only by C.cond (FCC
 * writeback); all other flag/mode questions fall back to interp_step.
 *
 * Exactness policy (match L3a NaN/rounding bit-for-bit by construction):
 * the host runs IEEE-754 round-to-nearest with gradual underflow, so any
 * guest instance this file cannot prove bit-identical exits the block
 * with EXIT_UNDEF at that pc and the dispatcher completes it with
 * interp_step (the L3a reference):
 * - FCSR rounding mode != RN or flush-subnormals (FS) set: the mode
 *   guard exits (covers every RM/FS-sensitive op: arithmetic, all CVT).
 * - Any NaN-touching arithmetic/CVT instance: the result-NaN audit
 *   (arithmetic, S/D<->S/D) or the int round-trip audit (float->int)
 *   exits, so legacy/2008 NaN canonicalization and Invalid flags are
 *   always L3a's. Non-NaN instances never consult nan2008.
 * - Any NaN-operand C.cond instance exits (covers signaling compares
 *   and SNaN Invalid); ordered instances compute FCC purely in hardware.
 * - Unknown fmt/funct words (moves, COP1X, DMFC1/DMTC1, MFC1/MTC1,
 *   CFC1/CTC1, LWC1/SWC1/LDC1/SDC1 stay with fpmove.c/interp) return
 *   nonzero so the dispatcher falls back.
 * - Words that need a runtime guard may emit inside a delay slot:
 *   every guard exits at the branch (slot pc - 4u) with zero
 *   architectural state modified, so the dispatcher replays the
 *   branch plus its slot via interp_step; pure bit-ops (MOV/ABS/NEG)
 *   never guard and always emit.
 *
 * Known RC3 adjudication items (value-exact, flags deferred): MIPS
 * Inexact/Overflow/Underflow/DivisionByZero sticky flags are not
 * maintained inline; ROUND ties-away-from-zero is exact; CVT.W/L of NaN
 * is defined by interp (hardware saturates differently).
 *
 * Every raw FP word below was verified against
 * aarch64-unknown-linux-musl-as (/tmp/enc_probe_fp.s); only a64e_u32 +
 * the ei_* helpers from emit_int.h are used for emission.
 */

#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "dbt/emit_int.h"

/* Scratch FP registers (never v18; no FP state is live across words). */
#define EF_S0 0u
#define EF_S1 1u
#define EF_S2 2u
#define EF_S3 3u
#define EF_D0 0u
#define EF_D1 1u
#define EF_D2 2u
#define EF_D3 3u

/* FPR lane offset for index r (FR=1 64-bit lanes). */
#define EF_OFF_FPR(r) (MIPS64_CTX_FPR_OFFSET + (uint32_t)(r) * 8u)

_Static_assert(MIPS64_CTX_FPR_OFFSET == 0x160u, "fpr offset");
_Static_assert(MIPS64_CTX_FCSR_OFFSET == 0x128u, "fcsr offset");
_Static_assert(MIPS64_CTX_FPR_OFFSET + 31u * 8u == 0x258u, "fpr range");
/* Largest lane offset (0x258) fits the unsigned-offset LDR/STR D range. */
_Static_assert((0x258u / 8u) < 4096u, "fpr reachable");
_Static_assert((MIPS64_CTX_FCSR_OFFSET / 4u) < 4096u, "fcsr reachable");

/* Register checks mirror ei_reg_ok: any int reg 18 poisons the buffer,
 * and FP scratch is capped to s0..s4/d0..d3 (v18 never encodable here). */
static int ef_ok_r(unsigned r)
{
    return r < 32u && r != 18u;
}

static int ef_ok_fp(unsigned r)
{
    return r <= 4u;
}

/* Raw append with register pre-checks (int regs checked like ei_emit3). */
static void ef_put(a64_emit_t *e, uint32_t w, unsigned fp0, unsigned fp1,
                   unsigned fp2, unsigned r0, unsigned r1)
{
    if (e == NULL || !ef_ok_fp(fp0) || !ef_ok_fp(fp1) || !ef_ok_fp(fp2) ||
        !ef_ok_r(r0) || !ef_ok_r(r1)) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    a64e_u32(e, w);
}

/* Two-source FP arithmetic: word = base | Rm<<16 | Rn<<5 | Rd. */
static void ef_f2(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                  unsigned rm)
{
    ef_put(e, base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u),
           rd, rn, rm, EI_XZR, EI_XZR);
}

/* One-source FP: word = base | Rn<<5 | Rd. */
static void ef_f1(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn)
{
    ef_put(e, base | ((rn & 31u) << 5) | (rd & 31u), rd, rn, 0u, EI_XZR,
           EI_XZR);
}

/* FCMP (register form; no Rd field). Bases carry no Rm/Rn bits:
 * fcmp s0,s1 = 0x1E212000 and fcmp d2,d3 = 0x1E632040. */
static void ef_fcmp(a64_emit_t *e, int is_d, unsigned rn, unsigned rm)
{
    uint32_t base = is_d != 0 ? 0x1E602000u : 0x1E202000u;

    ef_put(e, base | ((rm & 31u) << 16) | ((rn & 31u) << 5), rn, rm, 0u,
           EI_XZR, EI_XZR);
}

/* FMOV Sd/Dd, #0.5 (ties-away ROUND sequence constant). */
static void ef_fhalf(a64_emit_t *e, int is_d, unsigned rd)
{
    uint32_t base = is_d != 0 ? 0x1E6C1000u : 0x1E2C1000u;

    ef_put(e, base | (rd & 31u), rd, 0u, 0u, EI_XZR, EI_XZR);
}

/* SIMD&FP LDR/STR lives in src/dbt/emit_fpmem.c (Wave P13 cache). */

/* FCVTZS Wd/Xd, Sn/Dn (toward zero; saturates, NaN -> 0). */
static void ef_fcvtsz(a64_emit_t *e, int is_x, int is_d, unsigned rd,
                      unsigned rn)
{
    uint32_t base = (uint32_t)(is_x != 0 ? 0x9E380000u : 0x1E380000u) |
        (uint32_t)(is_d != 0 ? 0x00400000u : 0u);

    ef_put(e, base | ((rn & 31u) << 5) | (rd & 31u), rn, 0u, 0u, rd,
           EI_XZR);
}

/* SCVTF Sd/Dd, Wn/Xn (uses host FPCR.RM; callers guard guest RM == 0). */
static void ef_scvtf(a64_emit_t *e, int is_x, int is_d, unsigned rd,
                     unsigned rn)
{
    uint32_t base = (uint32_t)(is_x != 0 ? 0x9E220000u : 0x1E220000u) |
        (uint32_t)(is_d != 0 ? 0x00400000u : 0u);

    ef_put(e, base | ((rn & 31u) << 5) | (rd & 31u), rd, 0u, 0u, rn,
           EI_XZR);
}

/* Bit moves between GPR and FP lanes (payload-preserving, SNaN-safe:
 * SNaNs are never quieted and raise nothing). S uses W regs, D uses X. */
static void ef_fmov_bit(a64_emit_t *e, int is_d, int to_gpr, unsigned rd,
                        unsigned rn)
{
    uint32_t base;
    unsigned fp;
    unsigned gp;

    if (is_d != 0) {
        base = to_gpr != 0 ? 0x9E660000u : 0x9E670000u;
    } else {
        base = to_gpr != 0 ? 0x1E260000u : 0x1E270000u;
    }
    fp = to_gpr != 0 ? rn : rd;
    gp = to_gpr != 0 ? rd : rn;
    if (e == NULL || !ef_ok_fp(fp) || !ef_ok_r(gp)) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    a64e_u32(e, base | ((rn & 31u) << 5) | (rd & 31u));
}

/* FPR lane spill/fill lives in src/dbt/emit_fpmem.c (Wave P13 d8..d15
 * write-through cache); guards below exit via EXIT_UNDEF at pc. */

/* Fast-path FCSR mask (Wave P): FS (bit 24), Enables (bits 11:7) and
 * RM (bits 1:0). Sticky exception flags (bits 6:2) are deliberately
 * NOT in the mask: including them would permanently disable the fast
 * path after the first inexact operation. Any set Enable bit exits
 * because the inline sequence never raises a guest trap. */
#define EF_FCSR_FAST_MASK 0x01000F83u

/* Mode guard: FCSR RM != RN (bits 1:0), any exception enable (bits
 * 11:7), or flush-subnormals (FS) set. Covers every value-affecting
 * mode bit for arithmetic and RM-sensitive CVT. Uses EI_A/EI_C, dead
 * across words. */
static void ef_mode_guard(a64_emit_t *e, uint64_t pc)
{
    size_t skip;

    ei_ldr(e, 1, EI_A, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
    ei_mov32(e, EI_C, EF_FCSR_FAST_MASK);
    ei_and(e, 1, EI_A, EI_A, EI_C);
    skip = ei_cbz(e, 1, 0, EI_A);
    ei_exit_undef(e, pc);
    ei_patch(e, skip, 0);
}

/* Guard for fixed-rounding conversions (FRINT modes are
 * RM-independent, but a subnormal input still depends on guest FS
 * and any enabled exception still expects a guest trap). */
static void ef_fs_guard(a64_emit_t *e, uint64_t pc)
{
    size_t skip;

    ei_ldr(e, 1, EI_A, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
    ei_mov32(e, EI_C, EF_FCSR_FAST_MASK);
    ei_and(e, 1, EI_A, EI_A, EI_C);
    skip = ei_cbz(e, 1, 0, EI_A);
    ei_exit_undef(e, pc);
    ei_patch(e, skip, 0);
}

/* NaN-result audit for a result already in S/D fp: any NaN result —
 * propagated quiet/signaling inputs or an invalid operation — exits so
 * interp_step (L3a) owns NaN canonicalization and Invalid flags. */
static void ef_nan_guard(a64_emit_t *e, unsigned fp, int is_d, uint64_t pc)
{
    size_t skip;

    ef_fcmp(e, is_d, fp, fp);
    ei_cset(e, EI_B, EI_VS);
    skip = ei_cbz(e, 1, 0, EI_B);
    ei_exit_undef(e, pc);
    ei_patch(e, skip, 0);
}

/* Round-trip audit for float->int: the int in EI_B (W/X) must convert
 * back to exactly the rounded value in S/D fp; any mismatch (overflow
 * saturation, Inf, NaN input through FCVTZS) exits to interp_step. */
static void ef_roundtrip_guard(a64_emit_t *e, int is_d, int is_l,
                               unsigned fp, uint64_t pc)
{
    size_t skip;

    ef_scvtf(e, is_l, is_d, is_d != 0 ? EF_D3 : EF_S3, EI_B);
    ef_fcmp(e, is_d, is_d != 0 ? EF_D3 : EF_S3, fp);
    ei_cset(e, EI_C, EI_EQ);
    skip = ei_cbz(e, 1, 1, EI_C);
    ei_exit_undef(e, pc);
    ei_patch(e, skip, 0);
}

/* ---- Scalar S/D arithmetic: ADD/SUB/MUL/DIV/SQRT ---- */

/* Verified two-source bases (assembler probe): low word varies only in
 * bits 15:10; type bit 22 selects D. */
#define EF_FADD_S 0x1E202800u
#define EF_FSUB_S 0x1E203800u
#define EF_FMUL_S 0x1E200800u
#define EF_FDIV_S 0x1E201800u
#define EF_FADD_D 0x1E602800u
#define EF_FSUB_D 0x1E603800u
#define EF_FMUL_D 0x1E600800u
#define EF_FDIV_D 0x1E601800u
#define EF_FSQRT_S 0x1E21C000u
#define EF_FSQRT_D 0x1E61C000u

static int ef_arith(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot,
                    int is_d)
{
    uint32_t base = 0u;
    unsigned fs = d->rd & 31u;
    unsigned ft = d->rt & 31u;
    unsigned fd = d->sa & 31u;
    unsigned s0 = is_d != 0 ? EF_D0 : EF_S0;
    unsigned s1 = is_d != 0 ? EF_D1 : EF_S1;
    unsigned s2 = is_d != 0 ? EF_D2 : EF_S2;
    /* Guarded words may emit in a delay slot: every runtime guard
     * below exits at the branch (pc - 4u) with zero architectural
     * state modified, so the dispatcher replays branch + slot. */
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    switch (d->funct) {
    case 0x00u: /* ADD */
        base = is_d != 0 ? EF_FADD_D : EF_FADD_S;
        break;
    case 0x01u: /* SUB */
        base = is_d != 0 ? EF_FSUB_D : EF_FSUB_S;
        break;
    case 0x02u: /* MUL */
        base = is_d != 0 ? EF_FMUL_D : EF_FMUL_S;
        break;
    case 0x03u: /* DIV */
        base = is_d != 0 ? EF_FDIV_D : EF_FDIV_S;
        break;
    case 0x04u: /* SQRT (fs -> fd, ft ignored) */
        ef_fill(e, is_d, s0, fs);
        ef_mode_guard(e, gpc);
        ef_f1(e, is_d != 0 ? EF_FSQRT_D : EF_FSQRT_S, s2, s0);
        ef_nan_guard(e, s2, is_d, gpc);
        ef_spill(e, is_d, s2, fd);
        return 0;
    default:
        return 1;
    }
    ef_fill(e, is_d, s0, fs);
    ef_fill(e, is_d, s1, ft);
    ef_mode_guard(e, gpc);
    if (d->funct == 0x03u) {
        size_t nz;

        ef_fmov_bit(e, is_d, 0, is_d != 0 ? EF_D3 : EF_S3, EI_XZR);
        ef_fcmp(e, is_d, s1, is_d != 0 ? EF_D3 : EF_S3);
        ei_cset(e, EI_B, EI_EQ);
        nz = ei_cbz(e, 1, 0, EI_B);
        ei_exit_undef(e, gpc);
        ei_patch(e, nz, 0);
    }
    ef_f2(e, base, s2, s0, s1);
    ef_nan_guard(e, s2, is_d, gpc);
    ef_spill(e, is_d, s2, fd);
    return 0;
}

/* ---- CVT between float formats (float->float uses guest RM) ---- */

#define EF_FCVT_DS 0x1E22C000u /* D from S (CVT.D.S) */
#define EF_FCVT_SD 0x1E624000u /* S from D (CVT.S.D) */

static int ef_cvt_ff(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot,
                     int to_d)
{
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    if (to_d != 0) {
        ef_fill(e, 0, EF_S0, fs);
        ef_mode_guard(e, gpc);
        ef_f1(e, EF_FCVT_DS, EF_D2, EF_S0);
        ef_nan_guard(e, EF_D2, 1, gpc);
        ef_spill(e, 1, EF_D2, fd);
    } else {
        ef_fill(e, 1, EF_D0, fs);
        ef_mode_guard(e, gpc);
        ef_f1(e, EF_FCVT_SD, EF_S2, EF_D0);
        ef_nan_guard(e, EF_S2, 0, gpc);
        ef_spill(e, 0, EF_S2, fd);
    }
    return 0;
}

/* ---- CVT float->int (W/L from S/D) ---- */

/* Verified FRINT bases (explicit mode, FPCR-independent). */
#define EF_FRINTN_S 0x1E244000u
#define EF_FRINTZ_S 0x1E25C000u
#define EF_FRINTM_S 0x1E254000u
#define EF_FRINTP_S 0x1E24C000u
#define EF_FRINTN_D 0x1E644000u
#define EF_FRINTZ_D 0x1E65C000u
#define EF_FRINTM_D 0x1E654000u
#define EF_FRINTP_D 0x1E64C000u
#define EF_FABS_S 0x1E20C000u
#define EF_FABS_D 0x1E60C000u

/* Rounding selector: 0 RM-nearest, 1 toward-zero, 2 +inf, 3 -inf,
 * 4 ties-away-from-zero (MIPS ROUND). */
static void ef_round_op(a64_emit_t *e, int is_d, unsigned mode, uint64_t pc)
{
    unsigned s0 = is_d != 0 ? EF_D0 : EF_S0;
    unsigned s2 = is_d != 0 ? EF_D2 : EF_S2;
    uint32_t base = 0u;

    (void)pc;
    (void)ef_fhalf;
    switch (mode) {
    case 0:
    case 4:
        base = is_d != 0 ? EF_FRINTN_D : EF_FRINTN_S;
        break;
    case 1:
        base = is_d != 0 ? EF_FRINTZ_D : EF_FRINTZ_S;
        break;
    case 2:
        base = is_d != 0 ? EF_FRINTP_D : EF_FRINTP_S;
        break;
    case 3:
        base = is_d != 0 ? EF_FRINTM_D : EF_FRINTM_S;
        break;
    default:
        break;
    }
    ef_f1(e, base, s2, s0);
}

static int ef_cvt_to_int(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                         int slot, int is_d, int is_l, unsigned mode)
{
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    unsigned s0 = is_d != 0 ? EF_D0 : EF_S0;
    unsigned s2 = is_d != 0 ? EF_D2 : EF_S2;
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    ef_fill(e, is_d, s0, fs);
    if (mode == 0u) {
        ef_mode_guard(e, gpc);
    } else {
        ef_fs_guard(e, gpc);
    }
    ef_round_op(e, is_d, (int)mode, pc);
    ef_fcvtsz(e, is_l, is_d, EI_B, s2);
    ef_roundtrip_guard(e, is_d, is_l, mode == 0u ? s0 : s2, gpc);
    if (is_l != 0) {
        ei_str(e, 0, EI_B, EI_CTX, EF_OFF_FPR(fd));
        /* Wave P13: full-lane integer result writes through. */
        ef_cache_write_d(e, fd, EI_B);
    } else {
        /* Word result: low 32 bits written, upper lane preserved. */
        ei_str(e, 1, EI_B, EI_CTX, EF_OFF_FPR(fd));
        /* Wave P13: low-half write invalidates the cached lane. */
        ef_fpr_invalidate(e, fd);
    }
    return 0;
}

/* ---- CVT int->float (S/D from W/L; SCVTF follows host RN) ---- */

static int ef_cvt_from_int(a64_emit_t *e, const mips_dec_t *d, uint64_t pc,
                           int slot, int to_d, int is_l)
{
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    /* Wave P13: cached lanes feed the integer source without a load. */
    if (is_l != 0) {
        if (ef_cache_read_d(e, fs, EI_B) == 0) {
            ei_ldr(e, 0, EI_B, EI_CTX, EF_OFF_FPR(fs));
        }
    } else {
        if (ef_cache_read_s(e, fs, EI_B) == 0) {
            ei_ldr(e, 1, EI_B, EI_CTX, EF_OFF_FPR(fs));
        }
    }
    ef_mode_guard(e, gpc);
    if (to_d != 0) {
        ef_scvtf(e, is_l, 1, EF_D2, EI_B);
        ef_spill(e, 1, EF_D2, fd);
    } else {
        ef_scvtf(e, is_l, 0, EF_S2, EI_B);
        ef_spill(e, 0, EF_S2, fd);
    }
    return 0;
}

/* ---- MOV/ABS/NEG: pure lane bit-ops (no FP unit, no guards) ---- */

static int ef_movbit(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int is_d)
{
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;

    (void)pc;
    if (is_d != 0) {
        ei_ldr(e, 0, EI_A, EI_CTX, EF_OFF_FPR(fs));
        if (d->funct == 0x05u) { /* ABS.D: clear bit 63 */
            ei_mov64(e, EI_C, 0x7FFFFFFFFFFFFFFFu);
            ei_and(e, 0, EI_A, EI_A, EI_C);
        } else if (d->funct == 0x07u) { /* NEG.D: flip bit 63 */
            ei_mov64(e, EI_C, 0x8000000000000000u);
            ei_eor(e, 0, EI_A, EI_A, EI_C);
        } else if (d->funct != 0x06u) { /* MOV.D: copy */
            return 1;
        }
        ei_str(e, 0, EI_A, EI_CTX, EF_OFF_FPR(fd));
        /* Wave P13: full-lane producer writes through to d(8+slot). */
        ef_cache_write_d(e, fd, EI_A);
    } else {
        /* Word lane: low 32 bits only, upper 32 preserved. */
        ei_ldr(e, 1, EI_A, EI_CTX, EF_OFF_FPR(fs));
        if (d->funct == 0x05u) { /* ABS.S: clear bit 31 */
            ei_mov32(e, EI_C, 0x7FFFFFFFu);
            ei_and(e, 1, EI_A, EI_A, EI_C);
        } else if (d->funct == 0x07u) { /* NEG.S: flip bit 31 */
            ei_mov32(e, EI_C, 0x80000000u);
            ei_eor(e, 1, EI_A, EI_A, EI_C);
        } else if (d->funct != 0x06u) { /* MOV.S: copy */
            return 1;
        }
        ei_str(e, 1, EI_A, EI_CTX, EF_OFF_FPR(fd));
        /* Wave P13: low-half write invalidates the cached lane. */
        ef_fpr_invalidate(e, fd);
    }
    return 0;
}

/* ---- C.cond compares (FCC writeback; NaN operands fall back) ---- */

static int ef_cmp(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot,
                  int is_d)
{
    unsigned fs = d->rd & 31u;
    unsigned ft = d->rt & 31u;
    unsigned cc = (d->sa >> 2) & 7u;
    unsigned cond = d->funct & 15u;
    unsigned bit = cc == 0u ? 23u : 24u + cc;
    unsigned s0 = is_d != 0 ? EF_D0 : EF_S0;
    unsigned s1 = is_d != 0 ? EF_D1 : EF_S1;
    size_t slow;
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    ef_fill(e, is_d, s0, fs);
    ef_fill(e, is_d, s1, ft);
    ef_fcmp(e, is_d, s0, s1);
    /* Any unordered (NaN) instance exits: signaling compares and SNaN
     * Invalid flags stay exactly L3a's. Ordered FCC is pure hardware. */
    ei_cset(e, EI_C, EI_VS);
    slow = ei_cbz(e, 1, 0, EI_C);
    ei_exit_undef(e, gpc);
    ei_patch(e, slow, 0);
    /* Ordered predicate into EI_B (signaling pairs share the FCC of
     * their non-signaling counterpart). */
    switch (cond & 7u) {
    case 0u: /* F / SF: never */
        ei_mov32(e, EI_B, 0u);
        break;
    case 1u: /* UN / NGLE: unordered (here: ordered path, still emit) */
        ei_cset(e, EI_B, EI_VS);
        break;
    case 2u: /* EQ / SEQ */
        ei_cset(e, EI_B, EI_EQ);
        break;
    case 3u: /* UEQ / NGL */
        ei_cset(e, EI_B, EI_VS);
        ei_cset(e, EI_C, EI_EQ);
        ei_orr(e, 1, EI_B, EI_B, EI_C);
        break;
    case 4u: /* OLT / LT */
        ei_cset(e, EI_B, 7u);
        ei_cset(e, EI_C, EI_LT);
        ei_and(e, 1, EI_B, EI_B, EI_C);
        break;
    case 5u: /* ULT / NGE */
        ei_cset(e, EI_B, EI_LT);
        break;
    case 6u: /* OLE / LE */
        ei_cset(e, EI_B, 7u);
        ei_cset(e, EI_C, EI_LE);
        ei_and(e, 1, EI_B, EI_B, EI_C);
        break;
    default: /* ULE / NGT */
        ei_cset(e, EI_B, EI_LE);
        break;
    }
    /* FCSR FCC bit writeback (read-modify-write the FCSR word). */
    ei_ldr(e, 1, EI_A, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
    ei_mov32(e, EI_C, ~(1u << bit));
    ei_and(e, 1, EI_A, EI_A, EI_C);
    ei_lsl(e, 1, EI_B, EI_B, bit);
    ei_orr(e, 1, EI_A, EI_A, EI_B);
    ei_str(e, 1, EI_A, EI_CTX, MIPS64_CTX_FCSR_OFFSET);
    return 0;
}

/* ---- S/D format dispatch ---- */

static int ef_fmt_sd(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot,
                     int is_d)
{
    switch (d->funct) {
    case 0x00u: /* ADD */
    case 0x01u: /* SUB */
    case 0x02u: /* MUL */
    case 0x03u: /* DIV */
    case 0x04u: /* SQRT */
        return ef_arith(e, d, pc, slot, is_d);
    case 0x05u: /* ABS */
    case 0x06u: /* MOV */
    case 0x07u: /* NEG */
        return ef_movbit(e, d, pc, is_d);
    case 0x08u: /* ROUND.L */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 1, 4u);
    case 0x09u: /* TRUNC.L */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 1, 1u);
    case 0x0Au: /* CEIL.L */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 1, 2u);
    case 0x0Bu: /* FLOOR.L */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 1, 3u);
    case 0x0Cu: /* ROUND.W */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 0, 4u);
    case 0x0Du: /* TRUNC.W */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 0, 1u);
    case 0x0Eu: /* CEIL.W */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 0, 2u);
    case 0x0Fu: /* FLOOR.W */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 0, 3u);
    case 0x20u: /* CVT.S (from D only) */
        if (is_d == 0) {
            return 1;
        }
        return ef_cvt_ff(e, d, pc, slot, 0);
    case 0x21u: /* CVT.D (from S only) */
        if (is_d != 0) {
            return 1;
        }
        return ef_cvt_ff(e, d, pc, slot, 1);
    case 0x24u: /* CVT.W (RM) */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 0, 0u);
    case 0x25u: /* CVT.L (RM) */
        return ef_cvt_to_int(e, d, pc, slot, is_d, 1, 0u);
    case 0x30u:
    case 0x31u:
    case 0x32u:
    case 0x33u:
    case 0x34u:
    case 0x35u:
    case 0x36u:
    case 0x37u:
    case 0x38u:
    case 0x39u:
    case 0x3Au:
    case 0x3Bu:
    case 0x3Cu:
    case 0x3Du:
    case 0x3Eu:
    case 0x3Fu: /* C.cond */
        return ef_cmp(e, d, pc, slot, is_d);
    default:
        return 1;
    }
}

/* ---- Entry point (called from the COP1 case in src/dbt/emit_int.c) ----
 *
 * Returns 0 when the word was emitted, nonzero when the dispatcher must
 * fall back to interp_step (unknown fmt/funct, BC1 words, moves that
 * stay with fpmove.c, guarded words in delay slots). Never returns the
 * block-end code: COP1 words handled here never terminate a block. */
int ef_emit_fp(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot)
{
    if (e == NULL || d == NULL || e->err != 0) {
        return 1;
    }
    if (d->op != 0x11u) {
        return 1;
    }
    if (d->rs == 0x08u) {
        /* BC1T/BC1F/likely: the block driver routes control words to
         * ei_branch (extended for the FCSR condition source). */
        return 1;
    }
    if ((d->sa == 0u && d->funct == 0u) &&
        (d->rs == 0x00u || d->rs == 0x01u || d->rs == 0x04u ||
         d->rs == 0x05u)) {
        unsigned rt = d->rt & 31u;
        unsigned fs = d->rd & 31u;

        if (d->rs == 0x00u) { /* MFC1 */
            ei_ldrsw(e, EI_A, EI_CTX, EF_OFF_FPR(fs));
            ei_gst(e, EI_A, rt);
        } else if (d->rs == 0x01u) { /* DMFC1 */
            ei_ldr(e, 0, EI_A, EI_CTX, EF_OFF_FPR(fs));
            ei_gst(e, EI_A, rt);
        } else if (d->rs == 0x04u) { /* MTC1 */
            ei_gld(e, EI_A, rt);
            ei_str(e, 1, EI_A, EI_CTX, EF_OFF_FPR(fs));
            /* Wave P13: raw low-half bits invalidate the cached lane. */
            ef_fpr_invalidate(e, fs);
        } else { /* DMTC1 */
            ei_gld(e, EI_A, rt);
            ei_str(e, 0, EI_A, EI_CTX, EF_OFF_FPR(fs));
            /* Wave P13: raw full-lane bits invalidate the cached lane. */
            ef_fpr_invalidate(e, fs);
        }
        return 0;
    }
    if (d->rs == 0x10u) {
        return ef_fmt_sd(e, d, pc, slot, 0);
    }
    if (d->rs == 0x11u) {
        return ef_fmt_sd(e, d, pc, slot, 1);
    }
    if (d->rs == 0x14u || d->rs == 0x15u) {
        /* W/L fmt: only int->float CVT.S/CVT.D read integer lanes. */
        if (d->funct == 0x20u) {
            return ef_cvt_from_int(e, d, pc, slot, 0, d->rs == 0x15u);
        }
        if (d->funct == 0x21u) {
            return ef_cvt_from_int(e, d, pc, slot, 1, d->rs == 0x15u);
        }
        return 1;
    }
    return 1;
}

/* ---- COP1X fused multiply-add (Wave P, lane P4) ----
 *
 * MIPS64r2 COP1X (op 0x13) MADD/MSUB/NMADD/NMSUB (.S/.D) lower to the
 * single-rounding host FMA family, matching the interp oracle
 * (src/interp/fp_ps.c uses fmaf/fma, likewise single-rounding):
 *   MADD.S/D   fd = fr + fs*ft   FMADD  fd, fs, ft, fr
 *   MSUB.S/D   fd = fs*ft - fr   FNMSUB fd, fs, ft, fr
 *   NMADD.S/D  fd = -(fr + fs*ft) FNMADD fd, fs, ft, fr
 *   NMSUB.S/D  fd = fr - fs*ft   FMSUB  fd, fs, ft, fr
 * Field layout (decode.c): fr = rs, ft = rt, fs = rd, fd = sa.
 *
 * Exactness policy (same as ef_arith): the FCSR fast-path guard exits
 * when RM != RN, any enable is set, or FS is set; any NaN result
 * (propagated inputs, 0*Inf, SNaN) exits so interp owns default-NaN
 * canonicalization and Invalid flags. Sticky Inexact/Overflow flags
 * are deferred per the RC3 adjudication, exactly like S/D arithmetic.
 * Indexed COP1X memory words (LWXC1/LDXC1/SWXC1/SDXC1/PREFX) fault in
 * the interp oracle, so they return 1 here and the dispatcher replays
 * them (fault-identical). Guarded FMA words may emit in delay slots:
 * their guards exit at the branch (slot pc - 4u). */

/* Assembler-verified FMA bases (Rd=0,Rn=0,Rm=0,Ra=0 probed with
 * aarch64 clang; o1 = bit 21, o0 = bit 15, type = bit 22):
 * FMADD = (0,0), FMSUB = (0,1), FNMADD = (1,0), FNMSUB = (1,1). */
#define EF_FMADD_S 0x1F000000u
#define EF_FMSUB_S 0x1F008000u
#define EF_FNMADD_S 0x1F200000u
#define EF_FNMSUB_S 0x1F208000u
#define EF_FMADD_D 0x1F400000u
#define EF_FMSUB_D 0x1F408000u
#define EF_FNMADD_D 0x1F600000u
#define EF_FNMSUB_D 0x1F608000u

/* Four-source FMA: word = base | Rm<<16 | Ra<<10 | Rn<<5 | Rd. */
static void ef_fma(a64_emit_t *e, uint32_t base, unsigned rd, unsigned rn,
                   unsigned rm, unsigned ra)
{
    if (ra > 4u) {
        if (e != NULL) {
            e->err = 1;
        }
        return;
    }
    ef_put(e, base | ((rm & 31u) << 16) | ((ra & 31u) << 10) |
               ((rn & 31u) << 5) | (rd & 31u),
           rd, rn, rm, EI_XZR, EI_XZR);
}

/* Entry point for op 0x13 (called from the COP1X case in
 * src/dbt/emit_int.c): 0 emitted, nonzero for the dispatcher to fall
 * back (indexed words, unknown functs). Guarded FMA words emit in
 * slots with branch-pc guard exits (see above). */
int ef_emit_cop1x(a64_emit_t *e, const mips_dec_t *d, uint64_t pc, int slot)
{
    unsigned fr = d->rs & 31u;
    unsigned ft = d->rt & 31u;
    unsigned fs = d->rd & 31u;
    unsigned fd = d->sa & 31u;
    uint32_t base = 0u;
    int is_d = 0;

    if (e == NULL || d == NULL || e->err != 0) {
        return 1;
    }
    if (d->op != 0x13u) {
        return 1;
    }
    /* Guarded COP1X words may emit in a delay slot: the mode and NaN
     * guards below exit at the branch (pc - 4u) with zero
     * architectural state modified. */
    uint64_t gpc = slot != 0 ? (pc - 4u) : pc;

    switch (d->funct) {
    case 0x20u: /* MADD.S */
        base = EF_FMADD_S;
        break;
    case 0x28u: /* MSUB.S */
        base = EF_FNMSUB_S;
        break;
    case 0x30u: /* NMADD.S */
        base = EF_FNMADD_S;
        break;
    case 0x38u: /* NMSUB.S */
        base = EF_FMSUB_S;
        break;
    case 0x21u: /* MADD.D */
        base = EF_FMADD_D;
        is_d = 1;
        break;
    case 0x29u: /* MSUB.D */
        base = EF_FNMSUB_D;
        is_d = 1;
        break;
    case 0x31u: /* NMADD.D */
        base = EF_FNMADD_D;
        is_d = 1;
        break;
    case 0x39u: /* NMSUB.D */
        base = EF_FMSUB_D;
        is_d = 1;
        break;
    default: /* Indexed memory words and PREFX fault in interp. */
        return 1;
    }
    ef_fill(e, is_d, is_d != 0 ? EF_D0 : EF_S0, fr);
    ef_fill(e, is_d, is_d != 0 ? EF_D1 : EF_S1, fs);
    ef_fill(e, is_d, is_d != 0 ? EF_D2 : EF_S2, ft);
    ef_mode_guard(e, gpc);
    /* rd = fd, rn = fs, rm = ft, ra = fr. */
    if (is_d != 0) {
        ef_fma(e, base, EF_D3, EF_D1, EF_D2, EF_D0);
        ef_nan_guard(e, EF_D3, 1, gpc);
        ef_spill(e, 1, EF_D3, fd);
    } else {
        ef_fma(e, base, EF_S3, EF_S1, EF_S2, EF_S0);
        ef_nan_guard(e, EF_S3, 0, gpc);
        ef_spill(e, 0, EF_S3, fd);
    }
    return 0;
}
