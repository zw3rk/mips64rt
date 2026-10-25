// Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
// SPDX-License-Identifier: Apache-2.0
//
// E02: canonical 32-bit sign-extension (ADDIU/ADDU/SLL/LW produce
// (int64)(int32)x), 64-bit DEXT/DEXTM/DEXTU/DINS/DINSM/DINSU field ops,
// and unaligned LDL/LDR/SDL/SDR byte patterns across LE and BE.
//
// MIPS64 N64+N32, runs under qemu-mips64el / qemu-mipsn32el (LE) and
// qemu-mips64 / qemu-mipsn32 (BE). All verdicts are qemu-observed ground
// truth unless marked UNVERIFIED.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;

#define CHECK(name, got, want)                                                 \
    do {                                                                       \
        unsigned long long _g = (unsigned long long)(got);                     \
        unsigned long long _w = (unsigned long long)(want);                    \
        int _ok = (_g == _w);                                                  \
        if (!_ok)                                                              \
            g_fail++;                                                          \
        printf("%-28s got=0x%016llx want=0x%016llx %s\n", (name), _g, _w,       \
               _ok ? "MATCH" : "MISMATCH");                                    \
    } while (0)

/* ---- data model / endianness ------------------------------------------ */
static void t_model(void)
{
    uint16_t u = 1u;
    const char *en = (*(const uint8_t *)&u != 0u) ? "LE" : "BE";
    printf("model: sizeof(void*)=%u sizeof(long)=%u sizeof(int)=%u "
           "sizeof(long long)=%u endian=%s\n",
           (unsigned)sizeof(void *), (unsigned)sizeof(long),
           (unsigned)sizeof(int), (unsigned)sizeof(unsigned long long), en);
}

/* ---- (1) ADDIU: 32-bit add of sign-extended imm, result sign-extended --
 * rs upper bits are ignored; bit 31 of the 32-bit sum becomes bits 63:32. */
__attribute__((noinline)) static void t_addiu(void)
{
    uint64_t rs = 0x123456789ABCDEF0ULL;
    uint64_t out = 0u;
    __asm__ volatile("addiu %0,%1,1" : "=r"(out) : "r"(rs));
    /* low32(rs) = 0x9ABCDEF0; +1 = 0x9ABCDEF1, sign bit set. */
    CHECK("T1a addiu +1", out, 0xFFFFFFFF9ABCDEF1ULL);

    rs = 0u;
    out = 0u;
    __asm__ volatile("addiu %0,%1,-1" : "=r"(out) : "r"(rs));
    CHECK("T1b addiu -1", out, 0xFFFFFFFFFFFFFFFFULL);
}

/* ---- (2) ADDU: low 32 bits added, upper 32 of operands ignored -------- */
__attribute__((noinline)) static void t_addu(void)
{
    uint64_t rs = 0xDEADBEEF00000001ULL;
    uint64_t rt = 0x12345678FFFFFFFFULL;
    uint64_t out = 0u;
    __asm__ volatile("addu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
    /* low32: 0x00000001 + 0xFFFFFFFF = 0x00000000, no sign bit. */
    CHECK("T2a addu wrap-to-zero", out, 0x0000000000000000ULL);

    rs = 0xAAAAAAAA80000000ULL;
    rt = 0x5555555500000000ULL;
    out = 0u;
    __asm__ volatile("addu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
    /* low32: 0x80000000 + 0 = 0x80000000, sign bit set. */
    CHECK("T2b addu sign-bit", out, 0xFFFFFFFF80000000ULL);
}

/* ---- (3) SLL: 32-bit shift, result sign-extended ----------------------- */
__attribute__((noinline)) static void t_sll(void)
{
    uint64_t rt = 0xFFFF000040000000ULL;
    uint64_t out = 0u;
    __asm__ volatile("sll %0,%1,1" : "=r"(out) : "r"(rt));
    /* low32(rt) = 0x40000000; <<1 = 0x80000000, sign bit set. */
    CHECK("T3a sll into sign", out, 0xFFFFFFFF80000000ULL);

    rt = 0x0000000080000001ULL;
    out = 0u;
    __asm__ volatile("sll %0,%1,0" : "=r"(out) : "r"(rt));
    /* shift by 0 still sign-extends bit 31. */
    CHECK("T3b sll sa=0 sext", out, 0xFFFFFFFF80000001ULL);
}

/* ---- (4) LW sign-extends, LWU zero-extends, LB/LBU likewise ------------ */
__attribute__((noinline)) static void t_lw(void)
{
    uint32_t w = 0x80000001u;
    uint64_t out = 0u;
    __asm__ volatile("lw %0,0(%1)" : "=r"(out) : "r"(&w));
    CHECK("T4a lw sext", out, 0xFFFFFFFF80000001ULL);

    out = 0u;
    __asm__ volatile("lwu %0,0(%1)" : "=r"(out) : "r"(&w));
    CHECK("T4b lwu zext", out, 0x0000000080000001ULL);

    {
        int8_t b = (int8_t)0x80;
        out = 0u;
        __asm__ volatile("lb %0,0(%1)" : "=r"(out) : "r"(&b));
        CHECK("T4c lb sext", out, 0xFFFFFFFFFFFFFF80ULL);
        out = 0u;
        __asm__ volatile("lbu %0,0(%1)" : "=r"(out) : "r"(&b));
        CHECK("T4d lbu zext", out, 0x0000000000000080ULL);
    }
}

/* ---- (5) DADDIU contrast: full 64-bit add, upper bits preserved -------- */
__attribute__((noinline)) static void t_daddiu(void)
{
    uint64_t rs = 0x123456789ABCDEF0ULL;
    uint64_t out = 0u;
    __asm__ volatile("daddiu %0,%1,1" : "=r"(out) : "r"(rs));
    CHECK("T5a daddiu 64-bit", out, 0x123456789ABCDEF1ULL);

    {
        uint64_t rt = 0x0000000000000001ULL;
        out = 0u;
        __asm__ volatile("daddu %0,%1,%2" : "=r"(out) : "r"(rs), "r"(rt));
        CHECK("T5b daddu 64-bit", out, 0x123456789ABCDEF1ULL);
    }
}

/* ---- (6) DEXT/DEXTM/DEXTU ------------------------------------------------
 * V = 0xFEDCBA9876543210: bits[63:48]=FEDC [47:32]=BA98 [31:16]=7654 [15:0]=3210 */
#define E02_VEC 0xFEDCBA9876543210ULL

__attribute__((noinline)) static void t_dext(void)
{
    uint64_t rs = E02_VEC;
    uint64_t out = 0u;
    __asm__ volatile("dext %0,%1,8,8" : "=r"(out) : "r"(rs));
    CHECK("T6a dext 8,8", out, 0x0000000000000032ULL);

    out = 0u;
    __asm__ volatile("dext %0,%1,0,32" : "=r"(out) : "r"(rs));
    CHECK("T6b dext 0,32", out, 0x0000000076543210ULL);
}

__attribute__((noinline)) static void t_dextm(void)
{
    uint64_t rs = E02_VEC;
    uint64_t out = 0u;
    /* NOTE (GAS quirk, verified by execution): this GAS spells DEXTM as
     * dextm rd,rs,pos,POS_PLUS_SIZE (4th operand = pos+size, must be in
     * 33..64); the sibling DINSM keeps the plain (pos,size) spelling.
     * dextm 16,48 extracts bits[63:16], a 48-bit field. */
    __asm__ volatile("dextm %0,%1,16,48" : "=r"(out) : "r"(rs));
    /* bits[63:16] of VEC = 0x0000FEDCBA987654. */
    CHECK("T7 dextm 16,48", out, 0x0000FEDCBA987654ULL);
}

__attribute__((noinline)) static void t_dextu(void)
{
    uint64_t rs = E02_VEC;
    uint64_t out = 0u;
    __asm__ volatile("dextu %0,%1,48,16" : "=r"(out) : "r"(rs));
    /* bits[63:48] = 0xFEDC. */
    CHECK("T8a dextu 48,16", out, 0x000000000000FEDCULL);

    out = 0u;
    __asm__ volatile("dextu %0,%1,32,32" : "=r"(out) : "r"(rs));
    /* bits[63:32] = 0xFEDCBA98. */
    CHECK("T8b dextu 32,32", out, 0x00000000FEDCBA98ULL);
}

/* ---- (7) DINS/DINSM/DINSU: deposit rs[size-1:0] at rd[pos+size-1:pos] -- */
__attribute__((noinline)) static void t_dins(void)
{
    uint64_t rd = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t rs = 0x00000000000000ABULL;
    __asm__ volatile("dins %0,%1,8,8" : "+r"(rd) : "r"(rs));
    CHECK("T9 dins 8,8", rd, 0xFFFFFFFFFFFFABFFULL);
}

__attribute__((noinline)) static void t_dinsm(void)
{
    uint64_t rd = 0u;
    uint64_t rs = 0x00000000DEADBEEFULL;
    __asm__ volatile("dinsm %0,%1,16,32" : "+r"(rd) : "r"(rs));
    /* bits[47:16] := 0xDEADBEEF. */
    CHECK("T10 dinsm 16,32", rd, 0x0000DEADBEEF0000ULL);
}

__attribute__((noinline)) static void t_dinsu(void)
{
    uint64_t rd = 0u;
    uint64_t rs = 0x0000000000001234ULL;
    __asm__ volatile("dinsu %0,%1,48,16" : "+r"(rd) : "r"(rs));
    /* bits[63:48] := 0x1234. */
    CHECK("T11 dinsu 48,16", rd, 0x1234000000000000ULL);
}

/* 8-byte aligned static window: A = wbuf+8 (Amod8 = 0 guaranteed),
 * X = wbuf+11 (Xmod8 = 3). Pattern byte wbuf[k] = 0xA0+k. */
static _Alignas(8) uint8_t wbuf[32];

static void wfill(void)
{
    unsigned k;
    for (k = 0; k < sizeof(wbuf); k++)
        wbuf[k] = (uint8_t)(0xA0u + k);
}

/* ---- (8) LDL/LDR: canonical (0,7) pair loads the unaligned doubleword
 * at X ---------------------------------------------------------------
 * LDL(X) takes mem[X..end of X's word] into one end of rt; LDR(X+7)
 * takes mem[start of next word..X+7] into the other end. Together they
 * reconstruct the 8 bytes at [X..X+7], which straddle words A and B.
 * (A same-address pair only recombines halves of one word and does
 * NOT reconstruct; its spans are shown decomposed below as ground
 * truth for the span/placement mapping.) */
__attribute__((noinline)) static void t_ldl_ldr(void)
{
    uint8_t *X = wbuf + 11; /* mod 3, word A = wbuf+8 */
    uint8_t *Y = wbuf + 18; /* X+7, mod 2, word B = wbuf+16 */
    uint64_t r1 = 0u, r2 = 0u, r3 = 0u, r4 = 0u;
    uint64_t pair = 0u;
    uint16_t u = 1u;
    int le = (*(const uint8_t *)&u != 0u);
    wfill();
    __asm__ volatile("ldl %0,0(%1)" : "+r"(r1) : "r"((void *)X));
    __asm__ volatile("ldr %0,0(%1)" : "+r"(r2) : "r"((void *)X));
    r3 = 0xFFFFFFFFFFFFFFFFULL;
    __asm__ volatile("ldl %0,0(%1)" : "+r"(r3) : "r"((void *)X));
    r4 = 0xFFFFFFFFFFFFFFFFULL;
    __asm__ volatile("ldr %0,0(%1)" : "+r"(r4) : "r"((void *)X));
    pair = 0u;
    __asm__ volatile("ldl %0,0(%1)\n\tldr %0,0(%2)"
                     : "+r"(pair)
                     : "r"((void *)X), "r"((void *)Y));
    printf("T12 Xmod8=%d Ymod8=%d\n", (int)((uintptr_t)X % 8u),
           (int)((uintptr_t)Y % 8u));
    printf("T12 ldl-only X: rt0=0x%016llx rtFF=0x%016llx\n",
           (unsigned long long)r1, (unsigned long long)r3);
    printf("T12 ldr-only X: rt0=0x%016llx rtFF=0x%016llx\n",
           (unsigned long long)r2, (unsigned long long)r4);
    {
        uint64_t ref = 0u;
        unsigned k;
        /* Reference rebuilt byte-by-byte in memory order. */
        for (k = 0; k < 8; k++) {
            unsigned b = wbuf[11 + k];
            ref |= (uint64_t)b << (le ? (8u * k) : (8u * (7u - k)));
        }
        CHECK("T12 pair ldl(X)+ldr(X+7)", pair, ref);
    }
}

/* ---- (9) SDL/SDR: canonical (0,7) pair stores V at unaligned X ---------
 * SDL(X) deposits the high bytes at mem[X..end of word A];
 * SDR(X+7) deposits the low bytes at mem[start of word B..X+7].
 * Footprint wbuf[10..19] plus guards wbuf[10], wbuf[19] are checked. */
__attribute__((noinline)) static void t_sdl_sdr(void)
{
    uint8_t *X = wbuf + 11; /* mod 3, word A = wbuf+8 */
    uint8_t *Y = wbuf + 18; /* X+7, mod 2, word B = wbuf+16 */
    uint64_t v = 0xA1B2C3D4E5F60718ULL;
    unsigned k;
    char line[128];
    size_t pos = 0u;
    uint16_t u = 1u;
    int le = (*(const uint8_t *)&u != 0u);
    int ok = 1;
    wfill();
    __asm__ volatile("sdl %0,0(%1)\n\tsdr %0,0(%2)"
                     :
                     : "r"(v), "r"((void *)X), "r"((void *)Y)
                     : "memory");
    for (k = 0; k < 8; k++) {
        unsigned got = wbuf[11 + k];
        unsigned wantb = (unsigned)((v >> (le ? (8u * k) : (8u * (7u - k))))
                                    & 0xFFu);
        if (got != wantb)
            ok = 0;
    }
    if (wbuf[10] != 0xAAu || wbuf[19] != 0xB3u)
        ok = 0;
    for (k = 10; k < 20; k++)
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%02x%s",
                                wbuf[k], (k + 1u < 20u) ? " " : "");
    line[sizeof(line) - 1u] = '\0';
    printf("T13 sdl+sdr: stored=0x%016llx guards=%02x/%02x %s\n",
           (unsigned long long)v, wbuf[10], wbuf[19],
           ok ? "MATCH" : "MISMATCH");
    printf("T13 footprint wbuf[10:20]: %s\n", line);
    if (!ok)
        g_fail++;
}

int main(void)
{
    t_model();
    t_addiu();
    t_addu();
    t_sll();
    t_lw();
    t_daddiu();
    t_dext();
    t_dextm();
    t_dextu();
    t_dins();
    t_dinsm();
    t_dinsu();
    t_ldl_ldr();
    t_sdl_sdr();
    printf("E02-RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
