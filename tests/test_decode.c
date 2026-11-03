/*
 * tests/test_decode.c — Table-driven self-test for mips_decode (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-native test: fixed instruction words map to expected decoded
 * fields (every mips_dec_t field is asserted for every case), pure
 * classifiers are checked per word, and mips_fetch is exercised LE+BE
 * through a scratch guest_base window.
 *
 * NOTE (RC1 integration): src/os/mem.c is on master, so this test
 * links the real guest_mem_init against a scratch reservation window
 * (guest_base overwritten below, no regions) and exercises the real
 * TASK_SIZE bound in mips_fetch.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/decode.h"

/* Scratch guest window for the fetch checks (covers pc 0..0x2fff). */
static uint8_t fetch_window[0x3000];

/*
 * Point the Phase 1 reservation at the scratch buffer (see NOTE above):
 * region_count stays 0 so mips_fetch applies only the TASK_SIZE bound
 * here, through the real guest_mem_init from src/os/mem.c.
 */
static void use_scratch_window(mips64_ctx_t *ctx)
{
    if (guest_mem_init(ctx) != 0) {
        printf("FAIL fetch: guest_mem_init failed\n");
        return;
    }
    ctx->guest_base = (uint64_t)(uintptr_t)fetch_window;
    mips_mem_reset();
}

typedef struct {
    const char *name;
    uint32_t word;
    uint8_t op;
    uint8_t rs;
    uint8_t rt;
    uint8_t rd;
    uint8_t sa;
    uint8_t funct;
    uint16_t imm;
    uint32_t target;
    int32_t simm;
    uint32_t uimm;
} decode_case_t;

static const decode_case_t cases[] = {
    { "nop", 0x00000000U, 0, 0, 0, 0, 0, 0x00, 0x0000, 0x0000000U, 0, 0U },
    { "sll", 0x00094100U, 0, 0, 9, 8, 4, 0x00, 0x4100, 0x0094100U, 16640, 16640U },
    { "srl", 0x000521c2U, 0, 0, 5, 4, 7, 0x02, 0x21c2, 0x00521c2U, 8642, 8642U },
    { "sra", 0x00063043U, 0, 0, 6, 6, 1, 0x03, 0x3043, 0x0063043U, 12355, 12355U },
    { "sllv", 0x00653004U, 0, 3, 5, 6, 0, 0x04, 0x3004, 0x0653004U, 12292, 12292U },
    { "srlv", 0x00a63806U, 0, 5, 6, 7, 0, 0x06, 0x3806, 0x0a63806U, 14342, 14342U },
    { "srav", 0x00c74007U, 0, 6, 7, 8, 0, 0x07, 0x4007, 0x0c74007U, 16391, 16391U },
    { "jr", 0x03e00008U, 0, 31, 0, 0, 0, 0x08, 0x0008, 0x3e00008U, 8, 8U },
    { "jalr", 0x0320f809U, 0, 25, 0, 31, 0, 0x09, 0xf809, 0x320f809U, -2039, 63497U },
    { "movz", 0x0043100aU, 0, 2, 3, 2, 0, 0x0a, 0x100a, 0x043100aU, 4106, 4106U },
    { "movn", 0x0062180bU, 0, 3, 2, 3, 0, 0x0b, 0x180b, 0x062180bU, 6155, 6155U },
    { "syscall", 0x0000000cU, 0, 0, 0, 0, 0, 0x0c, 0x000c, 0x000000cU, 12, 12U },
    { "break", 0x0000010dU, 0, 0, 0, 0, 4, 0x0d, 0x010d, 0x000010dU, 269, 269U },
    { "sync", 0x0000000fU, 0, 0, 0, 0, 0, 0x0f, 0x000f, 0x000000fU, 15, 15U },
    { "mfhi", 0x00004010U, 0, 0, 0, 8, 0, 0x10, 0x4010, 0x0004010U, 16400, 16400U },
    { "mthi", 0x00200011U, 0, 1, 0, 0, 0, 0x11, 0x0011, 0x0200011U, 17, 17U },
    { "mflo", 0x00004812U, 0, 0, 0, 9, 0, 0x12, 0x4812, 0x0004812U, 18450, 18450U },
    { "mtlo", 0x00a00013U, 0, 5, 0, 0, 0, 0x13, 0x0013, 0x0a00013U, 19, 19U },
    { "dsllv", 0x00653014U, 0, 3, 5, 6, 0, 0x14, 0x3014, 0x0653014U, 12308, 12308U },
    { "dsrlv", 0x00a63816U, 0, 5, 6, 7, 0, 0x16, 0x3816, 0x0a63816U, 14358, 14358U },
    { "dsrav", 0x00c74017U, 0, 6, 7, 8, 0, 0x17, 0x4017, 0x0c74017U, 16407, 16407U },
    { "mult", 0x00220018U, 0, 1, 2, 0, 0, 0x18, 0x0018, 0x0220018U, 24, 24U },
    { "multu", 0x00431819U, 0, 2, 3, 3, 0, 0x19, 0x1819, 0x0431819U, 6169, 6169U },
    { "div", 0x0064201aU, 0, 3, 4, 4, 0, 0x1a, 0x201a, 0x064201aU, 8218, 8218U },
    { "divu", 0x0085301bU, 0, 4, 5, 6, 0, 0x1b, 0x301b, 0x085301bU, 12315, 12315U },
    { "dmult", 0x00e6381cU, 0, 7, 6, 7, 0, 0x1c, 0x381c, 0x0e6381cU, 14364, 14364U },
    { "dmultu", 0x0109411dU, 0, 8, 9, 8, 4, 0x1d, 0x411d, 0x109411dU, 16669, 16669U },
    { "ddiv", 0x012a401eU, 0, 9, 10, 8, 0, 0x1e, 0x401e, 0x12a401eU, 16414, 16414U },
    { "ddivu", 0x014b501fU, 0, 10, 11, 10, 0, 0x1f, 0x501f, 0x14b501fU, 20511, 20511U },
    { "add", 0x012a4020U, 0, 9, 10, 8, 0, 0x20, 0x4020, 0x12a4020U, 16416, 16416U },
    { "addu", 0x014b5021U, 0, 10, 11, 10, 0, 0x21, 0x5021, 0x14b5021U, 20513, 20513U },
    { "sub", 0x016c6022U, 0, 11, 12, 12, 0, 0x22, 0x6022, 0x16c6022U, 24610, 24610U },
    { "subu", 0x018d7023U, 0, 12, 13, 14, 0, 0x23, 0x7023, 0x18d7023U, 28707, 28707U },
    { "and", 0x00430824U, 0, 2, 3, 1, 0, 0x24, 0x0824, 0x0430824U, 2084, 2084U },
    { "or", 0x00641825U, 0, 3, 4, 3, 0, 0x25, 0x1825, 0x0641825U, 6181, 6181U },
    { "xor", 0x00852026U, 0, 4, 5, 4, 0, 0x26, 0x2026, 0x0852026U, 8230, 8230U },
    { "nor", 0x00a62827U, 0, 5, 6, 5, 0, 0x27, 0x2827, 0x0a62827U, 10279, 10279U },
    { "slt", 0x00c7382aU, 0, 6, 7, 7, 0, 0x2a, 0x382a, 0x0c7382aU, 14378, 14378U },
    { "sltu", 0x00e8482bU, 0, 7, 8, 9, 0, 0x2b, 0x482b, 0x0e8482bU, 18475, 18475U },
    { "dadd", 0x0211802cU, 0, 16, 17, 16, 0, 0x2c, 0x802c, 0x211802cU, -32724, 32812U },
    { "daddu", 0x0232822dU, 0, 17, 18, 16, 8, 0x2d, 0x822d, 0x232822dU, -32211, 33325U },
    { "dsub", 0x0253842eU, 0, 18, 19, 16, 16, 0x2e, 0x842e, 0x253842eU, -31698, 33838U },
    { "dsubu", 0x0274862fU, 0, 19, 20, 16, 24, 0x2f, 0x862f, 0x274862fU, -31185, 34351U },
    { "tge", 0x00431030U, 0, 2, 3, 2, 0, 0x30, 0x1030, 0x0431030U, 4144, 4144U },
    { "tgeu", 0x00621831U, 0, 3, 2, 3, 0, 0x31, 0x1831, 0x0621831U, 6193, 6193U },
    { "tlt", 0x00852032U, 0, 4, 5, 4, 0, 0x32, 0x2032, 0x0852032U, 8242, 8242U },
    { "tltu", 0x00a62833U, 0, 5, 6, 5, 0, 0x33, 0x2833, 0x0a62833U, 10291, 10291U },
    { "teq", 0x00c73834U, 0, 6, 7, 7, 0, 0x34, 0x3834, 0x0c73834U, 14388, 14388U },
    { "tne", 0x00e84836U, 0, 7, 8, 9, 0, 0x36, 0x4836, 0x0e84836U, 18486, 18486U },
    { "dsll", 0x00064138U, 0, 0, 6, 8, 4, 0x38, 0x4138, 0x0064138U, 16696, 16696U },
    { "dsrl", 0x0008433aU, 0, 0, 8, 8, 12, 0x3a, 0x433a, 0x008433aU, 17210, 17210U },
    { "dsra", 0x000a453bU, 0, 0, 10, 8, 20, 0x3b, 0x453b, 0x00a453bU, 17723, 17723U },
    { "dsll32", 0x0006417cU, 0, 0, 6, 8, 5, 0x3c, 0x417c, 0x006417cU, 16764, 16764U },
    { "dsrl32", 0x0008437eU, 0, 0, 8, 8, 13, 0x3e, 0x437e, 0x008437eU, 17278, 17278U },
    { "dsra32", 0x000a457fU, 0, 0, 10, 8, 21, 0x3f, 0x457f, 0x00a457fU, 17791, 17791U },
    { "bltz", 0x04800010U, 1, 4, 0, 0, 0, 0x10, 0x0010, 0x0800010U, 16, 16U },
    { "bgez", 0x04a1fffcU, 1, 5, 1, 31, 31, 0x3c, 0xfffc, 0x0a1fffcU, -4, 65532U },
    { "bltzl", 0x04820010U, 1, 4, 2, 0, 0, 0x10, 0x0010, 0x0820010U, 16, 16U },
    { "bgezl", 0x04a3fffcU, 1, 5, 3, 31, 31, 0x3c, 0xfffc, 0x0a3fffcU, -4, 65532U },
    { "bltzal", 0x04d01234U, 1, 6, 16, 2, 8, 0x34, 0x1234, 0x0d01234U, 4660, 4660U },
    { "bgezal", 0x04f11234U, 1, 7, 17, 2, 8, 0x34, 0x1234, 0x0f11234U, 4660, 4660U },
    { "bltzall", 0x04921234U, 1, 4, 18, 2, 8, 0x34, 0x1234, 0x0921234U, 4660, 4660U },
    { "bgezall", 0x04b31234U, 1, 5, 19, 2, 8, 0x34, 0x1234, 0x0b31234U, 4660, 4660U },
    { "tgei", 0x04c80001U, 1, 6, 8, 0, 0, 0x01, 0x0001, 0x0c80001U, 1, 1U },
    { "tgeiu", 0x04c90001U, 1, 6, 9, 0, 0, 0x01, 0x0001, 0x0c90001U, 1, 1U },
    { "tlti", 0x04ca0001U, 1, 6, 10, 0, 0, 0x01, 0x0001, 0x0ca0001U, 1, 1U },
    { "tltiu", 0x04cb0001U, 1, 6, 11, 0, 0, 0x01, 0x0001, 0x0cb0001U, 1, 1U },
    { "teqi", 0x04cc0001U, 1, 6, 12, 0, 0, 0x01, 0x0001, 0x0cc0001U, 1, 1U },
    { "tnei", 0x04ce0001U, 1, 6, 14, 0, 0, 0x01, 0x0001, 0x0ce0001U, 1, 1U },
    { "j", 0x08100000U, 2, 0, 16, 0, 0, 0x00, 0x0000, 0x0100000U, 0, 0U },
    { "jal", 0x0fffffffU, 3, 31, 31, 31, 31, 0x3f, 0xffff, 0x3ffffffU, -1, 65535U },
    { "beq", 0x10850064U, 4, 4, 5, 0, 1, 0x24, 0x0064, 0x0850064U, 100, 100U },
    { "bne", 0x14c7ff9cU, 5, 6, 7, 31, 30, 0x1c, 0xff9c, 0x0c7ff9cU, -100, 65436U },
    { "blez", 0x19007fffU, 6, 8, 0, 15, 31, 0x3f, 0x7fff, 0x1007fffU, 32767, 32767U },
    { "bgtz", 0x1d208000U, 7, 9, 0, 16, 0, 0x00, 0x8000, 0x1208000U, -32768, 32768U },
    { "beql", 0x514b0001U, 20, 10, 11, 0, 0, 0x01, 0x0001, 0x14b0001U, 1, 1U },
    { "bnel", 0x558dfffeU, 21, 12, 13, 31, 31, 0x3e, 0xfffe, 0x18dfffeU, -2, 65534U },
    { "blezl", 0x59c0abcdU, 22, 14, 0, 21, 15, 0x0d, 0xabcd, 0x1c0abcdU, -21555, 43981U },
    { "bgtzl", 0x5de00000U, 23, 15, 0, 0, 0, 0x00, 0x0000, 0x1e00000U, 0, 0U },
    { "addi", 0x20a4ffffU, 8, 5, 4, 31, 31, 0x3f, 0xffff, 0x0a4ffffU, -1, 65535U },
    { "addiu", 0x24e67fffU, 9, 7, 6, 15, 31, 0x3f, 0x7fff, 0x0e67fffU, 32767, 32767U },
    { "slti", 0x29288000U, 10, 9, 8, 16, 0, 0x00, 0x8000, 0x1288000U, -32768, 32768U },
    { "sltiu", 0x2d2b0001U, 11, 9, 11, 0, 0, 0x01, 0x0001, 0x12b0001U, 1, 1U },
    { "andi", 0x316aabcdU, 12, 11, 10, 21, 15, 0x0d, 0xabcd, 0x16aabcdU, -21555, 43981U },
    { "ori", 0x35ac1234U, 13, 13, 12, 2, 8, 0x34, 0x1234, 0x1ac1234U, 4660, 4660U },
    { "xori", 0x39ee0000U, 14, 15, 14, 0, 0, 0x00, 0x0000, 0x1ee0000U, 0, 0U },
    { "lui", 0x3c041234U, 15, 0, 4, 2, 8, 0x34, 0x1234, 0x0041234U, 4660, 4660U },
    { "daddi", 0x60850010U, 24, 4, 5, 0, 0, 0x10, 0x0010, 0x0850010U, 16, 16U },
    { "daddiu", 0x64a50010U, 25, 5, 5, 0, 0, 0x10, 0x0010, 0x0a50010U, 16, 16U },
    { "madd", 0x70062200U, 28, 0, 6, 4, 8, 0x00, 0x2200, 0x0062200U, 8704, 8704U },
    { "maddu", 0x70273101U, 28, 1, 7, 6, 4, 0x01, 0x3101, 0x0273101U, 12545, 12545U },
    { "mul", 0x70494102U, 28, 2, 9, 8, 4, 0x02, 0x4102, 0x0494102U, 16642, 16642U },
    { "msub", 0x706a5104U, 28, 3, 10, 10, 4, 0x04, 0x5104, 0x06a5104U, 20740, 20740U },
    { "msubu", 0x708c6105U, 28, 4, 12, 12, 4, 0x05, 0x6105, 0x08c6105U, 24837, 24837U },
    { "clz", 0x70a73020U, 28, 5, 7, 6, 0, 0x20, 0x3020, 0x0a73020U, 12320, 12320U },
    { "clo", 0x70c84021U, 28, 6, 8, 8, 0, 0x21, 0x4021, 0x0c84021U, 16417, 16417U },
    { "dclz", 0x70ea5024U, 28, 7, 10, 10, 0, 0x24, 0x5024, 0x0ea5024U, 20516, 20516U },
    { "dclo", 0x710c6025U, 28, 8, 12, 12, 0, 0x25, 0x6025, 0x10c6025U, 24613, 24613U },
    { "sdbbp", 0x7000003fU, 28, 0, 0, 0, 0, 0x3f, 0x003f, 0x000003fU, 63, 63U },
    { "ext", 0x7c021a80U, 31, 0, 2, 3, 10, 0x00, 0x1a80, 0x0021a80U, 6784, 6784U },
    { "dexm", 0x7cc67c01U, 31, 6, 6, 15, 16, 0x01, 0x7c01, 0x0c67c01U, 31745, 31745U },
    { "dextu", 0x7cc67c02U, 31, 6, 6, 15, 16, 0x02, 0x7c02, 0x0c67c02U, 31746, 31746U },
    { "dext", 0x7cc63a03U, 31, 6, 6, 7, 8, 0x03, 0x3a03, 0x0c63a03U, 14851, 14851U },
    { "ins", 0x7c867c84U, 31, 4, 6, 15, 18, 0x04, 0x7c84, 0x0867c84U, 31876, 31876U },
    { "dinsm", 0x7c467c05U, 31, 2, 6, 15, 16, 0x05, 0x7c05, 0x0467c05U, 31749, 31749U },
    { "dinsu", 0x7c46fc06U, 31, 2, 6, 31, 16, 0x06, 0xfc06, 0x046fc06U, -1018, 64518U },
    { "dins", 0x7c467a07U, 31, 2, 6, 15, 8, 0x07, 0x7a07, 0x0467a07U, 31239, 31239U },
    { "wsbh", 0x7c0210a0U, 31, 0, 2, 2, 2, 0x20, 0x10a0, 0x00210a0U, 4256, 4256U },
    { "rdhwr", 0x7c03e83bU, 31, 0, 3, 29, 0, 0x3b, 0xe83b, 0x003e83bU, -6085, 59451U },
    { "mfc0", 0x40086000U, 16, 0, 8, 12, 0, 0x00, 0x6000, 0x0086000U, 24576, 24576U },
    { "dmfc0", 0x40286000U, 16, 1, 8, 12, 0, 0x00, 0x6000, 0x0286000U, 24576, 24576U },
    { "mtc0", 0x40886000U, 16, 4, 8, 12, 0, 0x00, 0x6000, 0x0886000U, 24576, 24576U },
    { "dmtc0", 0x40a86000U, 16, 5, 8, 12, 0, 0x00, 0x6000, 0x0a86000U, 24576, 24576U },
    { "tlbwi", 0x42000002U, 16, 16, 0, 0, 0, 0x02, 0x0002, 0x2000002U, 2, 2U },
    { "eret", 0x42000018U, 16, 16, 0, 0, 0, 0x18, 0x0018, 0x2000018U, 24, 24U },
    { "bc0f", 0x41000005U, 16, 8, 0, 0, 0, 0x05, 0x0005, 0x1000005U, 5, 5U },
    { "bc0tl", 0x4103fff8U, 16, 8, 3, 31, 31, 0x38, 0xfff8, 0x103fff8U, -8, 65528U },
    { "mfc1", 0x44084800U, 17, 0, 8, 9, 0, 0x00, 0x4800, 0x0084800U, 18432, 18432U },
    { "dmfc1", 0x44284800U, 17, 1, 8, 9, 0, 0x00, 0x4800, 0x0284800U, 18432, 18432U },
    { "cfc1", 0x44484800U, 17, 2, 8, 9, 0, 0x00, 0x4800, 0x0484800U, 18432, 18432U },
    { "mtc1", 0x44884800U, 17, 4, 8, 9, 0, 0x00, 0x4800, 0x0884800U, 18432, 18432U },
    { "dmtc1", 0x44a84800U, 17, 5, 8, 9, 0, 0x00, 0x4800, 0x0a84800U, 18432, 18432U },
    { "ctc1", 0x44c84800U, 17, 6, 8, 9, 0, 0x00, 0x4800, 0x0c84800U, 18432, 18432U },
    { "bc1f", 0x45000005U, 17, 8, 0, 0, 0, 0x05, 0x0005, 0x1000005U, 5, 5U },
    { "bc1t", 0x45010005U, 17, 8, 1, 0, 0, 0x05, 0x0005, 0x1010005U, 5, 5U },
    { "bc1fl", 0x4502fff8U, 17, 8, 2, 31, 31, 0x38, 0xfff8, 0x102fff8U, -8, 65528U },
    { "bc1tl", 0x4503fff8U, 17, 8, 3, 31, 31, 0x38, 0xfff8, 0x103fff8U, -8, 65528U },
    { "lb", 0x81ac0001U, 32, 13, 12, 0, 0, 0x01, 0x0001, 0x1ac0001U, 1, 1U },
    { "lh", 0x84ac0002U, 33, 5, 12, 0, 0, 0x02, 0x0002, 0x0ac0002U, 2, 2U },
    { "lwl", 0x88a40003U, 34, 5, 4, 0, 0, 0x03, 0x0003, 0x0a40003U, 3, 3U },
    { "lw", 0x8d28fff8U, 35, 9, 8, 31, 31, 0x38, 0xfff8, 0x128fff8U, -8, 65528U },
    { "lbu", 0x91ee00ffU, 36, 15, 14, 0, 3, 0x3f, 0x00ff, 0x1ee00ffU, 255, 255U },
    { "lhu", 0x95ee0002U, 37, 15, 14, 0, 0, 0x02, 0x0002, 0x1ee0002U, 2, 2U },
    { "lwr", 0x98e60007U, 38, 7, 6, 0, 0, 0x07, 0x0007, 0x0e60007U, 7, 7U },
    { "lwu", 0x9fa60000U, 39, 29, 6, 0, 0, 0x00, 0x0000, 0x3a60000U, 0, 0U },
    { "ll", 0xc0850000U, 48, 4, 5, 0, 0, 0x00, 0x0000, 0x0850000U, 0, 0U },
    { "lld", 0xd0850000U, 52, 4, 5, 0, 0, 0x00, 0x0000, 0x0850000U, 0, 0U },
    { "ld", 0xdc850000U, 55, 4, 5, 0, 0, 0x00, 0x0000, 0x0850000U, 0, 0U },
    { "lwc1", 0xc4880000U, 49, 4, 8, 0, 0, 0x00, 0x0000, 0x0880000U, 0, 0U },
    { "ldc1", 0xd4880000U, 53, 4, 8, 0, 0, 0x00, 0x0000, 0x0880000U, 0, 0U },
    { "sb", 0xa0410000U, 40, 2, 1, 0, 0, 0x00, 0x0000, 0x0410000U, 0, 0U },
    { "sh", 0xa4ac0002U, 41, 5, 12, 0, 0, 0x02, 0x0002, 0x0ac0002U, 2, 2U },
    { "swl", 0xa8a40003U, 42, 5, 4, 0, 0, 0x03, 0x0003, 0x0a40003U, 3, 3U },
    { "sw", 0xad6a0010U, 43, 11, 10, 0, 0, 0x10, 0x0010, 0x16a0010U, 16, 16U },
    { "sdl", 0xb0850000U, 44, 4, 5, 0, 0, 0x00, 0x0000, 0x0850000U, 0, 0U },
    { "sdr", 0xb4450000U, 45, 2, 5, 0, 0, 0x00, 0x0000, 0x0450000U, 0, 0U },
    { "swr", 0xb8a40003U, 46, 5, 4, 0, 0, 0x03, 0x0003, 0x0a40003U, 3, 3U },
    { "cache", 0xbc850012U, 47, 4, 5, 0, 0, 0x12, 0x0012, 0x0850012U, 18, 18U },
    { "pref", 0xcc850012U, 51, 4, 5, 0, 0, 0x12, 0x0012, 0x0850012U, 18, 18U },
    { "sc", 0xe0860000U, 56, 4, 6, 0, 0, 0x00, 0x0000, 0x0860000U, 0, 0U },
    { "scd", 0xf0820000U, 60, 4, 2, 0, 0, 0x00, 0x0000, 0x0820000U, 0, 0U },
    { "sd", 0xfc850000U, 63, 4, 5, 0, 0, 0x00, 0x0000, 0x0850000U, 0, 0U },
    { "swc1", 0xe4880000U, 57, 4, 8, 0, 0, 0x00, 0x0000, 0x0880000U, 0, 0U },
    { "sdc1", 0xf4880000U, 61, 4, 8, 0, 0, 0x00, 0x0000, 0x0880000U, 0, 0U },
    { "jalx", 0x74123456U, 29, 0, 18, 6, 17, 0x16, 0x3456, 0x0123456U, 13398, 13398U },
    { "cop2", 0x48a40003U, 18, 5, 4, 0, 0, 0x03, 0x0003, 0x0a40003U, 3, 3U },
};

#define N_CASES (sizeof(cases) / sizeof(cases[0]))

typedef struct {
    const char *name;
    uint32_t word;
    int is_branch;
    int is_likely;
    int is_jump;
    int is_link;
    int is_load;
    int is_store;
    int is_trap;
} class_case_t;

static const class_case_t class_cases[] = {
    { "nop", 0x00000000U, 0, 0, 0, 0, 0, 0, 0 },
    { "sll", 0x00094100U, 0, 0, 0, 0, 0, 0, 0 },
    { "jr", 0x03e00008U, 0, 0, 1, 0, 0, 0, 0 },
    { "jalr", 0x0320f809U, 0, 0, 1, 1, 0, 0, 0 },
    { "syscall", 0x0000000cU, 0, 0, 0, 0, 0, 0, 1 },
    { "break", 0x0000010dU, 0, 0, 0, 0, 0, 0, 1 },
    { "sdbbp", 0x7000003fU, 0, 0, 0, 0, 0, 0, 1 },
    { "mult", 0x00220018U, 0, 0, 0, 0, 0, 0, 0 },
    { "teq", 0x00c73834U, 0, 0, 0, 0, 0, 0, 1 },
    { "tne", 0x00e84836U, 0, 0, 0, 0, 0, 0, 1 },
    { "tge", 0x00431030U, 0, 0, 0, 0, 0, 0, 1 },
    { "bltz", 0x04800010U, 1, 0, 0, 0, 0, 0, 0 },
    { "bgezl", 0x04a3fffcU, 1, 1, 0, 0, 0, 0, 0 },
    { "bltzal", 0x04d01234U, 1, 0, 0, 1, 0, 0, 0 },
    { "bltzall", 0x04921234U, 1, 1, 0, 1, 0, 0, 0 },
    { "bgezall", 0x04b31234U, 1, 1, 0, 1, 0, 0, 0 },
    { "tgei", 0x04c80001U, 0, 0, 0, 0, 0, 0, 1 },
    { "tnei", 0x04ce0001U, 0, 0, 0, 0, 0, 0, 1 },
    { "j", 0x08100000U, 0, 0, 1, 0, 0, 0, 0 },
    { "jal", 0x0fffffffU, 0, 0, 1, 1, 0, 0, 0 },
    { "beq", 0x10850064U, 1, 0, 0, 0, 0, 0, 0 },
    { "bne", 0x14c7ff9cU, 1, 0, 0, 0, 0, 0, 0 },
    { "beql", 0x514b0001U, 1, 1, 0, 0, 0, 0, 0 },
    { "blezl", 0x59c0abcdU, 1, 1, 0, 0, 0, 0, 0 },
    { "addi", 0x20a4ffffU, 0, 0, 0, 0, 0, 0, 0 },
    { "daddiu", 0x64a50010U, 0, 0, 0, 0, 0, 0, 0 },
    { "madd", 0x70062200U, 0, 0, 0, 0, 0, 0, 0 },
    { "clz", 0x70a73020U, 0, 0, 0, 0, 0, 0, 0 },
    { "ext", 0x7c021a80U, 0, 0, 0, 0, 0, 0, 0 },
    { "rdhwr", 0x7c03e83bU, 0, 0, 0, 0, 0, 0, 0 },
    { "mfc0", 0x40086000U, 0, 0, 0, 0, 0, 0, 0 },
    { "eret", 0x42000018U, 0, 0, 0, 0, 0, 0, 0 },
    { "bc0f", 0x41000005U, 1, 0, 0, 0, 0, 0, 0 },
    { "bc0tl", 0x4103fff8U, 1, 1, 0, 0, 0, 0, 0 },
    { "mfc1", 0x44084800U, 0, 0, 0, 0, 0, 0, 0 },
    { "bc1t", 0x45010005U, 1, 0, 0, 0, 0, 0, 0 },
    { "bc1fl", 0x4502fff8U, 1, 1, 0, 0, 0, 0, 0 },
    { "lb", 0x81ac0001U, 0, 0, 0, 0, 1, 0, 0 },
    { "lw", 0x8d28fff8U, 0, 0, 0, 0, 1, 0, 0 },
    { "lwl", 0x88a40003U, 0, 0, 0, 0, 1, 0, 0 },
    { "ldl", 0x6a140000U, 0, 0, 0, 0, 1, 0, 0 },
    { "ldr", 0x6e130000U, 0, 0, 0, 0, 1, 0, 0 },
    { "ll", 0xc0850000U, 0, 0, 0, 0, 1, 0, 0 },
    { "lld", 0xd0850000U, 0, 0, 0, 0, 1, 0, 0 },
    { "ld", 0xdc850000U, 0, 0, 0, 0, 1, 0, 0 },
    { "lwc1", 0xc4880000U, 0, 0, 0, 0, 1, 0, 0 },
    { "ldc1", 0xd4880000U, 0, 0, 0, 0, 1, 0, 0 },
    { "sb", 0xa0410000U, 0, 0, 0, 0, 0, 1, 0 },
    { "sw", 0xad6a0010U, 0, 0, 0, 0, 0, 1, 0 },
    { "swl", 0xa8a40003U, 0, 0, 0, 0, 0, 1, 0 },
    { "swr", 0xb8a40003U, 0, 0, 0, 0, 0, 1, 0 },
    { "sdl", 0xb0850000U, 0, 0, 0, 0, 0, 1, 0 },
    { "sdr", 0xb4450000U, 0, 0, 0, 0, 0, 1, 0 },
    { "sc", 0xe0860000U, 0, 0, 0, 0, 0, 1, 0 },
    { "scd", 0xf0820000U, 0, 0, 0, 0, 0, 1, 0 },
    { "sd", 0xfc850000U, 0, 0, 0, 0, 0, 1, 0 },
    { "swc1", 0xe4880000U, 0, 0, 0, 0, 0, 1, 0 },
    { "sdc1", 0xf4880000U, 0, 0, 0, 0, 0, 1, 0 },
    { "cache", 0xbc850012U, 0, 0, 0, 0, 0, 0, 0 },
    { "pref", 0xcc850012U, 0, 0, 0, 0, 0, 0, 0 },
    { "jalx", 0x74123456U, 0, 0, 0, 0, 0, 0, 0 },
    { "cop2", 0x48a40003U, 0, 0, 0, 0, 0, 0, 0 },
};

#define N_CLASS (sizeof(class_cases) / sizeof(class_cases[0]))

static int failures;

static void check_field(const char *name, const char *field,
    unsigned long got, unsigned long want)
{
    if (got != want) {
        printf("FAIL %s: %s got %lu want %lu\n", name, field, got, want);
        failures++;
    }
}

static void check_case(const decode_case_t *c)
{
    mips_dec_t d;

    mips_decode(c->word, &d);
    check_field(c->name, "word", (unsigned long)d.word, (unsigned long)c->word);
    check_field(c->name, "op", (unsigned long)d.op, (unsigned long)c->op);
    check_field(c->name, "rs", (unsigned long)d.rs, (unsigned long)c->rs);
    check_field(c->name, "rt", (unsigned long)d.rt, (unsigned long)c->rt);
    check_field(c->name, "rd", (unsigned long)d.rd, (unsigned long)c->rd);
    check_field(c->name, "sa", (unsigned long)d.sa, (unsigned long)c->sa);
    check_field(c->name, "funct", (unsigned long)d.funct, (unsigned long)c->funct);
    check_field(c->name, "imm", (unsigned long)d.imm, (unsigned long)c->imm);
    check_field(c->name, "target", (unsigned long)d.target, (unsigned long)c->target);
    if (d.simm != c->simm) {
        printf("FAIL %s: simm got %d want %d\n", c->name, (int)d.simm, (int)c->simm);
        failures++;
    }
    check_field(c->name, "uimm", (unsigned long)d.uimm, (unsigned long)c->uimm);
}

static void check_fetch_le(mips64_ctx_t *ctx)
{
    uint32_t word = 0U;
    mips_dec_t d;

    ctx->is_be = 0U;
    fetch_window[0x100] = 0x34U;
    fetch_window[0x101] = 0x12U;
    fetch_window[0x102] = 0x04U;
    fetch_window[0x103] = 0x3cU;
    if (mips_fetch(ctx, 0x100U, &word) != 0 || word != 0x3c041234U) {
        printf("FAIL fetch-le: got 0x%08x want 0x3c041234\n", word);
        failures++;
    }
    mips_decode(word, &d);
    if (d.op != MIPS64_OP_LUI || d.rt != 4U || d.imm != 0x1234U) {
        printf("FAIL fetch-le-decode: op=%u rt=%u imm=0x%x\n",
            d.op, d.rt, d.imm);
        failures++;
    }
}

static void check_fetch_be(mips64_ctx_t *ctx)
{
    uint32_t word = 0U;

    ctx->is_be = 1U;
    fetch_window[0x200] = 0x3cU;
    fetch_window[0x201] = 0x04U;
    fetch_window[0x202] = 0x12U;
    fetch_window[0x203] = 0x34U;
    if (mips_fetch(ctx, 0x200U, &word) != 0 || word != 0x3c041234U) {
        printf("FAIL fetch-be: got 0x%08x want 0x3c041234\n", word);
        failures++;
    }
    ctx->is_be = 0U;
    if (mips_fetch(ctx, 0x200U, &word) != 0 || word != 0x3412043cU) {
        printf("FAIL fetch-be-as-le: got 0x%08x want 0x3412043c\n", word);
        failures++;
    }
}

static void check_fetch_faults(mips64_ctx_t *ctx)
{
    uint32_t word = 0xdeadbeefU;

    ctx->is_be = 0U;
    if (mips_fetch(ctx, 0x101U, &word) != MIPS_FAULT) {
        printf("FAIL fetch: misaligned 0x101 did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, 0x102U, &word) != MIPS_FAULT) {
        printf("FAIL fetch: misaligned 0x102 did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, 0x103U, &word) != MIPS_FAULT) {
        printf("FAIL fetch: misaligned 0x103 did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, mips_task_size(ctx), &word) != MIPS_FAULT) {
        printf("FAIL fetch: pc == task_size did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, UINT64_MAX, &word) != MIPS_FAULT) {
        printf("FAIL fetch: pc == UINT64_MAX did not fault\n");
        failures++;
    }
    if (mips_fetch(NULL, 0x100U, &word) != MIPS_FAULT) {
        printf("FAIL fetch: null ctx did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, 0x100U, NULL) != MIPS_FAULT) {
        printf("FAIL fetch: null word did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, 0x100U, &word) != 0 || word != 0x3c041234U) {
        printf("FAIL fetch: pc 0 after faults got 0x%08x\n", word);
        failures++;
    }
}

static void check_fetch_regions(mips64_ctx_t *ctx)
{
    uint32_t word = 0U;
    mips64_region_t cover;

    fetch_window[0x1000] = 0x00U;
    fetch_window[0x1001] = 0x00U;
    fetch_window[0x1002] = 0x00U;
    fetch_window[0x1003] = 0x0cU;
    fetch_window[0x1ffc] = 0x00U;
    fetch_window[0x1ffd] = 0x00U;
    fetch_window[0x1ffe] = 0x00U;
    fetch_window[0x1fff] = 0x0cU;
    /* Lane H4: cover lives in the process-global table, loaded via
     * the public snapshot/restore entry points (no host mapping is
     * touched; fetch reads the scratch window through guest_base). */
    memset(&cover, 0, sizeof cover);
    cover.start = 0x1000U;
    cover.end = 0x2000U;
    cover.prot = MIPS_PROT_READ | MIPS_PROT_EXEC;
    mips_mem_restore(&cover, 1U);
    if (mips_fetch(ctx, 0x1000U, &word) != 0 || word != 0x0c000000U) {
        printf("FAIL fetch-region: covered 0x1000 got 0x%08x\n", word);
        failures++;
    }
    if (mips_fetch(ctx, 0x1ffcU, &word) != 0 || word != 0x0c000000U) {
        printf("FAIL fetch-region: covered 0x1ffc got 0x%08x\n", word);
        failures++;
    }
    if (mips_fetch(ctx, 0x0U, &word) != MIPS_FAULT) {
        printf("FAIL fetch-region: gap 0x0 did not fault\n");
        failures++;
    }
    if (mips_fetch(ctx, 0x2000U, &word) != MIPS_FAULT) {
        printf("FAIL fetch-region: end-exclusive 0x2000 did not fault\n");
        failures++;
    }
    /* RC1: fetch requires PROT_EXEC, so a PROT_NONE page faults
     * instead of trapping the host (branch-likely pageend probe). */
    cover.prot = 0U;
    mips_mem_restore(&cover, 1U);
    if (mips_fetch(ctx, 0x1000U, &word) != MIPS_FAULT) {
        printf("FAIL fetch-region: PROT_NONE 0x1000 did not fault\n");
        failures++;
    }
    mips_mem_reset();
}

int main(void)
{
    size_t i;
    mips64_ctx_t ctx;

    failures = 0;
    for (i = 0; i < N_CASES; i++) {
        check_case(&cases[i]);
    }
    for (i = 0; i < N_CLASS; i++) {
        const class_case_t *c = &class_cases[i];
        mips_dec_t d;
        int want_slot;

        mips_decode(c->word, &d);
        if (!!mips_is_branch(&d) != c->is_branch) {
            printf("FAIL %s: is_branch got %d want %d\n",
                c->name, !!mips_is_branch(&d), c->is_branch);
            failures++;
        }
        if (!!mips_is_branch_likely(&d) != c->is_likely) {
            printf("FAIL %s: is_branch_likely got %d want %d\n",
                c->name, !!mips_is_branch_likely(&d), c->is_likely);
            failures++;
        }
        if (!!mips_is_jump(&d) != c->is_jump) {
            printf("FAIL %s: is_jump got %d want %d\n",
                c->name, !!mips_is_jump(&d), c->is_jump);
            failures++;
        }
        if (!!mips_is_link(&d) != c->is_link) {
            printf("FAIL %s: is_link got %d want %d\n",
                c->name, !!mips_is_link(&d), c->is_link);
            failures++;
        }
        if (!!mips_is_load(&d) != c->is_load) {
            printf("FAIL %s: is_load got %d want %d\n",
                c->name, !!mips_is_load(&d), c->is_load);
            failures++;
        }
        if (!!mips_is_store(&d) != c->is_store) {
            printf("FAIL %s: is_store got %d want %d\n",
                c->name, !!mips_is_store(&d), c->is_store);
            failures++;
        }
        if (!!mips_is_trap(&d) != c->is_trap) {
            printf("FAIL %s: is_trap got %d want %d\n",
                c->name, !!mips_is_trap(&d), c->is_trap);
            failures++;
        }
        want_slot = (c->is_branch || c->is_jump) ? 1 : 0;
        if (!!mips_has_delay_slot(&d) != want_slot) {
            printf("FAIL %s: has_delay_slot got %d want %d\n",
                c->name, !!mips_has_delay_slot(&d), want_slot);
            failures++;
        }
    }
    /* Null-pointer safety: decoders and classifiers must not crash. */
    mips_decode(0x00000000U, NULL);
    if (mips_is_branch(NULL) != 0 || mips_is_branch_likely(NULL) != 0 ||
        mips_is_jump(NULL) != 0 || mips_is_link(NULL) != 0 ||
        mips_has_delay_slot(NULL) != 0 || mips_is_load(NULL) != 0 ||
        mips_is_store(NULL) != 0 || mips_is_trap(NULL) != 0) {
        printf("FAIL null: classifier on NULL did not return 0\n");
        failures++;
    }
    /* Fetch checks over the scratch window (N64 LE/BE, then N32 bound). */
    memset(&ctx, 0, sizeof(ctx));
    ctx.is_n32 = 0U;
    use_scratch_window(&ctx);
    check_fetch_le(&ctx);
    check_fetch_be(&ctx);
    check_fetch_faults(&ctx);
    check_fetch_regions(&ctx);
    memset(&ctx, 0, sizeof(ctx));
    ctx.is_n32 = 1U;
    use_scratch_window(&ctx);
    check_fetch_le(&ctx);
    check_fetch_faults(&ctx);

    if (failures != 0) {
        printf("DECODE: %d failure(s)\n", failures);
        return 1;
    }
    printf("DECODE: all %lu cases + %lu classifier checks passed\n",
        (unsigned long)N_CASES, (unsigned long)N_CLASS);
    printf("FETCH: LE+BE window, misalign/limit/region faults passed\n");
    printf("GUEST_MEM_INIT: real src/os/mem.c reservation (RC1)\n");
    return 0;
}