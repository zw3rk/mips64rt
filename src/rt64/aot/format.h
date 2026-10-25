/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MIPS64RT_RT64_AOT_FORMAT_H
#define MIPS64RT_RT64_AOT_FORMAT_H

#include <stddef.h>
#include <stdint.h>

/* This module only encodes and structurally validates bytes. A decoded view is
 * not trusted input and MUST NOT be executed or published RX. A later owner
 * must verify cache ownership, all opaque digests/profile values, live guest
 * bytes/generations, relocation semantics, and private staging before use.
 */
#define MIPS64_AOT_FORMAT_VERSION 1u
#define MIPS64_AOT_HEADER_BYTES 192u
#define MIPS64_AOT_FORMAT_V2 2u
#define MIPS64_AOT_HEADER_V2_BYTES 224u
#define MIPS64_AOT_RECORD_DIGEST_OFFSET 192u
#define MIPS64_AOT_BLOCK_HEADER_BYTES 24u
#define MIPS64_AOT_RELOCATION_BYTES 24u
#define MIPS64_AOT_DIGEST_BYTES 32u
#define MIPS64_AOT_MAX_FILE_BYTES (16u * 1024u * 1024u)
#define MIPS64_AOT_MAX_BLOCKS 4096u
#define MIPS64_AOT_MAX_SOURCE_BYTES 128u
#define MIPS64_AOT_MAX_BLOCK_TEXT_BYTES (64u * 1024u)
#define MIPS64_AOT_MAX_RELOCS_PER_BLOCK 256u
#define MIPS64_AOT_MAX_RELOCS 65536u

/* MIPS64r2 guest ABIs (SPEC 1.1): N64 (ELFCLASS64, 64-bit pointers)
 * and N32 (ELFCLASS32, 32-bit pointers, 64-bit registers). Both run on
 * the same 64-bit register file; `xlen` is always 64. */
typedef enum mips64_aot_abi {
    MIPS64_AOT_ABI_N64 = 1,
    MIPS64_AOT_ABI_N32 = 2
} mips64_aot_abi_t;

typedef enum mips64_aot_memory_model {
    MIPS64_AOT_MEMORY_SPARSE_CHECKED = 1
} mips64_aot_memory_model_t;

typedef enum mips64_aot_relocation_kind {
    MIPS64_AOT_RELOC_HELPER_ID = 1,
    MIPS64_AOT_RELOC_GUEST_RELATIVE = 2,
    MIPS64_AOT_RELOC_BLOCK_RELATIVE = 3
} mips64_aot_relocation_kind_t;

typedef struct mips64_aot_relocation {
    uint16_t kind;
    uint8_t width;       /* helper/guest MOV64: 16; block B26: 4 */
    uint32_t patch_offset;
    /* Helper ID or guest-VA-relative input offset; block target packs block
     * index in low32 and target A64 byte offset in high32. No host pointers. */
    uint64_t target;
    /* The format checks the raw block target's alignment/bounds, but leaves
     * addend arithmetic, B26 range and opcode-template checks to the future
     * applicator. */
    int64_t addend;
} mips64_aot_relocation_t;

/* Source offsets and guest-relative targets are input-image guest-VA offsets,
 * not file offsets. ELF mapping and live load bias remain applicator work. */

typedef struct mips64_aot_block {
    uint64_t source_offset;
    const uint8_t *source_bytes;
    uint32_t source_size;
    const uint8_t *a64_text;
    uint32_t a64_size;
    const mips64_aot_relocation_t *relocations;
    uint16_t relocation_count;
} mips64_aot_block_t;

typedef struct mips64_aot_image {
    uint8_t input_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[MIPS64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
    uint32_t block_count;
    const mips64_aot_block_t *blocks;
} mips64_aot_image_t;

/* Borrowed spans point into encoded bytes; callers must keep the entire input
 * alive and unchanged while using the view. This view conveys no authority.
 */
typedef struct mips64_aot_block_view {
    uint64_t source_offset;
    const uint8_t *source_bytes;
    uint32_t source_size;
    const uint8_t *a64_text;
    uint32_t a64_size;
    const uint8_t *relocations; /* fixed-width LE records, may be NULL if empty */
    uint16_t relocation_count;
} mips64_aot_block_view_t;

typedef struct mips64_aot_view {
    const uint8_t *encoded;
    size_t encoded_size;
    uint16_t format_version;
    uint16_t header_bytes;
    uint8_t record_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t input_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[MIPS64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[MIPS64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
    uint32_t block_count;
} mips64_aot_view_t;

/* All integer wire fields are little-endian. Encoder input spans must not
 * overlap destination. On failure these functions return -1 with errno set
 * and leave `written`/`out` unchanged. */
int mips64_aot_encode(const mips64_aot_image_t *image, uint8_t *destination,
                  size_t capacity, size_t *written);
/* V2 extends the header with an opaque whole-record digest. The codec does
 * not compute or validate it; even v2 decode success conveys no authority.
 * V1 encoding and decoding remain available for structural tooling only. */
int mips64_aot_encode_v2(const mips64_aot_image_t *image,
                      const uint8_t record_digest[MIPS64_AOT_DIGEST_BYTES],
                      uint8_t *destination, size_t capacity, size_t *written);
int mips64_aot_decode(const uint8_t *encoded, size_t encoded_size,
                  mips64_aot_view_t *out);
int mips64_aot_view_block(const mips64_aot_view_t *view, uint32_t index,
                      mips64_aot_block_view_t *out);
int mips64_aot_view_relocation(const mips64_aot_block_view_t *block, uint16_t index,
                           mips64_aot_relocation_t *out);

#endif

/* MIPS64 ELF admission (SPEC 1.1): little-endian, e_machine == EM_MIPS
 * (8), with ELFCLASS64 for N64 and ELFCLASS32 for N32. N64 objects leave
 * the EF_MIPS_ABI field clear (`EF_MIPS_ABI_O64` lives outside that mask);
 * N32 objects carry EF_MIPS_ABI2; `EF_MIPS_NAN2008` selects the 2008-NaN
 * encoding (SPEC 2.1/2.2). */
#define MIPS64_ELF_CLASS32 1u
#define MIPS64_ELF_CLASS64 2u
#define MIPS64_ELF_DATA2LSB 1u
#define MIPS64_EM_MIPS 8u
#define MIPS64_EF_MIPS_ABI2 0x20u
#define MIPS64_EF_MIPS_NAN2008 0x400u
#define MIPS64_EF_MIPS_ABI 0xf00u
#define MIPS64_EF_MIPS_ABI_O64 0x2000u
