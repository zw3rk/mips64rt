/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L6a SHA-256 (FIPS 180-4). See `sha256.h`.
 */

#include "rt64/aot/sha256.h"

#include <string.h>

static const uint32_t round_keys[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr(uint32_t v, unsigned n)
{
    return (v >> n) | (v << (32u - n));
}

static void compress(mips64_sha256_t *ctx, const uint8_t *block)
{
    uint32_t w[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    unsigned i;

    for (i = 0; i < 16u; i++) {
        w[i] = ((uint32_t)block[i * 4u] << 24u) |
               ((uint32_t)block[i * 4u + 1u] << 16u) |
               ((uint32_t)block[i * 4u + 2u] << 8u) |
               (uint32_t)block[i * 4u + 3u];
    }
    for (i = 16u; i < 64u; i++) {
        uint32_t s0 = rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^
                      (w[i - 15u] >> 3u);
        uint32_t s1 = rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^
                      (w[i - 2u] >> 10u);

        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    for (i = 0; i < 64u; i++) {
        uint32_t s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + round_keys[i] + w[i];
        uint32_t s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void mips64_sha256_init(mips64_sha256_t *ctx)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

void mips64_sha256_update(mips64_sha256_t *ctx, const uint8_t *data, size_t len)
{
    size_t at = 0;

    if (ctx == NULL || (data == NULL && len > 0))
        return;
    ctx->total += (uint64_t)len;
    while (at < len) {
        size_t room = MIPS64_SHA256_BLOCK_BYTES - ctx->buffered;
        size_t take = len - at < room ? len - at : room;

        memcpy(ctx->block + ctx->buffered, data + at, take);
        ctx->buffered += take;
        at += take;
        if (ctx->buffered == MIPS64_SHA256_BLOCK_BYTES) {
            compress(ctx, ctx->block);
            ctx->buffered = 0;
        }
    }
}

void mips64_sha256_final(mips64_sha256_t *ctx, uint8_t out[MIPS64_SHA256_BYTES])
{
    uint64_t bit_len;
    uint8_t pad = 0x80u;
    uint8_t zero = 0x00u;
    uint8_t trailer[8];
    unsigned i;

    bit_len = ctx->total * 8u;
    for (i = 0; i < 8u; i++)
        trailer[i] = (uint8_t)(bit_len >> (56u - 8u * i));
    mips64_sha256_update(ctx, &pad, 1u);
    while (ctx->buffered != 56u)
        mips64_sha256_update(ctx, &zero, 1u);
    /* Feed the length directly: the buffer is at exactly 56 bytes, so
     * this completes one final block without recursing through the
     * padding logic above. */
    memcpy(ctx->block + 56u, trailer, 8u);
    compress(ctx, ctx->block);
    ctx->buffered = 0;
    for (i = 0; i < 8u; i++) {
        out[i * 4u] = (uint8_t)(ctx->state[i] >> 24u);
        out[i * 4u + 1u] = (uint8_t)(ctx->state[i] >> 16u);
        out[i * 4u + 2u] = (uint8_t)(ctx->state[i] >> 8u);
        out[i * 4u + 3u] = (uint8_t)ctx->state[i];
    }
}

void mips64_sha256(const uint8_t *data, size_t len,
                 uint8_t out[MIPS64_SHA256_BYTES])
{
    mips64_sha256_t ctx;

    mips64_sha256_init(&ctx);
    mips64_sha256_update(&ctx, data, len);
    mips64_sha256_final(&ctx, out);
}
