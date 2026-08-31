#include "../kernels.h"

#include <cstdint>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <adf.h>
#include <aie_api/aie.hpp>
#include "aie_api/aie_types.hpp"
#include <adf.h>
#include <cstddef>
#include <cstdint>

namespace {

/*
 * SHA-256 round constants.
 */
alignas(32) static const uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static inline uint32_t rotr32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32U - n));
}

static inline uint32_t big_sigma0(uint32_t x)
{
    return rotr32(x, 2) ^
           rotr32(x, 13) ^
           rotr32(x, 22);
}

static inline uint32_t big_sigma1(uint32_t x)
{
    return rotr32(x, 6) ^
           rotr32(x, 11) ^
           rotr32(x, 25);
}

static inline uint32_t small_sigma0(uint32_t x)
{
    return rotr32(x, 7) ^
           rotr32(x, 18) ^
           (x >> 3);
}

static inline uint32_t small_sigma1(uint32_t x)
{
    return rotr32(x, 17) ^
           rotr32(x, 19) ^
           (x >> 10);
}

static inline uint32_t choose(
    uint32_t x,
    uint32_t y,
    uint32_t z)
{
    /*
     * Equivalent to:
     *
     * (x & y) ^ (~x & z)
     */
    return z ^ (x & (y ^ z));
}

static inline uint32_t majority(
    uint32_t x,
    uint32_t y,
    uint32_t z)
{
    /*
     * Equivalent to:
     *
     * (x & y) ^ (x & z) ^ (y & z)
     */
    return (x & y) ^ (z & (x ^ y));
}

/*
 * Process one 512-bit SHA-256 block.
 *
 * w[0..15] must contain the original block words.
 * This function generates w[16..63] and performs all 64 rounds.
 */
static inline void sha256_compress(
    uint32_t *__restrict state,
    uint32_t *__restrict w)
{
    /*
     * Generate W[16] ... W[63].
     */
    for (int i = 16; i < 64; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(48, 48)
    {
        w[i] =
            small_sigma1(w[i - 2]) +
            w[i - 7] +
            small_sigma0(w[i - 15]) +
            w[i - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    /*
     * Do not force pipelining here initially because every SHA-256
     * round depends on the result of the preceding round.
     */
    for (int i = 0; i < 64; ++i)
    chess_loop_range(64, 64)
    {
        const uint32_t t1 =
            h +
            big_sigma1(e) +
            choose(e, f, g) +
            K[i] +
            w[i];

        const uint32_t t2 =
            big_sigma0(a) +
            majority(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/*
 * Fixed-length SHA-256 for a 96-byte message.
 *
 * Input:
 *     24 x uint32_t
 *
 * Output:
 *      8 x uint32_t
 *
 * Input words are interpreted in SHA-256 big-endian logical order.
 * For example, 0x11223344 represents message bytes:
 *
 *     11 22 33 44
 */
static inline void sha256_stream_96(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    alignas(32) uint32_t state[8] = {
        0x6a09e667U,
        0xbb67ae85U,
        0x3c6ef372U,
        0xa54ff53aU,
        0x510e527fU,
        0x9b05688cU,
        0x1f83d9abU,
        0x5be0cd19U
    };

    alignas(32) uint32_t w[64];

    /*
     * First 64-byte block.
     */
    for (int i = 0; i < 16; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(16, 16)
    {
        w[i] = readincr(input);
    }

    sha256_compress(state, w);

    /*
     * Remaining 32 bytes.
     */
    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        w[i] = readincr(input);
    }

    /*
     * Fixed SHA-256 padding for a 96-byte message.
     */
    w[8]  = 0x80000000U;
    w[9]  = 0U;
    w[10] = 0U;
    w[11] = 0U;
    w[12] = 0U;
    w[13] = 0U;
    w[14] = 0U;
    w[15] = 0x00000300U;

    sha256_compress(state, w);

    /*
     * Eight 32-bit output words.
     */
    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        writeincr(output, state[i]);
    }
}

}


void prf_opt_96(
    input_stream<uint32_t> *__restrict bufin,
    output_stream<uint32_t> *__restrict bufout)
{
    sha256_stream_96(bufin, bufout);
}