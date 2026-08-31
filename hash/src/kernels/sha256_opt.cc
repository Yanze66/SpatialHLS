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

/*
 * Message length in bytes.
 *
 * You can change this value directly, for example:
 *
 *   0, 1, 3, 32, 64, 100, 6368, ...
 *
 * It can also be overridden from the compiler command line:
 *
 *   -DSHA256_MESSAGE_LEN=32
 */
#ifndef SHA256_MESSAGE_LEN
#define SHA256_MESSAGE_LEN 96
#endif

namespace {

/* SHA-256 round constants. */
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

/*
 * Equivalent to:
 *
 *     (x & y) ^ (~x & z)
 *
 * This formulation usually needs fewer intermediate operations.
 */
static inline uint32_t choose(
    uint32_t x,
    uint32_t y,
    uint32_t z)
{
    return z ^ (x & (y ^ z));
}

/*
 * Equivalent to:
 *
 *     (x & y) ^ (x & z) ^ (y & z)
 */
static inline uint32_t majority(
    uint32_t x,
    uint32_t y,
    uint32_t z)
{
    return (x & y) ^ (z & (x ^ y));
}

/*
 * Convert four big-endian bytes into one uint32_t.
 */
static inline uint32_t load_be32(
    const uint8_t *__restrict input)
{
    return
        (static_cast<uint32_t>(input[0]) << 24) |
        (static_cast<uint32_t>(input[1]) << 16) |
        (static_cast<uint32_t>(input[2]) << 8)  |
        static_cast<uint32_t>(input[3]);
}

/*
 * Write one uint32_t into four big-endian bytes.
 */
static inline void store_be32(
    uint8_t *__restrict output,
    uint32_t value)
{
    output[0] = static_cast<uint8_t>(value >> 24);
    output[1] = static_cast<uint8_t>(value >> 16);
    output[2] = static_cast<uint8_t>(value >> 8);
    output[3] = static_cast<uint8_t>(value);
}

/*
 * Process one 512-bit SHA-256 block.
 *
 * block_words[0..15] must contain the block in SHA-256 big-endian
 * 32-bit word representation.
 */
static inline void sha256_compress(
    uint32_t *__restrict state,
    uint32_t *__restrict w)
{
    /*
     * Generate W[16] ... W[63].
     */
    for (int i = 16; i < 64; ++i)chess_prepare_for_pipelining {
        

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
     * SHA-256 compression rounds.
     *
     * The rounds have a true loop-carried dependency, so completely
     * unrolling this loop usually consumes excessive code space.
     */
    for (int i = 0; i < 64; ++i) {
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
 * Read and hash one message from the AIE input stream.
 *
 * Input format
 * ------------
 * Every input uint32_t contains four consecutive message bytes in
 * big-endian order:
 *
 *     word = 0x11223344
 *
 * represents bytes:
 *
 *     11 22 33 44
 *
 * For a message length that is not divisible by four, the valid bytes
 * of the final word must occupy the most significant bytes.
 *
 * For example, a 3-byte final fragment AA BB CC should be supplied as:
 *
 *     0xAABBCC00
 */
template <std::size_t MESSAGE_BYTES>
static inline void sha256_stream(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    constexpr std::size_t FULL_BLOCKS =
        MESSAGE_BYTES / 64U;

    constexpr std::size_t REMAINING_BYTES =
        MESSAGE_BYTES % 64U;

    constexpr std::size_t REMAINING_WORDS =
        (REMAINING_BYTES + 3U) / 4U;

    constexpr uint64_t MESSAGE_BITS =
        static_cast<uint64_t>(MESSAGE_BYTES) * 8ULL;

    /*
     * SHA-256 chaining state.
     */
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

    /*
     * SHA-256 message schedule.
     *
     * Only 256 bytes, replacing the original multiple 6-KB arrays.
     */
    alignas(32) uint32_t w[64];

    /*
     * Process complete 64-byte blocks directly from the stream.
     *
     * There is no intermediate byte-buffer copy for these blocks.
     */
    for (std::size_t block = 0; block < FULL_BLOCKS; ++block) {
        for (int i = 0; i < 16; ++i) chess_prepare_for_pipelining{
            

            /*
             * This preserves the byte order of the original sequence:
             *
             * readincr()
             *     -> copy_u32_u8()
             *     -> fill()
             *
             * The two original byte conversions canceled each other.
             */
            w[i] = readincr(input);
        }

        sha256_compress(state, w);
    }

    /*
     * At most two final SHA-256 blocks are needed:
     *
     * - one block when remaining bytes <= 55
     * - two blocks when remaining bytes >= 56
     */
    alignas(32) uint8_t tail[128];

    /*
     * Clear both possible padding blocks.
     */
    for (int i = 0; i < 128; ++i)chess_prepare_for_pipelining {
        
        tail[i] = 0;
    }

    /*
     * Read the message fragment remaining after all full blocks.
     */
    for (std::size_t i = 0; i < REMAINING_WORDS; ++i) {
        const uint32_t word = readincr(input);
        const std::size_t offset = i * 4U;

        /*
         * Only store bytes that belong to the message. This correctly
         * handles message lengths that are not divisible by four.
         */
        if (offset < REMAINING_BYTES) {
            tail[offset] =
                static_cast<uint8_t>(word >> 24);
        }

        if (offset + 1U < REMAINING_BYTES) {
            tail[offset + 1U] =
                static_cast<uint8_t>(word >> 16);
        }

        if (offset + 2U < REMAINING_BYTES) {
            tail[offset + 2U] =
                static_cast<uint8_t>(word >> 8);
        }

        if (offset + 3U < REMAINING_BYTES) {
            tail[offset + 3U] =
                static_cast<uint8_t>(word);
        }
    }

    /*
     * Add the mandatory SHA-256 1-bit padding marker.
     */
    tail[REMAINING_BYTES] = 0x80U;

    /*
     * Determine whether padding occupies one or two blocks.
     */
    constexpr std::size_t PADDED_TAIL_BYTES =
        (REMAINING_BYTES <= 55U) ? 64U : 128U;

    /*
     * Store the original message length as a 64-bit big-endian value
     * in the final eight bytes.
     */
    tail[PADDED_TAIL_BYTES - 8U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 56);

    tail[PADDED_TAIL_BYTES - 7U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 48);

    tail[PADDED_TAIL_BYTES - 6U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 40);

    tail[PADDED_TAIL_BYTES - 5U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 32);

    tail[PADDED_TAIL_BYTES - 4U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 24);

    tail[PADDED_TAIL_BYTES - 3U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 16);

    tail[PADDED_TAIL_BYTES - 2U] =
        static_cast<uint8_t>(MESSAGE_BITS >> 8);

    tail[PADDED_TAIL_BYTES - 1U] =
        static_cast<uint8_t>(MESSAGE_BITS);

    /*
     * Compress the final one or two padded blocks.
     */
    constexpr std::size_t TAIL_BLOCKS =
        PADDED_TAIL_BYTES / 64U;

    for (std::size_t block = 0; block < TAIL_BLOCKS; ++block) {
        const uint8_t *block_ptr = tail + block * 64U;

        for (int i = 0; i < 16; ++i) chess_prepare_for_pipelining{
            
            w[i] = load_be32(block_ptr + i * 4);
        }

        sha256_compress(state, w);
    }

    /*
     * state[0..7] are exactly the eight big-endian logical words of
     * the SHA-256 digest.
     *
     * This produces the same stream representation intended by:
     *
     *     writeincr(bufout, fill(out + 4 * i));
     *
     * but avoids the temporary 32-byte output array.
     */
    for (int i = 0; i < 8; ++i) chess_prepare_for_pipelining{
        
        writeincr(output, state[i]);
    }
}

} // namespace

/*
 * AIE graph kernel.
 *
 * The interface is unchanged from the original implementation.
 */
void prf_opt(
    input_stream<uint32_t> *__restrict bufin,
    output_stream<uint32_t> *__restrict bufout)
{
    sha256_stream<SHA256_MESSAGE_LEN>(bufin, bufout);
}