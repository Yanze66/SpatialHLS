#include "../kernels.h"

#include <cstdint>
#include <adf.h>
#include <aie_api/aie.hpp>

using namespace adf;

namespace {

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


#define SHA256_ROUND(A,B,C,D,E,F,G,H,WI,KI)             \
    do {                                                \
        const uint32_t _s1 =                            \
            rotr32((E), 6) ^                            \
            rotr32((E), 11) ^                           \
            rotr32((E), 25);                            \
                                                        \
        const uint32_t _ch =                            \
            (G) ^ ((E) & ((F) ^ (G)));                  \
                                                        \
        const uint32_t _t1 =                            \
            (H) + _s1 + _ch + (KI) + (WI);              \
                                                        \
        const uint32_t _s0 =                            \
            rotr32((A), 2) ^                            \
            rotr32((A), 13) ^                           \
            rotr32((A), 22);                            \
                                                        \
        const uint32_t _maj =                           \
            ((A) & (B)) ^                               \
            ((C) & ((A) ^ (B)));                        \
                                                        \
        const uint32_t _t2 = _s0 + _maj;                \
                                                        \
        (D) += _t1;                                     \
        (H)  = _t1 + _t2;                               \
    } while (0)


#define SHA256_ROUND8(BASE)                              \
    do {                                                \
        SHA256_ROUND(a,b,c,d,e,f,g,h,                   \
                     w[(BASE)+0], K[(BASE)+0]);          \
        SHA256_ROUND(h,a,b,c,d,e,f,g,                   \
                     w[(BASE)+1], K[(BASE)+1]);          \
        SHA256_ROUND(g,h,a,b,c,d,e,f,                   \
                     w[(BASE)+2], K[(BASE)+2]);          \
        SHA256_ROUND(f,g,h,a,b,c,d,e,                   \
                     w[(BASE)+3], K[(BASE)+3]);          \
        SHA256_ROUND(e,f,g,h,a,b,c,d,                   \
                     w[(BASE)+4], K[(BASE)+4]);          \
        SHA256_ROUND(d,e,f,g,h,a,b,c,                   \
                     w[(BASE)+5], K[(BASE)+5]);          \
        SHA256_ROUND(c,d,e,f,g,h,a,b,                   \
                     w[(BASE)+6], K[(BASE)+6]);          \
        SHA256_ROUND(b,c,d,e,f,g,h,a,                   \
                     w[(BASE)+7], K[(BASE)+7]);          \
    } while (0)


static inline void sha256_compress(
    uint32_t *__restrict state,
    uint32_t *__restrict w)
{
    /*
     * Expand W[16..63].
     */
    for (int i = 0; i < 48; i += 2)
    chess_prepare_for_pipelining
    chess_loop_range(24, 24)
    {
        const uint32_t w16 =
            w[i] +
            w[i + 9] +
            small_sigma0(w[i + 1]) +
            small_sigma1(w[i + 14]);

        w[i + 16] = w16;

        const uint32_t w17 =
            w[i + 1] +
            w[i + 10] +
            small_sigma0(w[i + 2]) +
            small_sigma1(w[i + 15]);

        w[i + 17] = w17;
    }


    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];


    SHA256_ROUND8(0);
    SHA256_ROUND8(8);
    SHA256_ROUND8(16);
    SHA256_ROUND8(24);
    SHA256_ROUND8(32);
    SHA256_ROUND8(40);
    SHA256_ROUND8(48);
    SHA256_ROUND8(56);


    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

#undef SHA256_ROUND8
#undef SHA256_ROUND

} // namespace


/*
 * ================================================================
 * SHA2-simple thash
 *
 * Input:
 *
 *   data[8]       = 32-byte WOTS chain value
 *   pub_seed[8]   = 32-byte public seed
 *   addr[8]       = 32-byte SPHINCS+ ADRS
 *
 * Only the first 22 ADRS bytes participate in SHA2 thash.
 *
 * Output:
 *
 *   next_data[8]
 *
 * One invocation = one WOTS chain step.
 * ================================================================
 */

/*
 * ================================================================
 * WOTS SHA2-simple chain stage
 *
 * Input:
 *
 *   data[8]       = current WOTS chain value
 *   pub_seed[8]   = public seed
 *   addr[8]       = current WOTS address
 *
 * Operation:
 *
 *   next_data =
 *       SHA2-simple-thash(
 *           pub_seed,
 *           addr,
 *           data
 *       )
 *
 * Then:
 *
 *   hash_addr = hash_addr + 1
 *
 * Output:
 *
 *   next_data[8]
 *   pub_seed[8]
 *   next_addr[8]
 *
 * Therefore multiple identical AIE tiles can be connected:
 *
 *   stage0 -> stage1 -> ... -> stage14
 *
 * ================================================================
 */

void sha256(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    /*
     * ============================================================
     * Input packet
     *
     * 8 + 8 + 8 = 24 words
     * ============================================================
     */

    alignas(32) uint32_t data[8];
    alignas(32) uint32_t pub_seed[8];
    alignas(32) uint32_t addr[8];

    alignas(32) uint32_t w[64];


    /*
     * ============================================================
     * Cached state:
     *
     * SHA256_Compress(
     *     IV,
     *     pub_seed[32] || zero[32]
     * )
     *
     * Every WOTS chain step with the same pub_seed can reuse it.
     * ============================================================
     */

    static uint32_t seed_state[8];

    static uint32_t cached_pub_seed[8];

    static bool seed_valid = false;


    /*
     * ============================================================
     * 1. Read current chain value
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        data[i] =
            readincr(input);
    }


    /*
     * ============================================================
     * 2. Read public seed
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        pub_seed[i] =
            readincr(input);
    }


    /*
     * ============================================================
     * 3. Read current WOTS address
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        addr[i] =
            readincr(input);
    }


    /*
     * ============================================================
     * 4. Check whether pub_seed changed
     * ============================================================
     */

    bool seed_changed =
        !seed_valid;


    if (!seed_changed) {

        for (int i = 0; i < 8; ++i)
        chess_prepare_for_pipelining
        chess_loop_range(8, 8)
        {
            if (cached_pub_seed[i] !=
                pub_seed[i])
            {
                seed_changed = true;
            }
        }
    }


    /*
     * ============================================================
     * 5. Compute seeded SHA256 state when necessary
     *
     * Block:
     *
     *      pub_seed[32]
     *      ||
     *      zero[32]
     *
     * ============================================================
     */

    if (seed_changed) {

        /*
         * SHA-256 IV
         */
        seed_state[0] = 0x6a09e667U;
        seed_state[1] = 0xbb67ae85U;
        seed_state[2] = 0x3c6ef372U;
        seed_state[3] = 0xa54ff53aU;

        seed_state[4] = 0x510e527fU;
        seed_state[5] = 0x9b05688cU;
        seed_state[6] = 0x1f83d9abU;
        seed_state[7] = 0x5be0cd19U;


        /*
         * First half:
         *
         * pub_seed
         */
        for (int i = 0; i < 8; ++i)
        chess_prepare_for_pipelining
        chess_loop_range(8, 8)
        {
            w[i] =
                pub_seed[i];
        }


        /*
         * Second half:
         *
         * zero padding used by SPHINCS+ seeded state
         */
        for (int i = 8; i < 16; ++i)
        chess_prepare_for_pipelining
        chess_loop_range(8, 8)
        {
            w[i] = 0U;
        }


        /*
         * Precompute public-seed state.
         */
        sha256_compress(
            seed_state,
            w
        );


        /*
         * Cache pub_seed.
         */
        for (int i = 0; i < 8; ++i)
        chess_prepare_for_pipelining
        chess_loop_range(8, 8)
        {
            cached_pub_seed[i] =
                pub_seed[i];
        }


        seed_valid = true;
    }


    /*
     * ============================================================
     * 6. Start this WOTS thash from cached seeded state
     * ============================================================
     */

    uint32_t state[8];


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        state[i] =
            seed_state[i];
    }


    /*
     * ============================================================
     * 7. Construct SHA256 final block
     *
     * SHA2-simple WOTS thash:
     *
     *     compressed_ADRS[22]
     *     ||
     *     data[32]
     *
     *     = 54 bytes
     *
     *
     * Total SHA256 message:
     *
     *     previous seeded block = 64 bytes
     *     ADRS                  = 22 bytes
     *     data                  = 32 bytes
     *
     *     total = 118 bytes
     *
     *     118 * 8
     *         = 944
     *         = 0x03B0 bits
     *
     * ============================================================
     */


    /*
     * ADRS bytes 0..19
     */
    w[0] = addr[0];
    w[1] = addr[1];
    w[2] = addr[2];
    w[3] = addr[3];
    w[4] = addr[4];


    /*
     * ADRS byte 20 / 21
     *
     * +
     *
     * data byte 0 / 1
     *
     *
     * Because ADRS length is 22 bytes,
     * chain data starts halfway through this word.
     */
    w[5] =
        (addr[5] & 0xFFFF0000U) |
        (data[0] >> 16);


    /*
     * data bytes continue shifted by 16 bits.
     */

    w[6] =
        (data[0] << 16) |
        (data[1] >> 16);


    w[7] =
        (data[1] << 16) |
        (data[2] >> 16);


    w[8] =
        (data[2] << 16) |
        (data[3] >> 16);


    w[9] =
        (data[3] << 16) |
        (data[4] >> 16);


    w[10] =
        (data[4] << 16) |
        (data[5] >> 16);


    w[11] =
        (data[5] << 16) |
        (data[6] >> 16);


    w[12] =
        (data[6] << 16) |
        (data[7] >> 16);


    /*
     * Last two data bytes:
     *
     * xx xx 80 00
     */
    w[13] =
        (data[7] << 16) |
        0x00008000U;


    /*
     * SHA padding
     */
    w[14] =
        0U;


    /*
     * Total SHA256 message length:
     *
     * 118 bytes = 944 bits = 0x3B0
     */
    w[15] =
        0x000003B0U;


    /*
     * ============================================================
     * 8. ONE SHA256 compression
     *
     * result:
     *
     *      state = X_(j+1)
     *
     * ============================================================
     */

    sha256_compress(
        state,
        w
    );


    /*
     * ============================================================
     * 9. Advance WOTS hash address
     *
     * SHA2 address layout:
     *
     * hash address = byte 21
     *
     * Our AIE stream representation keeps four bytes in
     * natural display order:
     *
     *     byte20 byte21 byte22 byte23
     *
     * Therefore byte21 corresponds to bits [23:16].
     *
     *
     * Example:
     *
     * hash = 0
     *
     *     addr[5] = 0x00000000
     *
     * hash = 1
     *
     *     addr[5] = 0x00010000
     *
     * hash = 2
     *
     *     addr[5] = 0x00020000
     *
     * ...
     *
     * ============================================================
     */

    {
        uint32_t hash_value;

        hash_value =
            (addr[5] >> 16) &
            0xFFU;


        hash_value =
            hash_value + 1U;


        addr[5] =
            (addr[5] & 0xFF00FFFFU) |
            ((hash_value & 0xFFU) << 16);
    }


    /*
     * ============================================================
     * 10. Output packet
     *
     * SAME FORMAT AS INPUT:
     *
     *      next_data[8]
     *      pub_seed[8]
     *      next_addr[8]
     *
     * Total = 24 words
     *
     * ============================================================
     */


    /*
     * next chain value
     */
    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        writeincr(
            output,
            state[i]
        );
    }


    /*
     * forward pub_seed unchanged
     */
    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        writeincr(
            output,
            pub_seed[i]
        );
    }


    /*
     * forward updated address
     */
    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        writeincr(
            output,
            addr[i]
        );
    }
}