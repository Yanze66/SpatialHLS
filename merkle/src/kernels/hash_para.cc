#include "../kernels.h"
#include "slh_cfg.h"

#include <adf.h>
#include <cstdint>

using namespace adf;

namespace {

/*
 * ============================================================
 * Common byte helpers
 * ============================================================
 */

static inline void word_to_bytes_be(
    uint32_t x,
    uint8_t *b)
{
    b[0] = (uint8_t)(x >> 24);
    b[1] = (uint8_t)(x >> 16);
    b[2] = (uint8_t)(x >> 8);
    b[3] = (uint8_t)x;
}


static inline uint32_t bytes_to_word_be(
    const uint8_t *b)
{
    return
        ((uint32_t)b[0] << 24) |
        ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8)  |
        ((uint32_t)b[3]);
}


#if SLH_HASH_FAMILY == SLH_HASH_SHA2

/*
 * ============================================================
 * SHA-256 implementation
 * ============================================================
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


static inline uint32_t rotr32(
    uint32_t x,
    unsigned int n)
{
    return
        (x >> n) |
        (x << (32U - n));
}


static inline uint32_t s0(uint32_t x)
{
    return
        rotr32(x, 7) ^
        rotr32(x, 18) ^
        (x >> 3);
}


static inline uint32_t s1(uint32_t x)
{
    return
        rotr32(x, 17) ^
        rotr32(x, 19) ^
        (x >> 10);
}


#define SHA256_ROUND(A,B,C,D,E,F,G,H,WI,KI)             \
do {                                                    \
    const uint32_t _S1 =                                \
        rotr32((E),6) ^                                 \
        rotr32((E),11) ^                                \
        rotr32((E),25);                                 \
                                                        \
    const uint32_t _ch =                                \
        (G) ^ ((E) & ((F) ^ (G)));                      \
                                                        \
    const uint32_t _t1 =                                \
        (H) + _S1 + _ch + (KI) + (WI);                  \
                                                        \
    const uint32_t _S0 =                                \
        rotr32((A),2) ^                                 \
        rotr32((A),13) ^                                \
        rotr32((A),22);                                 \
                                                        \
    const uint32_t _maj =                               \
        ((A) & (B)) ^                                   \
        ((C) & ((A) ^ (B)));                            \
                                                        \
    const uint32_t _t2 = _S0 + _maj;                    \
                                                        \
    (D) += _t1;                                         \
    (H)  = _t1 + _t2;                                   \
} while (0)


#define SHA256_ROUND8(BASE)                              \
do {                                                    \
    SHA256_ROUND(a,b,c,d,e,f,g,h,                       \
                 w[(BASE)+0],K[(BASE)+0]);               \
    SHA256_ROUND(h,a,b,c,d,e,f,g,                       \
                 w[(BASE)+1],K[(BASE)+1]);               \
    SHA256_ROUND(g,h,a,b,c,d,e,f,                       \
                 w[(BASE)+2],K[(BASE)+2]);               \
    SHA256_ROUND(f,g,h,a,b,c,d,e,                       \
                 w[(BASE)+3],K[(BASE)+3]);               \
    SHA256_ROUND(e,f,g,h,a,b,c,d,                       \
                 w[(BASE)+4],K[(BASE)+4]);               \
    SHA256_ROUND(d,e,f,g,h,a,b,c,                       \
                 w[(BASE)+5],K[(BASE)+5]);               \
    SHA256_ROUND(c,d,e,f,g,h,a,b,                       \
                 w[(BASE)+6],K[(BASE)+6]);               \
    SHA256_ROUND(b,c,d,e,f,g,h,a,                       \
                 w[(BASE)+7],K[(BASE)+7]);               \
} while (0)


static inline void sha256_compress(
    uint32_t state[8],
    uint32_t w[64])
{
    for (int i = 16; i < 64; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(48,48)
    {
        w[i] =
            s1(w[i-2]) +
            w[i-7] +
            s0(w[i-15]) +
            w[i-16];
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


#else

/*
 * ============================================================
 * SHAKE256 / Keccak-f[1600]
 * ============================================================
 */

static const uint64_t RC[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};


static const uint8_t ROTC[24] = {
    1,3,6,10,15,21,
    28,36,45,55,2,14,
    27,41,56,8,25,43,
    62,18,39,61,20,44
};


static const uint8_t PILN[24] = {
    10,7,11,17,18,3,
    5,16,8,21,24,4,
    15,23,19,13,12,2,
    20,14,22,9,6,1
};


static inline uint64_t rol64(
    uint64_t x,
    unsigned int n)
{
    return
        (x << n) |
        (x >> (64U - n));
}


static inline void keccakf(
    uint64_t st[25])
{
    uint64_t bc[5];

    for (int round = 0;
         round < 24;
         ++round)
    {
        /*
         * Theta
         */
        for (int i = 0; i < 5; ++i) {
            bc[i] =
                st[i] ^
                st[i + 5] ^
                st[i + 10] ^
                st[i + 15] ^
                st[i + 20];
        }


        for (int i = 0; i < 5; ++i) {

            const uint64_t d =
                bc[(i + 4) % 5] ^
                rol64(
                    bc[(i + 1) % 5],
                    1
                );

            for (int j = 0;
                 j < 25;
                 j += 5)
            {
                st[j + i] ^= d;
            }
        }


        /*
         * Rho + Pi
         */
        uint64_t t = st[1];

        for (int i = 0; i < 24; ++i) {

            const int j =
                PILN[i];

            const uint64_t tmp =
                st[j];

            st[j] =
                rol64(
                    t,
                    ROTC[i]
                );

            t = tmp;
        }


        /*
         * Chi
         */
        for (int j = 0;
             j < 25;
             j += 5)
        {
            for (int i = 0; i < 5; ++i) {
                bc[i] = st[j+i];
            }

            for (int i = 0; i < 5; ++i) {

                st[j+i] =
                    bc[i] ^
                    ((~bc[(i+1)%5]) &
                     bc[(i+2)%5]);
            }
        }


        /*
         * Iota
         */
        st[0] ^= RC[round];
    }
}

#endif

} // namespace


/*
 * ================================================================
 * Unified SLH-DSA simple WOTS thash
 *
 * Fixed transport input:
 *
 *     data[8]      : 32 bytes
 *     pub_seed[8]  : 32 bytes
 *     addr[8]      : 32 bytes
 *
 * Only first SLH_N bytes of data/pub_seed are meaningful.
 *
 * Output:
 *
 *     SLH_N bytes
 *
 * ================================================================
 */

void slh_thash_simple(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    /*
     * Keep transport width fixed.
     */
    alignas(32) uint32_t data_words[8];
    alignas(32) uint32_t seed_words[8];
    alignas(32) uint32_t addr_words[8];

    uint8_t data[32];
    uint8_t seed[32];
    uint8_t addr[32];


    /*
     * ============================================================
     * Read 24 words
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8,8)
    {
        data_words[i] =
            readincr(input);
    }


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8,8)
    {
        seed_words[i] =
            readincr(input);
    }


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8,8)
    {
        addr_words[i] =
            readincr(input);
    }


    /*
     * ============================================================
     * Convert transport words to algorithm bytes.
     *
     * 0x51d93016 ->
     *
     * 51 d9 30 16
     *
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8,8)
    {
        word_to_bytes_be(
            data_words[i],
            data + 4*i
        );

        word_to_bytes_be(
            seed_words[i],
            seed + 4*i
        );

        word_to_bytes_be(
            addr_words[i],
            addr + 4*i
        );
    }


#if SLH_HASH_FAMILY == SLH_HASH_SHA2

    /*
     * ============================================================
     * SHA2-simple
     *
     * Reference:
     *
     * seeded_state =
     *
     * SHA256_Compress(
     *      IV,
     *      pub_seed[N] || zeros
     * )
     *
     * thash:
     *
     * SHA256 continuation over:
     *
     *      addr[0..21] || data[N]
     *
     * ============================================================
     */

    alignas(32) uint32_t w[64];

    static uint32_t cached_state[8];

    static uint8_t cached_seed[32];

    static bool cached_valid = false;


    bool changed =
        !cached_valid;


    if (!changed) {

        for (int i = 0;
             i < SLH_N;
             ++i)
        {
            if (cached_seed[i] != seed[i]) {
                changed = true;
            }
        }
    }


    /*
     * ============================================================
     * Seed-state precomputation
     * ============================================================
     */

    if (changed) {

        cached_state[0] = 0x6a09e667U;
        cached_state[1] = 0xbb67ae85U;
        cached_state[2] = 0x3c6ef372U;
        cached_state[3] = 0xa54ff53aU;

        cached_state[4] = 0x510e527fU;
        cached_state[5] = 0x9b05688cU;
        cached_state[6] = 0x1f83d9abU;
        cached_state[7] = 0x5be0cd19U;


        /*
         * 64-byte block:
         *
         * pub_seed[SLH_N] || zero...
         */
        uint8_t block0[64];

        for (int i = 0; i < 64; ++i) {
            block0[i] = 0;
        }


        for (int i = 0; i < SLH_N; ++i) {
            block0[i] = seed[i];
        }


        for (int i = 0; i < 16; ++i) {
            w[i] =
                bytes_to_word_be(
                    block0 + 4*i
                );
        }


        sha256_compress(
            cached_state,
            w
        );


        for (int i = 0; i < SLH_N; ++i) {
            cached_seed[i] = seed[i];
        }


        cached_valid = true;
    }


    /*
     * ============================================================
     * Current state starts from cached pub_seed state.
     * ============================================================
     */

    uint32_t state[8];

    for (int i = 0; i < 8; ++i) {
        state[i] = cached_state[i];
    }


    /*
     * ============================================================
     * Construct final 64-byte SHA-256 block.
     *
     * Remaining input:
     *
     *     22-byte compressed ADRS
     *     SLH_N-byte data
     *
     * Then SHA padding.
     * ============================================================
     */

    uint8_t block[64];

    for (int i = 0; i < 64; ++i) {
        block[i] = 0;
    }


    /*
     * SHA2 address compression is simply first 22 bytes
     * in this reference representation.
     */
    for (int i = 0;
         i < 22;
         ++i)
    {
        block[i] = addr[i];
    }


    /*
     * Chain input.
     */
    for (int i = 0;
         i < SLH_N;
         ++i)
    {
        block[22+i] = data[i];
    }


    /*
     * SHA padding.
     */
    const int remainder =
        22 + SLH_N;

    block[remainder] =
        0x80;


    /*
     * Total original message includes the already processed
     * 64-byte pub_seed block.
     */
    const uint64_t total_bits =
        (uint64_t)(
            64 +
            22 +
            SLH_N
        ) * 8ULL;


    /*
     * SHA-256 64-bit big-endian bit length.
     */
    block[56] =
        (uint8_t)(total_bits >> 56);

    block[57] =
        (uint8_t)(total_bits >> 48);

    block[58] =
        (uint8_t)(total_bits >> 40);

    block[59] =
        (uint8_t)(total_bits >> 32);

    block[60] =
        (uint8_t)(total_bits >> 24);

    block[61] =
        (uint8_t)(total_bits >> 16);

    block[62] =
        (uint8_t)(total_bits >> 8);

    block[63] =
        (uint8_t)total_bits;


    for (int i = 0; i < 16; ++i) {

        w[i] =
            bytes_to_word_be(
                block + 4*i
            );
    }


    /*
     * Exactly ONE compression per WOTS step
     * after seed state is cached.
     */
    sha256_compress(
        state,
        w
    );


    /*
     * Digest is truncated to N bytes.
     */
    for (int i = 0;
         i < SLH_N_WORDS;
         ++i)
    chess_prepare_for_pipelining
    {
        writeincr(
            output,
            state[i]
        );
    }


#else

    /*
     * ============================================================
     * SHAKE-simple
     *
     * Reference input:
     *
     * pub_seed[N]
     * ||
     * addr[32]
     * ||
     * data[N]
     *
     * SHAKE256 rate = 136 bytes.
     *
     * Max input:
     *
     * 32 + 32 + 32 = 96 bytes
     *
     * Therefore exactly one Keccak-f permutation.
     * ============================================================
     */

    constexpr int RATE =
        136;

    constexpr int MSG_LEN =
        2 * SLH_N + 32;


    uint8_t msg[96];

    int p = 0;


    for (int i = 0; i < SLH_N; ++i) {
        msg[p++] = seed[i];
    }


    for (int i = 0; i < 32; ++i) {
        msg[p++] = addr[i];
    }


    for (int i = 0; i < SLH_N; ++i) {
        msg[p++] = data[i];
    }


    uint64_t st[25];

    for (int i = 0; i < 25; ++i) {
        st[i] = 0;
    }


    /*
     * SHAKE absorbs bytes little-endian inside each lane.
     */
    for (int i = 0;
         i < MSG_LEN;
         ++i)
    {
        st[i >> 3] ^=
            (uint64_t)msg[i]
            <<
            (8 * (i & 7));
    }


    /*
     * SHAKE domain separation.
     */
    st[MSG_LEN >> 3] ^=
        (uint64_t)0x1FULL
        <<
        (8 * (MSG_LEN & 7));


    /*
     * Final rate padding bit.
     */
    st[(RATE - 1) >> 3] ^=
        (uint64_t)0x80ULL
        <<
        (8 * ((RATE - 1) & 7));


    /*
     * Exactly one Keccak permutation.
     */
    keccakf(st);


    /*
     * Squeeze first N bytes.
     */
    uint8_t digest[32];

    for (int i = 0;
         i < SLH_N;
         ++i)
    {
        digest[i] =
            (uint8_t)(
                st[i >> 3] >>
                (8 * (i & 7))
            );
    }


    /*
     * Convert back to the same word representation:
     *
     * c0 24 80 30 -> 0xc0248030
     */
    for (int i = 0;
         i < SLH_N_WORDS;
         ++i)
    chess_prepare_for_pipelining
    {
        const uint32_t x =
            bytes_to_word_be(
                digest + 4*i
            );

        writeincr(
            output,
            x
        );
    }

#endif
}
