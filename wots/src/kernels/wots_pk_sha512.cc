#include "../kernels.h"

#include <cstdint>
#include <adf.h>

using namespace adf;

namespace {

/*
 * ================================================================
 * SHA-512 constants
 * ================================================================
 */

alignas(32)
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,
    0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL,
    0xab1c5ed5da6d8118ULL,

    0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL,
    0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,
    0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL,

    0xe49b69c19ef14ad2ULL,
    0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL,
    0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL,
    0x76f988da831153b5ULL,

    0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,
    0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL,
    0x142929670a0e6e70ULL,

    0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,
    0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL,

    0xa2bfe8a14cf10364ULL,
    0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL,
    0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL,
    0xf40e35855771202aULL,
    0x106aa07032bbd1b8ULL,

    0x19a4c116b8d2d0c8ULL,
    0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,
    0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL,

    0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL,
    0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,
    0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL,

    0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL,
    0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL,
    0x1b710b35131c471bULL,

    0x28db77f523047d84ULL,
    0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,
    0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL,
    0x6c44198c4a475817ULL
};


/*
 * ================================================================
 * SHA512 helpers
 * ================================================================
 */

static inline uint64_t rotr64(
    uint64_t x,
    unsigned int n)
{
    return
        (x >> n) |
        (x << (64U - n));
}


static inline uint64_t load_be64(
    const uint8_t *p)
{
    return
        ((uint64_t)p[0] << 56) |
        ((uint64_t)p[1] << 48) |
        ((uint64_t)p[2] << 40) |
        ((uint64_t)p[3] << 32) |
        ((uint64_t)p[4] << 24) |
        ((uint64_t)p[5] << 16) |
        ((uint64_t)p[6] << 8)  |
        ((uint64_t)p[7]);
}


static inline void store_be64(
    uint8_t *p,
    uint64_t x)
{
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);

    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);
    p[7] = (uint8_t)x;
}


static inline void word_to_be_bytes(
    uint32_t x,
    uint8_t *p)
{
    p[0] =
        (uint8_t)(x >> 24);

    p[1] =
        (uint8_t)(x >> 16);

    p[2] =
        (uint8_t)(x >> 8);

    p[3] =
        (uint8_t)x;
}


static inline uint32_t bytes_to_word_be(
    const uint8_t *p)
{
    return
        ((uint32_t)p[0] << 24) |
        ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8)  |
        ((uint32_t)p[3]);
}


/*
 * ================================================================
 * SHA512 compression
 *
 * Compact loop version first.
 *
 * If this becomes the bottleneck, we can optimize it later in
 * exactly the same way as your SHA256 schedule/round implementation.
 * ================================================================
 */

static void sha512_compress(
    uint64_t *__restrict state,
    const uint8_t *__restrict block)
{
    alignas(32)
    uint64_t w[80];


    /*
     * First 16 words.
     */

    for (int i = 0; i < 16; ++i)
    {
        w[i] =
            load_be64(
                block + 8 * i
            );
    }


    /*
     * W[16..79].
     */

    for (int i = 16;
         i < 80;
         ++i)
    {
        const uint64_t s0 =
            rotr64(w[i - 15], 1) ^
            rotr64(w[i - 15], 8) ^
            (w[i - 15] >> 7);


        const uint64_t s1 =
            rotr64(w[i - 2], 19) ^
            rotr64(w[i - 2], 61) ^
            (w[i - 2] >> 6);


        w[i] =
            w[i - 16] +
            s0 +
            w[i - 7] +
            s1;
    }


    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];

    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];


    /*
     * 80 SHA512 rounds.
     */

    for (int i = 0;
         i < 80;
         ++i)
    {
        const uint64_t S1 =
            rotr64(e, 14) ^
            rotr64(e, 18) ^
            rotr64(e, 41);


        const uint64_t ch =
            (e & f) ^
            ((~e) & g);


        const uint64_t temp1 =
            h +
            S1 +
            ch +
            K512[i] +
            w[i];


        const uint64_t S0 =
            rotr64(a, 28) ^
            rotr64(a, 34) ^
            rotr64(a, 39);


        const uint64_t maj =
            (a & b) ^
            (a & c) ^
            (b & c);


        const uint64_t temp2 =
            S0 +
            maj;


        h = g;
        g = f;
        f = e;

        e =
            d +
            temp1;

        d = c;
        c = b;
        b = a;

        a =
            temp1 +
            temp2;
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
 * ================================================================
 * Append one byte to the SHA512 streaming block.
 *
 * When 128 bytes are accumulated:
 *
 *     SHA512_Compress(state, block)
 * ================================================================
 */

static inline void push_byte(
    uint64_t state[8],
    uint8_t block[128],
    int &block_pos,
    uint8_t x)
{
    block[block_pos++] =
        x;


    if (block_pos == 128)
    {
        sha512_compress(
            state,
            block
        );

        block_pos =
            0;
    }
}


/*
 * Push one AIE uint32 word in the byte order used by your
 * current SHA256 pipeline:
 *
 *     0x51d93016
 *
 * means:
 *
 *     51 d9 30 16
 */

static inline void push_word(
    uint64_t state[8],
    uint8_t block[128],
    int &block_pos,
    uint32_t x)
{
    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)(x >> 24)
    );

    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)(x >> 16)
    );

    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)(x >> 8)
    );

    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)x
    );
}

} // namespace


/*
 * ================================================================
 *
 * Final WOTS public-key compression for SHA2-256f.
 *
 *
 * Input:
 *
 *     67 packets
 *
 * each packet:
 *
 *     chain_pk[8]
 *     pub_seed[8]
 *     wots_addr[8]
 *
 *
 * Compute:
 *
 *     thash(
 *         dest,
 *         PK_0 || ... || PK_66,
 *         67,
 *         ctx,
 *         pk_addr
 *     )
 *
 *
 * SHA2-256f:
 *
 *     SPX_SHA512 = 1
 *
 * therefore:
 *
 *     final T_67 uses SHA512.
 *
 *
 * Output:
 *
 *     first 32 bytes
 *
 *     = 8 uint32 words
 *
 * ================================================================
 */

void wots_pk_sha512(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    constexpr int WOTS_LEN =
        67;


    /*
     * ============================================================
     * SHA512 state.
     * ============================================================
     */

    uint64_t state[8];


    /*
     * Current 128-byte block.
     */

    alignas(32)
    uint8_t block[128];


    int block_pos =
        0;


    /*
     * First packet data must be held briefly because before hashing
     * the PK data we need:
     *
     *     pub_seed
     *     pk_addr
     */

    uint32_t first_pk[8];

    uint32_t pub_seed[8];

    uint32_t first_addr[8];


    /*
     * ============================================================
     * 1. Read first chain PK
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    {
        first_pk[i] =
            readincr(input);
    }


    /*
     * pub_seed
     */

    for (int i = 0; i < 8; ++i)
    {
        pub_seed[i] =
            readincr(input);
    }


    /*
     * Address from first chain.
     *
     * We use it only to recover:
     *
     *     layer
     *     tree
     *     keypair
     */

    for (int i = 0; i < 8; ++i)
    {
        first_addr[i] =
            readincr(input);
    }


    /*
     * ============================================================
     * 2. SHA512 seeded state:
     *
     *     SHA512_Compress(
     *         IV,
     *         pub_seed[32] || zero[96]
     *     )
     *
     * This corresponds to ctx->state_seeded_512.
     * ============================================================
     */

    state[0] =
        0x6a09e667f3bcc908ULL;

    state[1] =
        0xbb67ae8584caa73bULL;

    state[2] =
        0x3c6ef372fe94f82bULL;

    state[3] =
        0xa54ff53a5f1d36f1ULL;

    state[4] =
        0x510e527fade682d1ULL;

    state[5] =
        0x9b05688c2b3e6c1fULL;

    state[6] =
        0x1f83d9abfb41bd6bULL;

    state[7] =
        0x5be0cd19137e2179ULL;


    /*
     * pub_seed = first 32 bytes
     */

    for (int i = 0; i < 8; ++i)
    {
        word_to_be_bytes(
            pub_seed[i],
            &block[4 * i]
        );
    }


    /*
     * remaining 96 bytes = zero
     */

    for (int i = 32;
         i < 128;
         ++i)
    {
        block[i] =
            0;
    }


    sha512_compress(
        state,
        block
    );


    /*
     * ============================================================
     * 3. Construct pk_addr
     *
     * Official copy_keypair_addr() copies:
     *
     *     layer
     *     tree
     *     keypair
     *
     * and WOTSPK type is 1.
     *
     * The remaining bytes are zero.
     * ============================================================
     */

    uint32_t pk_addr[8];


    for (int i = 0; i < 8; ++i)
    {
        pk_addr[i] =
            0U;
    }


    /*
     * bytes 0..7
     */

    pk_addr[0] =
        first_addr[0];

    pk_addr[1] =
        first_addr[1];


    /*
     * addr word2:
     *
     * bytes:
     *
     * 8  9  10 11
     *
     * byte9 = type = WOTSPK = 1
     *
     * byte10/11 = first half of keypair address
     */

    pk_addr[2] =
        (first_addr[2] & 0xFF00FFFFU) |
        0x00010000U;


    /*
     * bytes12/13 = remaining keypair bytes
     *
     * bytes14/15 = zero
     */

    pk_addr[3] =
        first_addr[3] &
        0xFFFF0000U;


    /*
     * pk_addr[4..7] stay zero.
     */


    /*
     * ============================================================
     * 4. Start SHA512 final input.
     *
     * SHA2 uses only first 22 address bytes.
     *
     * First push ADRS^c[22].
     * ============================================================
     */

    block_pos =
        0;


    /*
     * words 0..4 = first 20 bytes
     */

    for (int i = 0; i < 5; ++i)
    {
        push_word(
            state,
            block,
            block_pos,
            pk_addr[i]
        );
    }


    /*
     * Only first TWO bytes of pk_addr[5].
     *
     * Our uint32 convention:
     *
     *     byte20 = bits31:24
     *     byte21 = bits23:16
     */

    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)(pk_addr[5] >> 24)
    );


    push_byte(
        state,
        block,
        block_pos,
        (uint8_t)(pk_addr[5] >> 16)
    );


    /*
     * ============================================================
     * 5. First chain public key
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    {
        push_word(
            state,
            block,
            block_pos,
            first_pk[i]
        );
    }


    /*
     * ============================================================
     * 6. Remaining chain PKs:
     *
     * chain = 1 ... 66
     * ============================================================
     */

    for (int chain = 1;
         chain < WOTS_LEN;
         ++chain)
    {
        /*
         * chain PK = 8 words
         */

        for (int i = 0; i < 8; ++i)
        {
            const uint32_t pk_word =
                readincr(input);


            push_word(
                state,
                block,
                block_pos,
                pk_word
            );
        }


        /*
         * pub_seed:
         *
         * already known, discard forwarded copy.
         */

        for (int i = 0; i < 8; ++i)
        {
            (void)readincr(input);
        }


        /*
         * addr:
         *
         * already have layer/tree/keypair.
         *
         * discard.
         */

        for (int i = 0; i < 8; ++i)
        {
            (void)readincr(input);
        }
    }


    /*
     * ============================================================
     * At this point we have hashed:
     *
     *     22-byte pk_addr
     *     +
     *     67 * 32-byte chain public keys
     *
     *     = 22 + 2144
     *     = 2166 bytes
     *
     *
     * The SHA512 seeded state already accounted for:
     *
     *     128 bytes
     *
     *
     * Total SHA512 message length:
     *
     *     128 + 2166
     *     = 2294 bytes
     *
     *     2294 * 8
     *     = 18352 bits
     *     = 0x47B0
     * ============================================================
     */


    /*
     * We have:
     *
     *     2166 mod 128 = 118 bytes
     *
     * in the current final block.
     */

    /*
     * SHA512 padding start.
     */

    block[block_pos++] =
        0x80;


    /*
     * block_pos is now:
     *
     *     119
     *
     * SHA512 needs final 16 bytes for the bit length.
     *
     * Therefore this block cannot hold the length.
     *
     * Zero to end and compress it.
     */

    while (block_pos < 128)
    {
        block[block_pos++] =
            0;
    }


    sha512_compress(
        state,
        block
    );


    /*
     * New final block.
     */

    for (int i = 0;
         i < 128;
         ++i)
    {
        block[i] =
            0;
    }


    /*
     * SHA512 uses a 128-bit length.
     *
     * Message is much smaller than 2^64 bits:
     *
     * high 64 bits = 0
     *
     * low 64 bits:
     *
     *     18352 = 0x47B0
     */

    const uint64_t total_bits =
        0x47B0ULL;


    /*
     * bytes 112..119 = high 64 bits = zero
     *
     * bytes 120..127 = low 64-bit length
     */

    store_be64(
        &block[120],
        total_bits
    );


    sha512_compress(
        state,
        block
    );


    /*
     * ============================================================
     * 7. Output first SPX_N = 32 bytes
     *
     * SHA512 digest:
     *
     * state0 || state1 || state2 || state3 ...
     *
     * We need first 4 × uint64 = 32 bytes.
     *
     * Convert to the same AIE uint32 representation used throughout
     * your SHA2 pipeline.
     * ============================================================
     */

    uint8_t digest[32];


    store_be64(
        digest + 0,
        state[0]
    );

    store_be64(
        digest + 8,
        state[1]
    );

    store_be64(
        digest + 16,
        state[2]
    );

    store_be64(
        digest + 24,
        state[3]
    );


    for (int i = 0; i < 8; ++i)
    {
        writeincr(
            output,
            bytes_to_word_be(
                digest + 4 * i
            )
        );
    }
}
