#include "../kernels.h"

#include <adf.h>
#include <cstdint>

using namespace adf;


namespace {

/* ================================================================
 * SHA512 constants
 * ================================================================ */

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
        ((uint64_t)p[6] << 8) |
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


static inline void word_to_bytes(
    uint32_t x,
    uint8_t *p)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}


static inline uint32_t bytes_to_word(
    const uint8_t *p)
{
    return
        ((uint32_t)p[0] << 24) |
        ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) |
        ((uint32_t)p[3]);
}


/* ================================================================
 * SHA512 compression
 * ================================================================ */

static void sha512_compress(
    uint64_t *__restrict state,
    const uint8_t *__restrict block)
{
    alignas(32)
    uint64_t w[80];


    for (int i = 0; i < 16; ++i)
    {
        w[i] =
            load_be64(
                block + 8 * i
            );
    }


    for (int i = 16; i < 80; ++i)
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


    for (int i = 0; i < 80; ++i)
    {
        const uint64_t S1 =
            rotr64(e,14) ^
            rotr64(e,18) ^
            rotr64(e,41);

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
            rotr64(a,28) ^
            rotr64(a,34) ^
            rotr64(a,39);

        const uint64_t maj =
            (a & b) ^
            (a & c) ^
            (b & c);

        const uint64_t temp2 =
            S0 + maj;


        h = g;
        g = f;
        f = e;
        e = d + temp1;

        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
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


/* ================================================================
 * SHA2-256f Merkle T2
 * ================================================================ */

static inline void merkle_t2(
    uint32_t out[8],

    const uint32_t left[8],
    const uint32_t right[8],

    const uint64_t seed_state[8],

    const uint32_t base_addr[8],

    uint32_t height,
    uint32_t tree_index)
{
    uint8_t addr[32];

    alignas(32)
    uint8_t block[128];

    uint64_t state[8];


    /*
     * base subtree address
     */
    for (int i = 0; i < 8; ++i)
    {
        word_to_bytes(
            base_addr[i],
            &addr[4 * i]
        );
    }


    /*
     * Keep layer/tree only.
     */
    for (int i = 9; i < 32; ++i)
    {
        addr[i] = 0;
    }


    /*
     * HASHTREE = 2
     */
    addr[9] =
        2;


    /*
     * tree height
     */
    addr[17] =
        (uint8_t)height;


    /*
     * tree index
     */
    addr[18] =
        (uint8_t)(tree_index >> 24);

    addr[19] =
        (uint8_t)(tree_index >> 16);

    addr[20] =
        (uint8_t)(tree_index >> 8);

    addr[21] =
        (uint8_t)tree_index;


    /*
     * Reuse seeded state.
     */
    for (int i = 0; i < 8; ++i)
    {
        state[i] =
            seed_state[i];
    }


    for (int i = 0; i < 128; ++i)
    {
        block[i] = 0;
    }


    /*
     * ADRS[22]
     */
    for (int i = 0; i < 22; ++i)
    {
        block[i] =
            addr[i];
    }


    /*
     * left
     */
    for (int i = 0; i < 8; ++i)
    {
        word_to_bytes(
            left[i],
            &block[22 + 4 * i]
        );
    }


    /*
     * right
     */
    for (int i = 0; i < 8; ++i)
    {
        word_to_bytes(
            right[i],
            &block[54 + 4 * i]
        );
    }


    /*
     * 86 bytes payload.
     */
    block[86] =
        0x80;


    /*
     * (128 + 86) * 8 = 0x6B0
     */
    store_be64(
        &block[120],
        0x00000000000006B0ULL
    );


    sha512_compress(
        state,
        block
    );


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
        out[i] =
            bytes_to_word(
                digest + 4 * i
            );
    }
}


/* ================================================================
 * Seed state stream helpers
 *
 * Each uint64:
 *
 *   high32
 *   low32
 * ================================================================ */

static inline void write_seed_state(
    output_stream<uint32_t> *out,
    const uint64_t state[8])
{
    for (int i = 0; i < 8; ++i)
    {
        writeincr(
            out,
            (uint32_t)(
                state[i] >> 32
            )
        );

        writeincr(
            out,
            (uint32_t)(
                state[i]
            )
        );
    }
}


static inline void read_seed_state(
    input_stream<uint32_t> *in,
    uint64_t state[8])
{
    for (int i = 0; i < 8; ++i)
    {
        uint32_t hi =
            readincr(in);

        uint32_t lo =
            readincr(in);


        state[i] =
            ((uint64_t)hi << 32) |
            (uint64_t)lo;
    }
}


/* ================================================================
 * Forward common inter-level header
 *
 * seed_state = 16 words
 * base_addr  = 8 words
 * target     = 1 word
 *
 * total = 25 words
 * ================================================================ */

static inline void write_header(
    output_stream<uint32_t> *out,
    const uint64_t state[8],
    const uint32_t addr[8],
    uint32_t target)
{
    write_seed_state(
        out,
        state
    );


    for (int i = 0; i < 8; ++i)
    {
        writeincr(
            out,
            addr[i]
        );
    }


    writeincr(
        out,
        target
    );
}


static inline void read_header(
    input_stream<uint32_t> *in,
    uint64_t state[8],
    uint32_t addr[8],
    uint32_t &target)
{
    read_seed_state(
        in,
        state
    );


    for (int i = 0; i < 8; ++i)
    {
        addr[i] =
            readincr(in);
    }


    target =
        readincr(in);
}


/* ================================================================
 * Node record
 *
 * node_index + node[8]
 *
 * = 9 words
 * ================================================================ */

static inline void write_node(
    output_stream<uint32_t> *out,
    uint32_t index,
    const uint32_t node[8])
{
    writeincr(
        out,
        index
    );


    for (int i = 0; i < 8; ++i)
    {
        writeincr(
            out,
            node[i]
        );
    }
}


static inline void read_node(
    input_stream<uint32_t> *in,
    uint32_t &index,
    uint32_t node[8])
{
    index =
        readincr(in);


    for (int i = 0; i < 8; ++i)
    {
        node[i] =
            readincr(in);
    }
}

} // namespace

void merkle_level4(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    uint64_t seed_state[8];

    uint32_t base_addr[8];

    uint32_t target_leaf_idx;


    read_header(
        input,
        seed_state,
        base_addr,
        target_leaf_idx
    );


    /*
     * Two height-3 nodes.
     */

    uint32_t nodes[2][8];

    bool valid[2] = {
        false,
        false
    };


    /*
     * Authentication node at height 3.
     */

    const uint32_t auth_index =
        (target_leaf_idx >> 3) ^
        1U;


    uint32_t auth3[8];


    /*
     * Read two nodes.
     */

    for (int arrival = 0;
         arrival < 2;
         ++arrival)
    {
        uint32_t index;

        uint32_t node[8];


        read_node(
            input,
            index,
            node
        );


        for (int i = 0; i < 8; ++i)
        {
            nodes[index][i] =
                node[i];
        }


        valid[index] =
            true;


        if (index == auth_index)
        {
            for (int i = 0; i < 8; ++i)
            {
                auth3[i] =
                    node[i];
            }
        }
    }


    /*
     * Root.
     */

    uint32_t root[8];


    merkle_t2(
        root,

        nodes[0],
        nodes[1],

        seed_state,

        base_addr,

        4,

        0
    );


    /*
     * Previous authentication path.
     */

    uint32_t auth0[8];

    uint32_t auth1[8];

    uint32_t auth2[8];


    for (int i = 0; i < 8; ++i)
        auth0[i] = readincr(input);


    for (int i = 0; i < 8; ++i)
        auth1[i] = readincr(input);


    for (int i = 0; i < 8; ++i)
        auth2[i] = readincr(input);


    /*
     * ============================================================
     * FINAL OUTPUT IDENTICAL TO OLD merkle_collect:
     *
     * auth0
     * auth1
     * auth2
     * auth3
     * root
     *
     * 40 words
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
        writeincr(output, auth0[i]);


    for (int i = 0; i < 8; ++i)
        writeincr(output, auth1[i]);


    for (int i = 0; i < 8; ++i)
        writeincr(output, auth2[i]);


    for (int i = 0; i < 8; ++i)
        writeincr(output, auth3[i]);


    for (int i = 0; i < 8; ++i)
        writeincr(output, root[i]);
}
