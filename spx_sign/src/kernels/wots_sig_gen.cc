#include "../kernels.h"

#include <cstdint>
#include <adf.h>
#include <aie_api/aie.hpp>

using namespace adf;


namespace {

/* ================================================================
 * SHA256 constants
 * ================================================================ */

alignas(32)
static const uint32_t K[64] = {
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


static inline uint32_t small_sigma0(
    uint32_t x)
{
    return
        rotr32(x, 7) ^
        rotr32(x, 18) ^
        (x >> 3);
}


static inline uint32_t small_sigma1(
    uint32_t x)
{
    return
        rotr32(x, 17) ^
        rotr32(x, 19) ^
        (x >> 10);
}


#define SHA256_ROUND(A,B,C,D,E,F,G,H,WI,KI)             \
    do {                                                 \
        const uint32_t _s1 =                             \
            rotr32((E), 6) ^                             \
            rotr32((E),11) ^                             \
            rotr32((E),25);                              \
                                                         \
        const uint32_t _ch =                             \
            (G) ^ ((E) & ((F) ^ (G)));                   \
                                                         \
        const uint32_t _t1 =                             \
            (H) + _s1 + _ch + (KI) + (WI);               \
                                                         \
        const uint32_t _s0 =                             \
            rotr32((A), 2) ^                             \
            rotr32((A),13) ^                             \
            rotr32((A),22);                              \
                                                         \
        const uint32_t _maj =                            \
            ((A) & (B)) ^                                \
            ((C) & ((A) ^ (B)));                         \
                                                         \
        const uint32_t _t2 =                             \
            _s0 + _maj;                                  \
                                                         \
        (D) += _t1;                                      \
        (H)  = _t1 + _t2;                                \
    } while (0)


#define SHA256_ROUND8(BASE)                              \
    do {                                                 \
        SHA256_ROUND(a,b,c,d,e,f,g,h,                    \
                     w[(BASE)+0],K[(BASE)+0]);            \
        SHA256_ROUND(h,a,b,c,d,e,f,g,                    \
                     w[(BASE)+1],K[(BASE)+1]);            \
        SHA256_ROUND(g,h,a,b,c,d,e,f,                    \
                     w[(BASE)+2],K[(BASE)+2]);            \
        SHA256_ROUND(f,g,h,a,b,c,d,e,                    \
                     w[(BASE)+3],K[(BASE)+3]);            \
        SHA256_ROUND(e,f,g,h,a,b,c,d,                    \
                     w[(BASE)+4],K[(BASE)+4]);            \
        SHA256_ROUND(d,e,f,g,h,a,b,c,                    \
                     w[(BASE)+5],K[(BASE)+5]);            \
        SHA256_ROUND(c,d,e,f,g,h,a,b,                    \
                     w[(BASE)+6],K[(BASE)+6]);            \
        SHA256_ROUND(b,c,d,e,f,g,h,a,                    \
                     w[(BASE)+7],K[(BASE)+7]);            \
    } while (0)


static inline void sha256_compress(
    uint32_t *__restrict state,
    uint32_t *__restrict w)
{
    /*
     * Expand W[16..63].
     */

    for (int i = 0;
         i < 48;
         i += 2)
    chess_prepare_for_pipelining
    chess_loop_range(24,24)
    {
        const uint32_t w16 =
            w[i] +
            w[i + 9] +
            small_sigma0(
                w[i + 1]
            ) +
            small_sigma1(
                w[i + 14]
            );


        w[i + 16] =
            w16;


        const uint32_t w17 =
            w[i + 1] +
            w[i + 10] +
            small_sigma0(
                w[i + 2]
            ) +
            small_sigma1(
                w[i + 15]
            );


        w[i + 17] =
            w17;
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


/* ================================================================
 * Word -> bytes
 * ================================================================ */

static inline void word_to_bytes(
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


/* ================================================================
 * WOTS chain lengths
 *
 * SHA2-256f:
 *
 * WOTS_W    = 16
 * WOTS_LEN1 = 64
 * WOTS_LEN2 = 3
 * WOTS_LEN  = 67
 * ================================================================ */

static inline void compute_chain_lengths(
    uint8_t steps[67],
    const uint32_t msg_words[8])
{
    uint8_t msg[32];


    for (int i = 0;
         i < 8;
         ++i)
    {
        word_to_bytes(
            msg_words[i],
            &msg[4 * i]
        );
    }


    uint32_t csum =
        0;


    /*
     * First 64 base-16 digits.
     */

    for (int i = 0;
         i < 32;
         ++i)
    {
        const uint8_t hi =
            msg[i] >> 4;


        const uint8_t lo =
            msg[i] & 0x0FU;


        steps[2 * i] =
            hi;


        steps[2 * i + 1] =
            lo;


        csum +=
            15U - hi;


        csum +=
            15U - lo;
    }


    /*
     * WOTS checksum.
     */

    csum <<=
        4;


    steps[64] =
        (uint8_t)(
            (csum >> 12) &
            0x0FU
        );


    steps[65] =
        (uint8_t)(
            (csum >> 8) &
            0x0FU
        );


    steps[66] =
        (uint8_t)(
            (csum >> 4) &
            0x0FU
        );
}


/* ================================================================
 * Set WOTS keypair address.
 *
 * SHA2 keypair = bytes10..13.
 * ================================================================ */

static inline void set_keypair_addr_aie(
    uint32_t addr[8],
    uint32_t leaf_idx)
{
    /*
     * bytes10..11
     */

    addr[2] =
        (addr[2] & 0xFFFF0000U) |
        ((leaf_idx >> 16) &
         0xFFFFU);


    /*
     * bytes12..13.
     */

    addr[3] =
        (leaf_idx &
         0xFFFFU) << 16;
}


/* ================================================================
 * Seed state:
 *
 * SHA256_Compress(
 *     IV,
 *     PK.seed || zero[32]
 * )
 * ================================================================ */

static inline void prepare_seed_state(
    uint32_t state[8],
    const uint32_t pub_seed[8],
    uint32_t w[64])
{
    state[0] =
        0x6a09e667U;

    state[1] =
        0xbb67ae85U;

    state[2] =
        0x3c6ef372U;

    state[3] =
        0xa54ff53aU;

    state[4] =
        0x510e527fU;

    state[5] =
        0x9b05688cU;

    state[6] =
        0x1f83d9abU;

    state[7] =
        0x5be0cd19U;


    for (int i = 0;
         i < 8;
         ++i)
    {
        w[i] =
            pub_seed[i];


        w[i + 8] =
            0U;
    }


    sha256_compress(
        state,
        w
    );
}


/* ================================================================
 * X0 = PRF(SK.seed, addr)
 * ================================================================ */

static inline void wots_prf_one(
    uint32_t out[8],

    const uint32_t sk_seed[8],

    const uint32_t seeded_state[8],

    uint32_t addr[8],

    uint32_t w[64])
{
    uint32_t state[8];


    for (int i = 0;
         i < 8;
         ++i)
    {
        state[i] =
            seeded_state[i];
    }


    /*
     * ADRS bytes0..19.
     */

    w[0] = addr[0];
    w[1] = addr[1];
    w[2] = addr[2];
    w[3] = addr[3];
    w[4] = addr[4];


    /*
     * ADRS bytes20..21
     * ||
     * SK.seed
     */

    w[5] =
        (addr[5] &
         0xFFFF0000U) |
        (sk_seed[0] >> 16);


    w[6] =
        (sk_seed[0] << 16) |
        (sk_seed[1] >> 16);


    w[7] =
        (sk_seed[1] << 16) |
        (sk_seed[2] >> 16);


    w[8] =
        (sk_seed[2] << 16) |
        (sk_seed[3] >> 16);


    w[9] =
        (sk_seed[3] << 16) |
        (sk_seed[4] >> 16);


    w[10] =
        (sk_seed[4] << 16) |
        (sk_seed[5] >> 16);


    w[11] =
        (sk_seed[5] << 16) |
        (sk_seed[6] >> 16);


    w[12] =
        (sk_seed[6] << 16) |
        (sk_seed[7] >> 16);


    w[13] =
        (sk_seed[7] << 16) |
        0x00008000U;


    w[14] =
        0U;


    /*
     * 118 bytes = 944 bits.
     */

    w[15] =
        0x000003B0U;


    sha256_compress(
        state,
        w
    );


    for (int i = 0;
         i < 8;
         ++i)
    {
        out[i] =
            state[i];
    }
}


/* ================================================================
 * One WOTS F step.
 * ================================================================ */

static inline void wots_f_one(
    uint32_t data[8],

    const uint32_t seeded_state[8],

    const uint32_t addr[8],

    uint32_t w[64])
{
    uint32_t state[8];


    for (int i = 0;
         i < 8;
         ++i)
    {
        state[i] =
            seeded_state[i];
    }


    w[0] = addr[0];
    w[1] = addr[1];
    w[2] = addr[2];
    w[3] = addr[3];
    w[4] = addr[4];


    w[5] =
        (addr[5] &
         0xFFFF0000U) |
        (data[0] >> 16);


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


    w[13] =
        (data[7] << 16) |
        0x00008000U;


    w[14] =
        0U;


    w[15] =
        0x000003B0U;


    sha256_compress(
        state,
        w
    );


    for (int i = 0;
         i < 8;
         ++i)
    {
        data[i] =
            state[i];
    }
}


/* ================================================================
 * Common 8-worker implementation.
 * ================================================================ */

static void wots_sig_worker_impl(
    input_stream<uint32_t> *__restrict input,
    output_pktstream *__restrict output,
    int worker_id)
{
    constexpr int WOTS_LEN =
        67;


    constexpr int NUM_WORKERS =
        8;


    constexpr int NUM_GROUPS =
        9;


    /*
     * ============================================================
     * Input context.
     * ============================================================
     */

    uint32_t sk_seed[8];

    uint32_t pub_seed[8];

    uint32_t wots_msg[8];

    uint32_t base_addr[8];

    uint32_t target_leaf_idx;


    for (int i = 0;
         i < 8;
         ++i)
    {
        sk_seed[i] =
            readincr(input);
    }


    for (int i = 0;
         i < 8;
         ++i)
    {
        pub_seed[i] =
            readincr(input);
    }


    for (int i = 0;
         i < 8;
         ++i)
    {
        wots_msg[i] =
            readincr(input);
    }


    for (int i = 0;
         i < 8;
         ++i)
    {
        base_addr[i] =
            readincr(input);
    }


    target_leaf_idx =
        readincr(input);


    /*
     * ============================================================
     * Compute all 67 WOTS steps once.
     * ============================================================
     */

    uint8_t steps[WOTS_LEN];


    compute_chain_lengths(
        steps,
        wots_msg
    );


    /*
     * ============================================================
     * Precompute SHA256(PK.seed || zero) once per worker.
     * ============================================================
     */

    uint32_t seed_state[8];


    alignas(32)
    uint32_t w[64];


    prepare_seed_state(
        seed_state,
        pub_seed,
        w
    );


    /*
     * ============================================================
     * Process by GROUP:
     *
     * group0:
     *
     *     worker0 -> chain0
     *     ...
     *     worker7 -> chain7
     *
     * group1:
     *
     *     worker0 -> chain8
     *     ...
     *
     * ...
     *
     * group8:
     *
     *     worker0 -> 64
     *     worker1 -> 65
     *     worker2 -> 66
     *
     * NOTE:
     *
     * The eight hardware workers are NOT synchronized here.
     * This grouping only defines their logical chain assignment.
     *
     * Ordering is guaranteed by wots_sig_merge().
     * ============================================================
     */

    for (int group = 0;
         group < NUM_GROUPS;
         ++group)
    {
        const int chain =
            group * NUM_WORKERS +
            worker_id;


        /*
         * Workers3..7 have no chain in final group.
         */

        if (chain >= WOTS_LEN)
        {
            break;
        }


        uint32_t addr[8];

        uint32_t data[8];


        /*
         * Start from subtree address.
         */

        for (int i = 0;
             i < 8;
             ++i)
        {
            addr[i] =
                base_addr[i];
        }


        /*
         * Signature belongs to target WOTS key.
         */

        set_keypair_addr_aie(
            addr,
            target_leaf_idx
        );


        /*
         * chain = current chain index.
         *
         * SHA2 byte17.
         */

        addr[4] =
            (addr[4] &
             0xFF00FFFFU) |
            (
                ((uint32_t)chain &
                 0xFFU)
                << 16
            );


        /*
         * hash = 0.
         */

        addr[5] &=
            0xFF00FFFFU;


        /*
         * WOTSPRF = 5.
         */

        addr[2] =
            (addr[2] &
             0xFF00FFFFU) |
            0x00050000U;


        /*
         * ========================================================
         * Generate X0.
         * ========================================================
         */

        wots_prf_one(
            data,
            sk_seed,
            seed_state,
            addr,
            w
        );


        /*
         * Switch:
         *
         * WOTSPRF -> WOTS
         */

        addr[2] &=
            0xFF00FFFFU;


        /*
         * ========================================================
         * Signature element:
         *
         *     sig[chain]
         *         =
         *     X_steps[chain]
         * ========================================================
         */

        const int stop =
            (int)steps[chain];


        for (int k = 0;
             k < stop;
             ++k)
        {
            /*
             * hash address = k.
             */

            addr[5] =
                (addr[5] &
                 0xFF00FFFFU) |
                (
                    ((uint32_t)k &
                     0xFFU)
                    << 16
                );


            wots_f_one(
                data,
                seed_state,
                addr,
                w
            );
        }


        /*
         * ========================================================
         * Output packet:
         *
         *     chain_idx
         *     signature[8]
         *
         * ========================================================
         */

        const uint32_t packet_id =
            getPacketid(
                output,
                0
            );


        writeHeader(
            output,
            0,
            packet_id
        );


        writeincr(
            output,
            (uint32_t)chain,
            false
        );


        for (int i = 0;
             i < 8;
             ++i)
        {
            writeincr(
                output,
                data[i],
                i == 7
            );
        }
    }
}

} // namespace


/* ================================================================
 * Eight kernel entry points.
 * ================================================================ */

void wots_sig_chain0(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        0
    );
}


void wots_sig_chain1(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        1
    );
}


void wots_sig_chain2(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        2
    );
}


void wots_sig_chain3(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        3
    );
}


void wots_sig_chain4(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        4
    );
}


void wots_sig_chain5(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        5
    );
}


void wots_sig_chain6(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        6
    );
}


void wots_sig_chain7(
    input_stream<uint32_t> *in,
    output_pktstream *out)
{
    wots_sig_worker_impl(
        in,
        out,
        7
    );
}