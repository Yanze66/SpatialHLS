#include "../kernels.h"

#include <cstdint>
#include <adf.h>
#include <aie_api/aie.hpp>
#include "aie_api/aie_types.hpp"

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

namespace {

/*
 * SHAKE256:
 *
 * rate     = 1088 bits = 136 bytes
 * capacity = 512 bits
 */
static constexpr int SHAKE256_RATE_LANES = 17;


/*
 * Pack two consecutive uint32_t stream words into one
 * little-endian Keccak 64-bit lane.
 *
 * Input byte representation:
 *
 *   lo = bytes 0..3
 *   hi = bytes 4..7
 *
 * Keccak lane:
 *
 *   byte0 is least-significant byte.
 */
static inline uint64_t pack_u32x2(
    uint32_t lo,
    uint32_t hi)
{
    return
        static_cast<uint64_t>(lo) |
        (static_cast<uint64_t>(hi) << 32);
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};
/*
 * Keccak-f[1600].
 *
 * Put your optimized two-round implementation from fips202.cc here:
 *
 *     KeccakF1600_StatePermute()
 *
 * Recommended changes:
 *
 *     static inline
 *     uint64_t *__restrict state
 *
 * and test:
 *
 *     chess_prepare_for_pipelining
 *     chess_loop_range(12,12)
 *
 * on the 12-iteration two-round loop.
 */
static inline void KeccakF1600_StatePermute(
    uint64_t *__restrict state)
{
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2) chess_prepare_for_pipelining
        chess_loop_range(12,12){
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

} // namespace


/*
 * Input stream format: 24 words
 *
 *     input[0..7]   = chain data
 *     input[8..15]  = public seed
 *     input[16..23] = address
 *
 * PRF hash message:
 *
 *     PRF_PREFIX[0..7]
 *     pub_seed[0..7]
 *     addr[0..7], with addr[7] forced to zero
 *
 * Outputs:
 *
 *     prf_out:
 *         swapped digest[0..7]
 *         PRF address[0..7]
 *
 *     forward_out:
 *         original data[0..7]
 *         public seed[0..7]
 *         original address[0..7]
 */
void shake_f_96(
    input_stream<uint32_t> *__restrict prf_in,
    input_stream<uint32_t> *__restrict mask_in,
    output_stream<uint32_t> *__restrict data_out)
{
    /*
     * prf_in:
     *   [0..7]  = PRF digest
     *   [8..15] = address
     *
     * mask_in:
     *   [0..7]  = masked data
     *   [8..15] = pub_seed
     *
     * SHAKE input:
     *
     *   zero[8]
     *   PRF digest[8]
     *   masked_data[8]
     *
     * = 96 bytes
     */

    alignas(32) uint64_t s[25];

    /*
     * These must survive until output.
     */
    alignas(32) uint32_t addr[8];
    alignas(32) uint32_t pub_seed[8];


    /*
     * ============================================================
     * 1. First 32 bytes = zero[8]
     *
     * Four Keccak lanes.
     * ============================================================
     */

    s[0] = 0ULL;
    s[1] = 0ULL;
    s[2] = 0ULL;
    s[3] = 0ULL;


    /*
     * ============================================================
     * 2. PRF digest
     *
     * Direct stream -> s[4..7]
     *
     * No temporary PRF array.
     * ============================================================
     */

    {
        const uint32_t p0 = readincr(prf_in);
        const uint32_t p1 = readincr(prf_in);

        s[4] =
            static_cast<uint64_t>(p0) |
            (static_cast<uint64_t>(p1) << 32);
    }

    {
        const uint32_t p2 = readincr(prf_in);
        const uint32_t p3 = readincr(prf_in);

        s[5] =
            static_cast<uint64_t>(p2) |
            (static_cast<uint64_t>(p3) << 32);
    }

    {
        const uint32_t p4 = readincr(prf_in);
        const uint32_t p5 = readincr(prf_in);

        s[6] =
            static_cast<uint64_t>(p4) |
            (static_cast<uint64_t>(p5) << 32);
    }

    {
        const uint32_t p6 = readincr(prf_in);
        const uint32_t p7 = readincr(prf_in);

        s[7] =
            static_cast<uint64_t>(p6) |
            (static_cast<uint64_t>(p7) << 32);
    }


    /*
     * ============================================================
     * 3. Address
     *
     * Does NOT participate in SHAKE.
     * Just save it for next chain node.
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        addr[i] = readincr(prf_in);
    }


    /*
     * ============================================================
     * 4. masked_data
     *
     * Direct stream -> s[8..11]
     *
     * No temporary masked_data[] buffer.
     * ============================================================
     */

    {
        const uint32_t m0 = readincr(mask_in);
        const uint32_t m1 = readincr(mask_in);

        s[8] =
            static_cast<uint64_t>(m0) |
            (static_cast<uint64_t>(m1) << 32);
    }

    {
        const uint32_t m2 = readincr(mask_in);
        const uint32_t m3 = readincr(mask_in);

        s[9] =
            static_cast<uint64_t>(m2) |
            (static_cast<uint64_t>(m3) << 32);
    }

    {
        const uint32_t m4 = readincr(mask_in);
        const uint32_t m5 = readincr(mask_in);

        s[10] =
            static_cast<uint64_t>(m4) |
            (static_cast<uint64_t>(m5) << 32);
    }

    {
        const uint32_t m6 = readincr(mask_in);
        const uint32_t m7 = readincr(mask_in);

        s[11] =
            static_cast<uint64_t>(m6) |
            (static_cast<uint64_t>(m7) << 32);
    }


    /*
     * ============================================================
     * 5. pub_seed
     *
     * Does NOT participate in SHAKE.
     * Store only because it must be forwarded.
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        pub_seed[i] = readincr(mask_in);
    }


    /*
     * ============================================================
     * 6. SHAKE256 fixed padding
     * ============================================================
     */

    /*
     * byte 96 = 0x1F
     */
    s[12] = 0x000000000000001FULL;

    s[13] = 0ULL;
    s[14] = 0ULL;
    s[15] = 0ULL;

    /*
     * byte 135 |= 0x80
     */
    s[16] = 0x8000000000000000ULL;


    /*
     * ============================================================
     * 7. Capacity = zero
     * ============================================================
     */

    s[17] = 0ULL;
    s[18] = 0ULL;
    s[19] = 0ULL;
    s[20] = 0ULL;

    s[21] = 0ULL;
    s[22] = 0ULL;
    s[23] = 0ULL;
    s[24] = 0ULL;


    /*
     * ============================================================
     * 8. One Keccak-f[1600]
     * ============================================================
     */

    KeccakF1600_StatePermute(s);


    /*
     * ============================================================
     * 9. SHAKE output = next chain data
     *
     * Fully unrolled four-lane output.
     * ============================================================
     */

    {
        const uint64_t x = s[0];

        writeincr(
            data_out,
            static_cast<uint32_t>(x));

        writeincr(
            data_out,
            static_cast<uint32_t>(x >> 32));
    }

    {
        const uint64_t x = s[1];

        writeincr(
            data_out,
            static_cast<uint32_t>(x));

        writeincr(
            data_out,
            static_cast<uint32_t>(x >> 32));
    }

    {
        const uint64_t x = s[2];

        writeincr(
            data_out,
            static_cast<uint32_t>(x));

        writeincr(
            data_out,
            static_cast<uint32_t>(x >> 32));
    }

    {
        const uint64_t x = s[3];

        writeincr(
            data_out,
            static_cast<uint32_t>(x));

        writeincr(
            data_out,
            static_cast<uint32_t>(x >> 32));
    }


    /*
     * ============================================================
     * 10. Forward pub_seed
     * ============================================================
     */

    writeincr(data_out, pub_seed[0]);
    writeincr(data_out, pub_seed[1]);
    writeincr(data_out, pub_seed[2]);
    writeincr(data_out, pub_seed[3]);

    writeincr(data_out, pub_seed[4]);
    writeincr(data_out, pub_seed[5]);
    writeincr(data_out, pub_seed[6]);
    writeincr(data_out, pub_seed[7]);


    /*
     * ============================================================
     * 11. Advance chain address
     * ============================================================
     */

    addr[6] += 1U;


    /*
     * ============================================================
     * 12. Output next address
     * ============================================================
     */

    writeincr(data_out, addr[0]);
    writeincr(data_out, addr[1]);
    writeincr(data_out, addr[2]);
    writeincr(data_out, addr[3]);

    writeincr(data_out, addr[4]);
    writeincr(data_out, addr[5]);
    writeincr(data_out, addr[6]);
    writeincr(data_out, addr[7]);
}