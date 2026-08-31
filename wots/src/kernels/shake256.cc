#include "../kernels.h"

#include <adf.h>
#include <cstdint>

using namespace adf;

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

namespace {

/*
 * ================================================================
 * Keccak-f[1600] round constants
 * ================================================================
 */

static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
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


/*
 * ================================================================
 * Original fast two-round fused Keccak-f[1600].
 *
 * Keep this implementation exactly in the style that already
 * fits your AIE tile.
 * ================================================================
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


    /*
     * Load state.
     */
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


    /*
     * ============================================================
     * Two Keccak rounds per loop iteration.
     *
     * 24 rounds -> 12 loop iterations.
     * ============================================================
     */

    for (round = 0;
         round < NROUNDS;
         round += 2)
    chess_prepare_for_pipelining
    chess_loop_range(12, 12)
    {
        /*
         * ========================================================
         * Round r
         *
         * A -> E
         * ========================================================
         */

        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;


        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);


        /*
         * Row 0
         */

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


        /*
         * Row 1
         */

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


        /*
         * Row 2
         */

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


        /*
         * Row 3
         */

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


        /*
         * Row 4
         */

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


        /*
         * ========================================================
         * Round r + 1
         *
         * E -> A
         * ========================================================
         */

        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;


        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);


        /*
         * Row 0
         */

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


        /*
         * Row 1
         */

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


        /*
         * Row 2
         */

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


        /*
         * Row 3
         */

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


        /*
         * Row 4
         */

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


    /*
     * Store state.
     */

    state[0]  = Aba;
    state[1]  = Abe;
    state[2]  = Abi;
    state[3]  = Abo;
    state[4]  = Abu;

    state[5]  = Aga;
    state[6]  = Age;
    state[7]  = Agi;
    state[8]  = Ago;
    state[9]  = Agu;

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
 * ================================================================
 *
 * SHAKE256 simple thash for WOTS+
 *
 * Fixed for:
 *
 *     sphincs-shake-256*
 *     THASH=simple
 *
 *
 * Input stream order:
 *
 *     data[8]       32 bytes
 *     pub_seed[8]   32 bytes
 *     addr[8]       32 bytes
 *
 *
 * Actual SHAKE256 message:
 *
 *     pub_seed || addr || data
 *
 *     32 + 32 + 32 = 96 bytes
 *
 *
 * SHAKE256 rate:
 *
 *     136 bytes
 *
 * Therefore exactly ONE Keccak-f[1600] permutation.
 *
 *
 * IMPORTANT
 * ---------
 *
 * This kernel intentionally follows the SAME stream/lane
 * representation as your old shake_prf_96 implementation:
 *
 *     s = low_32 | high_32 << 32
 *
 * No bswap is introduced here.
 *
 * ================================================================
 */
/*
 * ================================================================
 * SHAKE256 WOTS chain stage
 *
 * Fixed for:
 *
 *     sphincs-shake-256*
 *     THASH=simple
 *
 *
 * Input packet:
 *
 *     data[8]
 *     pub_seed[8]
 *     addr[8]
 *
 * Operation:
 *
 *     next_data =
 *         SHAKE256(
 *             pub_seed[32] ||
 *             addr[32]     ||
 *             data[32],
 *             32 bytes
 *         )
 *
 * Then:
 *
 *     hash_addr = hash_addr + 1
 *
 * Output packet:
 *
 *     next_data[8]
 *     pub_seed[8]
 *     next_addr[8]
 *
 *
 * This makes every tile have exactly the same interface, so:
 *
 *     tile0 -> tile1 -> ... -> tile14
 *
 * performs all 15 WOTS chain hashes.
 *
 * ================================================================
 */

void thash_shake256_simple(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    /*
     * ============================================================
     * Local packet storage
     *
     * Unlike the single-step version, seed and addr must survive
     * until the output stage because every tile forwards:
     *
     *      next_data || seed || next_addr
     * ============================================================
     */

    alignas(32) uint32_t data[8];
    alignas(32) uint32_t pub_seed[8];
    alignas(32) uint32_t addr[8];

    /*
     * Keccak-f[1600] state.
     */
    alignas(32) uint64_t s[25];


    /*
     * ============================================================
     * 1. Read current chain data
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
     * 2. Read pub_seed
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
     * 3. Read ADRS
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
     * 4. Construct SHAKE256 input
     *
     * Message:
     *
     *     pub_seed[32]
     *     ||
     *     addr[32]
     *     ||
     *     data[32]
     *
     * Total:
     *
     *     96 bytes
     *
     * Keep EXACTLY the same lane convention as your existing
     * shake_prf_96 / thash kernel:
     *
     *     lane =
     *         low_word |
     *         (high_word << 32)
     *
     * No bswap.
     * ============================================================
     */


    /*
     * ------------------------------------------------------------
     * pub_seed -> lanes 0..3
     * ------------------------------------------------------------
     */

    s[0] =
        static_cast<uint64_t>(pub_seed[0]) |
        (static_cast<uint64_t>(pub_seed[1]) << 32);

    s[1] =
        static_cast<uint64_t>(pub_seed[2]) |
        (static_cast<uint64_t>(pub_seed[3]) << 32);

    s[2] =
        static_cast<uint64_t>(pub_seed[4]) |
        (static_cast<uint64_t>(pub_seed[5]) << 32);

    s[3] =
        static_cast<uint64_t>(pub_seed[6]) |
        (static_cast<uint64_t>(pub_seed[7]) << 32);


    /*
     * ------------------------------------------------------------
     * ADRS -> lanes 4..7
     *
     * SHAKE uses the complete 32-byte ADRS.
     * ------------------------------------------------------------
     */

    s[4] =
        static_cast<uint64_t>(addr[0]) |
        (static_cast<uint64_t>(addr[1]) << 32);

    s[5] =
        static_cast<uint64_t>(addr[2]) |
        (static_cast<uint64_t>(addr[3]) << 32);

    s[6] =
        static_cast<uint64_t>(addr[4]) |
        (static_cast<uint64_t>(addr[5]) << 32);

    s[7] =
        static_cast<uint64_t>(addr[6]) |
        (static_cast<uint64_t>(addr[7]) << 32);


    /*
     * ------------------------------------------------------------
     * current chain data -> lanes 8..11
     * ------------------------------------------------------------
     */

    s[8] =
        static_cast<uint64_t>(data[0]) |
        (static_cast<uint64_t>(data[1]) << 32);

    s[9] =
        static_cast<uint64_t>(data[2]) |
        (static_cast<uint64_t>(data[3]) << 32);

    s[10] =
        static_cast<uint64_t>(data[4]) |
        (static_cast<uint64_t>(data[5]) << 32);

    s[11] =
        static_cast<uint64_t>(data[6]) |
        (static_cast<uint64_t>(data[7]) << 32);


    /*
     * ============================================================
     * 5. SHAKE256 padding
     *
     * SHAKE256 rate:
     *
     *     136 bytes = 17 lanes
     *
     * Message length:
     *
     *     96 bytes
     *
     * byte 96:
     *
     *     0x1F
     *
     * byte 135:
     *
     *     final 0x80
     * ============================================================
     */

    s[12] =
        0x000000000000001FULL;

    s[13] = 0ULL;
    s[14] = 0ULL;
    s[15] = 0ULL;

    s[16] =
        0x8000000000000000ULL;


    /*
     * Capacity portion.
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
     * 6. Exactly ONE Keccak-f[1600]
     *
     * After this:
     *
     *     s[0..3]
     *
     * contain the next 32-byte WOTS chain value.
     * ============================================================
     */

    KeccakF1600_StatePermute(s);


    /*
     * ============================================================
     * 7. Advance WOTS hash address
     *
     * SHAKE ADRS layout:
     *
     *     hash address = byte 31
     *
     *
     * Current stream/native uint32 representation:
     *
     * addr[7]:
     *
     *     byte28 byte29 byte30 byte31
     *
     * On little-endian uint32 representation:
     *
     *     byte31 corresponds to bits [31:24].
     *
     *
     * Therefore:
     *
     * hash = 0:
     *
     *     addr[7] = 0x00000000
     *
     * hash = 1:
     *
     *     addr[7] = 0x01000000
     *
     * hash = 2:
     *
     *     addr[7] = 0x02000000
     *
     * ...
     * ============================================================
     */

    {
        uint32_t hash_value =
            (addr[7] >> 24) &
            0xFFU;


        hash_value =
            hash_value + 1U;


        /*
         * Preserve bytes 28..30.
         *
         * Replace byte 31 only.
         */
        addr[7] =
            (addr[7] & 0x00FFFFFFU) |
            ((hash_value & 0xFFU) << 24);
    }


    /*
     * ============================================================
     * 8. Output packet
     *
     * SAME FORMAT AS INPUT:
     *
     *     next_data[8]
     *     pub_seed[8]
     *     next_addr[8]
     *
     * Total:
     *
     *     24 uint32 words
     * ============================================================
     */


    /*
     * ------------------------------------------------------------
     * next_data
     *
     * Keep exactly the same output convention as the old
     * SHAKE kernel:
     *
     *     low 32 bits first
     *     high 32 bits second
     * ------------------------------------------------------------
     */

    {
        const uint64_t x =
            s[0];

        writeincr(
            output,
            static_cast<uint32_t>(x)
        );

        writeincr(
            output,
            static_cast<uint32_t>(x >> 32)
        );
    }


    {
        const uint64_t x =
            s[1];

        writeincr(
            output,
            static_cast<uint32_t>(x)
        );

        writeincr(
            output,
            static_cast<uint32_t>(x >> 32)
        );
    }


    {
        const uint64_t x =
            s[2];

        writeincr(
            output,
            static_cast<uint32_t>(x)
        );

        writeincr(
            output,
            static_cast<uint32_t>(x >> 32)
        );
    }


    {
        const uint64_t x =
            s[3];

        writeincr(
            output,
            static_cast<uint32_t>(x)
        );

        writeincr(
            output,
            static_cast<uint32_t>(x >> 32)
        );
    }


    /*
     * ------------------------------------------------------------
     * pub_seed unchanged
     * ------------------------------------------------------------
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
     * ------------------------------------------------------------
     * updated ADRS
     * ------------------------------------------------------------
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