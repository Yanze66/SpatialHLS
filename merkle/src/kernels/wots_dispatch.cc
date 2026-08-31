#include "../kernels.h"

#include <adf.h>
#include <cstdint>

using namespace adf;


namespace {

/*
 * AIE SHA2 representation:
 *
 * one word 0x00010203 represents bytes
 *
 *     00 01 02 03
 */

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
        ((uint32_t)p[2] << 8)  |
        ((uint32_t)p[3]);
}

}


/*
 * ================================================================
 * Input:
 *
 *     sk_seed[8]
 *     pub_seed[8]
 *     wots_msg[8]
 *     base_addr[8]
 *     target_leaf_idx
 *
 *
 * Output packet branches:
 *
 *     0  -> WOTS leaf 0
 *     1  -> WOTS leaf 1
 *     ...
 *     15 -> WOTS leaf 15
 *
 *     16 -> Merkle metadata
 *
 * ================================================================
 */

void wots_dispatch(
    input_stream<uint32_t> *__restrict input,
    output_pktstream *__restrict output)
{
    alignas(32) uint32_t sk_seed[8];
    alignas(32) uint32_t pub_seed[8];
    alignas(32) uint32_t wots_msg[8];
    alignas(32) uint32_t base_addr[8];

    uint32_t target_leaf_idx;


    /*
     * ============================================================
     * Read one complete XMSS/Merkle request.
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
        sk_seed[i] = readincr(input);

    for (int i = 0; i < 8; ++i)
        pub_seed[i] = readincr(input);

    for (int i = 0; i < 8; ++i)
        wots_msg[i] = readincr(input);

    for (int i = 0; i < 8; ++i)
        base_addr[i] = readincr(input);

    target_leaf_idx =
        readincr(input);


    /*
     * ============================================================
     * Generate 16 WOTS input packets.
     *
     * Each packet:
     *
     *     sk_seed[8]
     *     pub_seed[8]
     *     leaf_addr[8]
     *
     * Exactly 24 words, matching your current PRF kernel.
     * ============================================================
     */

    for (int leaf = 0;
         leaf < 16;
         ++leaf)
    {
        uint8_t addr_bytes[32];

        uint32_t leaf_addr[8];


        /*
         * Start from base subtree address.
         */
        for (int i = 0; i < 8; ++i)
        {
            word_to_bytes(
                base_addr[i],
                &addr_bytes[4 * i]
            );
        }


        /*
         * Keep only:
         *
         *     byte 0    layer
         *     byte 1..8 tree
         *
         * Everything after that is reconstructed locally.
         */

        for (int i = 9; i < 32; ++i)
        {
            addr_bytes[i] = 0;
        }


        /*
         * SHA2 address:
         *
         * keypair = bytes 10..13
         *
         * leaf < 16, therefore:
         *
         *     00 00 00 leaf
         */

        addr_bytes[10] =
            0;

        addr_bytes[11] =
            0;

        addr_bytes[12] =
            0;

        addr_bytes[13] =
            (uint8_t)leaf;


        /*
         * Convert address back into AIE words.
         */

        for (int i = 0; i < 8; ++i)
        {
            leaf_addr[i] =
                bytes_to_word(
                    &addr_bytes[4 * i]
                );
        }


        /*
         * Compiler-generated packet ID associated with
         * pktsplit output branch "leaf".
         */

        const uint32_t ID =
            getPacketid(
                output,
                leaf
            );


        writeHeader(
            output,
            0,
            ID
        );


        /*
         * ----------------------------------------
         * SK.seed
         * ----------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                sk_seed[i],
                false
            );
        }


        /*
         * ----------------------------------------
         * PK.seed
         * ----------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                pub_seed[i],
                false
            );
        }


        /*
         * ----------------------------------------
         * Leaf/WOTS address
         * ----------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                leaf_addr[i],
                i == 7
            );
        }
    }


    /*
     * ============================================================
     * Branch 16:
     *
     * Metadata for Merkle collector.
     *
     * pub_seed[8]
     * wots_msg[8]
     * base_addr[8]
     * target_leaf_idx
     *
     * = 25 words
     *
     *
     * wots_msg is not used yet for root/auth generation,
     * but forwarding it now keeps the interface ready for
     * WOTS-signature extraction later.
     * ============================================================
     */

    {
        const uint32_t ID =
            getPacketid(
                output,
                16
            );


        writeHeader(
            output,
            0,
            ID
        );


        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                pub_seed[i],
                false
            );
        }


        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                wots_msg[i],
                false
            );
        }


        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                base_addr[i],
                false
            );
        }


        writeincr(
            output,
            target_leaf_idx,
            true
        );
    }
}
