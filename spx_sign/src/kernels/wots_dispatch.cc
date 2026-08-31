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

} // namespace



/*
 * ================================================================
 * INPUT
 *
 *     sk_seed[8]
 *     pub_seed[8]
 *     wots_msg[8]
 *     base_addr[8]
 *     target_leaf_idx
 *
 * Total:
 *
 *     33 words
 *
 *
 * ================================================================
 * OUTPUT PACKET BRANCHES
 *
 *     0  -> WOTS leaf 0
 *     1  -> WOTS leaf 1
 *     ...
 *     15 -> WOTS leaf 15
 *
 *     16 -> Merkle metadata
 *
 *     17 -> WOTS signature worker 0
 *     18 -> WOTS signature worker 1
 *     ...
 *     24 -> WOTS signature worker 7
 *
 *
 * Therefore graph must use:
 *
 *     adf::pktsplit<25>
 *
 * ================================================================
 */

void wots_dispatch(
    input_stream<uint32_t> *__restrict input,
    output_pktstream *__restrict output)
{
    alignas(32)
    uint32_t sk_seed[8];

    alignas(32)
    uint32_t pub_seed[8];

    alignas(32)
    uint32_t wots_msg[8];

    alignas(32)
    uint32_t base_addr[8];


    uint32_t target_leaf_idx;



    /*
     * ============================================================
     * 1. Read one complete XMSS signing request.
     * ============================================================
     */

    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        sk_seed[i] =
            readincr(input);
    }


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        pub_seed[i] =
            readincr(input);
    }


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        wots_msg[i] =
            readincr(input);
    }


    for (int i = 0; i < 8; ++i)
    chess_prepare_for_pipelining
    chess_loop_range(8, 8)
    {
        base_addr[i] =
            readincr(input);
    }


    target_leaf_idx =
        readincr(input);



    /*
     * ============================================================
     * 2. Generate 16 WOTS leaf-generation packets.
     *
     * Branch:
     *
     *     0 .. 15
     *
     *
     * Each packet:
     *
     *     sk_seed[8]
     *     pub_seed[8]
     *     leaf_addr[8]
     *
     * = 24 words
     *
     *
     * Each branch corresponds to one XMSS leaf:
     *
     *     branch 0  -> keypair 0
     *     branch 1  -> keypair 1
     *     ...
     *     branch 15 -> keypair 15
     *
     * ============================================================
     */

    for (int leaf = 0;
         leaf < 16;
         ++leaf)
    {
        uint8_t addr_bytes[32];

        uint32_t leaf_addr[8];


        /*
         * --------------------------------------------------------
         * Start from base subtree address.
         *
         * Preserve:
         *
         *     layer
         *     tree
         *
         * --------------------------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            word_to_bytes(
                base_addr[i],
                &addr_bytes[4 * i]
            );
        }


        /*
         * Keep only subtree information.
         *
         * bytes:
         *
         *     0      layer
         *     1..8   tree
         *
         * Clear everything below it.
         */

        for (int i = 9;
             i < 32;
             ++i)
        {
            addr_bytes[i] =
                0;
        }


        /*
         * --------------------------------------------------------
         * keypair address:
         *
         * bytes 10..13
         *
         * Current tree has only 16 leaves:
         *
         *     00 00 00 leaf
         * --------------------------------------------------------
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
         * Convert address back into AIE natural words.
         */

        for (int i = 0; i < 8; ++i)
        {
            leaf_addr[i] =
                bytes_to_word(
                    &addr_bytes[4 * i]
                );
        }


        /*
         * --------------------------------------------------------
         * Packet header:
         *
         * pktsplit branch = leaf
         * --------------------------------------------------------
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
         * SK.seed
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
         * PK.seed
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
         * Leaf/WOTS address.
         *
         * TLAST on last word.
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
     * 3. Branch 16:
     *
     * Merkle metadata.
     *
     *
     * Payload:
     *
     *     pub_seed[8]
     *     wots_msg[8]
     *     base_addr[8]
     *     target_leaf_idx
     *
     * = 25 words
     *
     *
     * NOTE:
     *
     * wots_msg is currently not required to build root/auth,
     * but keeping it preserves your existing Merkle interface.
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


        /*
         * PK.seed
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
         * WOTS message
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                wots_msg[i],
                false
            );
        }


        /*
         * Base subtree address
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                base_addr[i],
                false
            );
        }


        /*
         * Target leaf.
         */

        writeincr(
            output,
            target_leaf_idx,
            true
        );
    }



    /*
     * ============================================================
     * 4. Branches 17..24:
     *
     * Eight WOTS-signature workers.
     *
     *
     * Every worker receives THE SAME signing context:
     *
     *     sk_seed[8]
     *     pub_seed[8]
     *     wots_msg[8]
     *     base_addr[8]
     *     target_leaf_idx
     *
     * = 33 words
     *
     *
     * Worker itself decides which chains it owns:
     *
     * worker0:
     *
     *     0, 8, 16, 24, 32, 40, 48, 56, 64
     *
     * worker1:
     *
     *     1, 9, 17, ..., 65
     *
     * ...
     *
     * worker7:
     *
     *     7, 15, 23, ..., 63
     *
     *
     * Dispatcher DOES NOT compute:
     *
     *     chain_lengths()
     *     chain address
     *     PRF
     *
     * Those belong inside wots_sig_chainX().
     * ============================================================
     */

    for (int worker = 0;
         worker < 8;
         ++worker)
    {
        /*
         * Signature branch:
         *
         * worker0 -> branch17
         * ...
         * worker7 -> branch24
         */

        const int branch =
            17 + worker;


        const uint32_t ID =
            getPacketid(
                output,
                branch
            );


        writeHeader(
            output,
            0,
            ID
        );


        /*
         * --------------------------------------------------------
         * SK.seed
         * --------------------------------------------------------
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
         * --------------------------------------------------------
         * PK.seed
         * --------------------------------------------------------
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
         * --------------------------------------------------------
         * WOTS message.
         *
         * Signature workers compute:
         *
         *     wots_steps[67]
         *
         * from this value.
         * --------------------------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                wots_msg[i],
                false
            );
        }


        /*
         * --------------------------------------------------------
         * Base subtree address.
         *
         * Signature worker will insert:
         *
         *     keypair = target_leaf_idx
         *     chain   = its chain number
         *     hash    = step
         *     type
         *
         * locally.
         * --------------------------------------------------------
         */

        for (int i = 0; i < 8; ++i)
        {
            writeincr(
                output,
                base_addr[i],
                false
            );
        }


        /*
         * --------------------------------------------------------
         * Target signing WOTS leaf.
         *
         * TLAST.
         * --------------------------------------------------------
         */

        writeincr(
            output,
            target_leaf_idx,
            true
        );
    }
}