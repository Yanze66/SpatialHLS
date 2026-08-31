#include <adf.h>
#include "adf/new_frontend/adf.h"
#include "kernels.h"

using namespace adf;


class simpleGraph : public adf::graph {

private:

    /*
     * ============================================================
     * Front-end dispatcher
     * ============================================================
     */
    kernel dispatcher;


    /*
     * ============================================================
     * 16 WOTS leaf accelerators
     * ============================================================
     */
    kernel wots_prf[16];

    kernel sha256_chain[16][15];

    kernel wots_hash512[16];


    /*
     * ============================================================
     * Four-level Merkle pipeline
     * ============================================================
     */
    kernel merkle_level[4];


    /*
     * ============================================================
     * WOTS signature side path
     *
     * 8 workers:
     *
     * worker0 -> chain 0,8,16,...
     * worker1 -> chain 1,9,17,...
     * ...
     * worker7 -> chain 7,15,23,...
     *
     * sig_collector:
     *
     * reorder -> sig[0] ... sig[66]
     * ============================================================
     */

    kernel sig_chain[8];

    kernel sig_collector;


    /*
     * ============================================================
     * Packet switches
     *
     * input_split:
     *
     * 0..15  -> WOTS leaf generation
     * 16     -> Merkle metadata
     * 17..24 -> WOTS signature workers
     * ============================================================
     */

    adf::pktsplit<25> input_split;

    adf::pktmerge<16> leaf_merge;

    adf::pktmerge<8> sig_packet_merge;


public:

    /*
     * One input remains unchanged.
     */
    input_plio in;


    /*
     * Merkle authentication path + root.
     */
    output_plio out;


    /*
     * WOTS signature.
     */
    output_plio out_sig;


    simpleGraph()
    {
        /*
         * ========================================================
         * PLIO
         * ========================================================
         */

        in =
            input_plio::create(
                "DataIn1",
                plio_32_bits,
                "data/input.txt"
            );


        /*
         * output 1:
         *
         * auth0
         * auth1
         * auth2
         * auth3
         * root
         */
        out =
            output_plio::create(
                "DataOut1",
                plio_32_bits,
                "data/output.txt"
            );


        /*
         * output 2:
         *
         * WOTS signature
         *
         * 67 × 8 words
         * =
         * 536 words
         */
        out_sig =
            output_plio::create(
                "DataOut2",
                plio_32_bits,
                "data/output2.txt"
            );


        /*
         * ========================================================
         * Dispatcher
         * ========================================================
         */

        dispatcher =
            kernel::create(
                wots_dispatch
            );


        source(dispatcher) =
            "src/kernels/wots_dispatch.cc";


        runtime<ratio>(
            dispatcher
        ) = 1;


        /*
         * ========================================================
         * 16 WOTS leaf accelerators
         * ========================================================
         */

        for (int leaf = 0;
             leaf < 16;
             ++leaf)
        {
            /*
             * PRF
             */
            wots_prf[leaf] =
                kernel::create(
                    wots_prf_sha256
                );


            source(
                wots_prf[leaf]
            ) =
                "src/kernels/wots_prf_gen.cc";


            runtime<ratio>(
                wots_prf[leaf]
            ) = 1;


            /*
             * 15 WOTS SHA256 chain stages
             */
            for (int stage = 0;
                 stage < 15;
                 ++stage)
            {
                sha256_chain[leaf][stage] =
                    kernel::create(
                        sha256
                    );


                source(
                    sha256_chain[leaf][stage]
                ) =
                    "src/kernels/sha256.cc";


                runtime<ratio>(
                    sha256_chain[leaf][stage]
                ) = 1;
            }


            /*
             * WOTS public-key T67
             */
            wots_hash512[leaf] =
                kernel::create(
                    wots_pk_sha512
                );


            source(
                wots_hash512[leaf]
            ) =
                "src/kernels/wots_pk_sha512.cc";


            runtime<ratio>(
                wots_hash512[leaf]
            ) = 1;
        }


        /*
         * ========================================================
         * Four Merkle kernels
         * ========================================================
         */

        merkle_level[0] =
            kernel::create(
                merkle_level1
            );


        source(
            merkle_level[0]
        ) =
            "src/kernels/merkle_level1.cc";


        runtime<ratio>(
            merkle_level[0]
        ) = 1;



        merkle_level[1] =
            kernel::create(
                merkle_level2
            );


        source(
            merkle_level[1]
        ) =
            "src/kernels/merkle_level2.cc";


        runtime<ratio>(
            merkle_level[1]
        ) = 1;



        merkle_level[2] =
            kernel::create(
                merkle_level3
            );


        source(
            merkle_level[2]
        ) =
            "src/kernels/merkle_level3.cc";


        runtime<ratio>(
            merkle_level[2]
        ) = 1;



        merkle_level[3] =
            kernel::create(
                merkle_level4
            );


        source(
            merkle_level[3]
        ) =
            "src/kernels/merkle_level4.cc";


        runtime<ratio>(
            merkle_level[3]
        ) = 1;


        /*
         * ========================================================
         * WOTS signature workers
         * ========================================================
         */

        sig_chain[0] =
            kernel::create(
                wots_sig_chain0
            );
        
        sig_chain[1] =
            kernel::create(
                wots_sig_chain1
            );

        sig_chain[2] =
            kernel::create(
                wots_sig_chain2
            );

        sig_chain[3] =
            kernel::create(
                wots_sig_chain3
            );

        sig_chain[4] =
            kernel::create(
                wots_sig_chain4
            );

        sig_chain[5] =
            kernel::create(
                wots_sig_chain5
            );

        sig_chain[6] =
            kernel::create(
                wots_sig_chain6
            );

        sig_chain[7] =
            kernel::create(
                wots_sig_chain7
            );


        for (int worker = 0;
             worker < 8;
             ++worker)
        {
            source(
                sig_chain[worker]
            ) =
                "src/kernels/wots_sig_gen.cc";


            runtime<ratio>(
                sig_chain[worker]
            ) = 1;
        }


        /*
         * Signature reorder / collector tile.
         */

        sig_collector =
            kernel::create(
                wots_sig_merge
            );


        source(
            sig_collector
        ) =
            "src/kernels/wots_sig_merge.cc";


        runtime<ratio>(
            sig_collector
        ) = 1;


        /*
         * ========================================================
         * Packet switches
         * ========================================================
         */

        input_split =
            adf::pktsplit<25>::create();


        leaf_merge =
            adf::pktmerge<16>::create();


        sig_packet_merge =
            adf::pktmerge<8>::create();


        /*
         * ========================================================
         * INPUT
         *
         * PLIO -> dispatcher
         * ========================================================
         */

        auto net_input =
            connect<stream>(
                in.out[0],
                dispatcher.in[0]
            );


        fifo_depth(
            net_input
        ) = 64;


        /*
         * ========================================================
         * dispatcher -> pktsplit<25>
         *
         * Dispatcher now produces considerably more data:
         *
         * 16 × WOTS requests
         * 1  × Merkle metadata
         * 8  × signature requests
         *
         * so increase FIFO.
         * ========================================================
         */

        auto net_dispatch =
            connect<pktstream>(
                dispatcher.out[0],
                input_split.in[0]
            );


        fifo_depth(
            net_dispatch
        ) = 256;


        /*
         * ========================================================
         * 16 WOTS leaf paths
         * ========================================================
         */

        for (int leaf = 0;
             leaf < 16;
             ++leaf)
        {
            /*
             * pktsplit -> PRF
             */
            auto net_prf_in =
                connect<pktstream, stream>(
                    input_split.out[leaf],
                    wots_prf[leaf].in[0]
                );


            fifo_depth(
                net_prf_in
            ) = 64;


            /*
             * PRF -> SHA256 stage0
             */
            auto net_prf_sha =
                connect<stream>(
                    wots_prf[leaf].out[0],
                    sha256_chain[leaf][0].in[0]
                );


            fifo_depth(
                net_prf_sha
            ) = 128;


            /*
             * SHA256 chain spatial pipeline
             */
            for (int stage = 0;
                 stage < 14;
                 ++stage)
            {
                auto net_sha =
                    connect<stream>(
                        sha256_chain[leaf][stage].out[0],
                        sha256_chain[leaf][stage + 1].in[0]
                    );


                fifo_depth(
                    net_sha
                ) = 128;
            }


            /*
             * SHA256[14] -> WOTS T67 SHA512
             *
             * Largest producer / consumer rate mismatch.
             */
            auto net_wots_pk =
                connect<stream>(
                    sha256_chain[leaf][14].out[0],
                    wots_hash512[leaf].in[0]
                );


            fifo_depth(
                net_wots_pk
            ) = 256;


            /*
             * WOTS leaf packet -> leaf merge
             */
            auto net_leaf =
                connect<pktstream>(
                    wots_hash512[leaf].out[0],
                    leaf_merge.in[leaf]
                );


            fifo_depth(
                net_leaf
            ) = 32;
        }


        /*
         * ========================================================
         * MERKLE PATH
         * ========================================================
         */


        /*
         * metadata:
         *
         * splitter branch 16
         * ->
         * Merkle level1 input1
         */
        auto net_metadata =
            connect<pktstream, stream>(
                input_split.out[16],
                merkle_level[0].in[1]
            );


        fifo_depth(
            net_metadata
        ) = 64;


        /*
         * 16 WOTS leaves
         * ->
         * Merkle Level 1
         */
        auto net_merkle_leaf =
            connect<pktstream>(
                leaf_merge.out[0],
                merkle_level[0].in[0]
            );


        fifo_depth(
            net_merkle_leaf
        ) = 128;


        /*
         * Merkle spatial pipeline:
         *
         * Level1 -> Level2
         */
        auto net_m12 =
            connect<stream>(
                merkle_level[0].out[0],
                merkle_level[1].in[0]
            );


        fifo_depth(
            net_m12
        ) = 256;


        /*
         * Level2 -> Level3
         */
        auto net_m23 =
            connect<stream>(
                merkle_level[1].out[0],
                merkle_level[2].in[0]
            );


        fifo_depth(
            net_m23
        ) = 128;


        /*
         * Level3 -> Level4
         */
        auto net_m34 =
            connect<stream>(
                merkle_level[2].out[0],
                merkle_level[3].in[0]
            );


        fifo_depth(
            net_m34
        ) = 128;


        /*
         * auth0..3 + root
         * ->
         * output.txt
         */
        auto net_output =
            connect<stream>(
                merkle_level[3].out[0],
                out.in[0]
            );


        fifo_depth(
            net_output
        ) = 64;


        /*
         * ========================================================
         * WOTS SIGNATURE SIDE PATH
         *
         * Branches:
         *
         * input_split[17] -> worker0
         * ...
         * input_split[24] -> worker7
         * ========================================================
         */

        for (int worker = 0;
             worker < 8;
             ++worker)
        {
            /*
             * Complete signing context:
             *
             * SK.seed[8]
             * PK.seed[8]
             * WOTS msg[8]
             * base_addr[8]
             * target_leaf_idx
             *
             * = 33 words
             */

            auto net_sig_in =
                connect<pktstream, stream>(
                    input_split.out[17 + worker],
                    sig_chain[worker].in[0]
                );


            /*
             * One request is already 33 words.
             *
             * Use 64 so a complete request fits with headroom.
             */
            fifo_depth(
                net_sig_in
            ) = 64;


            /*
             * Each worker emits:
             *
             * packet header
             * chain_index
             * sig[8]
             *
             * Workers have variable computation time because
             * wots_steps[i] ranges from 0 to 15.
             */

            auto net_sig_worker =
                connect<pktstream>(
                    sig_chain[worker].out[0],
                    sig_packet_merge.in[worker]
                );


            /*
             * Allow multiple finished signature elements to queue
             * without immediately backpressuring the SHA256 worker.
             */
            fifo_depth(
                net_sig_worker
            ) = 64;
        }


        /*
         * ========================================================
         * 8 signature workers -> pktmerge<8>
         *                       -> signature reorder tile
         * ========================================================
         */

        auto net_sig_merged =
            connect<pktstream>(
                sig_packet_merge.out[0],
                sig_collector.in[0]
            );


        /*
         * Use a relatively deep FIFO here because the 8 workers
         * finish chains at different rates.
         *
         * Each result is ~10 words including packet header.
         *
         * 256 words gives room for roughly 25 results.
         */
        fifo_depth(
            net_sig_merged
        ) = 256;


        /*
         * ========================================================
         * Ordered WOTS signature -> output2.txt
         *
         * Final stream:
         *
         * sig[0][8]
         * sig[1][8]
         * ...
         * sig[66][8]
         *
         * 536 words.
         * ========================================================
         */

        auto net_sig_out =
            connect<stream>(
                sig_collector.out[0],
                out_sig.in[0]
            );


        fifo_depth(
            net_sig_out
        ) = 128;


        /*
         * ========================================================
         * WOTS LEAF PLACEMENT
         *
         * Exactly your current placement:
         *
         * Two complete WOTS per row
         *
         * WOTS even:
         *     col 0..16
         *
         * WOTS odd:
         *     col 17..33
         * ========================================================
         */

        for (int leaf = 0;
             leaf < 16;
             ++leaf)
        {
            int row =
                leaf / 2;


            int base_col =
                (leaf % 2) * 17;


            /*
             * PRF
             */
            location<kernel>(
                wots_prf[leaf]
            ) =
                tile(
                    base_col,
                    row
                );


            /*
             * SHA256 × 15
             */
            for (int stage = 0;
                 stage < 15;
                 ++stage)
            {
                location<kernel>(
                    sha256_chain[leaf][stage]
                ) =
                    tile(
                        base_col + stage + 1,
                        row
                    );
            }


            /*
             * T67 SHA512
             */
            location<kernel>(
                wots_hash512[leaf]
            ) =
                tile(
                    base_col + 16,
                    row
                );
        }


        /*
         * ========================================================
         * CONTROL + MERKLE PLACEMENT
         *
         * Existing free area:
         *
         * columns 34..49
         * ========================================================
         */

        location<kernel>(
            dispatcher
        ) =
            tile(
                34,
                3
            );


        location<kernel>(
            merkle_level[0]
        ) =
            tile(
                35,
                3
            );


        location<kernel>(
            merkle_level[1]
        ) =
            tile(
                36,
                3
            );


        location<kernel>(
            merkle_level[2]
        ) =
            tile(
                37,
                3
            );


        location<kernel>(
            merkle_level[3]
        ) =
            tile(
                38,
                3
            );


        /*
         * ========================================================
         * SIGNATURE PLACEMENT
         *
         * Put eight signature SHA256 workers together in an
         * otherwise unused region.
         *
         * row 6:
         *
         * col34 ... col41
         *
         * collector:
         *
         * col42
         * ========================================================
         */

        for (int worker = 0;
             worker < 8;
             ++worker)
        {
            location<kernel>(
                sig_chain[worker]
            ) =
                tile(
                    34 + worker,
                    6
                );
        }


        location<kernel>(
            sig_collector
        ) =
            tile(
                42,
                6
            );
    }
};