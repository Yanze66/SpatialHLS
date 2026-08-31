#include <adf.h>
#include "adf/new_frontend/adf.h"
#include "kernels.h"

using namespace adf;

//把fifo全注释了可以布局，但是容易卡死；如果写了fifo，布局布线的时候可能会卡住
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
 * 16 WOTS accelerators.
 *
 * Each:
 *
 * PRF
 * ↓
 * SHA256 × 15
 * ↓
 * SHA512 T67
 * ============================================================
 */

kernel wots_prf[16];

kernel sha256_chain[16][15];

kernel wots_hash512[16];


/*
 * ============================================================
 * Merkle collector
 * ============================================================
 */

kernel merkle;


/*
 * ============================================================
 * Packet switches
 * ============================================================
 */

adf::pktsplit<17> input_split;

adf::pktmerge<16> leaf_merge;

public:

input_plio in;

output_plio out;


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


    out =
        output_plio::create(
            "DataOut1",
            plio_32_bits,
            "data/output.txt"
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
     * Create 16 complete WOTS accelerators
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
         * 15 chain stages
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
         * Final WOTS PK compression
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
     * Merkle
     * ========================================================
     */

    merkle =
        kernel::create(
            merkle_collect
        );


    source(merkle) =
        "src/kernels/merkle_collect.cc";


    runtime<ratio>(
        merkle
    ) = 1;


    /*
     * ========================================================
     * Packet switches
     * ========================================================
     */

    input_split =
        adf::pktsplit<17>::create();


    leaf_merge =
        adf::pktmerge<16>::create();


    /*
     * ========================================================
     * Input:
     *
     * PLIO
     * ↓
     * dispatcher
     * ↓
     * pktsplit<17>
     * ========================================================
     */

    connect<stream> net0(
        in.out[0],
        dispatcher.in[0]
    );
    fifo_depth(net0) = 32;

    connect<pktstream>net1(
        dispatcher.out[0],
        input_split.in[0]
    );
    fifo_depth(net1) = 32;


    /*
     * ========================================================
     * 16 WOTS paths.
     * ========================================================
     */

    for (int leaf = 0;
         leaf < 16;
         ++leaf)
    {
        /*
         * Packet branch -> normal stream.
         *
         * Packet header/TLAST are removed before PRF.
         */

        connect<pktstream, stream>net_ptk(
            input_split.out[leaf],
            wots_prf[leaf].in[0]
        );

        fifo_depth(net_ptk) = 32;

        /*
         * PRF -> SHA256 stage 0
         */

        connect<stream>net_wots(
            wots_prf[leaf].out[0],
            sha256_chain[leaf][0].in[0]
        );
        fifo_depth(net_wots) = 32;

        /*
         * SHA256 chain pipeline
         */

        for (int stage = 0;
             stage < 14;
             ++stage)
        {
            connect<stream>net_chain(
                sha256_chain[leaf][stage].out[0],
                sha256_chain[leaf][stage + 1].in[0]
            );
                    fifo_depth(net_chain) = 32;

        }


        /*
         * Last SHA256 -> T67 SHA512
         */

        connect<stream>net_leaf(
            sha256_chain[leaf][14].out[0],
            wots_hash512[leaf].in[0]
        );
         fifo_depth(net_leaf) = 32;

        /*
         * Leaf packet -> pktmerge<16>
         */

        connect<pktstream>net_out(
            wots_hash512[leaf].out[0],
            leaf_merge.in[leaf]
        );
                 fifo_depth(net_out) = 32;

    }


    /*
     * ========================================================
     * Metadata branch 16.
     *
     * pktsplit strips packet header and feeds normal stream
     * into second Merkle input.
     * ========================================================
     */

    connect<pktstream, stream>net_merge(
        input_split.out[16],
        merkle.in[1]
    );
                 fifo_depth(net_merge) = 32;


    /*
     * ========================================================
     * 16 leaf packets -> Merkle input 0.
     *
     * KEEP packet stream here because Merkle needs packet IDs.
     * ========================================================
     */

    connect<pktstream>net_merkle(
        leaf_merge.out[0],
        merkle.in[0]
    );
                 fifo_depth(net_merkle) = 32;


    /*
     * ========================================================
     * Merkle output:
     *
     * auth0
     * auth1
     * auth2
     * auth3
     * root
     *
     * 40 words.
     * ========================================================
     */

    connect<stream>net_output(
        merkle.out[0],
        out.in[0]
    );
                 fifo_depth(net_output) = 32;


    /*
     * ========================================================
     * Placement
     * ========================================================
     */

    for (int leaf = 0;
         leaf < 16;
         ++leaf)
    {
        /*
         * Two WOTS per row.
         */

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
         * SHA256:
         *
         * columns base+1 ... base+15
         */

        for (int stage = 0;
             stage < 15;
             ++stage)
        {
            location<kernel>(
                sha256_chain[leaf][stage]
            ) =
                tile(
                    base_col + 1 + stage,
                    row
                );
        }


        /*
         * WOTS final T67 SHA512:
         *
         * column base+16
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
     * Central control / collection region.
     */

    location<kernel>(
        dispatcher
    ) =
        tile(
            34,
            3
        );


    location<kernel>(
        merkle
    ) =
        tile(
            34,
            4
        );
}

}; 