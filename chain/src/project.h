#include <adf.h>
#include "adf/new_frontend/adf.h"
#include "kernels.h"



// //2 tile 版本 和 3tile版本


using namespace adf;

class simpleGraph : public adf::graph {
private:

    /*
     * 15 WOTS chain stages:
     *
     * step 0  -> step 1
     * step 1  -> step 2
     * ...
     * step 14 -> step 15
     */
    kernel sha256_chain[15];


public:

    input_plio  in;
    output_plio out;


    simpleGraph()
    {
        /*
         * ============================================================
         * PLIO
         * ============================================================
         */

        in = input_plio::create(
            "DataIn1",
            plio_32_bits,
            "data/input_1.txt"
        );


        out = output_plio::create(
            "DataOut1",
            plio_32_bits,
            "data/output_1.txt"
        );


        /*
         * ============================================================
         * Create 15 identical SHA256 chain kernels
         * ============================================================
         */

        for (int i = 0; i < 15; ++i)
        {
            sha256_chain[i] =
                kernel::create(sha256);

            source(sha256_chain[i]) =
                "src/kernels/sha256.cc";

            runtime<ratio>(sha256_chain[i]) =
                1;
        }


        /*
         * ============================================================
         * Stream connections
         *
         * Input packet format:
         *
         *     data[8]
         *     pub_seed[8]
         *     addr[8]
         *
         * Every tile outputs exactly the same 24-word format.
         * ============================================================
         */


        /*
         * PLIO -> stage 0
         */
        connect<stream> net_in(
            in.out[0],
            sha256_chain[0].in[0]
        );

        // fifo_depth(net_in) = 32;


        /*
         * stage 0 -> stage 1 -> ... -> stage 14
         */
        for (int i = 0; i < 14; ++i)
        {
            connect<stream> net(
                sha256_chain[i].out[0],
                sha256_chain[i + 1].in[0]
            );

            // fifo_depth(net) = 32;
        }


        /*
         * stage 14 -> output PLIO
         */
        connect<stream> net_out(
            sha256_chain[14].out[0],
            out.in[0]
        );

        // fifo_depth(net_out) = 32;


        /*
         * ============================================================
         * Tile placement
         *
         * Put 15 stages horizontally:
         *
         * (0,0) -> (1,0) -> ... -> (14,0)
         *
         * ============================================================
         */

        for (int i = 0; i < 15; ++i)
        {
            adf::location<kernel>(
                sha256_chain[i]
            ) =
                adf::tile(i, 0);
        }
    }
};