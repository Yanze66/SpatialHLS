#include "../kernels.h"

#include <adf.h>
#include <cstdint>

using namespace adf;


/*
 * ================================================================
 * Small ordered WOTS-signature collector.
 *
 * Input:
 *
 * packet:
 *
 *     chain_idx
 *     sig[8]
 *
 *
 * Output:
 *
 *     sig[0]
 *     sig[1]
 *     ...
 *     sig[66]
 *
 * No indices in final output.
 * ================================================================
 */

void wots_sig_merge(
    input_pktstream *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    constexpr int WOTS_LEN =
        67;


    /*
     * IMPORTANT:
     *
     * 8 is the ideal round-synchronous minimum.
     *
     * Because chain lengths differ, use a little extra slack.
     *
     * 16 entries:
     *
     *     16 × 32B
     *     = 512 B
     *
     * still much smaller than buffering all 2144 B.
     */

    constexpr int SIG_WINDOW =
        16;


    alignas(32)
    uint32_t sig_buf[SIG_WINDOW][8];


    uint32_t tag[SIG_WINDOW];


    bool valid[SIG_WINDOW];


    for (int i = 0;
         i < SIG_WINDOW;
         ++i)
    {
        valid[i] =
            false;

        tag[i] =
            0xFFFFFFFFU;
    }


    uint32_t next =
        0;


    /*
     * Exactly 67 result packets.
     */

    for (int arrival = 0;
         arrival < WOTS_LEN;
         ++arrival)
    {
        /*
         * Packet header.
         */
        (void)readincr(
            input
        );


        bool tlast;


        /*
         * chain index.
         */
        uint32_t chain =
            (uint32_t)readincr(
                input,
                tlast
            );


        const uint32_t slot =
            chain %
            SIG_WINDOW;


        /*
         * Read signature element.
         */

        for (int i = 0;
             i < 8;
             ++i)
        {
            sig_buf[slot][i] =
                (uint32_t)readincr(
                    input,
                    tlast
                );
        }


        tag[slot] =
            chain;


        valid[slot] =
            true;


        /*
         * ========================================================
         * Immediately emit every now-contiguous signature.
         *
         * This is why we do NOT need a 67-entry buffer.
         * ========================================================
         */

        while (next < WOTS_LEN)
        {
            const uint32_t next_slot =
                next %
                SIG_WINDOW;


            if (
                !valid[next_slot] ||
                tag[next_slot] != next
            )
            {
                break;
            }


            for (int i = 0;
                 i < 8;
                 ++i)
            {
                writeincr(
                    output,
                    sig_buf[next_slot][i]
                );
            }


            valid[next_slot] =
                false;


            tag[next_slot] =
                0xFFFFFFFFU;


            next++;
        }
    }
}
