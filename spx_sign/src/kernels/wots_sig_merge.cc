#include "../kernels.h"

#include <adf.h>
#include <cstdint>


using namespace adf;


/*
 * ================================================================
 * Reliable ordered WOTS signature collector.
 *
 *
 * Input:
 *
 *     67 packets in ANY order.
 *
 * Each packet:
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
 *
 * Output size:
 *
 *     67 × 8 words
 *
 *     = 536 words
 *
 *     = 2144 bytes
 *
 *
 * IMPORTANT:
 *
 * This version intentionally buffers all 67 signature elements.
 *
 * Reason:
 *
 * Without a feedback/barrier connection between the merge tile
 * and eight WOTS workers, there is no guaranteed bound on the
 * out-of-order distance between workers.
 *
 * Therefore this is the simplest reliable implementation while
 * keeping the graph unchanged.
 * ================================================================
 */


void wots_sig_merge(
    input_pktstream *__restrict input,
    output_stream<uint32_t> *__restrict output)
{
    constexpr int WOTS_LEN =
        67;


    constexpr int WORDS_PER_SIG =
        8;


    /*
     * ============================================================
     * Full WOTS signature storage.
     *
     * 67 × 8 × 4
     *
     * = 2144 bytes.
     *
     * ============================================================
     */

    alignas(32)
    uint32_t sig_buf[
        WOTS_LEN
    ][
        WORDS_PER_SIG
    ];


    /*
     * Debug / safety bookkeeping.
     *
     * Only 67 bytes logically, though compiler may align it.
     */

    bool received[
        WOTS_LEN
    ];


    /*
     * Initialize receive flags.
     */

    for (int i = 0;
         i < WOTS_LEN;
         ++i)
    {
        received[i] =
            false;
    }


    /*
     * ============================================================
     * Receive exactly 67 packets from pktmerge<8>.
     *
     * Arrival order does NOT matter.
     * ============================================================
     */

    for (int arrival = 0;
         arrival < WOTS_LEN;
         ++arrival)
    {
        /*
         * --------------------------------------------------------
         * Packet header.
         * --------------------------------------------------------
         */

        (void)readincr(
            input
        );


        bool tlast;


        /*
         * --------------------------------------------------------
         * Chain index.
         * --------------------------------------------------------
         */

        const uint32_t chain =
            (uint32_t)readincr(
                input,
                tlast
            );


        /*
         * --------------------------------------------------------
         * Read signature element.
         *
         * Even in the unlikely case chain is corrupt, consume the
         * complete packet so that stream framing remains correct.
         * --------------------------------------------------------
         */

        uint32_t temp[
            WORDS_PER_SIG
        ];


        for (int i = 0;
             i < WORDS_PER_SIG;
             ++i)
        {
            temp[i] =
                (uint32_t)readincr(
                    input,
                    tlast
                );
        }


        /*
         * --------------------------------------------------------
         * Store only legal WOTS chain indices.
         * --------------------------------------------------------
         */

        if (chain < WOTS_LEN)
        {
            for (int i = 0;
                 i < WORDS_PER_SIG;
                 ++i)
            {
                sig_buf[chain][i] =
                    temp[i];
            }


            received[chain] =
                true;
        }
    }


    /*
     * ============================================================
     * At this point all eight workers have finished.
     *
     * Output STRICTLY:
     *
     *     0
     *     1
     *     ...
     *     66
     *
     * ============================================================
     */

    for (int chain = 0;
         chain < WOTS_LEN;
         ++chain)
    {
        /*
         * In a correct execution:
         *
         *     received[chain] == true
         *
         * Since the workers generate every chain exactly once,
         * no special recovery should be needed.
         */

        if (received[chain])
        {
            for (int i = 0;
                 i < WORDS_PER_SIG;
                 ++i)
            {
                writeincr(
                    output,
                    sig_buf[chain][i]
                );
            }
        }
        else
        {
            /*
             * This should NEVER happen.
             *
             * Writing zeros keeps output length fixed at exactly
             * 536 words, which also makes a missing worker packet
             * immediately obvious in output2.txt.
             */

            for (int i = 0;
                 i < WORDS_PER_SIG;
                 ++i)
            {
                writeincr(
                    output,
                    0U
                );
            }
        }
    }
}