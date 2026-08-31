#include <adf.h>

//#ifndef FUNCTION_KERNELS_H
//#define FUNCTION_KERNELS_H
#ifndef sha256_h
#define sha256_h


// 

void sha256(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output);

void thash_shake256_simple(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output);

// void slh_thash_simple(
//     input_stream<uint32_t> *__restrict input,
//     output_stream<uint32_t> *__restrict output);

void wots_prf_sha256(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output);

void wots_pk_sha512(
    input_stream<uint32_t> *__restrict input,
    output_pktstream *__restrict output);

void wots_dispatch(
    input_stream<uint32_t> *__restrict input,
    output_pktstream *__restrict output
);


//这个可以单个处理全部leaf并输出auth，但是用串行的kernel可以快一点
void merkle_collect(
    input_pktstream *__restrict leaf_input,
    input_stream<uint32_t> *__restrict metadata_input,
    output_stream<uint32_t> *__restrict output
);

void merkle_level1(
    input_pktstream *__restrict leaf_input,
    input_stream<uint32_t> *__restrict metadata_input,
    output_stream<uint32_t> *__restrict output
);


void merkle_level2(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output
);


void merkle_level3(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output
);


void merkle_level4(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output
);




//signature generation
void wots_sig_chain0(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain1(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain2(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain3(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain4(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain5(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain6(
    input_stream<uint32_t> *,
    output_pktstream *
);

void wots_sig_chain7(
    input_stream<uint32_t> *,
    output_pktstream *
);


void wots_sig_merge(
    input_pktstream *,
    output_stream<uint32_t> *
);
#endif