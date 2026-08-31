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
    output_stream<uint32_t> *__restrict output
);

#endif