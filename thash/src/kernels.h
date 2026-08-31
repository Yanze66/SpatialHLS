#include <adf.h>

//#ifndef FUNCTION_KERNELS_H
//#define FUNCTION_KERNELS_H
#ifndef sha256_h
#define sha256_h

// len is the len of message, new_len should be pckaged message
void thash_f_prf_1(input_stream<uint32> *bufin,  output_stream<uint32>* bufout);
void thash_f(input_stream<uint32> *  data, input_stream<uint32> * addr,  output_stream<uint32>*  dout1, output_stream<uint32>*  dout2);
void thash_f_prf_2(input_stream<uint32> * bufin, /*int len , */ output_stream<uint32>*  bufout);
void thash_f_prf_f(input_stream<uint32> *  prf_in, input_stream<uint32> * mask_in,  output_stream<uint32>*  dout, output_stream<uint32>*  addr_out);


// 3 tile
void sha256_prf_96(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict prf_out,
    output_stream<uint32_t> *__restrict forward_out);

void sha256_f_96(
    input_stream<uint32_t> *__restrict prf_in,
    input_stream<uint32_t> *__restrict mask_in,
    output_stream<uint32_t> *__restrict data_out
    );

void sha256_mask_96(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict mask_out);        


// 2 tile, pre-compress
void trash0(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output);

    void trash1(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict output);

// 3 tile， shake 版本
void shake_prf_96(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict prf_out,
    output_stream<uint32_t> *__restrict forward_out);

void shake_f_96(
    input_stream<uint32_t> *__restrict prf_in,
    input_stream<uint32_t> *__restrict mask_in,
    output_stream<uint32_t> *__restrict data_out
    );

void shake_mask_96(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict mask_out);        

void shake_prf_96_opt(
    input_stream<uint32_t> *__restrict input,
    output_stream<uint32_t> *__restrict prf_out,
    output_stream<uint32_t> *__restrict forward_out);

#endif