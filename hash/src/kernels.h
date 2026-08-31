#include <adf.h>

//#ifndef FUNCTION_KERNELS_H
//#define FUNCTION_KERNELS_H
#ifndef sha256_h
#define sha256_h

// len is the len of message, new_len should be pckaged message
void prf(input_stream<uint32> *bufin,  output_stream_uint32* bufout);
void prf_opt(input_stream<uint32> *bufin,  output_stream_uint32* bufout);
void prf_opt_96(input_stream<uint32> *bufin,  output_stream_uint32* bufout);



#endif
