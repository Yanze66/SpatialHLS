#include "../kernels.h"
#include <cstdint>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <adf.h>
#include <aie_api/aie.hpp>
#include "aie_api/aie_types.hpp"


#define rightrotate(w,n) ((w>>n) | (w)<< (32-(n)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = __builtin_bswap32((val))//gcc __builtin_bswap32，
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = (val)
#else
#error "Unsupported target architecture endianess!"
#endif

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//shift data byte order
inline uint32_t swap32(uint32_t datain){
    uint32_t dataout = 0;
    dataout = ((datain&0x000000FF) <<24) + ((datain&0x0000FF00) <<8) + ((datain&0x00FF0000)>>8)+ ((datain&0xff000000)>>24) ;
    return dataout;
}

//this function package uint_8 into uint32
inline uint32_t fill(unsigned char * __restrict input){
    uint32_t output=0;
    output = (*input<<24) | (*(input+1)<<16) | (*(input+2)<<8) | *(input+3);    
    return output;
}

//this function generate w[0] to w[15] in pipeline
inline uint32_t parafill(unsigned char * __restrict input, uint32_t *__restrict output){
      
        for(int i=0;i<16;i++)chess_prepare_for_pipelining{
            *(output+i)=fill(input+i*4);
        }
    return 0;
}

/*****************these four function highly pipelined and reduce generation cycle of w[16] ... w[63] from 1500 to 1239****************************************************/
inline uint32_t gen_s0(uint32_t * __restrict input){     
        uint32_t s0= rightrotate(*(input+1), 7) ^ rightrotate(*(input+1), 18) ^ (*(input+1) >> 3);
    return s0;
}
inline uint32_t gen_s1(uint32_t * __restrict input){      
        uint32_t s1= rightrotate(*(input+14), 17) ^ rightrotate(*(input+14), 19) ^ (*(input+14) >> 10);
    return s1;
}

inline uint32_t gen_w(uint32_t * __restrict input){           
        uint32_t w= *input + *(input+9) + gen_s0(input) +gen_s1(input);      
    return w;
}

inline uint32_t gen_2w(uint32_t * __restrict input,uint32_t * __restrict output){
        
        
        *(output) = gen_w(input);  //this paragraph takes 1239 cycles.
        *(output+1) = gen_w(input+1);
        *(input+16) = *output;
        *(input+17) = *(output+1);

        //*(input+16) = gen_w(input);  //this paragraph takes 1489 cycles
        //*(input+17) = gen_w(input+1);

        //according to the ug-1079,it seems previous paragraph the because in this way, we operate data in two buffer
    return 0;
}
/******************************************************************************************************************/


//replace the glibc function memcpy() and memset(), which takes much time and may cause mistakes
inline void copy_u32_u8(unsigned char *__restrict buf, uint32_t data){
    *(buf)   = (data&0xff000000) >> 24;
    *(buf+1) = (data&0x00ff0000) >> 16;
    *(buf+2) = (data&0x0000ff00) >> 8;
    *(buf+3) = (data&0x000000ff) >> 0;
}

inline void copy_u8_u8(unsigned char *__restrict buf, const unsigned char *__restrict src, size_t len){
   
    for(int i=0;i<len;i++)chess_prepare_for_pipelining{
        *(buf +i)   = *(src +i);
    }
    
}

inline void zero(unsigned char *__restrict buf, size_t len){
   
    for(int i=0;i<len;i++)chess_prepare_for_pipelining{
        *(buf +i)   = 0;
    }
    
}

/******************************************************************************************************************/
inline void sha256(const unsigned char *__restrict data, size_t len, unsigned char *out) {
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;
    int r = (int)(len * 8  & 0x1ff); // devided by 512, change to bit operation
    int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;// origin + padding + 64-bit length
    unsigned char buf[new_len];
    
    //memset(buf + len,0,append); //zero
    zero(buf+len,append);
    if (len > 0) {
        copy_u8_u8(buf, data, len);
    }
    buf[len] = (unsigned char)0x80;
    uint64_t bits_len = len * 8;
    for (int i = 0; i < 8; i++) {
        buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    }
    uint32_t w[64];
    uint32_t temp_w[2];
    
    size_t chunk_len = new_len / 64; //512bit
    for (int idx = 0; idx < chunk_len; idx++) {
        parafill(buf+idx*64,w); 

        for (int i = 0; i < 48; i=i+2)chess_prepare_for_pipelining{ 
            gen_2w(w+i,temp_w);           
        }
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;
        for (int i = 0; i < 64; i++) {//
            uint32_t s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s_1 + ch + k[i] + w[i];
            uint32_t s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s_0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
                 
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
	
    copy_uint32(out, h0);
    copy_uint32(out + 1, h1);
    copy_uint32(out + 2, h2);
    copy_uint32(out + 3, h3);
    copy_uint32(out + 4, h4);
    copy_uint32(out + 5, h5);
    copy_uint32(out + 6, h6);
    copy_uint32(out + 7, h7);
	
    
}

/*************************************************/


/*************************************************/


void thash_f_prf_f(input_stream<uint32> * __restrict prf_in, input_stream<uint32> * __restrict mask_in,  output_stream<uint32>* __restrict dout, 
output_stream<uint32>* __restrict addr_out)
{
    int run_num =0;

    while(run_num < 120){
    
    int len=96;
    unsigned char out[32];
    unsigned char buf[len];
    
    uint32_t temp[16]; 
    
    for(int j=0;j<16;j++)
    
        chess_prepare_for_pipelining
        chess_loop_range(2, )
        {  
        
           temp[j]=readincr(prf_in);  // dout and addr

           
    }
    
    uint32_t temp_mask[8];
    for(int i=0;i<8;i++){
        temp_mask[i]=readincr(mask_in); 
    }
    uint32_t pub_seed[8];
    for(int i=0;i<8;i++){
        pub_seed[i]=readincr(mask_in); 
    }


   
    zero(buf,32);  //padding_f

    for(int i=0;i<8;i++){
        copy_u32_u8(buf+32+i*4,temp[i]); //prf
    }
    
    for(int i=0;i<8;i++){
        copy_u32_u8(buf+64+i*4,temp_mask[i]); //prf ^datain
    }
   

    sha256(buf,len,out); 

    for(int i=0;i<8;i++){
        writeincr(dout, fill(out+i*4)); //output data
    }

    //output pubseed
    for(int i=0;i<8;i++){
        writeincr(dout, pub_seed[i]);
    }

    //  
    //printf("\naddtr[6]=\n");   
    temp[14]=temp[14] +1;
    
    //output addr
    for(int i=8;i<16;i++){
        writeincr(addr_out, temp[i]);
    }
 
    
    
    run_num += 1;
 }

}