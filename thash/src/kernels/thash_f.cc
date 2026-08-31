#include "../kernels.h"
#include <cstdint>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <adf.h>
#include <aie_api/aie.hpp>
#include "aie_api/aie_types.hpp"



//this function package uint_8 into uint32
inline uint32_t fill(unsigned char * __restrict input){
    uint32_t output=0;
    output = (*input<<24) | (*(input+1)<<16) | (*(input+2)<<8) | *(input+3);    
    return output;
}

//this function generate pubseed[0] to pubseed[7] in pipeline
inline uint32_t parafill(unsigned char * __restrict input, uint32_t *__restrict output){
      
        for(int i=0;i<8;i++)chess_prepare_for_pipelining{
            *(output+i)=fill(input+i*4);
        }
    return 0;
}
/*************************************************/

//
void thash_f(input_stream<uint32> * __restrict data, input_stream<uint32> * __restrict addr, 
                /*unsigned char (&Pubseed)[32],*/ output_stream<uint32>* __restrict dout1, output_stream<uint32>* __restrict dout2)
{
    
    uint32_t datain[8]; //256bit in
    uint32_t temp_addr[8]; // 256bit addr
    uint32_t temp_pub[8];
    const uint32_t prf[8] = {0,0,0,0,0,0,0,0x00000003};

    int run_num =0;
while(run_num <120){ // we suppose to run 2 times
    
    for(int i=0;i<8;i++){
        datain[i] = readincr(data); //din
        temp_addr[i] = readincr(addr) ;       
    }

    for(int i=0;i<8;i++){
        temp_pub[i] = readincr(data);          
    }
        
   

 
    for(int i=0;i<8;i++){
        writeincr(dout1, prf[i]); 
        writeincr(dout2, prf[i]);              
    }
    
    for(int i=0;i<8;i++){
        writeincr(dout1, temp_pub[i]);       
        writeincr(dout2, temp_pub[i]);
    }

    

    temp_addr[7]=0;

    for(int i=0;i<8;i++){
        writeincr(dout1, temp_addr[i]);       
    }
    temp_addr[7]=0x00000001;
    for(int i=0;i<8;i++){
        writeincr(dout2, temp_addr[i]);       
    }

    for(int i=0;i<8;i++){
        writeincr(dout2, datain[i]);       
    }

    run_num += 1;
   }
 
}