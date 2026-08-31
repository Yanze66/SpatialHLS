// #include "project.h"
// #include <fstream>
// #include <cstdlib>
// #include <string.h>

// simpleGraph mygraph;



// #define run_num 1
// #if defined(__AIESIM__) || defined(__X86SIM__)
// int main(int argc, char **argv) 
// {
//     volatile int mlen = 32; 
//     unsigned char pubseed[32]={0x80,0xdc,0x3f,0x07,0x04,0x56,0xd8,0xd4,0x56,0x1e,0x29,0x76,0xce,
//                                 0x01,0x2b,0x98,0x7d,0xaa,0x47,0x70,0xbe,0xe8,0x35,0xca,0xca,0x9e,0xe8,0x52,0xa1,0xce,0x72,0xd5};
//     //volatile int new_len = package_msg(mlen);
    
//     unsigned char input[32]={0x20,0x72,0xa1,0xa2,0x66,0xf2,0x36,0xc9,0x3b,0x46,0xdf,0xa9,0xce,0x86,0x8e,0x79,0x29,0x81,0xd0,0xd0,0xa0,0x47,0x81,0x74,0x46,0xcb,0x7c,0x58,0x69,0x8f,0xd2,0x33};
//     unsigned char inaddr[32]={0x29,0x50,0xe1,0x76,0xaa,0x10,0x61,0x2a,0x15,0x9c,0xc3,0x9e,0xc1,0x5c,0xfd,0x55,0xdb,0x95,0x91,0xc8,0xf7,0x10,0xcf,0x2c,0x00,0x00,0x00,0x00,0xce,0xcf,0x83,0x6b};
    
//     unsigned char buff[32];  



//     uint8_t  *inputbuf_data  = (uint8_t*) GMIO::malloc(2*mlen*sizeof(uint8_t)); 
//     uint8_t *outputbuf_data = (uint8_t*) GMIO::malloc(32*sizeof(uint8_t));

//     uint8_t  *inputbuf_addr  = (uint8_t*) GMIO::malloc(mlen*sizeof(uint8_t)); 
//     uint8_t *outputbuf_addr = (uint8_t*) GMIO::malloc(32*sizeof(uint8_t));
    
//   printf("\nThe input data :");
//     	for(int i=0;i<mlen;i++)
// 	{
//         inputbuf_data[i]=input[i];
// 		printf("%x",inputbuf_data[i]);	
// 	}

//     printf("\nThe input pubseed  :");
//     	for(int i=0;i<32;i++)
// 	{
//         inputbuf_data[i+32]=pubseed[i];
// 		printf("%x",inputbuf_data[i+32]);	
// 	}

// printf("\nThe input addr :");
//     	for(int i=0;i<24;i++)
// 	{
//         inputbuf_addr[i]=inaddr[i];
//         printf("%x",inputbuf_addr[i]);
			
// 	}
//     for(int i=24;i<32;i++)
// 	{
//         inputbuf_addr[i]=0;
// 		printf("%x",inputbuf_addr[i]);	
// 	}
    

//     mygraph.init();
    
    
//     mygraph.run(run_num);
//     for(int i=0;i<run_num;i++){
//         mygraph.datain.gm2aie_nb(&inputbuf_data[0],2*mlen*sizeof(uint8_t));
//         mygraph.addrin.gm2aie_nb(&inputbuf_addr[0],mlen*sizeof(uint8_t));
//         mygraph.addrin.wait();

//         //mygraph.update(mygraph.pubseed, pubseed,32);
        
//         mygraph.dataout.aie2gm_nb(&outputbuf_data[0],32*sizeof(uint8_t));
//         mygraph.dataout.wait(); //important !! wait for data move to DDR
//         mygraph.addrout.aie2gm_nb(&outputbuf_addr[0],32*sizeof(uint8_t));
//         mygraph.addrout.wait(); 
//     }
    
//     mygraph.end();
//     printf("\n");
//     printf("\nOutput data :");
//     	for(int i=0;i<32;i++)
// 	{
 
// 		printf("%02x",outputbuf_data[i]);	
// 	}
  

//     printf("\nUpdated addr :");
//     	for(int i=0;i<32;i++)
// 	{
 
// 		printf("%02x",outputbuf_addr[i]);	
// 	}
//     printf("\n");

//     GMIO::free(inputbuf_data);
//     GMIO::free(outputbuf_data);
//     GMIO::free(inputbuf_addr);
//     GMIO::free(outputbuf_addr);    
//   return 0;
// } 
// #endif



//不需要gmio，用plio就好

#include "project.h"
#include <fstream>
#include <cstdlib>
#include <string.h>

simpleGraph mygraph;



#define run_num 1
#if defined(__AIESIM__) || defined(__X86SIM__)
int main(int argc, char **argv) 
{

    

    mygraph.init();
    
    
    mygraph.run(2);
    mygraph.wait();
    mygraph.end();
 
  return 0;
} 
#endif
