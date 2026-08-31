#include <adf.h>
#include "adf/new_frontend/adf.h"
#include "kernels.h"

// using namespace adf;

// class simpleGraph : public adf::graph {
// private:
//   kernel thash_f1;  
//   kernel sha2561;
//   kernel sha256_mask1;
//   kernel sha256_f1;
    

// public:
//    input_plio datain; 
//   input_plio addrin;
//   output_plio dataout;
//   output_plio addrout;

//   output_plio test1;
//   output_plio test2;
//   // output_plio out0;

    
//   simpleGraph()
//   {
   
//     thash_f1 = kernel::create(thash_f);
//     sha2561 = kernel::create(thash_f_prf_1);
//     sha256_mask1 = kernel::create(thash_f_prf_2);
//     sha256_f1 = kernel::create(thash_f_prf_f);

//     datain = input_plio::create("DataIn1",plio_32_bits, "data/input_1.txt");
//     addrin = input_plio::create("DataIn2",plio_32_bits, "data/input_2.txt");

//     dataout = output_plio::create("DataOut1",plio_32_bits, "data/output_1.txt");
//     addrout = output_plio::create("DataOut2",plio_32_bits, "data/output_2.txt");

   
    
//     test1 = output_plio::create(plio_32_bits, "data/output_test1.txt"); //output to PLIO as a comparison
//       test2 = output_plio::create(plio_32_bits, "data/output_test2.txt"); //output to PLIO as a comparison

    
    

//     connect<stream> net0 (datain.out[0], thash_f1.in[0]);  //net connections for stream-stream 
//     connect<stream> net1 (addrin.out[0], thash_f1.in[1]);
//     connect<stream> net2 (thash_f1.out[0], sha2561.in[0]);
//     connect<stream> net3 (thash_f1.out[1], sha256_mask1.in[0]);   
//     connect<stream> net4 (sha2561.out[0], sha256_f1.in[0]);
//     connect<stream> net5 (sha256_mask1.out[0], sha256_f1.in[1]);

//     connect<stream> net6 (sha256_f1.out[0], dataout.in[0]);
//     connect<stream> net7 (sha256_f1.out[1], addrout.in[0]);

//     connect<stream> net8 (sha2561.out[0], test1.in[0]);
//     connect<stream> net9 (sha256_mask1.out[0], test2.in[0]);

//     fifo_depth(net0) = 32;
//     fifo_depth(net1) = 32;
//     fifo_depth(net2) = 32;
//     fifo_depth(net3) = 32;
//     fifo_depth(net4) = 32;
//     fifo_depth(net5) = 32;
//     fifo_depth(net6) = 32;
//     fifo_depth(net7) = 32;
//     fifo_depth(net8) = 32;
//     fifo_depth(net9) = 32;

    
    
//     source(thash_f1) = "src/kernels/thash_f.cc";
//     source(sha2561) = "src/kernels/sha256.cc";
//     // source(sha2562) = "src/kernels/sha256.cc";
//     source(sha256_mask1) = "src/kernels/sha256_mask.cc";
//     source(sha256_f1) = "src/kernels/sha256_f.cc";

//     runtime<ratio>(thash_f1) = 0.1;
//     runtime<ratio>(sha2561) = 0.1;
//     // runtime<ratio>(sha2562) = 0.1;
//     runtime<ratio>(sha256_mask1) = 0.1;
//     runtime<ratio>(sha256_f1) = 0.1;

//     adf::location<kernel>(thash_f1)=adf::tile(26,0); 
//     adf::location<kernel>(sha2561)=adf::tile(26,1);
//     // adf::location<kernel>(sha2562)=adf::tile(26,2); 
//     adf::location<kernel>(sha256_mask1)=adf::tile(27,1); 
//     adf::location<kernel>(sha256_f1)=adf::tile(27,0);   
//     }
// };


// //2 tile 版本 和 3tile版本

using namespace adf;

class simpleGraph : public adf::graph {
private:
  kernel shake_prf;  //3tile // 和sha256可以切换
  kernel shake_f;
  kernel shake_mask;
    
  kernel thash_0; //2tile，预计算
  kernel thash_1;

  
public:
  // input_gmio datain;
  // input_gmio addrin;
  // output_gmio dataout;
  // output_gmio addrout;

  // output_plio out0;
    input_plio in;
    output_plio out;
        output_plio out1;

  simpleGraph()
  {
   
    shake_prf  = kernel::create(shake_prf_96);
    shake_f    = kernel::create(shake_f_96);
    shake_mask = kernel::create(shake_mask_96);

    thash_0 = kernel::create(trash0);
    thash_1 = kernel::create(trash1);

    in = input_plio::create("DataIn1",plio_32_bits, "data/input_1.txt");

    out = output_plio::create("DataOut1",plio_32_bits, "data/output_1.txt");
    out1 = output_plio::create("DataOut2",plio_32_bits, "data/output_test.txt");
    
    // out0 = output_plio::create(plio_32_bits, "data/output_1.txt"); //output to PLIO as a comparison
  
    connect<stream> net0 (in.out[0], shake_prf.in[0]);
    connect<stream> net1 (shake_prf.out[1], shake_mask.in[0]);
    connect<stream> net2 (shake_prf.out[0], shake_f.in[0]);
    connect<stream> net3 (shake_mask.out[0], shake_f.in[1]);
    connect<stream> net4 (shake_f.out[0], out.in[0]);

        connect<stream> net5 (in.out[0], thash_0.in[0]);
     connect<stream> net6 (thash_0.out[0], thash_1.in[0]);
    connect<stream> net7 (thash_1.out[0], out1.in[0]);
    

    // fifo_depth(net0) = 32;
    // fifo_depth(net1) = 32;
    // fifo_depth(net2) = 32;
    // fifo_depth(net3) = 32;
    // fifo_depth(net4) = 32;
    // fifo_depth(net5) = 32;
    // fifo_depth(net6) = 32;
    // fifo_depth(net7) = 32;

    source(shake_prf) = "src/kernels/shake_prf_96.cc";
    source(shake_f) = "src/kernels/shake_f_96.cc";
    source(shake_mask) = "src/kernels/shake_mask_96.cc";

    source(thash_0) = "src/kernels/trash0.cc";
    source(thash_1) = "src/kernels/trash1.cc";
    
    

    runtime<ratio>(shake_prf) = 1;
    runtime<ratio>(shake_f) = 1;
    runtime<ratio>(shake_mask) = 1;
    
    runtime<ratio>(thash_0) = 1;
    runtime<ratio>(thash_1) = 1;

    adf::location<kernel>(shake_prf)=adf::tile(26,0); 
    adf::location<kernel>(shake_mask)=adf::tile(26,1);
    adf::location<kernel>(shake_f)=adf::tile(27,0); 

    adf::location<kernel>(thash_0)=adf::tile(28,0); 
    adf::location<kernel>(thash_1)=adf::tile(29,0); 
  
    }
};