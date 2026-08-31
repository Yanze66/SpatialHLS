#include <adf.h>
#include "kernels.h"

using namespace adf;

class simpleGraph : public adf::graph {
private:
  kernel first,second,third;     
  //parameter lut0;

public:
  input_plio in;
  output_plio out0;
  output_plio out1;
    output_plio out2;

//   output_gmio out;
  simpleGraph()
  {
    in = input_plio::create("DataIn1",plio_32_bits, "data/input_1.txt");
    //in1 = input_plio::create(plio_32_bits, "data/input_1.txt");

    out0 = output_plio::create("DataOut0",plio_32_bits, "data/output_0.txt");
    out1 = output_plio::create("DataOut1",plio_32_bits, "data/output_1.txt");
    out2 = output_plio::create("DataOut2",plio_32_bits, "data/output_2.txt");


    //out1 = output_plio::create(plio_32_bits, "data/output_2.txt");
    
    first = kernel::create(prf);
    second = kernel::create(prf_opt);
        third = kernel::create(prf_opt_96);


    connect<stream> net0 (in.out[0], first.in[0]);  //net connections for stream-stream 
    connect<stream> net1 (in.out[0], second.in[0]);
    connect<stream> net2 (first.out[0], out0.in[0]); //to plio
    connect<stream> net3 (second.out[0], out1.in[0]); //to plio
    connect<stream> net4 (in.out[0], third.in[0]); //to plio

    connect<stream> net5 (third.out[0], out2.in[0]); //to plio


    fifo_depth(net0) = 15000;
    fifo_depth(net1) = 1024;
    fifo_depth(net2) = 1024;
    fifo_depth(net3) = 1024;
    fifo_depth(net4) = 1024;
    fifo_depth(net5) = 1024;
    //connect<parameter> (vectorInput, first.in[2]);    //connection for RTP_array
    //connect<parameter> (sync(first.inout[0]), vectorOutput);
    
    // connect<parameter> (mlen, first.in[1]);
    //connect<parameter> (new_len, first.in[2]);
    
    
    source(first) = "src/kernels/sha256.cc";
    source(second) = "src/kernels/sha256_opt.cc";
        source(third) = "src/kernels/sha256_opt_96.cc";

    //runtime<ratio>(first) = 0.1; //takes 4605 cycles
    runtime<ratio>(first) = 1;
    runtime<ratio>(second) = 1;
    runtime<ratio>(third) = 1;

     adf::location<kernel>(first)=adf::tile(26,0);
          adf::location<kernel>(second)=adf::tile(27,0);

     adf::location<kernel>(third)=adf::tile(28,0);

     
    }
};
