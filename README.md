# SpatialSLH

This is the bottom-up implementation of SpatialSLH project.

## ref_src 

This folder contains .exe file (on linux) for different stages running spx. It profiles the runtime, signature size and computing cycles reported in the manuscript. It also  prints golden number of the spx for testing the correctness of SpatialSLH.

## hash
This folder contains basic sha256 implementations and its optimization.

## thash
This folder contains sha256 and shake implementations and their optimization. We tried different number of test case to see how it performs when computing over multiple PEs, or compress multiple times on one PE, to therefore find the optimal solutions to implement the hash kernel. We try to implement both SHA256 and SHAKE on one PE, but find the 16KB programmable memory can not loads both kernels. Therefore we can only implement one of them everytime. But good thing is that, I write the way that they are interchangeable on the graph side.

## chains, wots, merkle, spx

Higher level implementation of spx...

You can find the graph and connection of these accelerators, and simulate to check the correctness. The output should be same with the golden results in src-ref. I will suggest to use x86 simulate to verify the implementation; otherwise it takes really long time (and memory space) to complete the whole project using HW simulation. 