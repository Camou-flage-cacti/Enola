##Reserving a registers with LLVM
- markSuperRegs() function in llvm/CodeGen/TargetRegisterInfo.h file
- Mark a register and all its aliases as reserved in the given set.
- ARMBaseRegisterInfo.cpp this file in urai paper reserves LR register
- urai paper github link: https://github.com/embedded-sec/uRAI


##Applying a LLVM IR level instrumentation pass at function compilation 
 - clang main.c -S -emit-llvm -o out.ll
 - opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
 - clang out_opt.ll -o out2



##Outputting cortex-m85 assembly to check instrumentation. 
 - This is a temporary solution to check the instrumentation for cortex-m85. It generates assembly file using llc compiler. (1) The first step is to use clang to get LLVM IR, (2) using the opt tool to apply the custom pass, (3) Use llc to generate assembly for cortex-m85 CPU
 - clang main.c -S -emit-llvm -o out.ll
 - opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
 - llc -march=arm -mcpu=cortex-m85 out_opt.ll -o outm_pass.s
