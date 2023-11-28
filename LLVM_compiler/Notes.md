## Reserving a registers with LLVM
- markSuperRegs() function in llvm/CodeGen/TargetRegisterInfo.h file
- Mark a register and all its aliases as reserved in the given set.
- ARMBaseRegisterInfo.cpp this file in urai paper reserves LR register
- urai paper github link: https://github.com/embedded-sec/uRAI


## Applying a LLVM IR level instrumentation pass at function compilation 
 - clang main.c -S -emit-llvm -o out.ll
 - opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
 - clang out_opt.ll -o out2



## Outputting cortex-m85 assembly to check instrumentation. (Front end instrumentation)
 - This is a temporary solution to check the instrumentation for cortex-m85. It generates assembly file using llc compiler. (1) The first step is to use clang to get LLVM IR, (2) using the opt tool to apply the custom pass, (3) Use llc to generate assembly for cortex-m85 CPU
 - clang main.c -S -emit-llvm -o out.ll
 - opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
 - llc -march=arm -mcpu=cortex-m85 out_opt.ll -o outm_pass.s

## Back-end instrumentation to generate target specific code:
- The front end pass previously developped can be run with **opt** tool, but its not platform specific. We can use this to instrument function calls
- To instrument raw instruction we need to implement or modify the LLVM back-end for a specific target function
- Registers will be reservered with the LLVM back-end as well.
- **llc** static compiler will be used to run the passs after development
- https://chat.openai.com/share/34ef3a27-679e-425a-9548-546e6b97aaf8
- need to update cmake file as well for target specific back-end
- helpful link for backend pass development: https://www.kharghoshal.xyz/blog/writing-machinefunctionpass
- We can add our funtion createARMEnolaCFAPass on ARMTargetMachine.cpp, and the postion of addPass() denotes at what stage our MachineFunctionPass will be executed