##Reserving a registers with LLVM
- markSuperRegs() function in llvm/CodeGen/TargetRegisterInfo.h file
- Mark a register and all its aliases as reserved in the given set.
- ARMBaseRegisterInfo.cpp this file in urai paper reserves LR register
- urai paper github link: https://github.com/embedded-sec/uRAI


##Applying a LLVM IR level instrumentation pass at function compilation 
 - clang main.c -S -emit-llvm -o out.ll
 - opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
 - clang out_opt.ll -o out2