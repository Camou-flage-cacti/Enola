clang main.c -S -emit-llvm -o out.ll
opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
llc -march=arm -mcpu=cortex-m85 out_opt.ll -mattr=+pacbti -o outm_pass.s
