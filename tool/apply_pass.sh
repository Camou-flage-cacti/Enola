clang main.c -S -emit-llvm -o out.ll
opt -enable-new-pm=0 -load root_path_of_llvm/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
clang out_opt.ll -o out2
