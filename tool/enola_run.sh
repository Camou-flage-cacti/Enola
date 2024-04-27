clang main.c -S -emit-llvm -o out.ll
llc -march=arm -mcpu=cortex-m85 out.ll -mattr=+pacbti -o outm_pass.s
