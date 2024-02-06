
compiler_flags ="-std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -O0 -Wno-keyword-macro"

/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/clang $(compiler_flags) application.c -S -emit-llvm -o application.ll
/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/opt $(compiler_flags) -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so -EnolaPass application.ll -S -o application_opt.ll
/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/llc $(compiler_flags) -filetype=obj application_opt.ll -o application_opt.o