if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <your_argument>"
    exit 1
fi

cFile="$1"

/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/clang $cFile -S -emit-llvm -o out.ll
/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/llc -march=arm -mcpu=cortex-m85 -O0 out_opt.ll -mattr=+pacbti -o outm_passARM.s
