if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <your_argument>"
    exit 1
fi

cFile="$1"

clang $cFile -S -emit-llvm -o out.ll
opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-project/build/lib/LLVMEnolaPass.so -EnolaPass out.ll -S -o out_opt.ll > /dev/null
llc -march=arm -mcpu=cortex-m85 -O0 out_opt.ll -mattr=+pacbti -o outm_pass.s
