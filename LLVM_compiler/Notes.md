##Reserving a registers with LLVM
- markSuperRegs() function in llvm/CodeGen/TargetRegisterInfo.h file
- Mark a register and all its aliases as reserved in the given set.
- ARMBaseRegisterInfo.cpp this file in urai paper reserves LR register
- urai paper github link: https://github.com/embedded-sec/uRAI