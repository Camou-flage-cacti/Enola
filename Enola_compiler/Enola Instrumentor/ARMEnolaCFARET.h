#ifndef LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H
#define LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include <deque>
#include <vector>

#define ARM_M85_ARMEnolaCFARET_NAME "ARM cortex-m85 CFA RET pass"

namespace llvm {
    class ARMEnolaCFARET : public MachineFunctionPass {

       bool instrumentRet (MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF);
    
        bool instrumentRetFromStack (MachineBasicBlock &MBB,
                    MachineInstr &MI,
                    const DebugLoc &DL,
                    const ARMBaseInstrInfo &TII,
                    const char *sym,
                    MachineFunction &MF);


        std::string extractFunctionName(const MachineInstr &MI);

        public:
            static char ID;
            ARMEnolaCFARET() : MachineFunctionPass(ID) {initializeARMEnolaCFARETPass(*PassRegistry::getPassRegistry());}
    

            bool runOnMachineFunction(MachineFunction &MF) override;

            StringRef getPassName() const override {
                return ARM_M85_ARMEnolaCFARET_NAME;
            }

    };
} // End llvm namespace

#endif