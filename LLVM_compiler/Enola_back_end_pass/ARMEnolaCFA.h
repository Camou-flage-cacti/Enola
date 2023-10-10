#ifndef LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H
#define LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H
#include "llvm/CodeGen/MachineFunctionPass.h"

#define ARM_M85_ARMEnolaCFA_NAME "ARM cortex-m85 CFA pass"

namespace llvm {
    class ARMEnolaCFA : public MachineFunctionPass {

        
       /* bool instrumentIndirectCall (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo *TII,
                           const char *sym);
        
        bool instrumentIndirectJump (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo *TII,
                           const char *sym); */

         bool instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym);
        
        /*bool instrumentRetLR (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo *TII,
                           const char *sym);*/
        public:
            static char ID;
            ARMEnolaCFA() : MachineFunctionPass(ID) {initializeARMEnolaCFAPass(*PassRegistry::getPassRegistry());}
    

            bool runOnMachineFunction(MachineFunction &MF) override;

            StringRef getPassName() const override {
                return ARM_M85_ARMEnolaCFA_NAME;
            }

    };
} // End llvm namespace

#endif