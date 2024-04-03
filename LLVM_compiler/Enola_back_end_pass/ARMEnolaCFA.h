#ifndef LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H
#define LLVM_LIB_TARGET_ARM_M85_ARMEnolaCFA_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include <deque>
#include <vector>

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
        Register getParameterOfindrect(MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF);
        bool instrumentIndirectParameterSetInst(MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF, Register &indirectReg);

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
        
        bool checkIfPcIsOperand(const MachineInstr &MI);

        bool instrumentCond (MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF);
    
        bool instrumentCondWithReportDirect (MachineBasicBlock &MBB,
                    MachineInstr &MI,
                    const DebugLoc &DL,
                    const ARMBaseInstrInfo &TII,
                    const char *sym,
                    MachineFunction &MF);

        std::string extractFunctionName(const MachineInstr &MI);



        bool instrumentIndirectParameter (MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF, Register indirectTarget);

        bool instrumentTrampolineParameter (MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF);
        
        bool instrumentBlxBased(MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF);
        
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