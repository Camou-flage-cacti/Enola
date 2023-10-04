#include "ARM.h"
#include "ARMInstrInfo.h"
#include "ARMSubtarget.h"
#include "ARMTargetMachine.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include "ARMEnolaCFA.h"
#include <iostream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "arm-Enola-CFA"

char ARMEnolaCFA::ID = 0;

INITIALIZE_PASS(ARMEnolaCFA, DEBUG_TYPE, ARM_M85_ARMEnolaCFA_NAME, false, false)


bool ARMEnolaCFA::instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const TargetInstrInfo *TII,
                           const char *sym) {
    unsigned targetReg;


    printf("Inside instrumentation of return ");

    // get target register xR
    targetReg = MI.getOperand(0).getReg();
    

    }
bool ARMEnolaCFA::runOnMachineFunction(MachineFunction &MF) {

    for (MachineFunction::iterator FI = MF.begin(); FI != MF.end(); ++FI) {
        MachineBasicBlock& MBB = *FI;

        for (MachineBasicBlock::iterator I = MBB.begin(); I!=MBB.end(); ++I) {
            MachineInstr &MI = *I;
            if(MI.isReturn())
            {
                //DEBUG(dbgs() << __func__ << "\n");

                printf("Encountered a return instruction %d", MI.getOpcode());
            }
            else 
            {

                printf("Encountered other instruction %d", MI.getOpcode());
            }
        }
    }

}