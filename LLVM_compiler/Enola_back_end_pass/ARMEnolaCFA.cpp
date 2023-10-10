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
#include "llvm/CodeGen/AsmPrinter.h"

#include "ARMEnolaCFA.h"
#include <iostream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "arm-Enola-CFA"

char ARMEnolaCFA::ID = 0;

INITIALIZE_PASS(ARMEnolaCFA, DEBUG_TYPE, ARM_M85_ARMEnolaCFA_NAME, true, true)


bool ARMEnolaCFA::instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym) {
   // unsigned targetReg;


    outs () << "Inside instrumentation of return \n";

    // get target register xR
   // targetReg = MI.getOperand(0).getReg();

    //MachineInstr *BMI;
    MachineInstrBuilder MIB;
    outs() << "Building PAC:\n";
   // BMI = BuildMI(MBB, MI, DL, TII.get(ARM::t2ADDri)).addReg(ARM::R12).addReg(ARM::R0).addImm(8);

    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG)).addReg(ARM::R12).addReg(ARM::PC).addReg(ARM::R12);

    outs() << "Consructed instructions: " << MIB <<"\n";

    return true;
    

    }
bool ARMEnolaCFA::runOnMachineFunction(MachineFunction &MF) {
    
    bool modified = false;

    std::string MFName = MF.getName().str();
    outs() << "Enola Instrumentation: "<<MFName<<"\n";
    const ARMBaseInstrInfo &TII = *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());

    for (auto &MBB : MF) {

        //outs() << "Contents of MachineBasicBlock:\n";
        //outs() << MBB << "\n";
        //const BasicBlock *BB = MBB.getBasicBlock();
        //outs() << "Contents of BasicBlock corresponding to MachineBasicBlock:\n";
        //outs() << BB << "\n";
        

        for(auto &MI:MBB){

            if(MI.getDesc().isCompare())
            {
                outs() << " This is a compare instruction: " <<  MI.getOpcode() <<"\n";
            }
            if(MI.getDesc().isReturn())
            {
                outs() << " This is a return instruction: " <<  MI.getOpcode() <<"\n";
                modified = instrumentRet(MBB, MI, MI.getDebugLoc(), TII, "dummy");
            }
            outs() << "The instruction belongs to: " << MI.getMF()->getName() << " Op-code " << MI.getOpcode() << " operand " << MI.getNumOperands() << "\n";

        }
    }

    return modified;

    /*for (MachineFunction::iterator FI = MF.begin(); FI != MF.end(); ++FI) {
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
    }*/

}

FunctionPass *llvm::createARMEnolaCFAPass() {
  return new ARMEnolaCFA();
}
