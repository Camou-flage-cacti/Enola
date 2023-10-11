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
   // if (TII.getIns)
    
    MIB = BuildMI(MBB, MI, DL,TII.get(ARM::tCMPi8)).addReg(ARM::R12).addImm(0).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);

    MachineInstr *MI3 = MIB;

    std::string instructionString2;
    llvm::raw_string_ostream OS2(instructionString2);
    MI3->print(OS2);
    outs()<<"constructed instruction in string cmp: "<<instructionString2<<"\n";

  //  MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PAC)).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG)).addReg(ARM::R1).addReg(ARM::R0).addReg(ARM::R2).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);

    outs() << "Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;

    // Convert the MachineInstr to a string representation.
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    outs()<<"constructed instruction in string : "<<instructionString<<"\n";

    /*
    
    MachineFunction &MF = ...; // Your MachineFunction

    // Get the MachineBasicBlock where you want to insert the inline assembly code.
    MachineBasicBlock &MBB = MF.front(); // You can choose a different basic block as needed.

    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

    // Create an InlineAsm object with your inline assembly code.
    const char *AssemblyCode = "your assembly code here";
    const char *ConstraintString = "constraint string here";
    unsigned NumOperands = 0; // The number of operands your assembly code expects.

    InlineAsm *IA = InlineAsm::get(InlineAsm::KindTy::AD_ATT, AssemblyCode, ConstraintString, NumOperands);

    // Create a MachineInstr with the inline assembly code.
    MachineInstrBuilder MIB = BuildMI(MBB, MBB.end(), DebugLoc(), TII->get(TargetOpcode));

    // Add the InlineAsm object as an operand.
    MIB.addExternalSymbol(IA);*/
    return true;
    

    }
bool ARMEnolaCFA::runOnMachineFunction(MachineFunction &MF) {
    
    bool modified = false;

    std::string MFName = MF.getName().str();

    if (MF.getSubtarget().getFeatureBits()[ARM::FeaturePACBTI])
    {
        outs() <<"PAC bit feature exists\n";
    }
    outs() << "Enola Instrumentation: "<<MFName<<"\n";
    const ARMBaseInstrInfo &TII = *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());
   // const TargetInstrInfo *x =  MF.getSubtarget().getInstrInfo();
  //  x->
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
