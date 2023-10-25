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
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/Target/TargetMachine.h"

#include "ARMEnolaCFA.h"
#include <iostream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "arm-Enola-CFA"

char ARMEnolaCFA::ID = 0;

INITIALIZE_PASS(ARMEnolaCFA, DEBUG_TYPE, ARM_M85_ARMEnolaCFA_NAME, true, true)

bool ARMEnolaCFA::instrumentCond (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
    outs() << "Building PAC for condition branch:\n";
    MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R12).add(predOps(ARMCC::AL)).addReg(ARM::PC).addReg(ARM::R12)
    .setMIFlag(MachineInstr::NoFlags);
    outs() << "Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"constructed instruction in string : "<<instructionString<<"\n";


}

bool ARMEnolaCFA::instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
   // unsigned targetReg;


    outs () << "Inside instrumentation of return \n";

    MachineInstrBuilder MIB;
    outs() << "Building PAC:\n";
   // BMI = BuildMI(MBB, MI, DL, TII.get(ARM::t2ADDri)).addReg(ARM::R12).addReg(ARM::R0).addImm(8);
   // if (TII.getIns)
 
   // MIB = BuildMI(MBB, MI, DL,TII.get(ARM::tCMPi8)).addReg(ARM::R12).addImm(0).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);
   //MIB = BuildMI(MBB, MI, DL,TII.get(ARM::t2ADDri)).addReg(ARM::R0).addReg(ARM::R1).addImm(8).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);

  //  MachineInstr *MI3 = MIB;

  //  std::string instructionString2;
  //  llvm::raw_string_ostream OS2(instructionString2);
  //  MI3->print(OS2);
   // outs()<<"constructed instruction in string cmp: "<<instructionString2<<"\n";

  //  MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PAC)).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R12).add(predOps(ARMCC::AL)).addReg(ARM::LR).addReg(ARM::R12)
    .setMIFlag(MachineInstr::NoFlags);

    outs() << "Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;
    const TargetMachine& TM = MF.getTarget();
    const Triple &TT = TM.getTargetTriple();
    StringRef CPU = TM.getTargetCPU();
    StringRef FS = TM.getTargetFeatureString();
    std::string ArchFS = ARM_MC::ParseARMTriple(TT, CPU);

    const ARMBaseTargetMachine &ATM =
        static_cast<const ARMBaseTargetMachine &>(TM);
    const ARMSubtarget STI(TT, std::string(CPU), ArchFS, ATM,
                            ATM.isLittleEndian());

   // outs()<<ATM.getTargetFeatureString().str()<<"\n";
// Retrieve the MCSubtargetInfo from the TargetSubtargetInfo.
    //const MCSubtargetInfo *MCSTI = TM.getMCSubtargetInfo();
    // Enable a specific feature.
    //STI2.setFeatureBits(STI.getFeatureBits() | ARM::FeatureMyFeature);
   // MF.getSubtarget().getmc.setFeatureBits(ARM::FeaturePACBTI);
    outs() <<"Target CPU : "<<CPU.str()<<"\n";

   /* if (!STI.hasPACBTI()) {
        outs() <<"hAS pac BTI feature\n";
    }*/
    // Convert the MachineInstr to a string representation.
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"constructed instruction in string : "<<instructionString<<"\n";

//    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

    // Create an InlineAsm object with your inline assembly code.
    //const char *AssemblyCode = "PACG r12, r14, r12";
  //  const char *ConstraintString = "";
   // unsigned NumOperands = 3; // The number of operands your assembly code expects.

  //  std::vector<Type *> AsmArgTypes;
  //  std::vector<Value *> AsmArgs;

  //  llvm::LLVMContext C;
   // FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(C), AsmArgTypes, false);

   // InlineAsm *IA = InlineAsm::get(AsmFTy, AssemblyCode, ConstraintString, NumOperands);

   

    // Create a MachineInstr with the inline assembly code.
 //   MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG));

    // Add the InlineAsm object as an operand.
   // MIB.addExternalSymbol(AssemblyCode);

    /*
    

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
 
    for (auto &MBB : MF) {

 
        for(auto &MI:MBB){

            //Handle all condition instructions
            if(MI.isConditionalBranch())
            {
                outs() << " This is a compare instruction: " <<  MI.getOpcode() <<"\n";
                MachineBasicBlock::iterator itr;
                MachineBasicBlock *currentBB;
                MachineFunction *currentMF;

                //Instrument true branch
                if (MI.getOperand(0).isMBB())
                {
                    currentBB = MI.getOperand(0).getMBB();
                    itr = currentBB->begin();
                    MachineInstr &trueBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    instrumentCond(*currentBB, trueBB_Ins, trueBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
                if (MI.getOperand(1).isMBB())
                {
                    //Instrument false branch
                    currentBB = MI.getOperand(1).getMBB();
                    itr = currentBB->begin();
                    MachineInstr &falseBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    instrumentCond(*currentBB, falseBB_Ins, falseBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
                //when the second operand is not a basic block, thus the immediate next MBB should be the other poosible target of the conditional insturction
                else if ((currentBB = MBB.getNextNode()) != NULL)
                {
                    itr = currentBB->begin();
                    MachineInstr &falseBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    instrumentCond(*currentBB, falseBB_Ins, falseBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
               
            }
            //Handle return instructions
            if(MI.getDesc().isReturn())
            {
                outs() << " This is a return instruction: " <<  MI.getOpcode() <<"\n";
                modified = instrumentRet(MBB, MI, MI.getDebugLoc(), TII, "dummy", MF);
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
