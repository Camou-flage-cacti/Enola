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
#include "llvm/CodeGen/RegisterScavenging.h"

#include "ARMEnolaCFA.h"
#include <iostream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "arm-Enola-CFA"

char ARMEnolaCFA::ID = 0;



INITIALIZE_PASS(ARMEnolaCFA, DEBUG_TYPE, ARM_M85_ARMEnolaCFA_NAME, true, true)


bool ARMEnolaCFA::checkIfPcIsOperand(const MachineInstr &MI)
{
    for(int i = 0; i < MI.getNumOperands(); i++)
    {
        MachineOperand MO = MI.getOperand(i);
        if(MO.isReg() && MO.getReg() == ARM::PC)
            return true;
    }
    return false;
}

std::string ARMEnolaCFA::extractFunctionName(const MachineInstr &MI) {
    std::string functionName = "";
    for(int i = 0; i < MI.getNumOperands(); i++)
    {
          const MachineOperand &MO = MI.getOperand(i); // Assuming the function name is in operand 0.
        //Function names are global or external
        if (MO.isGlobal()) {

            functionName = MO.getGlobal()->getName().str();
        }
    }
    outs() << "EnolaDebug-backEnd: No global symbol\n";
    return functionName;
  }
 /*Testing function: need to be removed later*/
bool ARMEnolaCFA::instrumentCond (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
    
    outs() << "EnolaDebug-backEnd: Building PAC for condition branch:\n";
    /*no need to instrument if already instrumented*/
    if(MI.getOpcode() == ARM::tMOVr && checkIfPcIsOperand(MI))
        return false;
    
    // std::vector<MachineInstr *> NewMIs;
    // MachineFunction & MF2 = *MI.getMF();

    // NewMIs.push_back(BuildMI(MF2, MI, DL, TII.get(ARM::tLDRpci)).addReg(ARM::R0).addImm(0).addImm(0).setMIFlag(MachineInstr::NoFlags));

    // NewMIs.push_back(BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R10).add(predOps(ARMCC::AL)).addReg(ARM::LR).addReg(ARM::R10)
    // .setMIFlag(MachineInstr::NoFlags));

    // insertInstsBefore(MI, NewMIs);

    /*LOAD r0, [pc, #0x0] - loads the value at the local : worng*/
    // MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tLDRpci), ARM::R0).addImm(0).addImm(0).setMIFlag(MachineInstr::NoFlags);

    /*PUSH {PC} - does not work covert the instruction to PUSH {} : worng*/
    //MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tPUSH)).add(predOps(ARMCC::AL)).addReg(ARM::PC).setMIFlag(MachineInstr::NoFlags);

    /*POP {r0} - works but as push does not work no value : worng*/
    //MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tPOP)).add(predOps(ARMCC::AL)).addReg(ARM::R0).setMIFlag(MachineInstr::NoFlags);


    /*Find a free register*/
    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
    RegScavenger RS;
    RS.enterBasicBlock(MBB);

    unsigned freeRegister = ARM::R0;

    for (;freeRegister < TRI->getNumRegs();freeRegister++) {
        if(freeRegister>= ARM::R0 && freeRegister <= ARM::R9 && RS.isRegUsed(freeRegister, false))
        {
            outs() << "EnolaDebug-backEnd: Found FREE register "<<freeRegister<<"\n";
            break;
        }
    }

    /*mov r0,pc: we need to use thumb instruction set for this one t2 and arm instruction does not work */
    MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tMOVr)).addReg(freeRegister).addReg(ARM::PC);

    /*sub gp, 4 instrumentation as reading pc will give +4 */
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2SUBri)).addReg(freeRegister).addReg(freeRegister).addImm(4).add(predOps(ARMCC::AL));

    /*pacg instruction with r10*/

    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R10).add(predOps(ARMCC::AL)).addReg(freeRegister).addReg(ARM::R10)
    .setMIFlag(MachineInstr::NoFlags);
    outs() << "EnolaDebug-backEnd: Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"EnolaDebug-backEnd: constructed instruction in string : "<<instructionString<<"\n";
    return true;
}

bool ARMEnolaCFA::instrumentTrampolineParameter (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
    outs() << "EnolaDebug-backEnd: Moving PC to r0:\n";
    
    MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::MOVr), ARM::R0).addReg(ARM::PC).add(predOps(ARMCC::AL)).add(condCodeOp())
    .setMIFlag(MachineInstr::NoFlags);
    outs() << "EnolaDebug-backEnd: Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"EnolaDebug-backEnd: constructed instruction in string : "<<instructionString<<"\n";
    return true;
}
bool ARMEnolaCFA::instrumentIndirectParameter (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF, Register indirectTarget) {
    outs() << "EnolaDebug-backEnd: Moving indirect target to r0:\n";
    
    MachineInstrBuilder MIB = BuildMI(MBB, MI, DL, TII.get(ARM::MOVr), ARM::R0).addReg(indirectTarget).add(predOps(ARMCC::AL)).add(condCodeOp())
    .setMIFlag(MachineInstr::NoFlags);
    outs() << "EnolaDebug-backEnd: Consructed instructions: " << MIB <<"\n";
    MachineInstr *MI2 = MIB;
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"EnolaDebug-backEnd: constructed instruction in string : "<<instructionString<<"\n";
    return true;
}

bool ARMEnolaCFA::instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
   // unsigned targetReg;


    outs () << "EnolaDebug-backEnd: Inside instrumentation of return \n";

    MachineInstrBuilder MIB;
    outs() << "EnolaDebug-backEnd: Building PAC:\n";
   // BMI = BuildMI(MBB, MI, DL, TII.get(ARM::t2ADDri)).addReg(ARM::R9).addReg(ARM::R0).addImm(8);
   // if (TII.getIns)
 
   // MIB = BuildMI(MBB, MI, DL,TII.get(ARM::tCMPi8)).addReg(ARM::R9).addImm(0).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);
   //MIB = BuildMI(MBB, MI, DL,TII.get(ARM::t2ADDri)).addReg(ARM::R0).addReg(ARM::R1).addImm(8).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);

  //  MachineInstr *MI3 = MIB;

  //  std::string instructionString2;
  //  llvm::raw_string_ostream OS2(instructionString2);
  //  MI3->print(OS2);
   // outs()<<"constructed instruction in string cmp: "<<instructionString2<<"\n";

  //  MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PAC)).add(predOps(ARMCC::AL)).setMIFlag(MachineInstr::NoFlags);
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R9).add(predOps(ARMCC::AL)).addReg(ARM::LR).addReg(ARM::R9)
    .setMIFlag(MachineInstr::NoFlags);

    outs() << "EnolaDebug-backEnd: Consructed instructions: " << MIB <<"\n";
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
    outs() <<"EnolaDebug-backEnd: Target CPU : "<<CPU.str()<<"\n";

   /* if (!STI.hasPACBTI()) {
        outs() <<"hAS pac BTI feature\n";
    }*/
    // Convert the MachineInstr to a string representation.
    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"EnolaDebug-backEnd: constructed instruction in string : "<<instructionString<<"\n";

//    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

    // Create an InlineAsm object with your inline assembly code.
    //const char *AssemblyCode = "PACG r9, r14, r9";
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

Register ARMEnolaCFA::getParameterOfindrect (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
    Register indirectTarger;
    //MachineInstr *deepCopiedInst = (MachineInstr *)malloc(sizeof(MachineInstr));
    //memcpy(deepCopiedInst, &MI, sizeof(MachineInstr)); 
    MachineBasicBlock::iterator MBIIterator =  MI.getIterator();
    const TargetSubtargetInfo &STI = MF.getSubtarget();
    const TargetRegisterInfo *TRI = STI.getRegisterInfo();
    outs() <<"EnolaDebug-backEnd: Inside getParameterOfindrect\n";

    while(MBIIterator != MBB.end())
    {
        MachineInstr &tempMI = *MBIIterator;
        
        if(tempMI.getOpcode() == ARM::BMOVPCRX_CALL || tempMI.getDesc().getOpcode() == ARM::BLX || tempMI.getDesc().getOpcode() == ARM::BX)
        {
            // ARM::MOV_pc
            //&& MI.getNumOperands()>1 && MI.getOperand(0).isReg() && MI.getOperand(1).isReg()
            outs() << "EnolaDebug-backEnd: Mov to register instruction with the following operands: \n";
            if (tempMI.getNumOperands() >= 1)
                indirectTarger = tempMI.getOperand(0).getReg();
            for (int i = 0; i < tempMI.getNumOperands(); i++)
            {
                if(tempMI.getOperand(i).isReg()){
                    StringRef targetReg = TRI->getRegAsmName(tempMI.getOperand(i).getReg());
                    outs() << targetReg.str()<<" , ";
                }
                outs() << tempMI.getOperand(i).getType()<<" , ";
            }
            outs() <<"\n";
            // if (TRI->getRegAsmName( tempMI.getOperand(0).getReg() == ARM::PC))
                //   outs() << "Indirect Branch:\n";
            break;
        }

        MBIIterator++;

    }
    
    return indirectTarger;

    }

bool ARMEnolaCFA:: instrumentIndirectParameterSetInst(MachineBasicBlock &MBB,
                        MachineInstr &MI,
                        const DebugLoc &DL,
                        const ARMBaseInstrInfo &TII,
                        const char *sym,
                        MachineFunction &MF, Register &indirectReg) {

    MachineBasicBlock::iterator MBIIterator =  MI.getIterator();
    const TargetSubtargetInfo &STI = MF.getSubtarget();
    const TargetRegisterInfo *TRI = STI.getRegisterInfo();
    while(MBIIterator != MBB.end())
    {
        MachineInstr &tempMI = *MBIIterator;
       // outs()<< "opcodes: "<<tempMI.getOpcode()<<"\n";
        
        if(tempMI.getOpcode() == ARM::LDRi12 && tempMI.getNumOperands() > 0 && tempMI.getOperand(0).isReg() && tempMI.getOperand(0).getReg() == indirectReg)
        {
            outs()<<"EnolaDebug-backEnd: Need to instrument the instruction\n";
            break;
        }
        MBIIterator++;
    }
    
    MachineInstr &toBeInstrmented = *MBIIterator;

    MachineInstrBuilder MIB = BuildMI(MBB, MI, MI.getDebugLoc(), TII.get(ARM::LDRi12), ARM::R0);

     /*for (const MachineOperand &MO : toBeInstrmented.operands()) {
        MO.print(outs());
        MIB.add(MO);
    }*/
    for (unsigned i = 1; i < toBeInstrmented.getNumOperands(); ++i) {
        MIB.add(toBeInstrmented.getOperand(i));
    }
    
    outs()<<"EnolaDebug-backEnd: it should be the ldr insturction: "<<toBeInstrmented.getOpcode()<<"\n";

    return true;

}
bool ARMEnolaCFA::runOnMachineFunction(MachineFunction &MF) {
    
    bool modified = false;

    /*Begin: verify that we intend to include Enola instrumentation for this function*/
    Function &F = MF.getFunction();
    
    if (!F.hasMetadata("Enola-back-end-flag")) {
        outs() << "EnolaDebug-backEnd: Function " << F.getName() << " has not metadata for Enola instrumentation!\n";
        return modified;
    }
    /*End: verify that we intend to include Enola instrumentation for this function*/

    //StringRef trampoline_function("secure_trace_storage");
    std::string MFName = MF.getName().str();

    const TargetSubtargetInfo &STI = MF.getSubtarget();
    const TargetRegisterInfo *TRI = STI.getRegisterInfo();

    // Now, you have access to the ARMBaseRegisterInfo
    const ARMBaseRegisterInfo *ARMBRI = static_cast<const ARMBaseRegisterInfo *>(TRI);

    const MCPhysReg* callee_saved = ARMBRI->getCalleeSavedRegs(&MF);

   /* while (callee_saved != NULL)
    {
        outs() << "current pointer value : "<<*callee_saved<<"\n";
        callee_saved++;
    }*/
    
    outs() << "EnolaDebug-backEnd: callee_saved value : "<<*callee_saved<<"\n";


    if (MF.getSubtarget().getFeatureBits()[ARM::FeaturePACBTI])
    {
        outs() <<"EnolaDebug-backEnd: PAC bit feature exists\n";
    }
    outs() << "EnolaDebug-backEnd: Enola Instrumentation: "<<MFName<<"\n";
    const ARMBaseInstrInfo &TII = *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());
    
    MachineBasicBlock::iterator itr;
    MachineBasicBlock *currentBB;
    MachineFunction *currentMF;
    
    for (auto &MBB : MF) {

 
        for(auto &MI:MBB){
            
            //Handle all condition instructions
            /*if(MI.isConditionalBranch())
            {
                outs() << "EnolaDebug-backEnd: This is a compare instruction: " <<  MI.getOpcode() <<"\n";
                
                //Instrument true branch
                if (MI.getOperand(0).isMBB())
                {
                    outs ()<< "EnolaDebug-backEnd: Conditional branch true branch function: " << MF.getFunction().getName().str() <<"\n";
                    currentBB = MI.getOperand(0).getMBB();
                    itr = currentBB->begin();
                    MachineInstr &trueBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    modified |= instrumentCond(*currentBB, trueBB_Ins, trueBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
                if (MI.getOperand(1).isMBB())
                {
                    outs ()<< "EnolaDebug-backEnd: Conditional branch false branch function: " << MF.getFunction().getName().str() <<"\n";
                    //Instrument false branch
                    currentBB = MI.getOperand(1).getMBB();
                    itr = currentBB->begin();
                    MachineInstr &falseBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    modified |= instrumentCond(*currentBB, falseBB_Ins, falseBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
                //when the second operand is not a basic block, thus the immediate next MBB should be the other poosible target of the conditional insturction
                else if ((currentBB = MBB.getNextNode()) != NULL)
                {
                    itr = currentBB->begin();
                    MachineInstr &falseBB_Ins = *itr;
                    currentMF = currentBB->getParent();
                    modified |= instrumentCond(*currentBB, falseBB_Ins, falseBB_Ins.getDebugLoc(), TII, "cmp", *currentMF);
                }
               
            }*/
            //Handle return instructions
            if(MI.getDesc().isReturn())
            {
                outs() << "EnolaDebug-backEnd:  This is a return instruction: " <<  MI.getOpcode() <<"\n";
                modified |= instrumentRet(MBB, MI, MI.getDebugLoc(), TII, "dummy", MF);
            }
            //add parameter to the secure_trace_storage trampoline function call
            else if(MI.isCall())
            {   
                std::string target_function_name = extractFunctionName(MI);
                outs() << "EnolaDebug-backEnd: Call instruction target function name: "<< target_function_name<<"\n";
                if (target_function_name == "secure_trace_storage")
                {
                    outs() << "EnolaDebug-backEnd: secure_trace_storage function call found: making instrumentation with pacg r10"<<"\n";
                    currentBB = MI.getParent();
                    itr = currentBB->begin();
                    MachineInstr &BBIns = *itr;
                    currentMF = currentBB->getParent();
                    modified |= instrumentCond(*currentBB, BBIns, BBIns.getDebugLoc(), TII, "cmp", *currentMF);
                 //   modified |= instrumentTrampolineParameter(MBB, MI, MI.getDebugLoc(), TII, "dummy", MF);
                }

                else if (target_function_name == "indirect_secure_trace_storage")
                {
                    outs() << "EnolaDebug-backEnd: indirect_secure_trace_storage function call found"<<"\n";
                    Register indirectTarget = getParameterOfindrect(MBB, MI, MI.getDebugLoc(), TII, "getIndirectParameter", MF);
                    if (indirectTarget.isValid())
                        //modified |= instrumentIndirectParameter(MBB, MI, MI.getDebugLoc(), TII, "setIndirectParameter", MF, indirectTarget);
                        modified |= instrumentIndirectParameterSetInst(MBB, MI, MI.getDebugLoc(), TII, "getIndirectParameterSetInst", MF, indirectTarget);
                }
                   
            }
            
            outs() << "EnolaDebug-backEnd: The instruction belongs to: " << MI.getMF()->getName() << " Op-code " << MI.getOpcode() << " operand " << MI.getNumOperands() << "\n";
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
