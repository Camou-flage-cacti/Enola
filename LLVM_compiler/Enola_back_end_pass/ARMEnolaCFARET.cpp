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
#include "llvm/CodeGen/LivePhysRegs.h"

#include "ARMEnolaCFARET.h"
#include <iostream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "arm-Enola-CFA RET"

char ARMEnolaCFARET::ID = 0;


unsigned int return_count = 0;

INITIALIZE_PASS(ARMEnolaCFARET, DEBUG_TYPE, ARM_M85_ARMEnolaCFARET_NAME, true, true)

std::string ARMEnolaCFARET::extractFunctionName(const MachineInstr &MI) {
    std::string functionName = "";
    for(int i = 0; i < MI.getNumOperands(); i++)
    {
          const MachineOperand &MO = MI.getOperand(i); // Assuming the function name is in operand 0.
        //Function names are global or external
        if (MO.isGlobal()) {

            functionName = MO.getGlobal()->getName().str();
        }
    }
    outs() << "EnolaDebug-ret-backEnd: No global symbol\n";
    return functionName;
}

bool ARMEnolaCFARET::instrumentRetFromStack (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {


    outs () << "EnolaDebug-ret-backEnd: Inside instrumentation of return from stack \n";

    unsigned int pc_location = 0;
    bool extraPush = false;
    MachineInstrBuilder MIB;

    outs()<<"Opcode : "<<MI.getOpcode()<<"\n"; 

    for(int i = 0; i< MI.getNumOperands(); i++)
    {
        if(MI.getOperand(i).isReg())
        {
            unsigned int ins_id = MI.getOperand(i).getReg().id();
            if((ins_id >= ARM::R4 && ins_id <= ARM::R12) || ins_id == ARM::PC)
                pc_location++;
        }
    }
    pc_location--;
    
    outs() << "EnolaDebug-ret-backEnd: Distance from SP: "<<pc_location <<"\n";

     /*Find a free register*/
    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
    RegScavenger RS;
    RS.enterBasicBlock(MBB);

    unsigned freeRegister = 0;

    for (;freeRegister < TRI->getNumRegs();freeRegister++) {
        if((freeRegister>= ARM::R4 && freeRegister <= ARM::R9 && RS.isRegUsed(freeRegister, false)) || (freeRegister== ARM::R12 && RS.isRegUsed(freeRegister, false)))
        {
            outs() << "EnolaDebug-ret-backEnd: Found FREE register "<<freeRegister<<"\n";
            break;
        }
    }
    /*we could not find a free register; need to push*/
    if(freeRegister == 0)
    {
        outs() << "EnolaDebug-ret-backEnd: No free registers found: needs extra push "<<freeRegister<<"\n";
        extraPush = true;
        MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tPUSH)).add(predOps(ARMCC::AL)).addReg(ARM::R4).setMIFlag(MachineInstr::NoFlags);

    }

    MachineInstr *MI2;
    std::string instructionString;

    outs() << "EnolaDebug-ret-backEnd: Building ldr sp instruction: "<< pc_location<<"\n";
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tLDRspi), freeRegister).addReg(ARM::SP).addImm(pc_location).addImm(14).addReg(0);
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tMOVr)).addReg(ARM::R0).addReg(ARM::R0);
 
    outs() << "EnolaDebug-ret-backEnd: Finished return from stack\n";
    return true;
    

}

bool ARMEnolaCFARET::instrumentRet (MachineBasicBlock &MBB,
                           MachineInstr &MI,
                           const DebugLoc &DL,
                           const ARMBaseInstrInfo &TII,
                           const char *sym,
                           MachineFunction &MF) {
   // unsigned targetReg;
    outs () << "EnolaDebug-ret-backEnd: Inside instrumentation of return \n";

    MachineInstrBuilder MIB;
    outs() << "EnolaDebug-ret-backEnd: Building PAC:\n";

   // MIB = BuildMI(MBB, MI, DL, TII.get(ARM::t2PACG), ARM::R11).add(predOps(ARMCC::AL)).addReg(ARM::LR).addReg(ARM::R11).setMIFlag(MachineInstr::NoFlags);
    MIB = BuildMI(MBB, MI, DL, TII.get(ARM::tMOVr)).addReg(ARM::R0).addReg(ARM::R0);

    outs() << "EnolaDebug-ret-backEnd: Consructed instructions: " << MIB <<"\n";
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

    outs() <<"EnolaDebug-ret-backEnd: Target CPU : "<<CPU.str()<<"\n";

    std::string instructionString;
    llvm::raw_string_ostream OS(instructionString);
    MI2->print(OS);
    
    outs()<<"EnolaDebug-ret-backEnd: constructed instruction in string : "<<instructionString<<"\n";
    
    return true;
    

}

bool ARMEnolaCFARET::runOnMachineFunction(MachineFunction &MF) {
    
    bool modified = false;

    /*Begin: verify that we intend to include Enola instrumentation for this function*/
    Function &F = MF.getFunction();
    
    if (!F.hasMetadata("Enola-back-end-flag")) {
        outs() << "EnolaDebug-ret-backEnd: Function " << F.getName() << " has not metadata for Enola instrumentation!\n";
        return modified;
    }
    /*End: verify that we intend to include Enola instrumentation for this function*/
    outs() << "\n\n\n--------------------EnolaDebug-ret-backEnd: Working on Function " << F.getName()<<"-----------------\n\n";
    //StringRef trampoline_function("secure_trace_storage");
    std::string MFName = MF.getName().str();

    const TargetSubtargetInfo &STI = MF.getSubtarget();
    const TargetRegisterInfo *TRI = STI.getRegisterInfo();

    // Now, you have access to the ARMBaseRegisterInfo
    const ARMBaseRegisterInfo *ARMBRI = static_cast<const ARMBaseRegisterInfo *>(TRI);

    const MCPhysReg* callee_saved = ARMBRI->getCalleeSavedRegs(&MF);

    
    outs() << "EnolaDebug-ret-backEnd: callee_saved value : "<<*callee_saved<<"\n";


    if (MF.getSubtarget().getFeatureBits()[ARM::FeaturePACBTI])
    {
        outs() <<"EnolaDebug-ret-backEnd: PAC bit feature exists\n";
    }
    outs() << "EnolaDebug-ret-backEnd: Enola Instrumentation: "<<MFName<<"\n";
    const ARMBaseInstrInfo &TII = *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());

    const char *trace_indirect = "indirect_secure_trace_storage";
    const char *report_direct = "secure_trace_storage";
    
    MachineBasicBlock::iterator itr;
    MachineBasicBlock *currentBB;
    MachineFunction *currentMF;
    
    for (auto &MBB : MF) {

        for(auto &MI:MBB){
            //Handle return instructions
            if(MI.getDesc().isReturn())
            {
                return_count++;
                outs() << "EnolaDebug-ret-backEnd:  This is a return instruction: \n";
                if(MI.getOpcode() == ARM::tPOP_RET)
                {
                    outs() << "EnolaDebug-ret-backEnd:  Return from stack.\n";
                    modified |= instrumentRetFromStack(MBB, MI, MI.getDebugLoc(), TII, "dummy", MF);
                }
                else
                {
                    outs() << "EnolaDebug-ret-backEnd:  Return from LR.\n";
                    modified |= instrumentRet(MBB, MI, MI.getDebugLoc(), TII, "dummy", MF);
                }
                
            }
            outs() << "EnolaDebug-ret-backEnd: The instruction belongs to: " << MI.getMF()->getName() << " Op-code " << MI.getOpcode() << " operand " << MI.getNumOperands() << "\n";
        }
    }

    outs()<<"Function: "<< MFName<< " Returns: "<<return_count <<"\n";
    return modified;

}

FunctionPass *llvm::createARMEnolaCFARETPass() {
  return new ARMEnolaCFARET();
}