//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <iostream>
#include <string>

using namespace llvm;
using namespace std;
#define DEBUG_TYPE "EnolaPass"

//STATISTIC(HelloCounter, "Counts number of functions greeted");

namespace {

  struct EnolaPass : public FunctionPass {
    static char ID; 
    EnolaPass() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
	    LLVMContext &context = F.getContext();
	    auto module = F.getParent();
		string functionName = F.getName().str();

		for(BasicBlock &BB: F)
		{
			for (Instruction &I : BB)
			{
				switch(I.getOpcode()) {

					case Instruction::Br: {
						BranchInst *bi = cast<BranchInst> (&I);
						if(bi->isUnconditional())
						{
							errs() << "Unconditional branch(static): no action from Enola"<< *bi <<"\n";
						}
						else
						{
							errs() <<"Conditional branch instruction: condition vlaue= " << bi->getCondition()<< " : " << *bi<<"\n";

							Value* condition = bi->getCondition();
							errs() << "Value is : " << condition <<"\n";
							BasicBlock* trueTarget = bi->getSuccessor(0);
							BasicBlock* falseTarget = bi->getSuccessor(1);

							// Print information about the conditional bi
							errs() << "Conditional Branch: " << *condition << "\n";
							errs() << "True Target: " << trueTarget->getName() << "\n";
							errs() << "False Target: " << falseTarget->getName() << "\n";
							insertSecureTraceTrampoline(trueTarget);
							insertSecureTraceTrampoline(falseTarget);

						}
						break;
					}
					default:
					errs() << I << "\n";
					break;
				}
			}
		}

		int count = 0;
		int numOfConnections = 0;
		for(BasicBlock &BB: F)
		{
			outs()<<"runOnfunction for idirect call analysis: " << BB.getName() <<"\n";

			if (IndirectBrInst *IBI = dyn_cast<IndirectBrInst> (BB.getTerminator()))
			{
				Value *target;
				if (auto *indirectBranchInst = dyn_cast <IndirectBrInst>(IBI))
				{
					target = indirectBranchInst->getAddress();
				}
				else
				{
					outs()<< __func__ << "ERROR: unknown indirect branch inst: " << *IBI << "\n";
					continue;
				}
				assert(target != nullptr);
				outs() << numOfConnections++ << "Type : IBranch, Target : "<<target<<"\n";

			}
			for (Instruction &I : BB)
			{
				if (auto *cb = dyn_cast<CallBase>(&I)) {
					if (cb) 
					{
						Function *callee = cb->getCalledFunction();
						if (callee) 
						{
							std::string callee_name = callee->getName().str();
							// Do not analyze llvm functions

							if ((callee_name).find("llvm") != std::string::npos)
							{
								continue;
							}
							else if (cb->isTailCall())
							{

								outs() << numOfConnections++ << "Type : Tail Call Callee_name"<< callee_name << "\n";   
							// continue;
							}

							// exclude instrinsic functions
							else if (callee->isIntrinsic()) 
							{
								outs() << numOfConnections++ << "Type : Instrinsic Function : Callee_name: "  << callee_name << "\n";   
							// std::string callee_name = callee->getName().str();
							// OutputJson << "\"" << NumOfConnections++ << "\" : {\"Type\"
							// :
							// \"Callee\", " << "\"Callee_name\": \"" << callee_name <<
							// "\"},\n";
							}
							else 
							{
								outs() << numOfConnections++ << "Type : Direct Call : Callee_name: "  << callee_name << "\n";
							}
					}
					else if (InlineAsm *IA = dyn_cast_or_null<InlineAsm>(cb->getCalledOperand()))
					{
						outs() << numOfConnections++ << "Type : InlineAsm : operand: "  << "\n";
						/*InlineAsm::ConstraintInfoVector Constraints = IA->ParseConstraints();
						for (const InlineAsm::ConstraintInfo &Info : Constraints) 
						{
							if (Info.isIndirect) 
							{
								OutputJson << " [+] Indirect operand: "
										<< IA->getAsmString().c_str();
							}
						}*/

					}
					else if (ConstantExpr *ConstEx = dyn_cast_or_null<ConstantExpr>(cb->getCalledOperand())) 
					{
						Instruction *Inst = ConstEx->getAsInstruction();

						if (CastInst *CI = dyn_cast_or_null<CastInst>(Inst)) 
						{
							if (Function *c = dyn_cast<Function>(Inst->getOperand(0))) 
							{
								// add connection
								// OutputJson << "\"" << NumOfConnections++ << "\" :
								// {\"Type\" :
								// \"Callee\", " << "\"Callee_name\": \"" <<
								// c->getName().str()
								// << "\"},\n";
							}
							else 
							{
								assert(false && "Unhandled Cast");
							}
						}
						else 
						{
							assert(false && "Unhandled Constant");
						}
						// delete Inst;
					}
					else if (cb->isIndirectCall())
					{
						string str;
            			raw_string_ostream rso_callee(str);
						int icall_num = 0;

						cb->print(rso_callee);
						outs() << "\nIndirect call: " << rso_callee.str() << "\n";
						outs() << rso_callee.str()<< "{Connections : Parent : " << F.getName().str() << "Function\" : {";

					}
				}
			}
		}
	}


	   /* FunctionType *printfType = FunctionType::get(Type::getInt32Ty(context), {Type::getInt8PtrTy(context)}, true);
	    FunctionCallee printfFunction = module->getOrInsertFunction("printf", printfType);

		string functionName = F.getName().str();
		string functionCallVarName = functionName + "_callCount";
		GlobalVariable *functionCallCount = module->getGlobalVariable(functionCallVarName);

		if(!functionCallCount)
		{
			functionCallCount = new GlobalVariable(*module, Type::getInt32Ty(context), false, GlobalValue::CommonLinkage, 0, functionCallVarName);
			functionCallCount->setInitializer(ConstantInt::get(Type::getInt32Ty(context), 0));
		}

		Instruction *firstInsruction = &F.front().front();
		IRBuilder<> builder(firstInsruction);
		
		Value *loadedCallCount = builder.CreateLoad(Type::getInt32Ty(context), functionCallCount, "loadvalue");
		Value *addedCallCount = builder.CreateAdd(loadedCallCount, builder.getInt32(1));
		builder.CreateStore(addedCallCount, functionCallCount);

		string printLog = functionName + " %d\n";
		Value *functionNamePtr = builder.CreateGlobalStringPtr(printLog);
		builder.CreateCall(printfFunction, {functionNamePtr, addedCallCount});*/


	    return false;
    }

	void insertSecureTraceTrampoline(BasicBlock *BB)
	{

		LLVMContext &Context = BB->getContext();
		IRBuilder<> builder(&BB->front());
		auto module = BB->getModule();

		// Create the function call
		FunctionType *FT = FunctionType::get(builder.getVoidTy(), false);
		FunctionCallee Callee = module->getOrInsertFunction("secure_trace_storage", FT);
		builder.CreateCall(Callee);
	}

  };
}

char EnolaPass::ID = 0;
static RegisterPass<EnolaPass> X("EnolaPass", "Enola Pass developement");
