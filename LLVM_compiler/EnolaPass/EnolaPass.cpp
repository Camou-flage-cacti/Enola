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
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <memory>


using namespace llvm;
using namespace std;
#define DEBUG_TYPE "EnolaPass"

//STATISTIC(HelloCounter, "Counts number of functions greeted");

namespace {

  struct EnolaPass : public FunctionPass {
    static char ID; 
    EnolaPass() : FunctionPass(ID) {}
	Function *indirectStorageFunction;
	bool indirectTraceFlag = true;

    bool runOnFunction(Function &F) override {
	    LLVMContext &context = F.getContext();
	    auto module = F.getParent();
		string functionName = F.getName().str();

		bool modifid = false;
		/*Set metadata for enola backend*/
		MDNode *MyMetadata = MDNode::get(context, MDString::get(context, functionName));
		F.setMetadata("Enola-back-end-flag", MyMetadata);

		for(BasicBlock &BB: F)
		{
			for (Instruction &I : BB)
			{
				switch(I.getOpcode()) {

					case Instruction::Switch: {
						errs() << "Found a switch statement\n";
						Instruction &Inst = I;
						SwitchInst *Switch = dyn_cast<SwitchInst>(&Inst);
						if(Switch == NULL)
							errs() << "Switch case object is NULL\n";
						
						auto numOf = Switch->getNumCases();
						errs()<<"Number of cases: "<< numOf <<"\n";
				
						for (const SwitchInst::CaseHandle &Case : Switch->cases()) {
							errs() << "Case " << Case.getCaseValue() << " to block " << Case.getCaseSuccessor() << "\n";
							//const BasicBlock *caseSuccessor =  *Case.getCaseSuccessor();
							BasicBlock *CaseBB = Case.getCaseSuccessor();
							modifid |= insertSecureTraceTrampoline(CaseBB);
						}
						BasicBlock *CaseBB = Switch->getDefaultDest(); //default branch
						modifid |= insertSecureTraceTrampoline(CaseBB);
						break;
					}
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
							modifid |= insertSecureTraceTrampoline(trueTarget);
							modifid |= insertSecureTraceTrampoline(falseTarget);

						}
						break;
					}
					default:
						errs() << I << "\n";
						break;
				}
				//auto *cb = dyn_cast<CallBase>(&I);
			}
		}

		int count = 0;
		int numOfConnections = 0;
		for(BasicBlock &BB: F)
		{
			errs()<<"runOnfunction for idirect call analysis: " << BB.getName() <<"\n";

			if (IndirectBrInst *IBI = dyn_cast<IndirectBrInst> (BB.getTerminator()))
			{
				Value *target;
				if (auto *indirectBranchInst = dyn_cast <IndirectBrInst>(IBI))
				{
					target = indirectBranchInst->getAddress();
				}
				else
				{
					errs()<< __func__ << "ERROR: unknown indirect branch inst: " << *IBI << "\n";
					continue;
				}
				assert(target != nullptr);
				errs() << numOfConnections++ << "Type : IBranch, Target : "<<target<<"\n";

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

								errs() << numOfConnections++ << "Type : Tail Call Callee_name: "<< callee_name << "\n";   
							// continue;
							}

							// exclude instrinsic functions
							else if (callee->isIntrinsic()) 
							{
								errs() << numOfConnections++ << "Type : Instrinsic Function : Callee_name: "  << callee_name << "\n";   
							// std::string callee_name = callee->getName().str();
							// OutputJson << "\"" << numOfConnections++ << "\" : {\"Type\"
							// :
							// \"Callee\", " << "\"Callee_name\": \"" << callee_name <<
							// "\"},\n";
							}
							else 
							{
								errs() << numOfConnections++ << "Type : Direct Call : Callee_name: "  << callee_name << "\n";
							}
					}
					else if (InlineAsm *IA = dyn_cast_or_null<InlineAsm>(cb->getCalledOperand()))
					{
						errs() << numOfConnections++ << "Type : InlineAsm : operand: "  << "\n";
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
						errs() << "\nIndirect call: " << rso_callee.str() << "\n";
						errs() << rso_callee.str()<< "{Connections : Parent : " << F.getName().str() << " Function\" : {";
						errs() << numOfConnections++ << "Type : Indirect Call Type Inst "<< rso_callee.str() << "\n";  
						rso_callee.str().clear();

						FunctionType *FuncTy = cb->getFunctionType();
            			FuncTy->print(rso_callee);

						errs()<< "------------ indirect_analysis: START -----------\n";
						errs() << "Functype: " << rso_callee.str();
						rso_callee.str().clear();

						bool isEmptySet = true;

						for (Function &Func : F.getParent()->getFunctionList()) 
						{
							if (Func.hasAddressTaken() && isTypesEq(Func.getFunctionType(), FuncTy, 0)) 
							{
								// print out the indirect callee label to the callees
								errs() << "<Indirect Call>: " <<  F.getName().str() << ", Callee_name: " << Func.getName().str() << "\n";
								// add connection (possible target func)

								errs() <<icall_num++ << Func.getName().str() << "\n";
								errs() << "\"" << numOfConnections++ << "Type : Indirect Call , Callee_name: "<< Func.getName().str() << "\n";
								isEmptySet = false;
							}
						}
						if (isEmptySet) 
						{
							errs() << "\n-----------------------------------------\n";
							errs() << "The violating indirect call: ";
							cb->print(rso_callee);
							errs() << rso_callee.str() << "\n";
							rso_callee.str().clear();
							errs() << "The violating indirect call TYPE: ";
							FuncTy->print(rso_callee);
							errs() << rso_callee.str() << "\n";
							errs() << "\n-----------------------------------------\n";
						}
						errs() << "\n------------ indirect_analysis: END------------\n";
						errs() << "}}},\n";

						/*Instrument indirect calls*/
						modifid |= insertIndirectSecureTraceTrampoline(&BB, &I);

					}
					 /*-------------- indirect_analysis: END --------*/
				}
				switch (I.getOpcode())
				{
					/*case Instruction::Br: {
						BranchInst *bi = cast<BranchInst>(&I);
						// check condition branches
						if (bi->isConditional()) {
						llvm::errs() << "<CondBranch> operand: " << *bi << ", src: " << bi
									<< ", parent:" << bi->getParent() << "\n";

						NumbOfCondBranches++;
						} else {
						NumbOfBranches++;
						llvm::errs() << "<BranchInst>: " << *bi << ", src: " << bi
									<< ", parent: " << bi->getParent()
									<< ", NumbOfBranches: " << NumbOfBranches << "\n";
						}
					} break;*/
					/*-------------------------------------------------------------------------------
					check indirect branch instructions
					---------------------------------------------------------------------------------*/
					case Instruction::IndirectBr: {
						IndirectBrInst *ibi = cast<IndirectBrInst>(&I);
						Value *target = ibi->getAddress();
						assert(target != nullptr);
						numOfConnections++;
						errs() << "<IndirectBrInst>: " << *ibi << "\n";
						errs() <<numOfConnections++<<"Type : IBranch , target: " << target<< "\n";
						
						modifid |= insertIndirectSecureTraceTrampoline(&BB, &I);
					} break;
					case Instruction::CallBr: {
						
						CallBrInst *cbi = cast<CallBrInst>(&I);
						errs() << "<CallBrInst>: " << *cbi << "\n";

						modifid |= insertIndirectSecureTraceTrampoline(&BB, &I);
					} break;
				//	case Instruction::Ret: {
						// ReturnInst *ret = cast<ReturnInst>(&I);
				//		string str;
				//		raw_string_ostream ret_inst(str);
						// std::string parent_str;
						// raw_string_ostream ret_parent(parent_str);
				//		I.print(ret_inst);
				//		errs() << numOfConnections++ << "Type : Ret , Ins : " << ret_inst.str() << "\", \"Parent\" : {";
				//		for (Function &Func : F.getParent()->getFunctionList()) {
						// if (Func.getName().equals(F.getName())) {
						//   errs() << "Ret: Parent is itself.\n";
						//   continue;
						// }
						// print out the indirect callee label to the callees
						// int ret = isParentFunc(&Func, &F);
				//		int ParentList[MAX_PARENTS] = {0};
				//		isParentFuncList(&Func, &F, ParentList);
				//		if (ParentList[0] == 0)
				//		{
							// errs() << "No parent.\t";
				//			continue;
				//		}
						// If we find the parent
					//	errs() << "Parent: " << Func.getName().str() << "[";
					//	OutputJson << "\"" << Func.getName().str() << "\" : [";
					//	for (auto x : ParentList)
					//	{
					//		if (x != 0){
						//	errs() << x << "\t";
						//	OutputJson << "\"" << x << "\", ";
						//	}
						//}   
						//OutputJson << "],\n";
						//errs() << "]\n";     
						// if (ParentList[0] > 0)
						// {
						//   errs() << "Parent list:\t";
						//   for (size_t i = 0; i < sizeof(ParentList)/sizeof(ParentList[0]); i++)
						//   {
						//     errs() << ParentList[i] << " ";
						//   }
						// }
						// if (ret > 0) {
						//   // errs() << Func.getName().str() << " ";
						//   OutputJson << "\"" << Func.getName().str() << "\" : \"" << ret
						//              << "\",";
						// }
						// }
					//	}
						// F.getParent();
					//	OutputJson << "}},";
						// ICallJson << "}";

					//	ret_inst.str().clear();
					//} break;
						// case Instruction::CatchRet:{
						//   CatchReturnInst *cret = cast<CatchReturnInst>(&I);
						//   errs() << "CatchReturnInst: " << *cret << ", src: " <<
						//   cret
						//   << "\n";
						// }

					default:
						break;
				}
			}
		}
		numOfConnections = 0;
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


	    return modifid;
    }

	bool insertSecureTraceTrampoline(BasicBlock *BB)
	{

		LLVMContext &Context = BB->getContext();
		IRBuilder<> builder(&BB->front());
		auto module = BB->getModule();

		// Create the function call
		FunctionType *FT = FunctionType::get(builder.getVoidTy(), false);
		FunctionCallee Callee = module->getOrInsertFunction("secure_trace_storage", FT);
		builder.CreateCall(Callee);

		return true;
	}
	
	bool insertIndirectSecureTraceTrampoline(BasicBlock *BB, Instruction *I)
	{

		LLVMContext &Context = BB->getContext();
		IRBuilder<> builder(BB);
		auto module = BB->getModule();
		//I->getIterator();
		//BasicBlock::iterator it = BB->begin();

		builder.SetInsertPoint(BB, I->getIterator());

		// Create the function call
		FunctionType *FT = FunctionType::get(builder.getVoidTy(), false);
		if(indirectTraceFlag)
		{
			indirectStorageFunction = Function::Create(FT, Function::ExternalLinkage, "indirect_secure_trace_storage", module);
			indirectTraceFlag = false;
		}

	//	auto targetIter = std::find(BB->begin(), BB->end(), &I);

		//FunctionCallee Callee = module->getOrInsertFunction("indirect_secure_trace_storage", FT);
	//	BB->inser getInstList();
		builder.CreateCall(indirectStorageFunction); 
		//.insert(targetIter, indirectStorageFunction)
		return true;
	}

	bool isTypesEq(Type *T1, Type *T2, unsigned depth = 0) 
	{
		if (T1 == T2) 
		{
			return true;
		}

		if (depth > 10) 
		{
			/*--------------------------------------------------------------*
			If we haven't found  a difference this deep just assume they are
			the same type. We need to overapproximate (i.e. say more things
			are equal than really are) so return true
			*---------------------------------------------------------------*/
			return true;
		}
		if (PointerType *Pty1 = dyn_cast<PointerType>(T1)) 
		{
			if (PointerType *Pty2 = dyn_cast<PointerType>(T2)) 
			{
				return isTypesEq(Pty1->getPointerElementType(), Pty2->getPointerElementType(), depth + 1);
			} 
			else 
			{
				return false;
			}
		}

		if (FunctionType *FTy1 = dyn_cast<FunctionType>(T1))
		{
				if (FunctionType *FTy2 = dyn_cast<FunctionType>(T2)) 
				{

				if (FTy1->getNumParams() != FTy2->getNumParams()) 
				{
					return false;
				}
				if (!isTypesEq(FTy1->getReturnType(), FTy2->getReturnType(), depth + 1)) 
				{
					return false;
				}

				for (unsigned i = 0; i < FTy1->getNumParams(); i++) 
				{
					if (FTy1->getParamType(i) == FTy1 && FTy2->getParamType(i) == FTy2) 
					{
						continue;
					} 
					else if (FTy1->getParamType(i) != FTy1 && FTy2->getParamType(i) != FTy2) 
					{
					// FTy1->getParamType(i)->dump();
					// FTy2->getParamType(i)->dump();
						if (!isTypesEq(FTy1->getParamType(i), FTy2->getParamType(i), depth + 1)) 
						{
							return false;
						}
					} 
					else 
					{
						return false;
					}
				}

				return true;

			} 
			else 
			{
				return false;
			}
		}
	if (StructType *STy1 = dyn_cast<StructType>(T1)) 
	{
		if (StructType *STy2 = dyn_cast<StructType>(T2)) 
		{
		if (STy2->getNumElements() != STy1->getNumElements()) {
			return false;
		}
		if (STy1->hasName() && STy2->hasName()) 
		{
			if (STy1->getName().startswith(STy2->getName()) || STy2->getName().startswith(STy1->getName())) 
			{
				return true;
			}
		}

		return false;

		}
		else 
		{
			return false;
		}
	}

	return false;

	}

  };
}

char EnolaPass::ID = 0;
static RegisterPass<EnolaPass> X("EnolaPass", "Enola Pass developement");
