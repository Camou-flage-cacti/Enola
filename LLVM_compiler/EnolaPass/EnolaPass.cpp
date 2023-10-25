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
							errs() << "Unconditional branch: "<< *bi <<"\n";
						}
						else
						{
							bi->getNextNode();
							errs() <<"Conditional branch instruction: condition vlaue = " << bi->getCondition()<< " : " << *bi<<"\n";
						}
						break;
					}
					default:
					errs() << I << "\n";
					break;
				}
			}
		}


	    /*FunctionType *printfType = FunctionType::get(Type::getInt32Ty(context), {Type::getInt8PtrTy(context)}, true);
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
  };
}

char EnolaPass::ID = 0;
static RegisterPass<EnolaPass> X("EnolaPass", "Enola Pass developement");
