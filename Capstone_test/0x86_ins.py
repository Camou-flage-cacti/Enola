import argparse
import binascii
import configparser
import logging
import math
import mmap
import os.path
import struct
import sys
from argparse import Namespace
from bitarray import bitarray
from capstone.arm import *
from capstone import *
from enum import Enum
from datetime import datetime
import angr

def main():
    control_flow_statements = []
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True

    proj = angr.Project('out', auto_load_libs=False)
    block = proj.factory.block(proj.entry)
    print(block.pp())

    main_func = proj.loader.find_symbol('main')
    block = proj.factory.block(main_func.rebased_addr) #get main function address from symbol and get the first basic block
    print('Main function address %s linked %s relative %s' % (main_func.rebased_addr, main_func.linked_addr, main_func.relative_addr))
    print(block.pp())

    state = proj.factory.blank_state(addr=main_func.rebased_addr)
    simgr = proj.factory.simgr(state)

    while len(simgr.active) > 0:
        simgr.step()
    
    #instructions = simgr.deadended[0].history.bbl_addrs.hardcopy
    disassembly = proj.factory.block(main_func.rebased_addr).capstone.insns
    print(disassembly)
    print("---------------------------------------------------")
    cfg = proj.analyses.CFGFast()

    main_node = cfg.get_any_node(main_func.rebased_addr)
    print("Predecessors of the entry point:", main_node.predecessors)
    print("Successors of the entry point:", main_node.successors)
    print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(main_node) ])

    #for address, block in cfg.kb.blocks.items():
     #   for instruction in block.capstone.insns:
      #      print(instruction)
            #print(f"Address: {hex(instruction.address)}, Instruction: {instruction.mnemonic} {instruction.op_str}")

    #print(instructions)
    with open('out', "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
        code = mm.read(mm.size() - mm.tell())
        current_addr = 0x401171

        #int count = 0
       # while True:
        print("---------------------------------------------------")
        #for i in md.disasm(code, current_addr):
         #   print("Instruction address=%s, mnemonic=%s, op str=%s" % (i.address, i.mnemonic, i.op_str))

if __name__ == "__main__":
    main()
