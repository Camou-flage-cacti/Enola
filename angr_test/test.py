#!/usr/bin/env python

import angr
from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_THUMB, arm, CS_OPT_SYNTAX_ATT
from capstone import *
from elftools.elf.elffile import ELFFile
import logging
logging.getLogger('angr.analyses').setLevel('INFO')

"""
usage: python test.py > log
"""

def analyze_on_target(filename):    
    
    proj = angr.Project(filename, main_opts={'arch': 'ArchARMCortexM'})
    print(proj.arch)
    print(hex(proj.entry))
    
    try:
        elf = ELFFile(open(filename, 'rb'))
    except IOError as e:
        print(e)
    code_section = elf.get_section_by_name('ER_CODE')
    if code_section:
        pass
    else:  # For FreeRTOS+MPU
        code_section = elf.get_section_by_name('ER_IROM_NS_PRIVILEGED')    
    
    #code = code_section.data()

    # static CFG
    # cfg = proj.analyses.CFGFast()
    cfg = proj.analyses.CFGEmulated(keep_state=True)

    print("This is the graph:", cfg.graph)
    print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
    
    print(type(proj.entry))
    
    entry_node = cfg.get_any_node(proj.entry)
    
    print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(proj.entry)))
    print("Predecessors of the entry point:", entry_node.predecessors)
    print("Successors of the entry point:", entry_node.successors)
    
    print("Successors (and type of jump)  of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])
    
    print("--------------------------------------\n\n")
    
    # the angr uses capstone to disassemble the binary without CS_MODE_MCLASS flag that cannot identify msr instruction 
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    
    analyzed_node = []
        
    # current_node = "__main"
    for edges in cfg.graph.edges():
        src_node = edges[0]
        dst_node = edges[1]
        
        block = proj.factory.block(src_node.addr)
    
        print("--------------------BB start----------------------")
        print('src_node: [0x%x] %s (src_node_size: %x), dst_node: [0x%x] %s (dst_node_size: %x)' % (src_node.addr-1, src_node.name, src_node.size, dst_node.addr-1, dst_node.name, dst_node.size))
        
        print("---------------result from angr.capstone-----------------")
        print(block.capstone.pp())
        
        # print("---------------result from capstone-----------------")
        # tmp_start = src_node.addr-1
        # tmp_start &= ~((tmp_start >> 16) << 16)
        # tmp_end = tmp_start + src_node.size
        
        # tmp =  code[tmp_start:tmp_end]
        # disassembled = md.disasm(tmp, src_node.addr)
        # for i, instr in enumerate(disassembled):
        #     text = ''
        #     for j in range(instr.size):
        #         text += '%02x' % instr.bytes[j]
        #     ins_size = int(len(text)/2)
        #     print(
        #         f'0x{instr.address:x}:\t{text}\t{instr.mnemonic}\t{instr.op_str}\t{ins_size}')                    
        
        # print("----------------------end capstone--------------------\n")
        
        if src_node in analyzed_node:
            pass
        else:
            analyzed_node.append(src_node)
            
        print("--------------------BB end----------------------\n")
            
if __name__ == '__main__':
    filename = "test_s.axf"
    print(filename)
    print("Hello")
    analyze_on_target(filename)
