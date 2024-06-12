import os
import shutil
import xml.etree.ElementTree as ET
import subprocess
import sys
import copy
import serial
import time
from datetime import datetime
import ctypes

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_THUMB, arm, CS_OPT_SYNTAX_ATT
from capstone import *
import json
import struct
from pathlib import Path
from bitarray import bitarray
import pandas as pd

#from scanner import *
import angr

out_metadata_path = os.getcwd()+'/'

file_path = 'bin/Blinky.axf'

enola_msr_function_base = 0x0
enola_msr_function_end = 0x0

offset = 0x400

out_static_analysis = 'static_analysis.log'


def check_bin_validity():
    # Check if the file exists
    if os.path.exists(file_path):
        print(f"The file '{file_path}' exists.")
    else:
        print(f"The file '{file_path}' does not exist.")

def reset_log():
    if os.path.exists(out_static_analysis):
        os.remove(out_static_analysis)
        print(f"File '{out_static_analysis}' has been removed.")
    else:
        print(f"File '{out_static_analysis}' does not exist.")
    

def write_log(path, log, file_type):
    try:
        with open(path, file_type) as file:
            file.write(log)
    except FileNotFoundError:
        print("The file does not exist.")
        sys.exit()
    except PermissionError:
        print("You do not have permission to write to this file. " + path)
        sys.exit()
    except IsADirectoryError:
        print("You attempted to open a directory as a file. " + path)
        sys.exit()
    except IOError as e:
        print(f"An I/O error occurred: {str(e)}")
        sys.exit()


# Open the binary file
def get_ENOLA_key_setting_function_range(enola_func_name):
    with open(file_path, 'rb') as f:
        # Create ELFFile object
        elf_file = ELFFile(f)

        # Iterate over sections
        for section in elf_file.iter_sections():
            # Check if the section is a symbol table
            if section.name == '.symtab':
                # Iterate over symbols
                for symbol in section.iter_symbols():
                    # Check if the symbol is a function
                    
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        # Get the function name and address range
                        func_name = symbol.name
                        func_start_addr = symbol['st_value']
                        func_end_addr = symbol['st_value'] + symbol['st_size']
                        if func_name == enola_func_name: #replace with your key setting function name
                            enola_msr_function_base = func_start_addr
                            enola_msr_function_end = func_end_addr
                            print(f"Function: {func_name}, Address Range: 0x{func_start_addr:x}-0x{func_end_addr:x}")


def disassemble_and_validate():
    # Define the architecture and mode (ARM and ARM mode)
    # Initialize the disassembler
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM +  CS_MODE_THUMB + CS_MODE_MCLASS)

    

    try:
        target_file = open(file_path, 'rb')
        print("debug!!!!!!!!!!")
    except IOError as e:
        print(e)

    elf = ELFFile(target_file)


    code_data = {}
    section_info = {}
    section_tmp = {}
    code_start = 0
    code_end = 0

    for section in elf.iter_sections():
        section_tmp["start"] = section['sh_addr']
        section_tmp["size"] = section['sh_size']
        section_info[section.name] = copy.copy(section_tmp)
        write_log(out_static_analysis,
                    f"{hex(section['sh_addr'])}, {section.name}, {section['sh_size']}\n", 'a+')

    
    code_section = elf.get_section_by_name('.text')
    if code_section:
        code_data[0] = copy.copy(code_section)
        code_start = copy.copy(section_info[".text"])
        print(code_start)
        write_log(out_static_analysis,
            f"Code start: {hex(code_start)}\n", 'a+')
        code_end = copy.copy(code_start + section_info[".text"]["size"])


    #code_section = elf.get_section_by_name('.text')
    if code_section:
        print(type(code_section))
        pass

    print("Disassembling")
    code = code_section.data()
    for instr in md.disasm(code, 0x10000400):
        if(instr.address < 0x10000494):
            print("0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str))
        # static CFG
        #print("End of code section")

    # Disassemble the binary
    for insn in md.disasm(code, 0x10000000):
        # Check if the instruction is an MSR instruction
        #print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic == 'msr' or insn.mnemonic == 'mrs':
            insn_address = insn.address
            if (insn_address >=enola_msr_function_base and insn_address <=enola_msr_function_end):
                print("ENOLA MSR")
            else:
                print("Unsafe MSR instruction at address 0x%x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
                print("Take measures to verify the MSR instructions")

def load_cfg(filename):
    print("In load CFG")
    proj = angr.Project(filename, main_opts={'arch': 'ArchARMCortexM'}, auto_load_libs=False)
    print("Angr project created")
    print(proj.arch)
    print(hex(proj.entry))

    try:
        elf = ELFFile(open(filename, 'rb'))
        print("debug!!!!!!!!!!")
    except IOError as e:
        print(e)
    code_section = elf.get_section_by_name('.text')

    if code_section:
        print(type(code_section))
        pass
    # else:  # For FreeRTOS+MPU
    #     code_section = elf.get_section_by_name('ER_IROM_NS_PRIVILEGED')

    code = code_section.data()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    for instr in md.disasm(code, 0x11000000):
        print("0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str))
    # static CFG
    #print("End of code section")
    #cfg = proj.analyses.CFGFast(normalize=True)
    cfg = proj.analyses.CFGEmulated(keep_state=True)

    return proj, cfg, code




def main():
    check_bin_validity()
    reset_log()
    disassemble_and_validate()


if __name__ == "__main__":
    main()