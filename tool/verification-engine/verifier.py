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
import mmap
from capstone.arm import *

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

def test_snippets():
    with(file_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

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

def abstract_execute():
    with open(opts.binfile, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

        offset = opts.text_start - opts.load_address
        write_log("hooking %s from 0x%08x to 0x%08x" % (opts.binfile, offset, opts.text_end - opts.load_address))
        mm.seek(offset)
        code = mm.read(mm.size() - mm.tell())

        current_address = opts.load_address + (offset)

        prev_address = -0x0001

        while True:
            taken = False
            if replay_stop == True:
                break

            for i in md.disasm(code, current_address):

                # Workaround for md.disasm returning dublicate instructions
                if i.address == prev_address:
                    continue
                else:
                    prev_address = i.address

                if (i.address in opts.omit_addresses):
                    logging.info("omit  at 0x%08x:         %-10s\t%s\t%s" %
                            (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

                    if i.address >= opts.text_end:
                        break

                    continue

                # branch w/ link instruction; bl <pc relative offset>
                if (i.id == ARM_INS_BL):
                    res = is_attestation_start(i, opts)
                    if (res):
                        replay_start = True
                        print("*******************replay start**************************")
                        ofd.write("start\n");
                        continue

                    res = is_attestation_end(i, opts)
                    if (res):
                        replay_stop = True
                        replay_start = False

                    if replay_start:
                        res = handle_branch_with_link(i, opts)
                        if res[0]:
                            taken = True
                            target_address = res[1]
                            stack.append(i.address + 4)
                            print("push stack ret address: %x" % (i.address + 4))
                            ofd.write("[bl]0x%x --> 0x%x\n" % (i.address, target_address))
                            break
                        else:
                            ofd.write("[bl][skip]0x%x\n" % (i.address))
                            pass

                elif (i.id == ARM64_INS_CSET):
                    if replay_start:
                        if 'ne' in i.op_str:
                            print 'ne-CSET:'+ i.mnemonic +'\t' +  i.op_str
                            last_ne_flag = True
                            last_flag = 'e'
                        elif 'eq' in i.op_str:
                            print 'eq-CSET:'+ i.mnemonic +'\t' +  i.op_str
                            last_ne_flag = False
                        elif 'gt' in i.op_str:
                            print 'gt-CSET:'+ i.mnemonic +'\t' +  i.op_str
                            last_lt_flag = False
                            last_flag = 'lg'
                        elif 'lt' in i.op_str:
                            print 'lt-CSET:'+ i.mnemonic +'\t' +  i.op_str
                            last_lt_flag = True 
                            last_flag = 'lg'
                        else:
                            print 'unknown-CSET:'+ i.mnemonic +'\t' +  i.op_str
                        
                ## branch instruction; b <pc relative offset>
                elif (i.id == ARM64_INS_B):
                    if replay_start:
                        if last_flag == 'e':
                            res = handle_branch(i, opts, trace, last_ne_flag)
                        else:
                            res = handle_branch(i, opts, trace, last_lt_flag)
                        if res[0]:
                            ofd.write("[b][y]0x%x --> 0x%x\n" % (i.address,res[1]))
                            taken = True
                            target_address = res[1]
                            break
                        else:
                            ofd.write("[b][n]0x%x\n" % (i.address))
                            pass # not taken

                ## branch while operand is register; br x1
                elif (i.id == ARM64_INS_BR):
                    if replay_start:
                        ofd.write("error[br]0x%x\n" % (i.address))
                        handle_branch_with_reg(i, opts)

                elif (i.id == ARM64_INS_BLR):
                    if replay_start:
                        ofd.write("error[blr]0x%x\n" % (i.address))
                        handle_branch_with_link_reg(i, opts)

                elif (i.id == ARM64_INS_RET):
                    if replay_start:
                        handle_ret(i, opts)
                        taken = True
                        target_address = stack.pop()
                        ofd.write("[ret]0x%x --> 0x%x\n" % (i.address,target_address))
                        break

                elif (i.id == ARM64_INS_TBZ):
                    if replay_start:
                        res = handle_tbz(i, opts, trace, last_ne_flag)
                        if res[0]:
                            taken = True
                            target_address = res[1]
                            ofd.write("[tbz][y]0x%x --> 0x%x\n" % (i.address,res[1]))
                            break
                        else:
                            ofd.write("[tbz][n]0x%x\n" % (i.address))
                            pass # not taken

                elif (i.id == ARM64_INS_TBNZ):
                    if replay_start:
                        res = handle_tbnz(i, opts, trace, last_ne_flag)
                        if res[0]:
                            taken = True
                            target_address = res[1]
                            ofd.write("[tnbz][y]0x%x --> 0x%x\n" % (i.address,res[1]))
                            break
                        else:
                            ofd.write("[tbnz][n]0x%x\n" % (i.address))
                            pass # not taken

                elif (i.id == ARM64_INS_CBNZ):
                    if replay_start:
                        res = handle_cbnz(i, opts, trace, last_ne_flag)
                        if res[0]:
                            taken = True
                            target_address = res[1]
                            ofd.write("[cbnz][y]0x%x --> 0x%x\n" % (i.address,res[1]))
                            break
                        else:
                            ofd.write("[cbnz][n]0x%x\n" % (i.address))
                            pass # not taken

                elif (i.id == ARM64_INS_CBZ):
                    if replay_start:
                        res = handle_cbz(i, opts, trace, last_ne_flag)
                        if res[0]:
                            taken = True
                            target_address = res[1]
                            ofd.write("[cbz][y]0x%x --> 0x%x\n" % (i.address,res[1]))
                            break
                        else:
                            ofd.write("[cbz][n]0x%x\n" % (i.address))
                            pass # not taken

                else:
                    pass


                if i.address >= opts.text_end:
                    break

                if taken:
                    break
            print("=========================block=========================")

            if taken:
                current_address = target_address
            else:
                current_address = (i.address if i.address > current_address
                                         else current_address + 4)

            if (current_address >= opts.text_end or
                current_address >= opts.load_address + mm.size()):
                break

            try:
                mm.seek(current_address - opts.load_address)
                code = mm.read(mm.size() - mm.tell())
            except:
                print ("current_address:0x%x, load_address:0x%x"%(current_address, opts.load_address))
                break

            if replay_stop == True:
                print("*******************replay stop**************************")
                break


def main():
    check_bin_validity()
    reset_log()
    disassemble_and_validate()


if __name__ == "__main__":
    main()