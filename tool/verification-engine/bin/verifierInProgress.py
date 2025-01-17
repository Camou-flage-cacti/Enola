from elftools.elf.elffile import ELFFile
from capstone import *
import angr
import struct
import os
import lief

# Specify the path to the ELF binary
binary_path = 'Blinky.axf'

# Initialize the Capstone disassembler for ARM (Thumb mode, suitable for Cortex-M33)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

exit_points = []
sim_func_call_return_stack = []
sim_func_call_names = []
occuerence_trace = []
omit_functions =["init_trampoline", "secure_trace_storage", "indirect_secure_trace_storage"]
loop_limit = {'crc32pseudo': 25, 'benchmark_body': 5}
paresed_bin = lief.parse(binary_path)
cbz_successors = []
depth_limit = 100
depth_counter = 0

def get_basic_block_from_addr(addr):
    #addr = addr + 1
    # Perform a control flow graph (CFG) analysis
    #proj = angr.Project(binary_path, main_opts={'arch': 'ArchARMCortexM'})
    #cfg = proj.analyses.CFGFast()
    
    # Retrieve the corresponding node from the CFG for the given address
       # Iterate through all nodes in the CFG
    for node in cfg.graph.nodes():
        block_start = node.addr
        block_size = node.size
        block_end = block_start + block_size

        # Check if the address falls within the block
        if block_start <= addr < block_end:
            # Get the basic block associated with the node
            basic_block = proj.factory.block(block_start)

            print(f"Basic block found at address: {hex(addr)} where start is {hex(block_start-1)} with size {basic_block.size} bytes")
            return basic_block
        
    print(f"No basic block contains address {hex(addr)}")
    return None

'''
    node = cfg.get_any_node(addr)

    if node is None:
        print(f"No basic block found for address {hex(addr)}")
        return None
    else:
        print(f"Basic block found for address {hex(addr)}")

    # Get the basic block associated with the node
    basic_block = proj.factory.block(node.addr)

    return basic_block
'''
def check_occurence_trace_presence(current_address):
    
    exists = False
    non_zero = False


    for i, (key, value) in enumerate(occuerence_trace):
        if key == current_address:
            if value > 0:
                occuerence_trace[i] = (key, value - 1)  # Decrement the value
                non_zero = True
            exists = True
            break  # Exit loop after finding the key

    return exists, non_zero

def get_function_name_from_address(address):
    # Iterate over the symbols to find the function name for the given address
    address = address + 1
    for symbol in paresed_bin.symbols:
        #print(f"0x{hex(symbol.value)} symbol name {symbol.name}")
        if symbol.value == address:
            return symbol.name
    return None

def parse_occurence_trace(traceFile):
    if not os.path.isfile(traceFile):
        exit("The trace file '%s' not found" % (traceFile))
    else:
        print("The trace file '%s' exists" % (traceFile))
    with open(traceFile, "rb") as f:
        # Read the first 4 bytes to get the total number of elements
        total_elements_bytes = f.read(4)
        total_elements = struct.unpack(">I", total_elements_bytes)[0]  # Assuming unsigned int (4 bytes)
        print(hex(total_elements))

        # Loop through each key-value pair
        for _ in range(total_elements):
            # Read 4 bytes for the key
            address_bytes = f.read(4)
            address = struct.unpack(">I", address_bytes)[0]  # Assuming unsigned int (4 bytes)
            
            # Read 4 bytes for the value
            occuerence_count_bytes = f.read(4)
            occuerence_count = struct.unpack(">I", occuerence_count_bytes)[0]  # Assuming unsigned int (4 bytes)

            # Append the key-value pair to the list
            occuerence_trace.append((address, occuerence_count))
        for key, value in occuerence_trace:
            print(f"Key: 0x{key:08X}, Value: 0x{value:08X}")

def find_exit_points(cfg, node, visited):
    """
    Recursive function to find exit points in the CFG.
    """
    # If the node has already been visited, skip it
    if node.addr in visited:
        return
    
    visited.add(node.addr)
    
    # If a node has no successors, it's an exit point
    successors = cfg.get_successors(node)
    if not successors:
        exit_points.append(node.addr & ~1)
    else:
        # Recursively explore successors
        for successor in successors:
            find_exit_points(cfg, successor, visited)


def getExitBasicBlocks():

    # Load the binary into an angr project
    #project = angr.Project(binary_path, auto_load_libs=False)
    global proj
    proj = angr.Project(binary_path, main_opts={'arch': 'ArchARMCortexM'})
    print(proj.arch)
    print(hex(proj.entry))

    
    global cfg
    # Generate the CFG
    cfg = proj.analyses.CFGFast()
    main_function = cfg.kb.functions.function(name='main')
    print(f"Main function found at address: 0x{main_function.addr:x}")
    #entry_state = proj.factory.entry_state()
    entry_addr = main_function.addr
    entry_node = cfg.get_any_node(entry_addr)
    visited = set()

    find_exit_points(cfg, entry_node, visited)

    print("Program exit points:")
    for exit_point in set(exit_points):
        print(f"  0x{exit_point:x}")

    '''

    # Locate the main function by its name or entry address
    main_function = cfg.kb.functions.function(name='main')

    if main_function is None:
        print("Main function not found.")
    else:
        print(f"Main function found at address: 0x{main_function.addr:x}")

        # Iterate over all blocks in the main function
        for block in main_function.blocks:
            block_address = block.addr
            print(f"Block at 0x{block_address:x}:")
            block.pp()  # Pretty-print the block's instructions

        # Identify exit blocks
        exit_blocks = []
        for block in main_function.blocks:
            successors = cfg.get_successors(block.addr)
            if not successors:
                exit_blocks.append(block.addr)

        print("Exit blocks:")
        for exit_block in exit_blocks:
            print(f"  0x{exit_block:x}")
    '''
        
def get_function_code_section(function_name, currect_address):
    if not function_name or not currect_address:
        print("Function name or address empty")
        return None
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)

        symtab_section = elf.get_section_by_name('.symtab')
        if not symtab_section:
            print("No symbol table found in this ELF file.")
        else:
            # Find the 'main' function symbol
            #main_symbol = None
            for symbol in symtab_section.iter_symbols():
                if symbol.name == function_name:
                    function_symbol = symbol
                    break
            
            if not function_symbol:
                print("No 'main' function found in the symbol table.")
                return None
            else:
                function_addr = function_symbol['st_value']
                function_size = function_symbol['st_size']

                # Mask out the Thumb bit if present
                function_addr &= ~1

                print(f"{function_name} function found at 0x{function_addr:x}, size: {function_size}")
                current_offset = currect_address - function_addr
                # Locate the section containing the main function
                for section in elf.iter_sections():
                    if section['sh_addr'] <= function_addr < (section['sh_addr'] + section['sh_size']):
                        # Calculate offset within the section
                        offset = function_addr - section['sh_addr'] + current_offset
                        # Extract the code bytes for the main function
                        code = section.data()[offset:offset + function_size - current_offset]
                        print('Returning Code section of %s with currect address 0x%x' %(function_name, currect_address))
                        return code

def AbstractExec():
    # Open the binary file
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)

        # Look for the symbol table section
        symtab_section = elf.get_section_by_name('.symtab')
        if not symtab_section:
            print("No symbol table found in this ELF file.")
        else:
            # Find the 'main' function symbol
            main_symbol = None
            for symbol in symtab_section.iter_symbols():
                if symbol.name == 'main':
                    main_symbol = symbol
                    break
            
            if not main_symbol:
                print("No 'main' function found in the symbol table.")
            else:
                main_addr = main_symbol['st_value']
                main_size = main_symbol['st_size']

                # Mask out the Thumb bit if present
                main_addr &= ~1

                print(f"'main' function found at 0x{main_addr:x}, size: {main_size}")

                # Locate the section containing the main function
                for section in elf.iter_sections():
                    if section['sh_addr'] <= main_addr < (section['sh_addr'] + section['sh_size']):
                        # Calculate offset within the section
                        offset = main_addr - section['sh_addr']
                        # Extract the code bytes for the main function
                        code = section.data()[offset:offset + main_size]
                        
                        # Disassemble the 'main' function
                        for insn in md.disasm(code, main_addr):
                            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
                            
"""                             if(insn.mnemonic == "bl"):
                                target_address = insn.op_str  # The target address is usually in the operand string
                                print("Found a BL instruction at 0x%x, targeting function at %s" % (insn.address, target_address))
                                clean_target_str = target_address.lstrip('#')
                                target_int = int(clean_target_str, 16)
                                sim_func_call_return_stack.append(target_int)
                                print(get_function_name_from_address(target_int)) """
                            
                                #break

'''

def simulateEnolaInstructions():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM + sum(opts.cs_mode_flags))
    md.detail = True
    replay_start = False
    replay_stop = False
    taken = False
    target_address = 0
    trace = ExecutionTrace(opts.tracefile)
    trace_idx = 0
    stack = []
    ofd = open(opts.outfile,'w')
    last_flag = 'eq'
    last_ne_flag = False
    last_lt_flag = False

    with open(opts.binfile, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

        offset = opts.text_start - opts.load_address
        logging.debug("hooking %s from 0x%08x to 0x%08x" % (opts.binfile, offset, opts.text_end - opts.load_address))
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
                if (i.id == ARM64_INS_BL):
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
                    #print("unhandled inst")
                    #print_insn_detail(i)
                ## branch w/ link instruction; bl <pc relative offset>
                #elif (i.id == ARM64_INS_BL):
                #    pass

                ## branch w/ link while operand is register; blr x1
                #elif (i.id == ARM64_INS_BLR and len(i.operands) == 1 and i.operands[0].reg == ARM64_REG_X1):
                #    pass

                ## check for currently unhandled instructions
                #elif (i.id == ARM64_INS_BR):
                #    logging.warn("br    at 0x%08x: %-10s\t%s\t%s" %
                #            (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

                #elif (i.id == ARM64_INS_BLR):
                #    logging.warn("blr    at 0x%08x: %-10s\t%s\t%s" %
                #            (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

                #else:
                #    logging.debug("      0x%08x: %-10s\t%s\t%s" %
                #            (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

                #logging.debug("      0x%08x: %-10s\t%s\t%s" %
                #    (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

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

    return
'''

def recursive_traversing(program_counter, program_current_function):
    cmp_flag = False
    global depth_counter
    global depth_limit

    print('\n\n\nCurrent program counter: 0x%x belongs to function %s' %(program_counter, program_current_function))

    #while program_counter not in exit_points:
    if program_counter in exit_points:
        print("\nHit a program exit\n")
        return True

    if depth_counter >= depth_limit:
        print("\nHit deapth limit\n")
        return False
    if not program_counter:
        print('Function symbol not found for address 0x%x' %(program_counter))
        return False
    
    print(f"At depth {depth_counter}")
    depth_counter = depth_counter  + 1
    
    code = get_function_code_section(program_current_function, program_counter)
    if not code:
        print("Code in PC null")
        
    #start disassembling the function
    for insn in md.disasm(code, program_counter):
        print("At disasm 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

        exits, non_zero = check_occurence_trace_presence(insn.address)

        if(exits and non_zero == False):
            print("\n\n Need to skip basic block execution")
            #get_basic_block_from_addr(insn.address)
        elif (exits): #This is just for debug information
            print("\n\nFound in occuerence trace 0x%x\n\n" %(insn.address))

        if(insn.mnemonic == "bl"):
            target_address = insn.op_str  # The target address is usually in the operand string
            #print("Found a BL instruction at 0x%x, targeting function at %s" % (insn.address, target_address))
            clean_target_str = target_address.lstrip('#')
            target_int = int(clean_target_str, 16)
            
            target_function = get_function_name_from_address(target_int)
            #print(target_function)
            if(target_function not in omit_functions):
                print('Simulate the called function with return address: 0x%x' %(insn.address + insn.size))
                sim_func_call_return_stack.append(insn.address + insn.size)
                program_counter = target_int
                sim_func_call_names.append(program_current_function)
                program_current_function = target_function #update called function

                return recursive_traversing(program_counter, program_current_function)
            
        elif(insn.mnemonic == "b"):
            target_address = insn.op_str
            clean_target_str = target_address.lstrip('#')
            target_int = int(clean_target_str, 16)
            target_function = get_function_name_from_address(target_int)

            if not target_function:
                print('branch within')
                target_function = program_current_function

            #print(target_function)
            if(target_function not in omit_functions):
                print("branch to %s" % (target_address))
                #sim_func_call_return_stack.append(insn.address + insn.size)
                program_counter = target_int
                program_current_function = target_function #update called function

                return recursive_traversing(program_counter, program_current_function)
            
        elif insn.mnemonic in ["bx", "pop", "popge"] and ("lr" in insn.op_str or "pc" in insn.op_str):
            # Handle function return by checking common return instructions
            program_counter = sim_func_call_return_stack.pop()
            program_current_function = sim_func_call_names.pop()
            print(f"Detected function return instruction at 0x{insn.address:x}, return value 0x{hex(program_counter)}")
            return recursive_traversing(program_counter, program_current_function)

        # need to handle comparator branches
        elif insn.mnemonic == "cbz":
            print("Conditional branch instrcutions get denominators")
            node = cfg.get_any_node(insn.address)
            successors = cfg.get_successors(node)
            for successor in successors:
                cbz_successors.append(successor.addr - 1)

            print(f"CBZ at 0x{insn.address:x} has successors:")
            #need to call recursive function and traverse all paths, but should consult with trace first
            for succ in successors:
                print(f" - Successor at 0x{succ.addr - 1 :x}")
                return False or recursive_traversing(succ.addr - 1, program_current_function)

        elif insn.mnemonic == "cbnz":
            print("Conditional branch instrcutions get denominators")
            node = cfg.get_any_node(insn.address)
            successors = cfg.get_successors(node)
            for successor in successors:
                cbz_successors.append(successor.addr)

            print(f"CBNZ at 0x{insn.address:x} has successors:")
            #need to call recursive function and traverse all paths, but should consult with trace first
            for succ in successors:
                print(f" - Successor at 0x{succ.addr:x}")
                return False or recursive_traversing(succ.addr - 1, program_current_function)

        elif insn.mnemonic == "cmp":
            print("cmp instrcutions get denominators")
            #need to indentify successor branches, the problem is now the iit, popge instructions, 
            #if the next instruction were b.cond instructions than it angr will give you all successors.
            cmp_flag = True
            continue
            node = cfg.get_any_node(insn.address)
            successors = cfg.get_successors(node)
            for successor in successors:
                cbz_successors.append(successor.addr)
                
            print(f"cmp at 0x{insn.address:x} has successors:")
            for succ in successors:
                print(f" - Successor at 0x{succ.addr:x}")
        elif insn.mnemonic == "itt" and cmp_flag:
            cmp_flag = False
            print("\nhandling itt instructions\n")

            basic_block = get_basic_block_from_addr(insn.address)
            if(basic_block):
                print(f"Total size of occuerence basic blcok 0x{basic_block.size}")

                instructions = basic_block.capstone.insns

                # Get the number of instructions
                num_instructions = len(instructions)
                print(f"Total instructions in occuerence basic blcok 0x{num_instructions}")
                
                block_end = basic_block.addr + basic_block.size - 1
                next_in_itt = insn.address + 2
                next_bb_after_itt = block_end 
                print(f"block addr {hex(basic_block.addr)}, block end: {hex(block_end)} program counter moved to {hex(program_counter)}")
                
                currect_successors = []
                currect_successors.append(next_in_itt)
                currect_successors.append(next_bb_after_itt)
                print(f"below are the successor that goes into recursive functions")
                for succ in currect_successors:
                    print(f" - Successor at 0x{succ:x}")
                return recursive_traversing(insn.address + 2, program_current_function) or recursive_traversing(next_bb_after_itt, program_current_function)



def testIterativeMethod():
    program_current_function = 'main' #program_entry
    program_counter = 0x10000400
    cmp_flag = False
    #while program_counter not in exit_points:
    for x in range(10):
        print('\n\n\nCurrent program counter: 0x%x belongs to function %s' %(program_counter, program_current_function))

        if not program_counter:
            print('Function symbol not found for address 0x%x' %(program_counter))
        code = get_function_code_section(program_current_function, program_counter)
        
        #start disassembling the function
        for insn in md.disasm(code, program_counter):
            print("At disasm 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

            exits, non_zero = check_occurence_trace_presence(insn.address)
            if(exits and non_zero == False):
                print("\n\n Need to skip basic block execution")
                #get_basic_block_from_addr(insn.address)
            elif (exits): #This is just for debug information
                print("\n\nFound in occuerence trace 0x%x\n\n" %(insn.address))
                '''
                #NEED TO SKIP THE WHOLE BRANCH NOT JUST THE BASIC BLOCK
                basic_block = get_basic_block_from_addr(insn.address)
                if(basic_block):
                    print(f"Total size of occuerence basic blcok 0x{basic_block.size}")

                    instructions = basic_block.capstone.insns

                    # Get the number of instructions
                    num_instructions = len(instructions)
                    print(f"Total instructions in occuerence basic blcok 0x{num_instructions}")
                    
                    block_end = basic_block.addr + basic_block.size
                    print(f"block addr {hex(basic_block.addr)}, block end: {hex(block_end)}")
                    program_counter = block_end
                    continue
                    while insn.address < block_end:
                        print(f"current ins address: {hex(insn.address)} end : {hex(block_end)}")
                        try:
                            insn = next(md.disasm(code[insn.address - basic_block.addr:], insn.address))
                            #print(f"Skipping instruction : {hex(insn.address)}")
                        except StopIteration:
                            break  # Stop the loop if no more instructions

                    continue  # Skip to the next iteration after skipping the block '''

            #else:
            #    get_basic_block_from_addr(insn.address)
            #if the above retruns false need to skip the whole basic block

            if(insn.mnemonic == "bl"):
                target_address = insn.op_str  # The target address is usually in the operand string
                #print("Found a BL instruction at 0x%x, targeting function at %s" % (insn.address, target_address))
                clean_target_str = target_address.lstrip('#')
                target_int = int(clean_target_str, 16)
                
                target_function = get_function_name_from_address(target_int)
                #print(target_function)
                if(target_function not in omit_functions):
                    print('Simulate the called function with return address: 0x%x' %(insn.address + insn.size))
                    sim_func_call_return_stack.append(insn.address + insn.size)
                    program_counter = target_int
                    sim_func_call_names.append(program_current_function)
                    program_current_function = target_function #update called function
                    break
            # this may be incomplete: it should change the program_counter
            elif(insn.mnemonic == "b"):
                target_address = insn.op_str
                clean_target_str = target_address.lstrip('#')
                target_int = int(clean_target_str, 16)
                target_function = get_function_name_from_address(target_int)
                if not target_function:
                    print('branch within')
                    target_function = program_current_function
                #print(target_function)
                if(target_function not in omit_functions):
                    print("branch to %s" % (target_address))
                    #sim_func_call_return_stack.append(insn.address + insn.size)
                    program_counter = target_int
                    program_current_function = target_function #update called function
                    break
            elif insn.mnemonic in ["bx", "pop"] and ("lr" in insn.op_str or "pc" in insn.op_str):
                # Handle function return by checking common return instructions
                program_counter = sim_func_call_return_stack.pop()
                program_current_function = sim_func_call_names.pop()
                print(f"Detected function return instruction at 0x{insn.address:x}, return value 0x{hex(program_counter)}")
                break

            # need to handle comparator branches
            elif insn.mnemonic == "cbz":
                print("Conditional branch instrcutions get denominators")
                node = cfg.get_any_node(insn.address)
                successors = cfg.get_successors(node)
                for successor in successors:
                    cbz_successors.append(successor.addr - 1)

                print(f"CBZ at 0x{insn.address:x} has successors:")
                #need to call recursive function and traverse all paths, but should consult with trace first
                for succ in successors:
                    print(f" - Successor at 0x{succ.addr - 1 :x}")

            elif insn.mnemonic == "cbnz":
                print("Conditional branch instrcutions get denominators")
                node = cfg.get_any_node(insn.address)
                successors = cfg.get_successors(node)
                for successor in successors:
                    cbz_successors.append(successor.addr)

                print(f"CBNZ at 0x{insn.address:x} has successors:")
                #need to call recursive function and traverse all paths, but should consult with trace first
                for succ in successors:
                    print(f" - Successor at 0x{succ.addr:x}")

            elif insn.mnemonic == "cmp":
                print("cmp instrcutions get denominators")
                #need to indentify successor branches, the problem is now the iit, popge instructions, 
                #if the next instruction were b.cond instructions than it angr will give you all successors.
                cmp_flag = True
                continue
                node = cfg.get_any_node(insn.address)
                successors = cfg.get_successors(node)
                for successor in successors:
                    cbz_successors.append(successor.addr)
                    
                print(f"cmp at 0x{insn.address:x} has successors:")
                for succ in successors:
                    print(f" - Successor at 0x{succ.addr:x}")
            elif insn.mnemonic == "itt" and cmp_flag:
                cmp_flag = False
                print("\nhandling itt instructions\n")

                basic_block = get_basic_block_from_addr(insn.address)
                if(basic_block):
                    print(f"Total size of occuerence basic blcok 0x{basic_block.size}")

                    instructions = basic_block.capstone.insns

                    # Get the number of instructions
                    num_instructions = len(instructions)
                    print(f"Total instructions in occuerence basic block 0x{num_instructions}")
                    
                    block_end = basic_block.addr + basic_block.size - 1
                    program_counter = block_end 
                    print(f"block addr {hex(basic_block.addr)}, block end: {hex(block_end)} program counter moved to {hex(program_counter)}")
                    
                    currect_successors = []
                    currect_successors.append(insn.address)
                    currect_successors.append(program_counter)
                    print(f"below are the successor that goes into recursive functions")
                    for succ in currect_successors:
                        print(f" - Successor at 0x{succ:x}")
                    break



def main():
    parse_occurence_trace('trace')
    #current_address = 0x1000041c
    #code = get_function_code_section('crc32pseudo', current_address)
    #for insn in md.disasm(code, current_address):
    #                        print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
    

    getExitBasicBlocks()
    #get_basic_block_from_addr(0x10000440)
    #AbstractExec()
    #func = get_function_name_from_address( 0x1000049a)
    #print(func)
    #testIterativeMethod()
    recursive_traversing(0x10000400, 'main')

    print(occuerence_trace)
    print('\n\nThe simulated stack state:')
    for n in sim_func_call_return_stack:
        print(hex(n))

    

if __name__ == "__main__":
    main()