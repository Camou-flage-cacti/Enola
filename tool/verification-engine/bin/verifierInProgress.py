from elftools.elf.elffile import ELFFile
from capstone import *
import angr

# Specify the path to the ELF binary
binary_path = 'Blinky.axf'

# Initialize the Capstone disassembler for ARM (Thumb mode, suitable for Cortex-M33)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

exit_points = []

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
        exit_points.append(node.addr)
    else:
        # Recursively explore successors
        for successor in successors:
            find_exit_points(cfg, successor, visited)


def getExitBasicBlocks():

    # Load the binary into an angr project
    #project = angr.Project(binary_path, auto_load_libs=False)
    proj = angr.Project(binary_path, main_opts={'arch': 'ArchARMCortexM'})
    print(proj.arch)
    print(hex(proj.entry))

    

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
                if symbol.name == 'crc32pseudo':
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
                        break


def main():
    #AbstractExec()
    getExitBasicBlocks()

if __name__ == "__main__":
    main()