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

from ibt_analysis import *
import angr

out_metadata_path = os.getcwd()+'/'

file_path = 'bin/Blinky.axf'

output_ibt_json = out_metadata_path + file_path + ".json"

# Check if the file exists
if os.path.exists(file_path):
    print(f"The file '{file_path}' exists.")
else:
    print(f"The file '{file_path}' does not exist.")

#proj = angr.Project(file_path, main_opts={'arch': 'ArchARMCortexM'})
#arch = archinfo.ArchARM(archinfo.Endness.LE)
#proj = angr.Project(file_path, arch=arch)
#proj = angr.Project(file_path, auto_load_libs=False)
#print("Angr project created")
##print(proj.arch)
#print(hex(proj.entry))
edge_table = analyze_on_target(
            file_path, out_metadata_path).edge_table

analyze_on_target(file_path, out_metadata_path).write_json(
            output_ibt_json)