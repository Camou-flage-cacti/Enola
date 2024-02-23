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


out_metadata_path = os.getcwd()

filename = "Blinkey.axf"

output_ibt_json = out_metadata_path + filename + ".json"

edge_table = analyze_on_target(
            filename, out_metadata_path).edge_table

analyze_on_target(filename, out_metadata_path).write_json(
            output_ibt_json)