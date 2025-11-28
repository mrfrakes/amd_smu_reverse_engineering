# make sure that the header (size 0x100) is removed from raw firmware
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# The Actual Script

from ghidra.program.model.address import Address
from ghidra.app.script import GhidraScript

import struct
import sys
from collections import namedtuple

program = getCurrentProgram()
path = program.getExecutablePath()
functions = program.getFunctionManager()
symbols = program.getSymbolTable()

# load the firmware from the binary file directly
# this can be done with ghidras own functions but the api is too complicated for me...
# we assume that firmware starts at 0x0, so make sure to remove the header (0x100)
with open(path, "rb") as f:
        firmware = list(f.read())


def ph(value):
    print(f"0x{value:08X}")

def phi(value):
    print(f"0x{value:08X} ", end='')

def phi2(value):
    print(f"0x{value:02X} ", end='')

def get_value(address):
    values = bytes(firmware[address:address+4])
    return struct.unpack("<I", values)[0]


def check_entry_criteria(value):
    result = False
    if ((value & 0xFF) == 0x36 and (value & 0xFF0000) == 0x00):
        result = True
    return result

table_entry = namedtuple("table_entry", ["table_address", "function_address", "queue_id", "message_id"])

def detect_functions():
    entries = []

    for i in range(0, len(firmware), 4):
        if i + 4 > len(firmware):
            break

        opcode = get_value(i)

        if(check_entry_criteria(opcode)):
            entries.append(table_entry(i, i, -1, -1))
    
    return entries

# just print the detected entries
def print_table_entries(entries):
    print("table entry func addr.  symbol")
    for entry in entries:
        func = functions.getFunctionAt(toAddr(entry.function_address))
        if func is None:
            print("Missing Function at ", end='')
            ph(entry.function_address)
            


print_table_entries(detect_functions())