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

gate_bits_mask = ~((1<<0) | (1<<1) | (1<<2) | 0x200)

def check_gate_criteria(value):
    masked = value & gate_bits_mask
    return masked == 0

def check_entry_criteria(value):
    result = False
    if ((value & 0xFF) == 0x36 and (value & 0xFF0000) == 0x00):
        result = True
    return result

table_entry = namedtuple("table_entry", ["table_address", "function_address", "queue_id", "message_id"])

# detect all valid table entries in the firmware
# by 1) detecting a valid gate_bit signature
# then 2) looking at the referenced address for a valid "entry" instruction signature
#
# most importantly this WONT detect empty/unimplemented message handlers!
def detect_table_entries():
    entries = []

    for i in range(0, len(firmware), 8):
        if i + 8 > len(firmware):
            break

        gate_bits = get_value(i)
        func_address = get_value(i+4)

        if(check_gate_criteria(gate_bits) and func_address < len(firmware)-4):
            opcode = get_value(func_address)
            if(check_entry_criteria(opcode)):
                entries.append(table_entry(i, func_address, -1, -1))
    
    return entries

# just print the detected entries
def print_table_entries(entries):
    print("table entry func addr.  symbol")
    for entry in entries:
        phi(entry.table_address)
        print(' ',end='')
        phi(entry.function_address)
        print(' ', end='')

        func = functions.getFunctionAt(toAddr(entry.function_address))
        if func is not None:
            print(func.getName())
        else:
            print("Missing Function at ", end='')
            ph(entry.function_address)


def build_queue_table(queue_table_address, queue_table_entry_count):
    queue_table = []
    for i in range(queue_table_address, queue_table_address + queue_table_entry_count*4, 4):
        pointer = get_value(i)
        if pointer not in queue_table:
            queue_table.append(pointer)
    return queue_table

# orders table entries by the queue the belong to.
# a valid mehtod to find the queue table is to go to the start of the frist message entry and find an XREF to it in ghidra
# the XREF is usually to the entry address - 4 TODO: figure out why
# e.g. if the entry starts at 0x7070, the table points to 0x706c 
#
# most importantly this WILL also detect empty/unimplemented message handlers and will result in correct message ids
# and allow them to be aligned against kernel source etc
def detect_with_queue_table(queue_table):
    entries = []
    queue_id = 0
    # we take every element except the last one because we can not know how many messages it has
    for queue in queue_table[:-1]:
        next_queue = queue_table[queue_id + 1]
        message_id = 1
        for i in range(queue + 4, len(firmware), 8):
            if i + 8 > len(firmware):
                break

            if i - 4 == next_queue:
                break
            
            gate_bits = get_value(i)
            func_address = get_value(i+4)

            # quick fix: do not check gate criteria when we already know that the entry is valid from the queue table
            # this helps with newer smu firmware
            #if(check_gate_criteria(gate_bits) and func_address < len(firmware)-4):
            opcode = get_value(func_address)
            if(check_entry_criteria(opcode)):
                entries.append(table_entry(i, func_address, queue_id, message_id))
            else:
                entries.append(table_entry(i, 0x00, queue_id, message_id)) #this is a reserved entry

            message_id = message_id + 1

        queue_id = queue_id + 1

    # the take every element in the last queue unti we encounter an invalid gate criteria... this is not ideal FIXME
    queue = queue_table[-1]
    message_id = 1
    for i in range(queue + 4, len(firmware), 8):
        if i + 8 > len(firmware):
            break
            
        gate_bits = get_value(i)
        func_address = get_value(i+4)

        # the quick fix from above wont work in this scenario... this is not ideal FIXME
        if(check_gate_criteria(gate_bits) and func_address < len(firmware)-4):
            opcode = get_value(func_address)
            if(check_entry_criteria(opcode)):
                entries.append(table_entry(i, func_address, queue_id, message_id))
            else:
                entries.append(table_entry(i, 0x00, queue_id, message_id)) #this is a reserved entry
        else:
            break

        message_id = message_id + 1

    return entries
            
 # just print the detected entries 
def print_table_entries_with_queue_table(entries):

    cur_queue = -1
    for entry in entries:
        if entry.queue_id != cur_queue:
            print(f"Start of Queue {entry.queue_id}")
            print("msgid  table entry func addr.  symbol")
            cur_queue = entry.queue_id
        print(' ',end='')
        phi2(entry.message_id)
        print(' ',end='')
        phi(entry.table_address)
        print(' ',end='')
        phi(entry.function_address)
        print(' ', end='')

        if entry.function_address != 0:
        
            func = functions.getFunctionAt(toAddr(entry.function_address))
            if func is not None:
                print(func.getName())
            else:
                print("Missing Function at ", end='')
                ph(entry.function_address)    
        else:
            print("No Handler / Reserved")         

queue_table_exists = False
queue_table_address = 0
queue_table_entries = 0

for sym in symbols.getAllSymbols(True):
    if "queue_table_" in sym.getName().lower():
        queue_table_exists = True
        queue_table_address = sym.getAddress().offset
        queue_table_entries = int(sym.getName().rsplit("_", 1)[-1])

if not queue_table_exists:
    entries = detect_table_entries()
    print_table_entries(entries)
else: 
    table = build_queue_table(queue_table_address, queue_table_entries)
    entries = detect_with_queue_table(table)
    print_table_entries_with_queue_table(entries)
