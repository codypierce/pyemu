#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

def my_cmp_handler(emu, address, op1, op2, op3):
    print "[*] Hit my_cmp_handler %x: %s (%x, %x)" % (address, emu.get_disasm(), op1, op2)
    
    return True

textstart = SegByName(".text")
textend = SegEnd(textstart)

emu = IDAPyEmu()

print "[*] Loading text section bytes into memory"

currenttext = textstart
while currenttext <= textend:
    emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
    currenttext += 1

print "[*] Text section loaded into memory"

datastart = SegByName(".data")
dataend = SegEnd(datastart)

print "[*] Loading data section bytes into memory"

currentdata = datastart
while currentdata <= dataend:
    emu.set_memory(currentdata, GetOriginalByte(currentdata), size=1)
    currentdata += 1

print "[*] Data section loaded into memory"

# Start the program counter at the current location in the disassembly window
emu.set_register("EIP", ScreenEA())

# This demonstrates setting local variables used in our comparisons
emu.set_stack_variable(0x2c, 0x00000000, name="var_2C")
emu.set_stack_variable(0x1d, 0x00000001, name="var_1D")
emu.set_stack_variable(0x1e, 0x00000002, name="var_1E")

# Set up our memory access handler
emu.set_mnemonic_handler("cmp", my_cmp_handler)

emu.execute(start=0x00427E43, end=0x00427E6B, steps=10)

print "[*] Done"