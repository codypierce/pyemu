#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

def my_memory_access_handler(emu, address, value, size, type):
    print "[*] Hit my_memory_access_handler %x: %s (%x, %x, %x, %s)" % (emu.get_register("EIP"), emu.get_disasm(), address, value, size, type)

    return True

emu = IDAPyEmu()

textstart = SegByName(".text")
textend = SegEnd(textstart)

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

# Set up our memory access handler
emu.set_memory_access_handler(my_memory_access_handler)

# Whether we want to fault on bad memory access (default True)
emu.memory.fault = False

emu.execute(start=0x0100BD72, end=0x0100BD79)

print "[*] Done"