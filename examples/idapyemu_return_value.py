#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

def reset_stack(emu, value1, value2, value3):
    emu.set_stack_argument(0x8, value1, name="arg_0")
    emu.set_stack_argument(0xc, value2, name="arg_4")
    emu.set_stack_argument(0x10, value3, name="arg_8")

    return True
    
def my_ret_handler(emu, address):
    global count
    
    value1 = emu.get_stack_argument("arg_0")
    value2 = emu.get_stack_argument("arg_4")
    value3 = emu.get_stack_argument("arg_8")
    
    print "[*] Returning %x: %x, %x, %x = %x" % (address, value1, value2, value3, emu.get_register("EAX"))

    reset_stack(emu, value1 + 1, value2 + 2, value3 + 3)
    emu.set_register("EIP", ScreenEA())
    
    count += 1
        
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

# This sets our stack values for the function
reset_stack(emu, 0x00000000, 0x00000001, 0x00000002)

# Set up our memory access handler
emu.set_mnemonic_handler("ret", my_ret_handler)

count = 0
while count <= 10:
    if not emu.execute():
        break

print "[*] Done"