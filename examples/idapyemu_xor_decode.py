#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *
        
textstart = SegByName(".text")
textend = SegEnd(textstart)

def my_stack_arg(emu, address):
    print "%x" % (emu.get_stack_variable(0x0))
    print "%x" % (emu.get_stack_variable(0x4))
    print "%x" % (emu.get_stack_variable(0x8))
    print "%x" % (emu.get_stack_variable(0xc))
    print "%x" % (emu.get_stack_variable(0x10))
    print "%x" % (emu.get_stack_variable(0x14))
    
    return True
    
def my_pc_handler(emu, address):
    print "%c" % (emu.get_register("bl"))
    
    return True

def my_pc_handler2(emu, address):
    emu.dump_regs()
    print "-> %c" % (emu.get_register("cl"))
    
    return True

def my_pc_handler3(emu, address):
    emu.dump_regs()
    
    return True
        
emu = IDAPyEmu()
emu.debug(0)
#emu.set_pc_handler(0x00401C62, my_pc_handler)
#emu.set_pc_handler(0x004017E7, my_pc_handler2)
#emu.set_pc_handler(0x004017EA, my_pc_handler3)
emu.set_pc_handler(0x004018A2, my_stack_arg)

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

emu.execute(start=0x004017DC, end=0x004018B8)
address = emu.get_register("EDX")
data = emu.get_memory(address, size=45)

print repr(data)
print "[*] Done"