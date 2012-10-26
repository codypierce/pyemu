#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

def my_breakpoint_handler(emu):
    print "[*] Hit my handler @ %x" % emu.get_register("EIP")
    
    return True

def my_memory_write_handler(emu, address, value, size):
    print "[*] Hit my_memory_write_handler(%x, %x, %x)" % (address, value, size)
    
    return True

def my_memory_access_handler(emu, address, value, size, type):
    print "[*] Hit my_memory_access_handler %x: %s (%x, %x, %x, %s)" % (emu.get_register("EIP"), emu.get_disasm(), address, value, size, type)

    return True

def my_stack_access_handler(emu, address, value, size, type):
    print "[*] Hit my_stack_access_handler %x: %s (%x, %x, %x, %s)" % (emu.get_register("EIP"), emu.get_disasm(), address, value, size, type)

    return True

def my_cmp_handler(emu, op1, op2, op3):
    print "[*] Hit my_cmp_handler %x: %s (%x, %x)" % (emu.get_register("EIP"), emu.get_disasm(), op1, op2)
    
    return True

def my_eax_handler(emu, value, type):
    print "[*] Hit my_eax_handler %x: %s (EAX, %x, %s)" % (emu.get_register("EIP"), emu.get_disasm(), value, type)
    
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

emu.set_register("EIP", ScreenEA())

#emu.set_memory(emu.cpu.EBP - 40, 0x41424344)
#emu.set_stack_variable(40, 0x12345678, name="var_28")
#emu.set_stack_argument(8, 0xaabbccdd, name="arg_0")

#emu.set_memory(0x41414141, "ABCDEFGHIJKLMNOP")

# Handler tests
#emu.set_breakpoint(0x00427E7A, my_breakpoint_handler)
#emu.set_memory_write_handler(my_memory_write_handler)
#emu.set_memory_access_handler(my_memory_access_handler)
#emu.set_stack_access_handler(my_stack_access_handler)
#emu.set_mnemonic_handler("cmp", my_cmp_handler)
#emu.set_register_handler("eax", my_eax_handler)

emu.execute(steps=8)

#steps = 0
#while steps <= 10:
#    emu.execute()
#    #print "%x" % emu.get_stack_variable("var_28")
#    #print "%x" % emu.get_stack_argument("arg_0")
#    steps += 1

#print repr(emu.get_memory(0x41414141, size=6))
    
#emu.cpu.dump_regs()

print "[*] Done"