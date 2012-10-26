#!/usr/bin/env python

import sys

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

def my_register_handler(emu, register, value, type):
    print "[*] my_register_handler(%s, %x, %s)" % (register, value, type)
    
    return True

def my_mnemonic_handler(emu, mnemonic, address, op1value, op2value, op3value):
    print "[*] my_mnemonic_handler(%s, 0x%08x," % (mnemonic, address),
    print op1value,
    print op2value,
    print op3value,
    print ")"
    
    return True

def my_opcode_handler(emu, opcode, address, op1value, op2value, op3value):
    print "[*] my_opcode_handler(%x, 0x%08x," % (opcode, address),
    print op1value,
    print op2value,
    print op3value,
    print ")"
    
    return True

def my_pc_handler(emu, address):
    print "[*] my_pc_handler(0x%08x)" % (address)
    
    return True
    
def my_memory_handler(emu, address, value, size, type):
    print "[*] my_memory_handler(0x%08x, %x, %x, %s)" % (address, value, size, type)
    
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

# This tests register handlers
# 32
emu.set_register_handler("eax", my_register_handler)
emu.set_register_handler("ecx", my_register_handler)
emu.set_register_handler("edx", my_register_handler)
emu.set_register_handler("ebx", my_register_handler)
emu.set_register_handler("edi", my_register_handler)
emu.set_register_handler("esi", my_register_handler)
emu.set_register_handler("esp", my_register_handler)
emu.set_register_handler("ebp", my_register_handler)
emu.set_register_handler("eip", my_register_handler)
# 16
emu.set_register_handler("ax", my_register_handler)
emu.set_register_handler("cx", my_register_handler)
emu.set_register_handler("dx", my_register_handler)
emu.set_register_handler("bx", my_register_handler)
emu.set_register_handler("di", my_register_handler)
emu.set_register_handler("si", my_register_handler)
emu.set_register_handler("sp", my_register_handler)
emu.set_register_handler("bp", my_register_handler)
# 8
emu.set_register_handler("ah", my_register_handler)
emu.set_register_handler("al", my_register_handler)
emu.set_register_handler("ch", my_register_handler)
emu.set_register_handler("cl", my_register_handler)
emu.set_register_handler("dh", my_register_handler)
emu.set_register_handler("dl", my_register_handler)
emu.set_register_handler("bh", my_register_handler)
emu.set_register_handler("bl", my_register_handler)

# This tests mnemonic handlers
emu.set_mnemonic_handler("mov", my_mnemonic_handler)
emu.set_mnemonic_handler("push", my_mnemonic_handler)
emu.set_mnemonic_handler("retn", my_mnemonic_handler)
emu.set_mnemonic_handler("test", my_mnemonic_handler)
emu.set_mnemonic_handler("add", my_mnemonic_handler)

# This tests opcode handlers
emu.set_opcode_handler(0x8b, my_opcode_handler)

# This tests the pc handlers
emu.set_pc_handler(0x0100BD73, my_pc_handler)
emu.set_pc_handler(0x0100BD77, my_pc_handler)
emu.set_pc_handler(0x01011A1F, my_pc_handler)

# This tests memory handlers
#emu.set_memory_access_handler(my_memory_access_handler)
emu.set_memory_handler(0x44444444, my_memory_handler)

# This sets our stack values for the function
emu.set_stack_argument(0x8, 0x44444444, name="arg_0")
emu.set_stack_argument(0xc, 0x55555555, name="arg_4")
emu.set_stack_argument(0x10, 0x66666666, name="arg_8")
emu.set_stack_argument(0x14, 0x77777777, name="arg_c")

emu.set_stack_variable(0x4, 0x11111111, name="var_4")
emu.set_stack_variable(0x8, 0x22222222, name="var_8")
emu.set_stack_variable(0xc, 0x33333333, name="var_C")
#emu.set_stack_variable(0x10, 0x44444444, name="var_10")
#emu.set_stack_variable(0x14, 0x55555555, name="var_14")
#emu.set_stack_variable(0x18, 0x66666666, name="var_18")
#emu.set_stack_variable(0x1c, 0x77777777, name="var_1C")
#emu.set_stack_variable(0x20, 0x88888888, name="var_20")

# Dont start at the top of the function, the prolog will be fucked
emu.execute(start=0x0100BD70, end=0x0100BD80)

emu.dump_regs()
emu.dump_stack()

print "[*] Done"