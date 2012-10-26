#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

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

# This sets our stack values for the function
emu.set_stack_argument(0x8, 0x99999999, name="arg_0")
emu.set_stack_argument(0xc, 0xaaaaaaaa, name="arg_4")

emu.set_stack_variable(0x4, 0x11111111, name="var_4")
emu.set_stack_variable(0x8, 0x22222222, name="var_8")
emu.set_stack_variable(0xc, 0x33333333, name="var_C")
emu.set_stack_variable(0x10, 0x44444444, name="var_10")
emu.set_stack_variable(0x14, 0x55555555, name="var_14")
emu.set_stack_variable(0x18, 0x66666666, name="var_18")
emu.set_stack_variable(0x1c, 0x77777777, name="var_1C")
emu.set_stack_variable(0x20, 0x88888888, name="var_20")

#calc.exe
#emu.execute(start=0x0100BD6F, end=0x0100BD8A)

#retroclient.exe
#emu.execute(start=0x0041E190, end=0x0041E214)
emu.execute(start=0x0041E190, steps=1000)

print "[*] Done"