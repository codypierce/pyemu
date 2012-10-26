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

emu.set_register("EIP", 0x00427E77)
#emu.cpu.EBP = 0x0095f700
#emu.cpu.ESP = 0x0095f6f8

emu.set_memory(emu.cpu.EBP - 40, 0x41424344)

while emu.get_register("EIP") <= 0x00427F1E:
    #emu.cpu.dump_regs()
    #emu.cpu.dump_stack(32)

    if not emu.execute():
        print "[!] Problem executing"
        break

result = emu.get_memory(emu.cpu.EBP - 36, size=4)

print "[*] Found %x == %x" % (testme, result)