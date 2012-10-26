#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *
        
textstart = SegByName(".text")
textend = SegEnd(textstart)

emu = IDAPyEmu()
emu.debug(1)

print "[*] Loading text section bytes into memory"

currenttext = textstart
while currenttext <= textend:
    emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
    currenttext += 1

print "[*] Text section loaded into memory"

emu.set_register("EIP", ScreenEA())
emu.set_register("ECX", 0x2)

print "[*] Starting emulation at 0x%08x" % (emu.get_register("EIP"))

emu.dump_regs()
emu.execute(steps=5)
emu.dump_regs()

print "[*] Ending emulation at 0x%08x" % (emu.get_register("EIP"))
print "[*] Finished!"