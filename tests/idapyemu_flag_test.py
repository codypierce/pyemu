#!/usr/bin/env python

import sys

sys.path.append(r'c:\code\python\pyemu')
sys.path.append(r'c:\code\python\pyemu\lib')

from PyEmu import IDAPyEmu

textstart = SegByName(".text")
textend = SegEnd(textstart)

ea = ScreenEA()

emu = IDAPyEmu()

print "[*] Loading text section bytes into memory"

currenttext = textstart
while currenttext <= textend:
    emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
    currenttext += 1

print "[*] Text section loaded into memory"

emu.set_register("EIP", ea)
emu.set_register("EAX", 0x1)
emu.set_register("EDX", 0x2)
emu.debug(1)

emu.cpu.dump_regs()
emu.execute(steps=1)
emu.cpu.dump_regs()