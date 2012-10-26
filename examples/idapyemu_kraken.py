#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\pyemu')
sys.path.append(r'C:\Code\Python\pyemu\lib')

from PyEmu import *

textstart = SegByName(".code")
textend = SegEnd(textstart)

emu = IDAPyEmu()
emu.debug(0)

print "[*] Loading text section bytes into memory"

currenttext = textstart
while currenttext <= textend:
    emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
    currenttext += 1

print "[*] Text section loaded into memory"
fh = open('c:\\kraken.asm', 'w')

emu.set_register("EIP", ScreenEA())
for x in range(0, textend - textstart):
    if not emu.execute():
        break
        
    d = emu.get_disasm()
    print "0x%08x: %s" % (emu.get_register("EIP"), d)
    fh.write("0x%08x: %s\n" % (emu.get_register("EIP"), d))
    
fh.close()

# Open a file to dump the decoded bytes
#fh = open('c:\\kraken.vxe', 'wb+')
#print "[*] Fetching 0x%08x - 0x%08x [0x%08x]" % (textstart, textend, textend - textstart)
#data = emu.get_memory(textstart, textend - textstart)
#fh.write(data)
#fh.close()