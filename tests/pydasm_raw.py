#!/usr/bin/env python

import sys

sys.path.append("..")
sys.path.append("../lib")

import pydasm

from PyDebug import *
from PyInstruction import *

class PyEmu:
    def __init__(self):
        self.register_handlers = []

# jmp [ebx*4+0x4fcf0c]
rawinstruction = "\xFF\x24\x9D\x0C\xCF\x4F\x00"
# jmp ds:off_77E7AB5E[eax*4]
rawinstruction = "\xFF\x24\x85\x5E\xAB\xE7\x77"
# xor edi, dword ptr dwKeyArray[ecx*4]
rawinstruction = "\x33\x7C\x8D\x48\x19\x03\x00"
# movsx edx, eax
rawinstruction = "\x0f\xbe\xc2"

instruction = pydasm.get_instruction(rawinstruction, pydasm.MODE_32)
pyinstruction = PyInstruction(instruction)

print "[*] %s" % pyinstruction.disasm
DebugInstruction(pyinstruction)