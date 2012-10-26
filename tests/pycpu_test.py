#!/usr/bin/env python

import sys

sys.path.append(r'c:\code\python\pyemu')
sys.path.append(r'c:\code\python\pyemu\lib')

import pydasm

from PyCPU import *
from PyDebug import *

class PyEmu:
    def __init__(self):
        self.register_handlers = []
        self.memory_handlers = []
        self.stack_base = 0x15000000
    def memory_access_handler(self, *args):
        return False
    
    def memory_write_handler(self, *args):
        return False
    
    
rawinstruction = "\x66\x89\x45\xF6"
instruction = pydasm.get_instruction(rawinstruction, pydasm.MODE_32)
pyinstruction = PyInstruction(instruction)

#DebugInstruction(pyinstruction)

emu = PyEmu()
cpu = PyCPU(emu)
cpu.set_debug(0)
cpu.EDX = 0xfe

print "EAX: 0x%08x EDX: 0x%08x" % (cpu.EAX, cpu.EDX)
print "Executing [%s]..." % pyinstruction.disasm,

# An oversight in pydasm mnemonic parsing
pyinstruction.mnemonic = pyinstruction.mnemonic.split()
if pyinstruction.mnemonic[0] in ["rep", "repe", "repne", "lock"]:
    pyinstruction.mnemonic = pyinstruction.mnemonic[1]
else:
    pyinstruction.mnemonic = pyinstruction.mnemonic[0]

# Check if we support this instruction
if pyinstruction.mnemonic in cpu.supported_instructions:
    # Execute!
    if not cpu.supported_instructions[pyinstruction.mnemonic](pyinstruction):
        sys.exit(-1)
else:
    print "[!] Unsupported instruction %s" % pyinstruction.mnemonic
    sys.exit(-1)
    
print "Done"
print "EAX: 0x%08x EDX: 0x%08x" % (cpu.EAX, cpu.EDX)
