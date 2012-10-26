#!/usr/bin/env python

########################################################################
#
# PyEmu: scriptable x86 emulator
#
# Cody Pierce - cpierce@tippingpoint.com - 2007
#
# License: None
#
########################################################################

import sys, os, time, struct, re

sys.path.append("lib")

import pydasm

'''
PyOperand:
    
    Stores information about a single operand.  We duplicate pydasm
    information in case one day we want to replace it.
'''
class PyOperand:
    def __init__(self, operand):
        self.type = 0x0
        self.reg = 0x0
        self.basereg = 0x0
        self.indexreg = 0x0
        self.scale = 0x0
        self.dispbytes = 0x0
        self.dispoffset = 0x0
        self.immbytes = 0x0
        self.immoffset = 0x0
        self.sectionbytes = 0x0
        self.section = 0x0
        self.displacement = 0x0
        self.immediate = 0x0
        self.flags = 0x0
        
        # Set up the operand information
        self.set_operand(operand)
    
    #
    # set_operand: Responsible for initializing the operands values from pydasm
    #    
    def set_operand(self, operand):
        self.type = operand.type
        self.reg = operand.reg
        self.basereg = operand.basereg
        self.indexreg = operand.indexreg
        self.scale = operand.scale
        self.dispbytes = operand.dispbytes
        self.dispoffset = operand.dispoffset
        self.immbytes = operand.immbytes
        self.immoffset = operand.immoffset
        self.sectionbytes = operand.sectionbytes
        self.section = operand.section
        self.displacement = operand.displacement
        self.immediate = operand.immediate
        self.flags = operand.flags

'''
PyInstruction:
    
    Contains information about each instruction including opcode and
    operands.  We duplicate pydasm information in case one day we want
    to replace it.
'''                       
class PyInstruction:
    def __init__(self, instruction):
        self.length = 0x0
        self.type = 0x0
        self.mode = 0x0
        self.opcode = 0x0
        self.modrm = 0x0
        self.sib = 0x0
        self.extindex = 0x0
        self.fpuindex = 0x0
        self.dispbytes = 0x0
        self.immbytes = 0x0
        self.sectionbytes = 0x0
        self.flags = 0x0
        
        self.disasm = ""
        self.mnemonic = ""
        self.op1 = ""
        self.op2 = ""
        self.op3 = ""

        # Set up our instruction values
        self.set_instruction(instruction)
    
    def group1(self):
        return bool(self.flags & 0xff000000)
    
    def group2(self):
        return bool(self.flags & 0x00ff0000)
    
    def group3(self):
        return bool(self.flags & 0x0000ff00)

    def lock(self):
        return bool(self.flags & 0x01000000)
    
    def repne(self):
        return bool(self.flags & 0x02000000)
    
    def rep(self):
        return bool(self.flags & 0x03000000)
        
    def repe(self):
        return bool(self.flags & 0x03000000)
    
    def es_override(self):
        return bool(self.flags & 0x00010000)
    
    def cs_override(self):
        return bool(self.flags & 0x00020000)
    
    def ss_override(self):
        return bool(self.flags & 0x00030000)
    
    def ds_override(self):
        return bool(self.flags & 0x00040000)
    
    def fs_override(self):
        return bool(self.flags & 0x00050000)
    
    def gs_override(self):
        return bool(self.flags & 0x00060000)
    
    def operand_so(self):
        return bool(self.flags & 0x00000100)
    
    def address_so(self):
        return bool(self.flags & 0x00001000)
        
    def get_rm(self):
        if self.modrm:
            return self.modrm & 0x7
        else:
            return False
        
        return False
    
    def get_reg_opcode(self):
        if self.modrm:
            return (self.modrm >> 3) & 0x7
        else:
            return False    
        
        return False
    
    def get_mod(self):
        if self.modrm:
            return (self.modrm >> 6) & 0x7
        else:
            return False
        
        return False

    def get_base(self):
        if self.sib:
            return self.sib & 0x7
        else:
            return False
        
        return False
        
    def get_index(self):
        if self.sib:
            return (self.sib >> 3) & 0x7
        else:
            return False
        
        return False
    
    def get_scale(self):
        if self.sib:
            return (self.sib >> 6) & 0x7
        else:
            return False
        
        return False   
	
	#
	# set_instruction: Initializes the class members from pydasm
	#
    def set_instruction(self, instruction):
        self.length = instruction.length
        self.type = instruction.type
        self.mode = instruction.mode
        self.opcode = instruction.opcode
        self.modrm = instruction.modrm
        self.sib = instruction.sib
        self.extindex = instruction.extindex
        self.fpuindex = instruction.fpuindex
        self.dispbytes = instruction.dispbytes
        self.immbytes = instruction.immbytes
        self.sectionbytes = instruction.sectionbytes
        self.flags = instruction.flags
        
        if instruction.op1.type:
            self.op1 = PyOperand(instruction.op1)
            
        if instruction.op2.type:
            self.op2 = PyOperand(instruction.op2)
            
        if instruction.op3.type:
            self.op3 = PyOperand(instruction.op3)
        
        # Disassembly string of instruction
        self.disasm = pydasm.get_instruction_string(instruction, pydasm.FORMAT_INTEL, 0x0).rstrip(" ")
        self.mnemonic = pydasm.get_mnemonic_string(instruction, pydasm.FORMAT_INTEL).rstrip(" ")
   