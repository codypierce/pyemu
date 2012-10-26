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

from PyContext import PyContext
from PyFlags import PyFlags
from PyInstruction import *
from PyDebug import *

'''
PyCPU:

    The heart of PyEmu.  The CPU class handles execution of instructions.
'''
class PyCPU:
    DEBUG = 0
    
    # Bitmap of eflags
    eflags_map = {"CF": 0x1,
                  "PF": 0x4,
                  "AF": 0x10,
                  "ZF": 0x40,
                  "SF": 0x80,
                  "TF": 0x100,
                  "IF": 0x200,
                  "DF": 0x400,
                  "OF": 0x800,
                  "IOPL": 0x2000,
                  "NT": 0x4000,
                  "RF": 0x10000,
                  "VM": 0x20000,
                  "AC": 0x40000,
                  "VIF": 0x80000,
                  "VIP": 0x100000,
                  "ID": 0x200000 }
    
    def __init__(self, emu):
        # We store the emu object so we can communicate and request info
        self.emu = emu
        
        # Initialize all our registers and flags
        self.EAX = 0x00000000
        self.ECX = 0x00000000
        self.EDX = 0x00000000
        self.EBX = 0x00000000
        self.ESP = 0x00000000
        self.EBP = 0x00000000
        self.ESI = 0x00000000
        self.EDI = 0x00000000
        self.EIP = 0x00000000
        
        self.GS = 0x0000
        self.FS = 0x0000
        self.ES = 0x0000
        self.DS = 0x0000
        
        self.CS = 0x0000
        self.SS = 0x0000
        
        self.CF = 0
        self.PF = 0
        self.AF = 0
        self.ZF = 0
        self.SF = 0
        self.TF = 0
        self.IF = 0
        self.DF = 0
        self.OF = 0
        self.IOPL = 0
        self.NT = 0
        self.RF = 0
        self.VM = 0
        self.AC = 0
        self.VIF = 0
        self.VIP = 0
        self.ID = 0
        
        # The function table of all the instructions supported.  I use a
        # mnemonic table instead of an opcode map to allow mnemonic handlers.
        self.supported_instructions = { "adc": lambda instruction: self.ADC(instruction),
                                        "add": lambda instruction: self.ADD(instruction),
                                        "and": lambda instruction: self.AND(instruction),
                                        "bswap": lambda instruction: self.BSWAP(instruction),
                                        "call": lambda instruction: self.CALL(instruction),
                                        "cdq": lambda instruction: self.CDQ(instruction),
                                        "clc": lambda instruction: self.CLC(instruction),
                                        "cld": lambda instruction: self.CLD(instruction),
                                        "cmp": lambda instruction: self.CMP(instruction),
                                        "cmps": lambda instruction: self.CMPS(instruction),
                                        "cmpsb": lambda instruction: self.CMPSB(instruction),
                                        "cmpsw": lambda instruction: self.CMPSW(instruction),
                                        "cmpsd": lambda instruction: self.CMPSD(instruction),
                                        "dec": lambda instruction: self.DEC(instruction),
                                        "div": lambda instruction: self.DIV(instruction),
                                        "idiv": lambda instruction: self.IDIV(instruction),
                                        "imul": lambda instruction: self.IMUL(instruction),
                                        "inc": lambda instruction: self.INC(instruction),
                                        "int": lambda instruction: self.INT(instruction),
                                        "int3": lambda instruction: self.INT(instruction),
                                        "ja": lambda instruction: self.JA(instruction),
                                        "jb": lambda instruction: self.JB(instruction),
                                        "jbe": lambda instruction: self.JBE(instruction),
                                        "jc": lambda instruction: self.JC(instruction),
                                        "jg": lambda instruction: self.JG(instruction),
                                        "jge": lambda instruction: self.JGE(instruction),
                                        "jl": lambda instruction: self.JL(instruction),
                                        "jle": lambda instruction: self.JLE(instruction),
                                        "jmp": lambda instruction: self.JMP(instruction),
                                        "jna": lambda instruction: self.JNA(instruction),
                                        "jnb": lambda instruction: self.JNB(instruction),
                                        "jnc": lambda instruction: self.JNC(instruction),
                                        "jng": lambda instruction: self.JNG(instruction),
                                        "jnl": lambda instruction: self.JNL(instruction),
                                        "jns": lambda instruction: self.JNS(instruction),
                                        "jnz": lambda instruction: self.JNZ(instruction),
                                        "js": lambda instruction: self.JS(instruction),
                                        "jz": lambda instruction: self.JZ(instruction),
                                        "lea": lambda instruction: self.LEA(instruction),
                                        "leave": lambda instruction: self.LEAVE(instruction),
                                        "mov": lambda instruction: self.MOV(instruction),
                                        "movs": lambda instruction: self.MOVS(instruction),
                                        "movsb": lambda instruction: self.MOVSB(instruction),
                                        "movsw": lambda instruction: self.MOVSW(instruction),
                                        "movsd": lambda instruction: self.MOVSD(instruction),
                                        "movsx": lambda instruction: self.MOVSX(instruction),
                                        "movzx": lambda instruction: self.MOVZX(instruction),
                                        "mul": lambda instruction: self.MUL(instruction),
                                        "neg": lambda instruction: self.NEG(instruction),
                                        "nop": lambda instruction: self.NOP(instruction),
                                        "not": lambda instruction: self.NOT(instruction),
                                        "or": lambda instruction: self.OR(instruction),
                                        "pop": lambda instruction: self.POP(instruction),
                                        "push": lambda instruction: self.PUSH(instruction),
                                        "pusha": lambda instruction: self.PUSHA(instruction),
                                        "rcr": lambda instruction: self.RCR(instruction),
                                        "rcl": lambda instruction: self.RCL(instruction),
                                        "ret": lambda instruction: self.RET(instruction),
                                        "retn": lambda instruction: self.RET(instruction),
                                        "rol": lambda instruction: self.ROL(instruction),
                                        "ror": lambda instruction: self.ROR(instruction),
                                        "sal": lambda instruction: self.SAL(instruction),
                                        "sar": lambda instruction: self.SAR(instruction),
                                        "sbb": lambda instruction: self.SBB(instruction),
                                        "scas": lambda instruction: self.SCAS(instruction),
                                        "scasb": lambda instruction: self.SCASB(instruction),
                                        "scasw": lambda instruction: self.SCASW(instruction),
                                        "scasd": lambda instruction: self.SCASD(instruction),
                                        "setna": lambda instruction: self.SETNA(instruction),
                                        "setle": lambda instruction: self.SETLE(instruction),
                                        "setge": lambda instruction: self.SETGE(instruction),
                                        "setg": lambda instruction: self.SETG(instruction),
                                        "sete": lambda instruction: self.SETE(instruction),
                                        "setc": lambda instruction: self.SETC(instruction),
                                        "setbe": lambda instruction: self.SETBE(instruction),
                                        "setb": lambda instruction: self.SETB(instruction),
                                        "setae": lambda instruction: self.SETAE(instruction),
                                        "seta": lambda instruction: self.SETA(instruction),
                                        "setps": lambda instruction: self.SETPS(instruction),
                                        "setpo": lambda instruction: self.SETPO(instruction),
                                        "setpe": lambda instruction: self.SETPE(instruction),
                                        "setp": lambda instruction: self.SETP(instruction),
                                        "seto": lambda instruction: self.SETO(instruction),
                                        "setns": lambda instruction: self.SETNS(instruction),
                                        "setnp": lambda instruction: self.SETNP(instruction),
                                        "setno": lambda instruction: self.SETNO(instruction),
                                        "setnl": lambda instruction: self.SETNL(instruction),
                                        "setnge": lambda instruction: self.SETNGE(instruction),
                                        "setng": lambda instruction: self.SETNG(instruction),
                                        "setne": lambda instruction: self.SETNE(instruction),
                                        "setnc": lambda instruction: self.SETNC(instruction),
                                        "setnbe": lambda instruction: self.SETNBE(instruction),
                                        "setnb": lambda instruction: self.SETNB(instruction),
                                        "setnae": lambda instruction: self.SETNAE(instruction),
                                        "setl": lambda instruction: self.SETL(instruction),
                                        "setnle": lambda instruction: self.SETNLE(instruction),
                                        "setnz": lambda instruction: self.SETNZ(instruction),
                                        "setz": lambda instruction: self.SETZ(instruction),
                                        "shl": lambda instruction: self.SHL(instruction),
                                        "shr": lambda instruction: self.SHR(instruction),
                                        "stos": lambda instruction: self.STOS(instruction),
                                        "stosb": lambda instruction: self.STOSB(instruction),
                                        "stosw": lambda instruction: self.STOSW(instruction),
                                        "stosd": lambda instruction: self.STOSD(instruction),
                                        "sub": lambda instruction: self.SUB(instruction),
                                        "test": lambda instruction: self.TEST(instruction),
                                        "xchg": lambda instruction: self.XCHG(instruction),
                                        "xor": lambda instruction: self.XOR(instruction)}

    def get_msb(self, value, size):
        return (value >> ((8 * size) - 1))
    
    def get_lsb(self, value):
        return (value & 0x1)
            
    def get_mask(self, size):
        return (2 ** (8 * size) - 1)
    
    #
    # get_register: This method takes either a register string or index
    #               returning its value.  Size is used for convenience.
    #               We also check our user handlers and call them if they
    #               exist.
    #
    def get_register(self, register, size):
        if size == 4:
            if register == "EAX" or register == 0:
                register = "EAX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EAX, "read")
                    
                return self.EAX
            elif register == "ECX" or register == 1:
                register = "ECX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ECX, "read")
                    
                return self.ECX
            elif register == "EDX" or register == 2:
                register = "EDX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EDX, "read")
                    
                return self.EDX
            elif register == "EBX" or register == 3:
                register = "EBX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EBX, "read")
                    
                return self.EBX
            elif register == "ESP" or register == 4:
                register = "ESP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ESP, "read")
                    
                return self.ESP
            elif register == "EBP" or register == 5:
                register = "EBP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EBP, "read")
                    
                return self.EBP
            elif register == "ESI" or register == 6:
                register = "ESI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ESI, "read")
                    
                return self.ESI
            elif register == "EDI" or register == 7:
                register = "EDI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EDI, "read")
                    
                return self.EDI
            elif register == "EIP":
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EIP, "read")
                    
                return self.EIP
        elif size == 2:
            # Registers
            if   register == "AX" or register == 0:
                register = "AX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EAX & 0xFFFF, "read")
                    
                return self.EAX & 0xFFFF
            elif register == "CX" or register == 1:
                register = "CX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ECX & 0xFFFF, "read")
                    
                return self.ECX & 0xFFFF
            elif register == "DX" or register == 2:
                register = "DX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EDX & 0xFFFF, "read")
                    
                return self.EDX & 0xFFFF
            elif register == "BX" or register == 3:
                register = "BX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EBX & 0xFFFF, "read")
                    
                return self.EBX & 0xFFFF
            elif register == "SP" or register == 4:
                register = "SP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ESP & 0xFFFF, "read")
                    
                return self.ESP & 0xFFFF
            elif register == "BP" or register == 5:
                register = "BP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EBP & 0xFFFF, "read")
                    
                return self.EBP & 0xFFFF
            elif register == "SI" or register == 6:
                register = "SI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ESI & 0xFFFF, "read")
                    
                return self.ESI & 0xFFFF
            elif register == "DI" or register == 7:
                register = "DI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EDI & 0xFFFF, "read")
                    
                return self.EDI & 0xFFFF
                
            # Segment registers
            elif register == "CS":
                register = "CS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.CS & 0xFFFF, "read")
                    
                return self.CS & 0xFFFF
            elif register == "SS":
                register = "SS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.SS & 0xFFFF, "read")
                    
                return self.SS & 0xFFFF
            elif register == "DS":
                register = "DS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.DS & 0xFFFF, "read")
                    
                return self.DS & 0xFFFF
            elif register == "ES":
                register = "ES"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ES & 0xFFFF, "read")
                    
                return self.ES & 0xFFFF
            elif register == "FS":
                register = "FS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.FS & 0xFFFF, "read")
                    
                return self.FS & 0xFFFF
            elif register == "GS":
                register = "GS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.GS & 0xFFFF, "read")
                    
                return self.GS & 0xFFFF
        elif size == 1:
            if   register == "AL" or register == 0:
                register = "AL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EAX & 0xFF, "read")
                    
                return self.EAX & 0xFF
            elif register == "CL" or register == 1:
                register = "CL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.ECX & 0xFF, "read")
                    
                return self.ECX & 0xFF
            elif register == "DL" or register == 2:
                register = "DL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EDX & 0xFF, "read")
                    
                return self.EDX & 0xFF
            elif register == "BL" or register == 3:
                register = "BL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, self.EBX & 0xFF, "read")
                    
                return self.EBX & 0xFF
            elif register == "AH" or register == 4:
                register = "AH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, ((self.EAX & 0xFF00) >> 8), "read")
                    
                return ((self.EAX & 0xFF00) >> 8)
            elif register == "CH" or register == 5:
                register = "CH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, ((self.ECX & 0xFF00) >> 8), "read")
                    
                return ((self.ECX & 0xFF00) >> 8)
            elif register == "DH" or register == 6:
                register = "DH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, ((self.EDX & 0xFF00) >> 8), "read")
                    
                return ((self.EDX & 0xFF00) >> 8)
            elif register == "BH" or register == 7:
                register = "BH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, ((self.EBX & 0xFF00) >> 8), "read")
                    
                return ((self.EBX & 0xFF00) >> 8)
            
            # Flags
            elif register == "CF":
                register = "CF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.CF & 0xFF), "read")
                    
                return (self.CF & 0xFF)
            elif register == "PF":
                register = "PF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.PF & 0xFF), "read")
                    
                return (self.PF & 0xFF)
            elif register == "AF":
                register = "AF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.AF & 0xFF), "read")
                    
                return (self.AF & 0xFF)
            elif register == "ZF":
                register = "ZF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.ZF & 0xFF), "read")
                    
                return (self.ZF & 0xFF)
            elif register == "SF":
                register = "SF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.SF & 0xFF), "read")
                    
                return (self.SF & 0xFF)
            elif register == "TF":
                register = "TF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.TF & 0xFF), "read")
                    
                return (self.TF & 0xFF)
            elif register == "IF":
                register = "IF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.IF & 0xFF), "read")
                    
                return (self.IF & 0xFF)
            elif register == "DF":
                register = "DF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.DF & 0xFF), "read")
                    
                return (self.DF & 0xFF)
            elif register == "OF":
                register = "OF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.OF & 0xFF), "read")
                    
                return (self.OF & 0xFF)
            elif register == "IOPL":
                register = "IOPL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.IOPL & 0xFF), "read")
                    
                return (self.IOPL & 0xFF)
            elif register == "NT":
                register = "NT"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.NT & 0xFF), "read")
                    
                return (self.NT & 0xFF)
            elif register == "RF":
                register = "RF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.RF & 0xFF), "read")
                    
                return (self.RF & 0xFF)
            elif register == "VM":
                register = "VM"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.VM & 0xFF), "read")
                    
                return (self.VM & 0xFF)
            elif register == "AC":
                register = "AC"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.AC & 0xFF), "read")
                    
                return (self.AC & 0xFF)
            elif register == "VIF":
                register = "VIF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.VIF & 0xFF), "read")
                    
                return (self.VIF & 0xFF)
            elif register == "VIP":
                register = "VIP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.VIP & 0xFF), "read")
                    
                return (self.VIP & 0xFF)
            elif register == "ID":
                register = "ID"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, (self.ID & 0xFF), "read")
                    
                return (self.ID & 0xFF)
        else:
            return False
        
        return False
    
    # Convenience get_register wrapper function
    def get_register32(self, register):
        return self.get_register(register, 4)
        
    def get_register16(self, register):
        return self.get_register(register, 2)
    
    def get_register8(self, register):
        return self.get_register(register, 1)
    
    #
    # get_memory: This is called when the CPU requests memory.  It also
    #             calls any handlers we may have.
    #
    def get_memory(self, address, size):
        value = self.emu.memory.get_memory(address, size)

        # The processor only fetches mem in dword max, this lets us hack
        # around code fetches
        if size <= 4:
            # Call our memory access handler
            if self.emu.memory_access_handler:
                self.emu.memory_access_handler(self.emu, address, value, size, "read")
            
            # Call our memory read handler    
            if self.emu.memory_read_handler:
                result = self.emu.memory_read_handler(self.emu, address, value, size)
            else:
                result = value
            
            # Call our memory handler
            if address in self.emu.memory_handlers:
                result = self.emu.memory_handlers[address](self.emu, address, value, size, "read")
            else:
                result = value
                    
            # Check if we are touching stack
            if address <= self.emu.stack_base and address >= (self.emu.stack_base - self.emu.stack_size):
                if self.emu.stack_access_handler:
                    self.emu.stack_access_handler(self.emu, address, value, size, "read")
                
                # Call our stack read handler    
                if self.emu.stack_read_handler:
                    result = self.emu.stack_read_handler(self.emu, address, value, size)
                else:
                    result = value
            elif address <= self.emu.heap_base and address >= (self.emu.heap_base + self.emu.heap_size):
                if self.emu.heap_access_handler:
                    self.emu.heap_access_handler(self.emu, address, value, size, "read")
                
                # Call our specific heap read handler
                if self.emu.heap_read_handler:
                    result = self.emu.heap_read_handler(self.emu, address, value, size)
                else:
                    result = value
                    
            # This lets the user control what is read
            if not isinstance(result, bool):
                return result
                 
        return value
    
    # Convenience wrappers for get_memory    
    def get_memory32(self, address):
        value = self.get_memory(address, 4)
        
        return value
    
    def get_memory16(self, address):
        value = self.get_memory(address, 2)
        
        return (value & 0x0000ffff)
    
    def get_memory8(self, address):
        value = self.get_memory(address, 1)
        
        return (value & 0x000000ff)
    
    #
    # get_context: Builds a context object for passing to the emulator
    #
    def get_context(self):
        newcontext = PyContext()
        
        newcontext.EAX = self.EAX
        newcontext.ECX = self.ECX
        newcontext.EDX = self.EDX
        newcontext.EBX = self.EBX
        newcontext.ESP = self.ESP
        newcontext.EBP = self.EBP
        newcontext.ESI = self.ESI
        newcontext.EDI = self.EDI
        newcontext.EIP = self.EIP
        
        newcontext.GS = self.GS
        newcontext.FS = self.FS
        newcontext.ES = self.ES
        newcontext.DS = self.DS

        newcontext.CS = self.DS
        newcontext.SS = self.SS
        
        flags = 0x0000000
        
        if self.CF: flags |= self.eflags_map["CF"]
        if self.PF: flags |= self.eflags_map["PF"]
        if self.AF: flags |= self.eflags_map["AF"]
        if self.ZF: flags |= self.eflags_map["ZF"]
        if self.SF: flags |= self.eflags_map["SF"]
        if self.TF: flags |= self.eflags_map["TF"]
        if self.IF: flags |= self.eflags_map["IF"]
        if self.DF: flags |= self.eflags_map["DF"]
        if self.OF: flags |= self.eflags_map["OF"]
        if self.IOPL: flags |= self.eflags_map["IOPL"]
        if self.NT: flags |= self.eflags_map["NT"]
        if self.RF: flags |= self.eflags_map["RF"]
        if self.VM: flags |= self.eflags_map["VM"]
        if self.AC: flags |= self.eflags_map["AC"]
        if self.VIF: flags |= self.eflags_map["VIF"]
        if self.VIP: flags |= self.eflags_map["VIP"]
        if self.ID: flags |= self.eflags_map["ID"]
        
        newcontext.EFLAGS = flags
        
        return newcontext
        
    def clear_eflags(self):
        self.CF = 0
        self.PF = 0
        self.AF = 0
        self.ZF = 0
        self.SF = 0
        self.TF = 0
        self.IF = 0
        self.DF = 0
        self.OF = 0
        self.IOPL = 0
        self.NT = 0
        self.RF = 0
        self.VM = 0
        self.AC = 0
        self.VIF = 0
        self.VIP = 0
        self.ID = 0
        
        return True
    
    #
    # sanitize_value: Masks the value based on size
    #
    def sanitize_value(self, value, size):
        if size == 1:
            return value & 0xff
        elif size == 2:
            return value & 0xffff
        elif size == 4:
            return value & 0xffffffff
        else:
            return False

    #
    # set_context: Will set the CPU context from a PyContext if called.
    #        
    def set_context(self, context):
        self.EAX = context.EAX
        self.ECX = context.ECX
        self.EDX = context.EDX
        self.EBX = context.EBX
        self.ESP = context.ESP
        self.EBP = context.EBP
        self.ESI = context.ESI
        self.EDI = context.EDI
        self.EIP = context.EIP
        
        self.GS = context.GS
        self.FS = context.FS
        self.ES = context.ES
        self.DS = context.DS
        
        self.CS = context.CS
        self.SS = context.SS
        
        if context.EFLAGS & self.eflags_map["CF"]:
            self.CF = 1
        if context.EFLAGS & self.eflags_map["PF"]:
            self.PF = 1
        if context.EFLAGS & self.eflags_map["AF"]:
            self.AF = 1
        if context.EFLAGS & self.eflags_map["ZF"]: 
            self.ZF = 1
        if context.EFLAGS & self.eflags_map["SF"]: 
            self.SF = 1
        if context.EFLAGS & self.eflags_map["TF"]: 
            self.TF = 1
        if context.EFLAGS & self.eflags_map["IF"]: 
            self.IF = 1
        if context.EFLAGS & self.eflags_map["DF"]: 
            self.DF = 1
        if context.EFLAGS & self.eflags_map["OF"]: 
            self.OF = 1
        if context.EFLAGS & self.eflags_map["IOPL"]: 
            self.IOPL = 1
        if context.EFLAGS & self.eflags_map["NT"]: 
            self.NT = 1
        if context.EFLAGS & self.eflags_map["RF"]: 
            self.RF = 1
        if context.EFLAGS & self.eflags_map["VM"]: 
            self.VM = 1
        if context.EFLAGS & self.eflags_map["AC"]: 
            self.AC = 1
        if context.EFLAGS & self.eflags_map["VIF"]: 
            self.VIF = 1
        if context.EFLAGS & self.eflags_map["VIP"]: 
            self.VIP = 1
        if context.EFLAGS & self.eflags_map["ID"]: 
            self.ID = 1
        
        return True
    
    #
    # set_register: Sets the supplied register to value.  can be used with
    #               the string representation or index. Also calls our user
    #               handler if present.
    #
    def set_register(self, register, value, size):
        value &= self.get_mask(size)
        if size == 4:
            if   register == "EAX" or register == 0:
                register = "EAX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EAX = value
                
                return True
            elif register == "ECX" or register == 1:
                register = "ECX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ECX = value
                
                return True
            elif register == "EDX" or register == 2:
                register = "EDX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDX = value
                
                return True
            elif register == "EBX" or register == 3:
                register = "EBX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBX = value
                
                return True
            elif register == "ESP" or register == 4:
                register = "ESP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ESP = value
                
                return True
            elif register == "EBP" or register == 5:
                register = "EBP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBP = value
                
                return True
            elif register == "ESI" or register == 6:
                register = "ESI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ESI = value
                
                return True
            elif register == "EDI" or register == 7:
                register = "EDI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDI = value
                
                return True
            elif register == "EIP":       
                register = "EIP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EIP = value
                
                return True
        elif size == 2:
            # Registers
            if   register == "AX" or register == 0:
                register = "AX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EAX = (self.EAX & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "CX" or register == 1:
                register = "CX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ECX = (self.ECX & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "DX" or register == 2:
                register = "DX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDX = (self.EDX & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "BX" or register == 3:
                register = "BX"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBX = (self.EBX & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "SP" or register == 4:
                register = "SP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ESP = (self.ESP & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "BP" or register == 5:
                register = "BP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBP = (self.EBP & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "SI" or register == 6:
                register = "SI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ESI = (self.ESI & 0xffff0000) | (value & 0xffff)
                
                return True
            elif register == "DI" or register == 7:
                register = "DI"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDI = (self.EDI & 0xffff0000) | (value & 0xffff)
                
                return True
            
            # Segment Registers
            elif register == "CS":
                register = "CS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.CS = value & 0xffff
                
                return True
            elif register == "SS":
                register = "SS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.SS = value & 0xffff
                
                return True
            elif register == "DS":
                register = "DS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.DS = value & 0xffff
                
                return True
            elif register == "ES":
                register = "ES"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ES = value & 0xffff
                
                return True
            elif register == "FS":
                register = "FS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.FS = value & 0xffff
                
                return True
            elif register == "GS":
                register = "GS"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.GS = value & 0xffff
                
                return True
        elif size == 1:
            if   register == "AL" or register == 0:
                register = "AL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EAX = (self.EAX & 0xffffff00) | (value & 0xff)
                
                return True
            elif register == "CL" or register == 1:
                register = "CL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ECX = (self.ECX & 0xffffff00) | (value & 0xff)
                
                return True
            elif register == "DL" or register == 2:
                register = "DL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDX = (self.EDX & 0xffffff00) | (value & 0xff)
                
                return True
            elif register == "BL" or register == 3:
                register = "BL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBX = (self.EBX & 0xffffff00) | (value & 0xff)
                
                return True
            elif register == "AH" or register == 4:
                register = "AH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EAX = (self.EAX & 0xffff00ff) | ((value & 0xff) << 8)
                
                return True
            elif register == "CH" or register == 5:
                register = "CH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.ECX = (self.ECX & 0xffff00ff) | ((value & 0xff) << 8)
                
                return True
            elif register == "DH" or register == 6:
                register = "DH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EDX = (self.EDX & 0xffff00ff) | ((value & 0xff) << 8)
                
                return True
            elif register == "BH" or register == 6:
                register = "BH"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                    
                self.EBX = (self.EBX & 0xffff00ff) | ((value & 0xff) << 8)
                
                return True
            
            # Flags
            elif register == "CF":
                register = "CF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.CF = (value & 0xff)
                
                return True
            elif register == "PF":
                register = "PF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.PF = (value & 0xff)
                
                return True
            elif register == "AF":
                register = "AF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.AF = (value & 0xff)
                
                return True
            elif register == "ZF":
                register = "ZF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.ZF = (value & 0xff)
                
                return True
            elif register == "SF":
                register = "SF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.SF = (value & 0xff)
                
                return True
            elif register == "TF":
                register = "TF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.TF = (value & 0xff)
                
                return True
            elif register == "IF":
                register = "IF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.IF = (value & 0xff)
                
                return True
            elif register == "DF":
                register = "DF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.DF = (value & 0xff)
                
                return True
            elif register == "OF":
                register = "OF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.OF = (value & 0xff)
                
                return True
            elif register == "IOPL":
                register = "IOPL"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.IOPL = (value & 0xff)
                
                return True
            elif register == "NT":
                register = "NT"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.NT = (value & 0xff)
                
                return True
            elif register == "RF":
                register = "RF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.RF = (value & 0xff)
                
                return True
            elif register == "VM":
                register = "VM"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.VM = (value & 0xff)
                
                return True
            elif register == "AC":
                register = "AC"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.AC = (value & 0xff)
                
                return True
            elif register == "VIF":
                register = "VIF"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.VIF = (value & 0xff)
                
                return True
            elif register == "VIP":
                register = "VIP"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.VIP = (value & 0xff)
                
                return True
            elif register == "ID":
                register = "ID"
                if register in self.emu.register_handlers:
                    self.emu.register_handlers[register](self.emu, register, value, "write")
                
                self.ID = (value & 0xff)
                
                return True 
        else:
            return False
        
        return False
    
    # Convenience wrappers for set_register
    def set_register32(self, register, value):
        return self.set_register(register, value, 4)
   
    def set_register16(self, register, value):
        return self.set_register(register, value, 2)
    
    def set_register8(self, register, value):
        return self.set_register(register, value, 1)
    
    #
    # set_memory: Handles setting of memory from the CPU.  Calls the memory
    #             manager via the emulator object.  We also call our user
    #             handlers if they are present.
    #
    def set_memory(self, address, value, size):
        # Call our global memory access handler
        if self.emu.memory_access_handler:
            self.emu.memory_access_handler(self.emu, address, value, size, "write")
        
        # Call our specific memory write handler    
        if self.emu.memory_write_handler:
            result = self.emu.memory_write_handler(self.emu, address, value, size)
        else:
            result = True
        
        # Call our address specific memory handler
        if address in self.emu.memory_handlers:
            result = self.emu.memory_handlers[address](self.emu, address, value, size, "write")
        else:
            result = True
                    
        # Check if we are on stack so we can trigger handlers
        if address <= self.emu.stack_base and address >= (self.emu.stack_base - self.emu.stack_size):
            if self.emu.stack_access_handler:
                self.emu.stack_access_handler(self.emu, address, value, size, "write")
            
            # Call our specific stack write handler    
            if self.emu.stack_write_handler:
                result = self.emu.stack_write_handler(self.emu, address, value, size)
            else:
                result = True
        elif address >= self.emu.heap_base and address <= (self.emu.heap_base + self.emu.heap_size):
            if self.emu.heap_access_handler:
                self.emu.heap_access_handler(self.emu, address, value, size, "write")
            
            # Call our specific heap write handler    
            if self.emu.heap_write_handler:
                result = self.emu.heap_write_handler(self.emu, address, value, size)
            else:
                result = True
                
        # This lets the user bypass memory writes
        if result:
            return self.emu.memory.set_memory(address, value, size)
        
        return False
    
    # Convenience wrappers for set_memory            
    def set_memory32(self, address, value):
        return self.set_memory(address, value, 4)
    
    def set_memory16(self, address, value):
        return self.set_memory(address, value, 2)
    
    def set_memory8(self, address, value):
        return self.set_memory(address, value, 1)
    
    def set_flags(self, mnemonic, op1, op2, result, size):
        mask = self.get_mask(size)
        
        op1 &= mask
        op2 &= mask
        result &= mask
        
        flags = PyFlags(mnemonic, op1, op2, result, size)
        
        cf = flags.get_CF()
        if cf != None:
            self.CF = cf
            
        af = flags.get_AF()
        if af != None:
            self.AF = af
            
        zf = flags.get_ZF()
        if zf != None:
            self.ZF = zf
            
        sf = flags.get_SF()
        if sf != None:
            self.SF = sf
            
        of = flags.get_OF()
        if of != None:
            self.OF = of
            
        pf = flags.get_PF()
        if pf != None:
            self.PF = pf
        
        return True

    # Sign extends a value
    def sign_extend(self, number, orig_size, dest_size):
        orig_max = (2 ** (8 * orig_size) - 1)
        dest_max = (2 ** (8 * dest_size) - 1)
        
        orig_shift = (8 * orig_size)
        dest_shirt = (8 * dest_size)
        
        masknumber = number & orig_max
        msb = masknumber >> (orig_shift - 1)
        
        if msb:
            signextended = ((dest_max << orig_shift) | masknumber) & dest_max
        else:
            signextended = number & dest_max
        
        return signextended
    
    # Swaps a dword bytes
    def swap_bytes(self, value):
        return (((value & 0xff) << 24) | (((value & 0xff00) >> 8) << 16) | (((value & 0xff0000) >> 16) << 8) | ((value & 0xff000000) >> 24))
    
    #
    # execute: The method for advancing execution.  EIP will be saved and
    #          any user pc handlers will be called.  Then we fetch and execute.
    #          
    def execute(self):
        
        # Check our program counter handlers
        if self.EIP in self.emu.pc_handlers:
            self.emu.pc_handlers[self.EIP](self.emu, self.EIP)
        
        if self.EIP in self.emu.os.libraries:
            library = self.emu.os.libraries[self.EIP]
            #if self.DEBUG > 1:
            print "[*] Calling 0x%08x:%s" % (self.EIP, library['name'])
            
            if library['name'] in self.emu.library_handlers:
                result = self.emu.library_handlers[library['name']](library['name'], library['address'], library['dll'])
                
                if not result:
                    return False
                else:
                    return result
            else:
                print "[*] Need a handler"
                return False
                       
        oldeip = self.EIP
        
        # Fetch raw instruction from memory
        rawinstruction = self.get_memory(self.EIP, 32)
        if not rawinstruction:
            print "[!] Problem fetching raw bytes from 0x%08x" % (self.EIP)
            
            return False
        
        # Decode instruction from raw returning a pydasm.instruction
        instruction = pydasm.get_instruction(rawinstruction, pydasm.MODE_32)
        if not instruction:
            print "[!] Problem decoding instruction"
            
            return False
        
        # Create our python class for instruction, we do this in case we ever leave pydasm
        pyinstruction = PyInstruction(instruction)
        
        if self.DEBUG > 0:
            print "[*] Executing [0x%x][%x] %s" % (self.EIP, pyinstruction.opcode, pyinstruction.disasm)
        
        # An oversight in pydasm mnemonic parsing
        pyinstruction.mnemonic = pyinstruction.mnemonic.split()
        if pyinstruction.mnemonic[0] in ["rep", "repe", "repne", "lock"]:
            pyinstruction.mnemonic = pyinstruction.mnemonic[1]
        else:
            pyinstruction.mnemonic = pyinstruction.mnemonic[0]
        
        # Check if we support this instruction
        if pyinstruction.mnemonic in self.supported_instructions:
            # Execute!
            if not self.supported_instructions[pyinstruction.mnemonic](pyinstruction):
                
                return False
        else:
            print "[!] Unsupported instruction %s" % pyinstruction.mnemonic
            
            return False
        
        # If EIP has not changed we advance to the next instruction in code
        if self.EIP == oldeip:
            self.EIP += pyinstruction.length 

        # Everything checked out
        return True
    
    #
    # get_memory_address: Calculates the memory address from the instruction.
    #
    def get_memory_address(self, instruction, opnum, size):
        # Get the proper operand
        if opnum == 1:
            op = instruction.op1
        elif opnum == 2:
            op = instruction.op2
        elif opnum == 3:
            op = instruction.op3
        else:
            print "[!] get_memory_address() couldnt understand opnum"
            
            return False
 
        
        # Call our convenience functions for mod/rm bytes
        mod = instruction.get_mod()
        rm = instruction.get_rm()
        
        # Call our convenience function for s/i/b bytes
        scale = instruction.get_scale()
        index = instruction.get_index()
        base = instruction.get_base()
        
        if size == 2:
            # do 16 bit
            if mod == 0x0:
                # do register deref
                if rm == 0x5:
                    address = op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching displacement memory for %x" % address
                        
                    return address
                elif rm == 0x4:
                    # do sib
                    if base == 0x5:
                        # If base reg is 5 we must use displacement
                        if scale == 0x0:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register16(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 8)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching 32 bit sib %x" % address
                        
                    return address
                else:
                    address = self.get_register16(op.basereg)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching register [%d] %x" % (op.basereg, address)
                        
                    return address
            elif mod == 0x1:
                # do register deref + displacement8
                if rm == 0x4:
                    if base == 0x5:
                        # If base reg is 5 we must use displacement + ebp
                        if scale == 0x0:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 8)
                    
                    address += (op.displacement & 0xff)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + sib + disp8 %x" % address
                        
                    return address
                else:
                    address = self.get_register16(op.basereg) + op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + disp8 %x" % address
                        
                    return address
            elif mod == 0x2:
                # do register deref + displacement32
                if rm == 0x4:
                    if base == 0x5:
                        # If base reg is 5 we must use displacement + ebp
                        if scale == 0x0:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register16("EBP") + (self.get_register16(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register16(base)
                            else:
                                address = self.get_register16(base) + (self.get_register16(index) * 8)
                        
                    address += op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + sib + disp32 %x" % address
                        
                    return address
                else:
                    address = self.get_register16(op.basereg) + op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + disp32 %x" % address
                        
                    return address
            elif mod == 0x3:
                address = self.get_register16(op.basereg)
                
                if self.DEBUG > 2:
                    print "[*] Fetching plain register %x" % op.reg
                    
                return address
            else:
                print "[!] get_memory_address(): unknown memory"
                
                return False
        else:
            # do 32 bit
            # do mod
            if mod == 0x0:
                # do register deref
                if rm == 0x5:
                    address = op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching displacement memory for %x" % address
                        
                    return address
                elif rm == 0x4:
                    # do sib
                    if base == 0x5:
                        # If base reg is 5 we must use displacement
                        if scale == 0x0:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = op.displacement + (self.get_register32(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 8)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching 32 bit sib %x" % address
                        
                    return address
                else:
                    address = self.get_register32(op.basereg)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching register [%d] %x" % (op.basereg, address)
                        
                    return address
            elif mod == 0x1:
                # do register deref + displacement8
                if rm == 0x4:
                    if base == 0x5:
                        # If base reg is 5 we must use displacement + ebp
                        if scale == 0x0:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address =  self.get_register32("EBP") + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register32("EBP") + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register32("EBP") + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = (op.displacement & 0xff)
                            else:
                                address = self.get_register32("EBP") + (self.get_register32(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 8)
                    
                    address += (op.displacement & 0xff)
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + sib + disp8 %x" % address
                        
                    return address
                else:
                    address = self.get_register32(op.basereg) + op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + disp8 %x" % address
                        
                    return address
            elif mod == 0x2:
                # do register deref + displacement32
                if rm == 0x4:
                    if base == 0x5:
                        # If base reg is 5 we must use displacement + ebp
                        if scale == 0x0:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address =  self.get_register32("EBP") + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address =  self.get_register32("EBP") + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register32("EBP") + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = op.displacement
                            else:
                                address = self.get_register32("EBP") + (self.get_register32(index) * 8)
                    else:
                        if scale == 0x0:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index))
                        elif scale == 0x1:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 2)
                        elif scale == 0x2:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 4)
                        elif scale == 0x3:
                            if index == 0x4:
                                address = self.get_register32(base)
                            else:
                                address = self.get_register32(base) + (self.get_register32(index) * 8)
                        
                    address += op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + sib + disp32 %x" % address
                        
                    return address
                else:
                    address = self.get_register32(op.basereg) + op.displacement
                    
                    if self.DEBUG > 2:
                        print "[*] Fetching reg + disp32 %x" % address
                        
                    return address
            elif mod == 0x3:
                address = self.get_register32(op.basereg)
                
                if self.DEBUG > 2:
                    print "[*] Fetching plain register %x" % op.reg
                    
                return address
            else:
                print "[!] get_memory_address(): unknown memory"
                
                return False
                
        return False
        
    #
    # get_disasm: will fetch the current instruction and pretty it up
    #
    def get_disasm(self, instruction=None):
        if not self.emu.memory.is_valid(self.EIP):
            return False
            
        if not instruction:
            rawinstruction = self.get_memory(self.EIP, 32)
            if not rawinstruction:
                print "[!] Problem fetching raw bytes from 0x%08x" % (self.EIP)
                
                return False
            
            # Decode instruction from raw returning a pydasm.instruction
            instruction = pydasm.get_instruction(rawinstruction, pydasm.MODE_32)
            if not instruction:
                print "[!] Problem decoding instruction"
                
                return False
        
        return pydasm.get_instruction_string(instruction, pydasm.FORMAT_INTEL, self.EIP).rstrip(" ")
    
    def set_debug(self, level):
        self.DEBUG = level
        
        return True

    #
    # dispatch_interrupt: Handles any software interrupts that may be generated
    #                     in the CPU (int 3)
    #
    def dispatch_interrupt(self, interrupt):
        if interrupt in self.emu.interrupt_handlers:
            return self.emu.interrupt_handlers[interrupt](self, interrupt, self.EIP)
        else:
            if self.DEBUG > 2:
                print "[!] Skipping int %d" % (interrupt)
        
        return True
        
    #
    # dump_stack: Prints out the stack addresses and values
    #
    def dump_stack(self, count=64):
        if not self.emu.memory.is_valid(self.ESP):
            return False
        
        print "ESP:"
        for x in xrange(0, count, 4):
            address = self.ESP + (count / 2) - x
            
            if not self.emu.memory.is_valid(address):
                return False
                
            print "0x%08x: %x" % (address, self.get_memory32(address))
        print "\n"
        
        if not self.emu.memory.is_valid(self.EBP):
            return False
            
        print "EBP:"
        for x in xrange(0, count, 4):
            address = self.EBP + (count / 2) - x
            if not self.emu.memory.is_valid(address):
                return False
            
            print "0x%08x: %x" % (address, self.get_memory32(address))
        print "\n"
        
        return True

    #
    # dump_regs: Prints out the registers
    #    
    def dump_regs(self):
        sys.stdout.write("\n")
        sys.stdout.write("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n" %
        (self.EAX, self.EBX, self.ECX,
        self.EDX, self.ESI, self.EDI))
        sys.stdout.write("eip=%08x esp=%08x ebp=%08x iopl=%02x\n" % 
        (self.EIP, self.ESP, self.EBP, self.IOPL))
        sys.stdout.write("cs=%04x ss=%04x ds=%04x es=%04x fs=%04x gs=%04x    eflags=[" % (self.CS, self.SS, self.DS, self.ES, self.FS, self.GS))
        
        if self.CF: sys.stdout.write("CF ")
        if self.PF: sys.stdout.write("PF ")
        if self.AF: sys.stdout.write("AF ")
        if self.ZF: sys.stdout.write("ZF ")
        if self.SF: sys.stdout.write("SF ")
        if self.TF: sys.stdout.write("TF ")
        if self.IF: sys.stdout.write("IF ")
        if self.DF: sys.stdout.write("DF ")
        if self.OF: sys.stdout.write("OF ")
        if self.NT: sys.stdout.write("NT ")
        if self.RF: sys.stdout.write("RF ")
        if self.VM: sys.stdout.write("VM ")
        if self.AC: sys.stdout.write("AC ")
        if self.VIF: sys.stdout.write("VIF ")
        if self.VIP: sys.stdout.write("VIP ")
        if self.ID: sys.stdout.write("ID ")
        
        sys.stdout.write("]\n\n")
        
        if self.emu.memory.is_valid(self.EIP):
            sys.stdout.write("%08x  %s\n\n" % (self.EIP, self.get_disasm()))

    '''
    Instructions:
    
        The following code will execute each instruction based on the mnemonic.
        This code was auto generated for the most part except the actual logic.
        Each one should be very similar and first sets up the operands,
        executes the proper opcode, does its thing, then calls any user opcode
        and mnemonic handlers.  If something goes wrong we return False
        which should bail the execution.
    '''
    def ADC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #10 /r ADC r/m8,r8 Add with carry byte register to r/m8
        if instruction.opcode == 0x10:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value + self.CF

                self.set_flags("ADC", op1value, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value + self.CF

                self.set_flags("ADC", op1valuederef, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #11 /r ADC r/m16,r16 Add with carry r16 to r/m16
        #11 /r ADC r/m32,r32 Add with CF r32 to r/m32
        elif instruction.opcode == 0x11:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value + self.CF

                self.set_flags("ADC", op1value, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value + self.CF

                self.set_flags("ADC", op1valuederef, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #13 /r ADC r16,r/m16 Add with carry r/m16 to r16
        #13 /r ADC r32,r/m32 Add with CF r/m32 to r32
        elif instruction.opcode == 0x13:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value + self.CF

                self.set_flags("ADC", op1value, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)
                
                result = op1value + op2valuederef + self.CF

                self.set_flags("ADC", op1value, op2valuederef + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #14 ib ADC AL,imm8 Add with carry imm8 to AL
        elif instruction.opcode == 0x14:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value + op2value + self.CF

            self.set_flags("ADC", op1value, op2value + self.CF, result, size)

            result = self.sanitize_value(result, size)
            
            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #15 id ADC EAX,imm32 Add with carry imm32 to EAX
        #15 iw ADC AX,imm16 Add with carry imm16 to AX
        elif instruction.opcode == 0x15:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value + op2value + self.CF

            self.set_flags("ADC", op1value, op2value + self.CF, result, size)

            result = self.sanitize_value(result, size)
            
            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /2 id ADC r/m32,imm32 Add with CF imm32 to r/m32
        #81 /2 iw ADC r/m16,imm16 Add with carry imm16 to r/m16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value + op2value + self.CF

                self.set_flags("ADC", op1value, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value + self.CF

                self.set_flags("ADC", op1valuederef, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /2 ib ADC r/m16,imm8 Add with CF sign-extended imm8 to r/m16
        #83 /2 ib ADC r/m32,imm8 Add with CF sign-extended imm8 into r/m32
        elif instruction.opcode == 0x83 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value + op2value + self.CF

                self.set_flags("ADC", op1value, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value + self.CF

                self.set_flags("ADC", op1valuederef, op2value + self.CF, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False
            
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def ADD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #00 /r ADD r/m8,r8 Add r8 to r/m8
        if instruction.opcode == 0x00:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value

                self.set_flags("ADD", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value

                self.set_flags("ADD", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #01 /r ADD r/m16,r16 Add r16 to r/m16
        #01 /r ADD r/m32,r32 Add r32 to r/m32
        elif instruction.opcode == 0x01:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value

                self.set_flags("ADD", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)
                
                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value

                self.set_flags("ADD", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #03 /r ADD r16,r/m16 Add r/m16 to r16
        #03 /r ADD r32,r/m32 Add r/m32 to r32
        elif instruction.opcode == 0x03:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value + op2value

                self.set_flags("ADD", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
                
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)
                
                result = op1value + op2valuederef

                self.set_flags("ADD", op1value, op2valuederef, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #04 ib ADD AL,imm8 Add imm8 to AL
        elif instruction.opcode == 0x04:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value + op2value

            self.set_flags("ADD", op1value, op2value, result, size)

            result = self.sanitize_value(result, size)

            self.set_register(0, result, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #05 id ADD EAX,imm32 Add imm32 to EAX
        #05 iw ADD AX,imm16 Add imm16 to AX
        elif instruction.opcode == 0x05:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value + op2value

            self.set_flags("ADD", op1value, op2value, result, size)

            result = self.sanitize_value(result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /0 id ADD r/m32,imm32 Add imm32 to r/m32
        #81 /0 iw ADD r/m16,imm16 Add imm16 to r/m16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value + op2value

                self.set_flags("ADD", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value

                self.set_flags("ADD", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /0 ib ADD r/m16,imm8 Add sign-extended imm8 to r/m16
        #83 /0 ib ADD r/m32,imm8 Add sign-extended imm8 to r/m32
        elif instruction.opcode == 0x83 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value + op2value
                
                self.set_flags("ADD", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef + op2value

                self.set_flags("ADD", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def AND(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #20 /r AND r/m8,r8 r/m8  r8
        if instruction.opcode == 0x20:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #21 /r AND r/m16,r16 r/m16  r16
        #21 /r AND r/m32,r32 r/m32  r32
        elif instruction.opcode == 0x21:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #23 /r AND r16,r/m16 r16  r/m16
        #23 /r AND r32,r/m32 r32  r/m32
        elif instruction.opcode == 0x23:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)
                op2valuederef = self.get_memory(op2value, size)
                
                # Do logic
                result = op1value & op2valuederef

                self.set_flags("LOGIC", op1value, op2valuederef, result, size)

                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #24 ib AND AL,imm8 AL  imm8
        elif instruction.opcode == 0x24:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value & op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #25 id AND EAX,imm32 EAX  imm32
        #25 iw AND AX,imm16 AX  imm16
        elif instruction.opcode == 0x25:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value & op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /4 id AND r/m32,imm32 r/m32  imm32
        #81 /4 iw AND r/m16,imm16 r/m16  imm16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /4 ib AND r/m16,imm8 r/m16  imm8 (sign-extended)
        #83 /4 ib AND r/m32,imm8 r/m32  imm8 (sign-extended)
        elif instruction.opcode == 0x83 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def BSWAP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #0F C8 rd BSWAP r32 reverse the byte order of a 32-bit register
        if instruction.opcode >= 0xc8 and instruction.opcode <= 0xcf:
            if so:
                size = 2
                
                print "[!] Undefined behavior"
                return False
            else:
                size = 4
            
            value = self.swap_bytes(self.get_register(op1.reg, size))
            self.set_register(op1.reg, value, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
        else:
            return False
            
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
        
        return True
        
    def CALL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #9A cd CALL ptr16:16 Call far, absolute, address given in operand
        #9A cp CALL ptr16:32 Call far, absolute, address given in operand
        if instruction.opcode == 0x9a:

            print "[!] Unsupported until test case found"
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #E8 cd CALL rel32 Call near, relative, displacement relative to next instruction
        #E8 cw CALL rel16 Call near, relative, displacement relative to next instruction
        elif instruction.opcode == 0xe8:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            eip = self.get_register32("EIP") + instruction.length + op1value
            returneip = self.get_register32("EIP") + instruction.length
            
            # dec esp
            esp = self.get_register32("ESP") - 4
            
            # store returneip
            self.set_memory32(esp, returneip)
            
            # set new esp
            self.set_register32("ESP", esp)
            
            # change to new eip
            self.set_register32("EIP", eip)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /2 CALL r/m16 Call near, absolute indirect, address given in r/m16
        #FF /2 CALL r/m32 Call near, absolute indirect, address given in r/m32
        elif instruction.opcode == 0xff and instruction.extindex == 0x2:
            
            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                eip = op1value
                returneip = self.get_register32("EIP") + instruction.length
                
                # dec esp
                esp = self.get_register32("ESP") - 4
                
                # store returneip
                self.set_memory32(esp, returneip)
                
                # set new esp
                self.set_register32("ESP", esp)
                
                # change to new eip
                self.set_register32("EIP", eip)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                eip = op1valuederef
                returneip = self.get_register32("EIP") + instruction.length
                
                # dec esp
                esp = self.get_register32("ESP") - 4
                
                # store returneip
                self.set_memory32(esp, returneip)
                
                # set new esp
                self.set_register32("ESP", esp)
                
                # change to new eip
                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /3 CALL m16:16 Call far, absolute indirect, address given in m16:16
        #FF /3 CALL m16:32 Call far, absolute indirect, address given in m16:32
        elif instruction.opcode == 0xff and instruction.extindex == 0x3:
    
            print "[!] Unsupported until test case found"
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)

        return True


    def CDQ(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #99 CDQ EDX:EAX . sign-extend of EAX
        if instruction.opcode == 0x99:
            op1value = self.get_register32("EAX")
            
            # Do logic
            if op1value >> 31:
                self.set_register32("EDX", 0xffffffff)
            else:
                self.set_register32("EDX", 0x0) 

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CLC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F8 CLC Clear CF flag
        if instruction.opcode == 0xf8:

            # Do logic
            self.CF = 0

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CLD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #FC CLD Clear DF flag
        if instruction.opcode == 0xfc:

            # Do logic
            self.DF = 0

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CMP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #38 /r CMP r/m8,r8 Compare r8 with r/m8
        if instruction.opcode == 0x38:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - op2value

                self.set_flags("CMP", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #39 /r CMP r/m16,r16 Compare r16 with r/m16
        #39 /r CMP r/m32,r32 Compare r32 with r/m32
        elif instruction.opcode == 0x39:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - op2value

                self.set_flags("CMP", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #3B /r CMP r16,r/m16 Compare r/m16 with r16
        #3B /r CMP r32,r/m32 Compare r/m32 with r32
        elif instruction.opcode == 0x3b:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)
                
                result = op1value - op2valuederef

                self.set_flags("CMP", op1value, op2valuederef, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #3C ib CMP AL, imm8 Compare imm8 with AL
        elif instruction.opcode == 0x3c:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - op2value

            self.set_flags("CMP", op1value, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #3D id CMP EAX, imm32 Compare imm32 with EAX
        #3D iw CMP AX, imm16 Compare imm16 with AX
        elif instruction.opcode == 0x3d:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - op2value

            self.set_flags("CMP", op1value, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #80 /7 ib CMP r/m8,imm8 Compare imm8 with r/m8
        elif instruction.opcode == 0x80 and instruction.extindex == 0x7:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - op2value

                self.set_flags("CMP", op1valuederef, op2value, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /7 id CMP r/m32,imm32 Compare imm32 with r/m32
        #81 /7 iw CMP r/m16, imm16 Compare imm16 with r/m16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - op2value

                self.set_flags("CMP", op1valuederef, op2value, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /7 ib CMP r/m16,imm8 Compare imm8 with r/m16
        #83 /7 ib CMP r/m32,imm8 Compare imm8 with r/m32
        elif instruction.opcode == 0x83 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - op2value

                self.set_flags("CMP", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - op2value

                self.set_flags("CMP", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CMPS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #A6 CMPS m8, m8 Compares byte at address DS:(E)SI with byte at address ES:(E)DI and sets the status flags accordingly
        if instruction.opcode == 0xa6:

            op1value = self.get_memory(self.get_memory_address(instruction, 1, size), size)
            op2value = self.get_memory_address(instruction, 2, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A7 CMPS m16, m16 Compares word at address DS:(E)SI with word at address ES:(E)DI and sets the status flags accordingly
        #A7 CMPS m32, m32 Compares doubleword at address DS:(E)SI with doubleword at address ES:(E)DI and sets the status flags accordingly
        elif instruction.opcode == 0xa7:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_memory_address(instruction, 1, size)
            op2value = self.get_memory_address(instruction, 2, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CMPSB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #A6 CMPSB Compares byte at address DS:(E)SI with byte at address ES:(E)DI and sets the status flags accordingly
        if instruction.opcode == 0xa6:
            size = 1
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.DS + self.get_register16("SI")
                    op2value = self.ES + self.get_register16("DI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register32("ESI")
                    op2value = self.get_register32("EDI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CMPSW(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #A7 CMPSW Compares word at address DS:(E)SI with word at address ES:(E)DI and sets the status flags accordingly
        if instruction.opcode == 0xa7:
            
            size = 2
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.DS + self.get_register16("SI")
                    op2value = self.ES + self.get_register16("DI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register32("ESI")
                    op2value = self.get_register32("EDI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def CMPSD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #A7 CMPSD Compares doubleword at address DS:(E)SI with doubleword at address ES:(E)DI and sets the status flags accordingly
        if instruction.opcode == 0xa7:
            
            size = 4
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.DS + self.get_register16("SI")
                        op2value = self.ES + self.get_register16("DI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.DS + self.get_register16("SI")
                    op2value = self.ES + self.get_register16("DI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register32("ESI")
                        op2value = self.get_register32("EDI")
                        
                        op1valuederef = self.get_memory(op1value, size)
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1valuederef - op2valuederef

                        self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register32("ESI")
                    op2value = self.get_register32("EDI")
                    
                    op1valuederef = self.get_memory(op1value, size)
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op1valuederef - op2valuederef

                    self.set_flags("CMP", op1valuederef, op2valuederef, result, size)
                                        
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def DEC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #48+rd DEC r32 Decrement r32 by 1
        #48+rw DEC r16 Decrement r16 by 1
        if instruction.opcode >= 0x48 and instruction.opcode <= 0x4f:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            # Do logic
            result = op1value - 1
            oldcf = self.CF

            self.set_flags("DEC", op1value, 1, result, size)
            self.CF = oldcf

            result = self.sanitize_value(result, size)

            self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FE /1 DEC r/m8 Decrement r/m8 by 1
        elif instruction.opcode == 0xfe and instruction.extindex == 0x1:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = op1value - 1
                oldcf = self.CF

                self.set_flags("DEC", op1value, 1, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - 1
                oldcf = self.CF

                self.set_flags("DEC", op1valuederef, 1, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /1 DEC r/m16 Decrement r/m16 by 1
        #FF /1 DEC r/m32 Decrement r/m32 by 1
        elif instruction.opcode == 0xff and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = op1value - 1
                oldcf = self.CF

                self.set_flags("DEC", op1value, 1, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - 1
                oldcf = self.CF

                self.set_flags("DEC", op1valuederef, 1, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def DIV(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F6 /6 DIV r/m8 Unsigned divide AX by r/m8, with result stored in AL . Quotient, AH . Remainder
        if instruction.opcode == 0xf6 and instruction.extindex == 0x6:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                ax = self.get_register16("AX")
                
                if op1value == 0 or op1value > self.get_mask(size):
                    return self.emu.raise_exception("DE", self.EIP)
                    
                temp = ax / op1value
                if temp > 0xff:
                    return False
                else:
                    self.set_register8("AL", temp)
                    self.set_register8("AH", ax % op1value)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                ax = self.get_register16("AX")
                
                if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                    return self.emu.raise_exception("DE", self.EIP)
                    
                temp = ax / op1valuederef
                if temp > 0xff:
                    return False
                else:
                    self.set_register8("AL", temp)
                    self.set_register8("AH", ax % op1valuederef)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /6 DIV r/m16 Unsigned divide DX:AX by r/m16, with result stored in AX . Quotient, DX .
        #F7 /6 DIV r/m32 Unsigned divide EDX:EAX by r/m32, with result stored in EAX . Quotient, EDX .
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x6:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if size == 2:
                    ax = self.get_register16("AX")
                    dx = self.get_register16("DX")
                    axdx = ((dx << 16) | ax)
                    
                    if op1value == 0 or op1value > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                    
                    temp = axdx / op1value
                    
                    if temp > 0xffff:
                        return False
                    else:
                        self.set_register16("AX", temp)
                        self.set_register16("DX", axdx % op1value)
                else:
                    eax = self.get_register32("EAX")
                    edx = self.get_register32("EDX")
                    eaxedx = ((edx << 32) | eax)
                    
                    if op1value == 0 or op1value > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                    
                    temp = eaxedx / op1value
                    
                    if temp > 0xffffffff:
                        return False
                    else:
                        self.set_register32("EAX", temp)
                        self.set_register32("EDX", eaxedx % op1value)
                        
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    ax = self.get_register16("AX")
                    dx = self.get_register16("DX")
                    axdx = ((dx << 16) | ax)
                    
                    if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                    
                    temp = axdx / op1valuederef
                    
                    if temp > 0xffff:
                        return False
                    else:
                        self.set_register16("AX", temp)
                        self.set_register16("DX", axdx % op1valuederef)
                else:
                    eax = self.get_register32("EAX")
                    edx = self.get_register32("EDX")
                    eaxedx = ((edx << 32) | eax)
                    
                    if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                    temp = eaxedx / op1valuederef
                    
                    if temp > 0xffffffff:
                        return False
                    else:
                        self.set_register32("EAX", temp)
                        self.set_register32("EDX", eaxedx % op1valuederef)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def IDIV(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F6 /7 IDIV r/m8 Signed divide AX by r/m8, with result stored in AL . Quotient, AH . Remainder
        if instruction.opcode == 0xf6 and instruction.extindex == 0x7:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                ax = self.get_register16("AX")
                
                if op1value == 0 or op1value > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                temp = ax / op1value
                
                if temp > 0xff:
                    return False
                else:
                    self.set_register8("AL", temp)
                    self.set_register8("AH", ax % op1value)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                ax = self.get_register16("AX")
                
                if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                
                temp = ax / op1valuederef

                if temp > 0xff:
                    return False
                else:
                    self.set_register8("AL", temp)
                    self.set_register8("AH", ax % op1valuederef)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /7 IDIV r/m16 Signed divide DX:AX by r/m16, with result stored in AX . Quotient, DX .
        #F7 /7 IDIV r/m32 Signed divide EDX:EAX by r/m32, with result stored in EAX . Quotient, EDX .
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if size == 2:
                    ax = self.get_register16("AX")
                    dx = self.get_register16("DX")
                    axdx = ((dx << 16) | ax)
                    
                    if op1value == 0 or op1value > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                    temp = axdx / op1value
                    
                    if temp > 0xffff:
                        return False
                    else:
                        self.set_register16("AX", temp)
                        self.set_register16("DX", axdx % op1value)
                else:
                    eax = self.get_register32("EAX")
                    edx = self.get_register32("EDX")
                    eaxedx = ((edx << 32) | eax)
                    
                    if op1value == 0 or op1value> self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                    temp = eaxedx / op1value
                    
                    if temp > 0xffffffff:
                        return False
                    else:
                        self.set_register32("EAX", temp)
                        self.set_register32("EDX", eaxedx % op1value)
                        
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    ax = self.get_register16("AX")
                    dx = self.get_register16("DX")
                    axdx = ((dx << 16) | ax)
                    
                    if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                    temp = axdx / op1valuederef
                    
                    if temp > 0xffff:
                        return False
                    else:
                        self.set_register16("AX", temp)
                        self.set_register16("DX", axdx % op1valuederef)
                else:
                    eax = self.get_register32("EAX")
                    edx = self.get_register32("EDX")
                    eaxedx = ((edx << 32) | eax)
                    
                    if op1valuederef == 0 or op1valuederef > self.get_mask(size):
                        return self.emu.raise_exception("DE", self.EIP)
                        
                    temp = eaxedx / op1valuederef
                    
                    if temp > 0xffffffff:
                        return False
                    else:
                        self.set_register32("EAX", temp)
                        self.set_register32("EDX", eaxedx % op1valuederef)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def IMUL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        op3 = None
        
        if instruction.op3:
            op3 = instruction.op3

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #0F AF /r IMUL r16,r/m16 word register . word register * r/m word
        #0F AF /r IMUL r32,r/m32 doubleword register . doubleword register * r/m doubleword
        if instruction.opcode == 0xaf:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value * op2value
                
                self.set_flags("IMUL", op1value, op2value, result, size)
                
                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)
                
                result = op1value * op2value
                
                self.set_flags("IMUL", op1value, op2value, result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #69 /r id IMUL r32,imm32 doubleword register . r/m32 * immediate doubleword
        #69 /r id IMUL r32,r/ m32,imm32 doubleword register . r/m32 * immediate doubleword
        #69 /r iw IMUL r16,imm16 word register . r/m16 * immediate word
        #69 /r iw IMUL r16,r/ m16,imm16 word register . r/m16 * immediate word
        elif instruction.opcode == 0x69:
            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op3:
                op3value = op3.immediate & self.get_mask(size)
                
                if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                    op2value = self.get_register(op2.reg, size)
                            
                    # Do logic
                    result = op2value * op3value
                    
                    self.set_flags("IMUL", op2value, op3value, result, size)
                    
                    self.set_register(op1.reg, result, size)
                    
                elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                    op2value = self.get_register(op2.reg, size)
                    
                    # Do logic
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op2value * op3value
                    
                    self.set_flags("IMUL", op2value, op3value, result, size)
                    
                    self.set_register(op1.reg, result, size)
            else:
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value * op2value
                print result
                self.set_flags("IMUL", op2value, op3value, result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #6B /r ib IMUL r16,imm8 word register . word register * sign-extended immediate byte
        #6B /r ib IMUL r16,r/m16,imm8 word register . r/m16 * sign-extended immediate byte
        #6B /r ib IMUL r32,imm8 doubleword register . doubleword register * signextended immediate byte
        #6B /r ib IMUL r32,r/m32,imm8 doubleword register . r/m32 * sign-extended immediate byte
        elif instruction.opcode == 0x6b:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            # Do logic
            if op3:
                op3value = self.sign_extend((op3.immediate & self.get_mask(size)), 1, size)
                
                if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                    op2value = self.get_register(op2.reg, size)
                            
                    # Do logic
                    result = op2value * op3value
                    
                    self.set_flags("IMUL", op2value, op3value, result, size)
                    
                    self.set_register(op1.reg, result, size)
                    
                elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                    op2value = self.get_register(op2.reg, size)
                    
                    # Do logic
                    op2valuederef = self.get_memory(op2value, size)
                    
                    result = op2value * op3value
                    
                    self.set_flags("IMUL", op2value, op3value, result, size)
                    
                    self.set_register(op1.reg, result, size)
            else:
                op2value = self.sign_extend((op2.immediate & self.get_mask(size)), 1, size)
                        
                # Do logic
                result = op1value * op2value
                
                self.set_flags("IMUL", op2value, op3value, result, size)
                
                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F6 /5 IMUL r/m8 AX. AL * r/m byte
        elif instruction.opcode == 0xf6 and instruction.extindex == 0x5:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("AL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op2value * op1valuederef
                
                self.OF = 0
                self.CF = 0
                
                self.set_register16("AX", result)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("AL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op2value * op1valuederef
                
                self.OF = 0
                self.CF = 0
                
                self.set_register16("AX", result)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /5 IMUL r/m16 DX:AX . AX * r/m word
        #F7 /5 IMUL r/m32 EDX:EAX . EAX * r/m doubleword
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if size == 2:
                if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register16("AX")
                
                    # Do logic
                    result = op2value * op1value
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register16("DX", high)
                    self.set_register16("AX", low)
    
                elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_memory_address(instruction, 1, size)
                    op2value = self.get_register16("AX")
                    
                    # Do logic
                    op1valuederef = self.get_memory(op1value, size)
                    
                    result = op2value * op1valuederef
                    
                    high = (result >> 16)
                    low = (result & 0xffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register16("DX", high)
                    self.set_register16("AX", low)
            else:
                if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register32("EAX")
                
                    # Do logic
                    result = op2value * op1value
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register32("EDX", high)
                    self.set_register32("EAX", low)
    
                elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_memory_address(instruction, 1, size)
                    op2value = self.get_register32("EAX")
                    
                    # Do logic
                    op1valuederef = self.get_memory(op1value, size)
                    
                    result = op2value * op1valuederef
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register32("EDX", high)
                    self.set_register32("EAX", low)
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def INC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #40+ rd INC r32 Increment doubleword register by 1
        #40+ rw INC r16 Increment word register by 1
        if instruction.opcode >= 0x40 and instruction.opcode <= 0x47:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            # Do logic
            op2value = 1

            result = op1value + op2value
            oldcf = self.CF

            self.set_flags("INC", op1value, op2value, result, size)
            self.CF = oldcf

            result = self.sanitize_value(result, size)

            self.set_register(op1.reg, result, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FE /0 INC r/m8 Increment r/m byte by 1
        elif instruction.opcode == 0xfe and instruction.extindex == 0x0:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                op2value = 1
                
                result = op1value + op2value
                
                oldcf = self.CF

                self.set_flags("INC", op1value, op2value, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                op2value = 1
                
                result = op1valuederef + op2value
                
                oldcf = self.CF

                self.set_flags("INC", op1valuederef, op2value, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /0 INC r/m16 Increment r/m word by 1
        #FF /0 INC r/m32 Increment r/m doubleword by 1
        elif instruction.opcode == 0xff and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                op2value = 1
                
                result = op1value + op2value
                
                oldcf = self.CF

                self.set_flags("INC", op1value, op2value, result, size)
                self.CF = oldcf

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                op2value = 1
                
                result = op1valuederef + op2value
                
                oldcf = self.CF

                self.set_flags("INC", op1value, op2value, result, size)
                
                self.CF = oldcf

                result = self.sanitize_value(result, size)
                
                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def INT(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #CC INT 3 Trap to debugger
        if instruction.opcode >= 0xcc:

            op1value = 3

            self.dispatch_interrupt(op1value)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #CD ib INT imm8 Trap to interrupt vector
        elif instruction.opcode == 0xcd:
            size = 1
            
            op1value = op1.immediate & self.get_mask(size)
            
            self.dispatch_interrupt(op1value)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #77 cb JA rel8 Valid Valid Jump short if above (CF=0 and ZF=0).
        if instruction.opcode == 0x77:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.CF and not self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)        
        #0F 87 cw/cd JA rel16/32 Jump near if above (CF=0 and ZF=0)
        elif instruction.opcode == 0x87:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.CF and not self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #72 cb JB rel8 Valid Valid Jump short if below (CF=1).
        if instruction.opcode == 0x72:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                            
        #0F 82 cw/cd JB rel16/32 Jump near if below (CF=1)
        elif instruction.opcode == 0x82:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JBE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #76 cb JBE rel8 Valid Valid Jump short if below or equal (CF=1 or ZF=1).
        if instruction.opcode == 0x76:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.CF or self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 86 cw/cd JBE rel16/32 Jump near if below or equal (CF=1 or ZF=1)
        elif instruction.opcode == 0x86:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.CF or self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JNA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #76 cb JNA rel8 Valid Valid Jump short if not above (CF=1 or ZF=1).
        if instruction.opcode == 0x76:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.CF or self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 86 cd JNA rel32 Valid Valid Jump near if not above (CF=1 or ZF=1).
        elif instruction.opcode == 0x86:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.CF or self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def JG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7F cb JG rel8 Valid Valid Jump short if greater (ZF=0 and SF=OF).
        if instruction.opcode == 0x7f:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.ZF and (self.SF == self.OF):
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                            
        #0F 8F cw/cd JG rel16/32 Jump near if greater (ZF=0 and SF=OF)
        elif instruction.opcode == 0x8f:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.ZF and (self.SF == self.OF):
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                            
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JGE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7D cb JGE rel8 Valid Valid Jump short if greater or equal (SF=OF).
        if instruction.opcode == 0x7d:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.SF == self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 8D cw/cd JGE rel16/32 Jump near if greater or equal (SF=OF)
        elif instruction.opcode == 0x8d:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.SF == self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JNL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7D cb JNL rel8 Valid Valid Jump short if not less (SF=OF).
        if instruction.opcode == 0x7d:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.SF == self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 8D cd JNL rel32 Valid Valid Jump near if not less (SF=OF).
        elif instruction.opcode == 0x8d:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.SF == self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7C cb JL rel8 Valid Valid Jump short if less (SF? OF).
        if instruction.opcode == 0x7c:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.SF != self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                            
        #0F 8C cw/cd JL rel16/32 Jump near if less (SF<>OF)
        elif instruction.opcode == 0x8c:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.SF != self.OF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
        
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                            
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JLE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7E cb JLE rel8 Valid Valid Jump short if less or equal (ZF=1 or SF != OF).
        if instruction.opcode == 0x7e:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.ZF or (self.SF != self.OF):
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 8E cw/cd JLE rel16/32 Jump near if less or equal (ZF=1 or SF<>OF)
        elif instruction.opcode == 0x8e:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.ZF or (self.SF != self.OF):
                op1value = op1.immediate
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JNG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #7E cb JNG rel8 Valid Valid Jump short if not greater (ZF=1 or SF != OF).
        if instruction.opcode == 0x7e:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.ZF or (self.SF != self.OF):
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 8E cw JNG rel16 N.S. Valid Jump near if not greater (ZF=1 or SF != OF)
        #0F 8E cd JNG rel32 Valid Valid Jump near if not greater (ZF=1 or SF != OF).
        elif instruction.opcode == 0x8e:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.ZF or (self.SF != self.OF):
                op1value = op1.immediate
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JMP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #E9 cd JMP rel32 Jump near, relative, displacement relative to next instruction
        #E9 cw JMP rel16 Jump near, relative, displacement relative to next instruction
        if instruction.opcode == 0xe9:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            result = self.get_register32("EIP") + instruction.length + op1value

            self.set_register32("EIP", result)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #EA cd JMP ptr16:16 Jump far, absolute, address given in operand
        #EA cp JMP ptr16:32 Jump far, absolute, address given in operand
        elif instruction.opcode == 0xea:

            print "[!] Unsupported until test case found"
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #EB cb JMP rel8 Jump short, relative, displacement relative to next instruction
        elif instruction.opcode == 0xeb:

            size = 1

            op1value = op1.immediate
            
            # Do logic
            result = self.get_register32("EIP") + instruction.length + (op1value)

            self.set_register32("EIP", result)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /4 JMP r/m16 Jump near, absolute indirect, address given in r/m16
        #FF /4 JMP r/m32 Jump near, absolute indirect, address given in r/m32
        elif instruction.opcode == 0xff and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = op1value

                self.set_register32("EIP", result)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                result = self.get_memory(op1value, size)

                self.set_register32("EIP", result)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /5 JMP m16:16 Jump far, absolute indirect, address given in m16:16
        #FF /5 JMP m16:32 Jump far, absolute indirect, address given in m16:32
        elif instruction.opcode == 0xff and instruction.extindex == 0x5:

            print "[!] Unsupported until test case found"
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def JC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #72 cb JC rel8 Valid Valid Jump short if carry (CF=1).
        if instruction.opcode == 0x72:
            
            size = 1

            op1value = op1.immediate

            # Do logic
            if self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 82 cw JC rel16 N.S. Valid Jump near if carry (CF=1).
        #0F 82 cd JC rel32 Valid Valid Jump near if carry (CF=1).
        elif instruction.opcode == 0x82:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
        
        return True


    def JNC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #73 cb JNC rel8 Valid Valid Jump short if not carry (CF=0).
        if instruction.opcode == 0x73:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 83 cw/cd JNC rel16/32 Jump near if not carry (CF=0)
        elif instruction.opcode == 0x83:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

        
    def JNB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #73 cb JNB rel8 Valid Valid Jump short if not below (CF=0).
        if instruction.opcode == 0x73:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 83 cw/cd JNB rel16/32 Jump near if not below (CF=0)
        elif instruction.opcode == 0x83:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.CF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JNS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #79 cb JNS rel8 Valid Valid Jump short if not sign (SF=0).
        if instruction.opcode == 0x79:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.SF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 89 cw/cd JNS rel16/32 Jump near if not sign (SF=0)
        elif instruction.opcode == 0x89:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.SF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JNZ(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #75 cb JNZ rel8 Valid Valid Jump short if not zero (ZF=0).
        if instruction.opcode == 0x75:

            size = 1

            op1value = op1.immediate

            # Do logic
            if not self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 85 cw/cd JNZ rel16/32 Jump near if not zero (ZF=0)
        elif instruction.opcode == 0x85:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if not self.ZF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                self.set_register32("EIP", eip)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #78 cb JS rel8 Valid Valid Jump short if sign (SF=1).
        if instruction.opcode == 0x78:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.SF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)
    
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #0F 88 cw/cd JS rel16/32 Jump near if sign (SF=1)
        elif instruction.opcode == 0x88:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.SF:
                eip = self.get_register32("EIP") + instruction.length + op1value

                if so:
                    eip = eip & 0xffff

                self.set_register32("EIP", eip)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def JZ(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 84 cw/cd JZ rel16/32 Jump near if 0 (ZF=1)
        #0F 84 cw/cd JZ rel16/32 Jump near if 0 (ZF=1)
        if instruction.opcode == 0x84:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate

            # Do logic
            if self.ZF:
                result = self.get_register32("EIP") + instruction.length + op1value

                self.set_register32("EIP", result)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #74 cb JZ rel8 Jump short if zero (ZF = 1)
        elif instruction.opcode == 0x74:

            size = 1

            op1value = op1.immediate

            # Do logic
            if self.ZF:
                result = self.get_register32("EIP") + instruction.length + op1value
                
                self.set_register32("EIP", result)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def LEA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #8D /r LEA r16,m Store effective address for m in register r16
        #8D /r LEA r32,m Store effective address for m in register r32
        if instruction.opcode == 0x8d:
            
            if so:
                size = 2
            else:
                size = 4

            op2value = self.get_memory_address(instruction, 2, size)
            
            # Do logic
            self.set_register(op1.reg, op2value, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def LEAVE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C9 LEAVE Set ESP to EBP, then pop EBP
        #C9 LEAVE Set SP to BP, then pop BP
        if instruction.opcode == 0xc9:


            # Do logic
            ebp = self.get_register32("EBP")
            newebp = self.get_memory32(ebp)

            self.set_register32("ESP", ebp + 4)
            self.set_register32("EBP", newebp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def MOV(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        oo = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 20 /r MOV r32,CR0 Move CR0 to r32
        #0F 20 /r MOV r32,CR2 Move CR2 to r32
        #0F 20 /r MOV r32,CR3 Move CR3 to r32
        #0F 20 /r MOV r32,CR4 Move CR4 to r32
        if instruction.opcode == 0x20:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
                
            op1value = self.get_register(op1.reg, osize)

            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 20 /r MOV r32,CR0 Move CR0 to r32
        #0F 20 /r MOV r32,CR2 Move CR2 to r32
        #0F 20 /r MOV r32,CR3 Move CR3 to r32
        #0F 20 /r MOV r32,CR4 Move CR4 to r32
        elif instruction.opcode == 0x20:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            op1value = self.get_register(op1.reg, osize)

            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 21/r MOV r32, DR0-DR7 Move debug register to r32
        elif instruction.opcode == 0x21:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            op1value = self.get_register(op1.reg, osize)

            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 22 /r MOV CR0,r32 Move r32 to CR0
        #0F 22 /r MOV CR2,r32 Move r32 to CR2
        #0F 22 /r MOV CR3,r32 Move r32 to CR3
        #0F 22 /r MOV CR4,r32 Move r32 to CR4
        elif instruction.opcode == 0x22:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
                
            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F 22 /r MOV CR0,r32 Move r32 to CR0
        #0F 22 /r MOV CR2,r32 Move r32 to CR2
        #0F 22 /r MOV CR3,r32 Move r32 to CR3
        #0F 22 /r MOV CR4,r32 Move r32 to CR4
        elif instruction.opcode == 0x22:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
                
            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #88 /r MOV r/m8,r8 Move r8 to r/m8
        elif instruction.opcode == 0x88:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                self.set_register(op1.reg, op2value, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                self.set_memory(op1value, op2value, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #89 /r MOV r/m16,r16 Move r16 to r/m16
        #89 /r MOV r/m32,r32 Move r32 to r/m32
        elif instruction.opcode == 0x89:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, osize)
                op2value = self.get_register(op2.reg, osize)

                # Do logic
                self.set_register(op1.reg, op2value, osize)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_register(op2.reg, osize)

                # Do logic
                if instruction.fs_override():
                    fs = self.get_register16("FS")
                    offset = op2.displacement
                    baseaddress = self.emu.get_selector(fs).base
                    
                    op1value = self.get_memory(baseaddress + offset, size)
                else:
                    op1value = self.get_memory_address(instruction, 1, asize)
                    
                self.set_memory(op1value, op2value, asize)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #8A /r MOV r8,r/m8 Move r/m8 to r8.
        elif instruction.opcode == 0x8a:

            size = 1

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                self.set_register(op1.reg, op2value, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)
                self.set_register(op1.reg, op2valuederef, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #8B /r MOV r16,r/m16 Move r/m16 to r16
        #8B /r MOV r32,r/m32 Move r/m32 to r32
        elif instruction.opcode == 0x8b:
            
            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            op1value = self.get_register(op1.reg, osize)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, osize)

                # Do logic
                self.set_register(op1.reg, op2value, osize)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                # We check for a segment override first
                if instruction.fs_override():
                    fs = self.get_register16("FS")
                    offset = op2.displacement
                    baseaddress = self.emu.get_selector(fs).base
                    
                    op2value = baseaddress + offset
                else:
                    op2value = self.get_memory_address(instruction, 2, asize)

                # Do logic
                op2valuederef = self.get_memory(op2value, asize)

                self.set_register(op1.reg, op2valuederef, osize)
    
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #8C /r MOV r/m16,Sreg** Move segment register to r/m16
        elif instruction.opcode == 0x8c:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, osize)

                # Do logic
                return False

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, asize)

                # Do logic
                return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A0 MOV AL,moffs8* Move byte at (seg:offset) to AL
        elif instruction.opcode == 0xa0:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
                
            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A1 MOV AX,moffs16* Move word at (seg:offset) to AX
        #A1 MOV EAX,moffs32* Move doubleword at (seg:offset) to EAX
        elif instruction.opcode == 0xa1:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
                
            # Do logic
            # We are going to just get fs for now
            if instruction.fs_override():
                fs = self.get_register16("FS")
                offset = op2.displacement
                baseaddress = self.emu.get_selector(fs).base
                
                op2value = self.get_memory(baseaddress + offset, asize)
                self.set_register(0, op2value, osize)
            else:
                op2value = self.get_memory_address(instruction, 2, asize)
                offset = op2.displacement
                op2valuederef = self.get_memory(op2value + offset, asize)
                
                self.set_register(0, op2valuederef, osize)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A3 MOV moffs16*,AX Move AX to (seg:offset)
        #A3 MOV moffs32*,EAX Move EAX to (seg:offset)
        elif instruction.opcode == 0xa3:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4
            
            op2value = self.get_register(0, osize)
            
            # Do logic
            # We are going to just get fs for now
            if instruction.fs_override():
                fs = self.get_register16("FS")
                offset = op2.displacement
                baseaddress = self.emu.get_selector(fs).base
                
                self.set_memory(baseaddress + offset, op2value, asize)
            else:
                print "[!] Please add this segment"
                
                return False
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #B0+ rb MOV r8,imm8 Move imm8 to r8
        elif instruction.opcode >= 0xb0 and instruction.opcode <= 0xb7:
            
            size = 1

            op1value = self.get_register(op1.reg, size)
            op2value = op2.immediate & self.get_mask(size)
            
            self.set_register8(op1.reg, op2value)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #B8+ rd MOV r32,imm32 Move imm32 to r32
        #B8+ rw MOV r16,imm16 Move imm16 to r16
        elif instruction.opcode >= 0xb8 and instruction.opcode <= 0xbf:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            op1value = self.get_register(op1.reg, osize)
            op2value = op2.immediate & self.get_mask(osize)

            # Do logic
            self.set_register(op1.reg, op2value, osize)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C6 /0 MOV r/m8,imm8 Move imm8 to r/m8
        elif instruction.opcode == 0xc6 and instruction.extindex == 0x0:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                self.set_register(op1.reg, op2value, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                self.set_memory(op1value, op2value, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C7 /0 MOV r/m16,imm16 Move imm16 to r/m16
        #C7 /0 MOV r/m32,imm32 Move imm32 to r/m32
        elif instruction.opcode == 0xc7 and instruction.extindex == 0x0:

            if oo:
                osize = 2
            else:
                osize = 4

            if ao:
                asize = 2
            else:
                asize = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, osize)
                op2value = op2.immediate & self.get_mask(osize)

                # Do logic
                self.set_register(op1.reg, op2value, osize)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, asize)
                op2value = op2.immediate & self.get_mask(osize)

                # Do logic
                self.set_memory(op1value, op2value, asize)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def MOVS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #A4 MOVS m8, m8 Move byte at address DS:(E)SI to address ES:(E)DI
        if instruction.opcode == 0xa4:

            op1value = self.get_memory(self.get_memory_address(instruction, 1, size), size)
            op2value = self.get_memory_address(instruction, 2, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A5 MOVS m16, m16 Move word at address DS:(E)SI to address ES:(E)DI
        #A5 MOVS m32, m32 Move doubleword at address DS:(E)SI to address ES:(E)DI
        elif instruction.opcode == 0xa5:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_memory_address(instruction, 1, size)
            op2value = self.get_memory_address(instruction, 2, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def MOVSB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #A4 MOVSB
        if instruction.opcode == 0xa4:
            size = 1
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.DS + self.get_register16("SI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                            self.set_register16("SI", op2value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                            self.set_register16("SI", op2value - size)
                    
                        
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.DS + self.get_register16("SI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                        self.set_register16("SI", op2value + size)
                    else:
                        self.set_register16("DI", op1value - size)
                        self.set_register16("SI", op2value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register32("ECX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register32("ESI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                            self.set_register32("ESI", op2value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                            self.set_register32("ESI", op2value - size)
                    
                        
                        repcount -= 1
                        
                    self.set_register32("ECX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register32("ESI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                        self.set_register32("ESI", op2value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        self.set_register32("ESI", op2value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False
        
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def MOVSW(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #A5 MOVSW
        if instruction.opcode == 0xa5:
            size = 2
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.DS + self.get_register16("SI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                            self.set_register16("SI", op2value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                            self.set_register16("SI", op2value - size)
                    
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.DS + self.get_register16("SI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                        self.set_register16("SI", op2value + size)
                    else:
                        self.set_register16("DI", op1value - size)
                        self.set_register16("SI", op2value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register32("ECX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register32("ESI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                            self.set_register32("ESI", op2value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                            self.set_register32("ESI", op2value - size)
                    
                        
                        repcount -= 1
                        
                    self.set_register32("ECX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register32("ESI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                        self.set_register32("ESI", op2value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        self.set_register32("ESI", op2value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                        
        return True

    def MOVSD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #A5 MOVSD
        if instruction.opcode == 0xa5:
            size = 4
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.DS + self.get_register16("SI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                            self.set_register16("SI", op2value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                            self.set_register16("SI", op2value - size)
                    
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.DS + self.get_register16("SI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                        self.set_register16("SI", op2value + size)
                    else:
                        self.set_register16("DI", op1value - size)
                        self.set_register16("SI", op2value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register32("ECX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register32("ESI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        self.set_memory(op1value, op2valuederef, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                            self.set_register32("ESI", op2value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                            self.set_register32("ESI", op2value - size)
                    
                        repcount -= 1
                        
                    self.set_register32("ECX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register32("ESI")
                    
                    op2valuederef = self.get_memory(op2value, size)
                    self.set_memory(op1value, op2valuederef, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                        self.set_register32("ESI", op2value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        self.set_register32("ESI", op2value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                        
        return True


    def MOVSX(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F BE /r MOVSX r16,r/m8 Move byte to word with sign-extension
        #0F BE /r MOVSX r32,r/m8 Move byte to doubleword, sign-extension
        if instruction.opcode == 0xbe:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)
                
                result = self.sign_extend(op2value, 1, size)
    
                self.set_register(op1.reg, result, size)
            
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)
                
                op2valuederef = self.get_memory(op2value, 1)
                
                result = self.sign_extend(op2valuederef, 1, size)
    
                self.set_register(op1.reg, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F BF /r MOVSX r32,r/m16 Move word to doubleword, sign-extension
        elif instruction.opcode == 0xbf:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)
                
                result = self.sign_extend(op2value, 2, size)
    
                self.set_register(op1.reg, result, size)
            
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)
                
                op2valuederef = self.get_memory(op2value, 2)
                
                result = self.sign_extend(op2valuederef, 2, size)
    
                self.set_register(op1.reg, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def MOVZX(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F B6 /r MOVZX r16,r/m8 Move byte to word with zero-extension
        #0F B6 /r MOVZX r32,r/m8 Move byte to doubleword, zero-extension
        if instruction.opcode == 0xb6:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)
                
                result = op2value
    
                self.set_register(op1.reg, result, size)
            
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)
                
                op2valuederef = self.get_memory(op2value, 1)
                
                result = op2valuederef
    
                self.set_register(op1.reg, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F B7 /r MOVZX r32,r/m16 Move word to doubleword, zero-extension
        elif instruction.opcode == 0xb7:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)
                
                result = op2value
    
                self.set_register(op1.reg, result, size)
            
            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)
                
                op2valuederef = self.get_memory(op2value, 2)
                
                result = op2valuederef
    
                self.set_register(op1.reg, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def MUL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F6 /4 MUL r/m8 Unsigned multiply (AX . AL * r/m8)
        if instruction.opcode == 0xf6 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("AL")
                
                # Do logic
                result = op2value * op1value
                
                self.OF = 0
                self.CF = 0
                
                self.set_register16("AX", result)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("AL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op2value * op1valuederef
                
                self.OF = 0
                self.CF = 0
                
                self.set_register16("AX", result)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /4 MUL r/m16 Unsigned multiply (DX:AX . AX * r/m16)
        #F7 /4 MUL r/m32 Unsigned multiply (EDX:EAX . EAX * r/m32) 
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if size == 2:
                if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register16("AX")
                
                    # Do logic
                    result = op2value * op1value
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register16("DX", high)
                    self.set_register16("AX", low)
    
                elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_memory_address(instruction, 1, size)
                    op2value = self.get_register16("AX")
                    
                    # Do logic
                    op1valuederef = self.get_memory(op1value, size)
                    
                    result = op2value * op1valuederef
                    
                    high = (result >> 16)
                    low = (result & 0xffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register16("DX", high)
                    self.set_register16("AX", low)
            else:
                if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register32("EAX")
                
                    # Do logic
                    result = op2value * op1value
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register32("EDX", high)
                    self.set_register32("EAX", low)
    
                elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_memory_address(instruction, 1, size)
                    op2value = self.get_register32("EAX")
                    
                    # Do logic
                    op1valuederef = self.get_memory(op1value, size)
                    
                    result = op2value * op1valuederef
                    
                    high = (result >> 32)
                    low = (result & 0xffffffff)
                    
                    if high:
                        self.OF = 1
                        self.CF = 1
                    else:
                        self.OF = 0
                        self.CF = 0
                    
                    self.set_register32("EDX", high)
                    self.set_register32("EAX", low)
                    
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def NEG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F6 /3 NEG r/m8 Twos complement negate r/m8
        if instruction.opcode == 0xf6 and instruction.extindex == 0x3:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = -op1value

                self.set_flags("NEG", op1value, 0, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = -op1valuederef

                self.set_flags("NEG", op1valuederef, 0, result, size)

                self.set_memory(op1value, result, size)


            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /3 NEG r/m16 Twos complement negate r/m16
        #F7 /3 NEG r/m32 Twos complement negate r/m32
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = -op1value

                self.set_flags("NEG", op1value, 0, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = -op1valuederef

                self.set_flags("NEG", op1valuederef, 0, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def NOP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        opcode = instruction.opcode
        if opcode in self.emu.opcode_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        #90 NOP No operation
        return True


    def NOT(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #F6 /2 NOT r/m8 Reverse each bit of r/m8
        if instruction.opcode == 0xf6 and instruction.extindex == 0x2:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = ~op1value

                self.set_flags("LOGIC", op1value, 0, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = ~op1valuederef

                self.set_flags("LOGIC", op1valuederef, 0, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /2 NOT r/m16 Reverse each bit of r/m16
        #F7 /2 NOT r/m32 Reverse each bit of r/m32
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                result = ~op1value

                self.set_flags("LOGIC", op1value, 0, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = ~op1valuederef

                self.set_flags("LOGIC", op1valuederef, 0, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def OR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #08 /r OR r/m8,r8 r/m8  r8
        if instruction.opcode == 0x08:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value | op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef | op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #09 /r OR r/m16,r16 r/m16  r16
        #09 /r OR r/m32,r32 r/m32  r32
        elif instruction.opcode == 0x09:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value | op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef | op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #0B /r OR r16,r/m16 r16  r/m16
        #0B /r OR r32,r/m32 r32  r/m32
        elif instruction.opcode == 0x0b:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value | op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)

                result = op1value | op2valuederef

                self.set_flags("LOGIC", op1value, op2valuederef, result, size)

                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #0C ib OR AL,imm8 AL  imm8
        elif instruction.opcode == 0x0c:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value | op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #0D id OR EAX,imm32 EAX  imm32
        #0D iw OR AX,imm16 AX  imm16
        elif instruction.opcode == 0x0d:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value | op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
        #81 /1 id OR r/m32,imm32 r/m32  imm32
        #81 /1 iw OR r/m16,imm16 r/m16  imm16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value | op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef | op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #83 /1 ib OR r/m16,imm8 r/m16  imm8 (sign-extended)
        #83 /1 ib OR r/m32,imm8 r/m32  imm8 (sign-extended)
        elif instruction.opcode == 0x83 and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value | op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef | op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def POP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #07 POP ES Pop top of stack into ES; increment stack pointer
        if instruction.opcode == 0x07:

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F A9 POP GS Pop top of stack into GS; increment stack pointer
        elif instruction.opcode == 0xa9:

            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #1F POP DS Pop top of stack into DS; increment stack pointer
        elif instruction.opcode == 0x1f:

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #58+ rd POP r32 Pop top of stack into r32; increment stack pointer
        #58+ rw POP r16 Pop top of stack into r16; increment stack pointer
        elif instruction.opcode >= 0x58 and instruction.opcode <= 0x5f:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            # Do logic
            popvalue = self.get_memory32(self.get_register("ESP", size))
            esp = self.get_register32("ESP") + 4

            self.set_register(op1.reg, popvalue, size)
            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #8F /0 POP r/m16 Pop top of stack into m16; increment stack pointer
        #8F /0 POP r/m32 Pop top of stack into m32; increment stack pointer
        elif instruction.opcode == 0x8f and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                popvalue = self.get_memory32(self.get_register("ESP", size))
                esp = self.get_register32("ESP") + 4

                self.set_register(op1.reg, popvalue, size)
                self.set_register("ESP", esp)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                popvalue = self.get_memory32(self.get_register("ESP", size))
                esp = self.get_register32("ESP") + 4

                self.set_memory(op1value, popvalue, size)
                self.set_register("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def PUSH(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #06 PUSH ES Push ES
        if instruction.opcode == 0x06:

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #0F A0 PUSH FS Push FS
        elif instruction.opcode == 0xa0:

            # Do logic
            return False

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #16 PUSH SS Push SS
        elif instruction.opcode == 0x16:

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #50+rd PUSH r32 Push r32
        #50+rw PUSH r16 Push r16
        elif instruction.opcode >= 0x50 and instruction.opcode <= 0x57:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            # Do logic
            esp = self.get_register32("ESP") - 4

            self.set_memory32(esp, op1value)

            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #68 PUSH imm16 Push imm16
        #68 PUSH imm32 Push imm32
        elif instruction.opcode == 0x68:

            if so:
                size = 2
            else:
                size = 4

            op1value = op1.immediate & self.get_mask(size)

            # Do logic
            esp = self.get_register32("ESP") - 4

            self.set_memory32(esp, op1value)

            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #6A PUSH imm8 Push imm8
        elif instruction.opcode == 0x6a:
            
            size = 1

            op1value = op1.immediate & self.get_mask(size)

            # Do logic
            esp = self.get_register32("ESP") - 4

            self.set_memory32(esp, op1value)

            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #FF /6 PUSH r/m16 Push r/m16
        #FF /6 PUSH r/m32 Push r/m32
        elif instruction.opcode == 0xff and instruction.extindex == 0x6:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                esp = self.get_register32("ESP") - 4

                self.set_memory32(esp, op1value)

                self.set_register32("ESP", esp)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                esp = self.get_register32("ESP") - 4

                self.set_memory32(esp, op1valuederef)

                self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def PUSHA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #60 PUSHA Invalid Valid Push AX, CX, DX, BX, original SP, BP, SI, and DI.
        #60 PUSHAD Invalid Valid Push EAX, ECX, EDX, EBX, original ESP, EBP,ESI, and EDI.
        if instruction.opcode == 0x60:
            if so:
                size = 2
            else:
                size = 4
                
            # Do logic
            # Save our esp before we start so we can push it
            temp_esp = self.get_register32("ESP")
            
            # EAX
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("EAX"))
            self.set_register32("ESP", esp)

            # ECX
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("ECX"))
            self.set_register32("ESP", esp)
            
            # EDX
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("EDX"))
            self.set_register32("ESP", esp)
            
            # EBX
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("EBX"))
            self.set_register32("ESP", esp)
            
            # ESP
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, temp_esp)
            self.set_register32("ESP", esp)
            
            # EBP
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("EBP"))
            self.set_register32("ESP", esp)
            
            # ESI
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("ESI"))
            self.set_register32("ESP", esp)
            
            # EDI
            esp = self.get_register32("ESP") - 4
            self.set_memory32(esp, self.get_register32("EDI"))
            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def RCR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /3 ib RCR r/m8, imm8 Rotate 9 bits (CF, r/m8) right imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x3:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                tempcount = (op2value & 0x1f) % 9
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9
                
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /3 ib RCR r/m16, imm8 Rotate 17 bits (CF, r/m16) right imm8 times
        #C1 /3 ib RCR r/m32, imm8 Rotate 33 bits (CF, r/m32) right imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /3 RCR r/m8, 1 Rotate 17 bits (CF, r/m16) right once
        elif instruction.opcode == 0xd0 and instruction.extindex == 0x3:

            size = 1
            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                tempcount = (op2value & 0x1f) % 9
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1
                    
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /3 RCR r/m16, 1 Rotate 17 bits (CF, r/m16) right once
        #D1 /3 RCR r/m32, 1 Rotate 33 bits (CF, r/m32) right once
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /3 RCR r/m8, CL Rotate 9 bits (CF, r/m8) right CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x3:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                tempcount = (op2value & 0x1f) % 9
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9
                
                if op2value == 1:
                    self.OF = (op1valuederef >> 7) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /3 RCR r/m16, CL Rotate 17 bits (CF, r/m16) right CL times
        #D3 /3 RCR r/m32, CL Rotate 33 bits (CF, r/m32) right CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1value = (op1value / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                while tempcount:
                    tempcf = self.get_lsb(op2value)
                    op1valuederef = (op1valuederef / 2) + (self.CF * 2 ** size)
                    self.CF = tempcf
                    tempcount -= 1

                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def RCL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /2 ib RCL r/m8, imm8 Rotate 9 bits (CF, r/m8) left imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x2:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                tempcount = (op2value & 0x1f) % 9
                
                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & 0xff

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9
                
                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1

                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /2 ib RCL r/m16, imm8 Rotate 17 bits (CF, r/m16) left imm8 times
        #C1 /2 ib RCL r/m32, imm8 Rotate 33 bits (CF, r/m32) left imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f

                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
    
                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
            
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /2 RCL r/m8, 1 Rotate 17 bits (CF, r/m16) left once
        elif instruction.opcode == 0xd0 and instruction.extindex == 0x2:

            size = 1
            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                tempcount = (op2value & 0x1f) % 9
 
                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
               
                self.set_register(op1.reg, op1value, size)
                               
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9
       
                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                         
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /2 RCL r/m16, 1 Rotate 17 bits (CF, r/m16) left once
        #D1 /2 RCL r/m32, 1 Rotate 33 bits (CF, r/m32) left once
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f

                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f
   
                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /2 RCL r/m8, CL Rotate 9 bits (CF, r/m8) left CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x2:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                tempcount = (op2value & 0x1f) % 9

                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 9

                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                
                if op2value == 1:
                    self.OF = (op1valuederef >> 7) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /2 RCL r/m16, CL Rotate 17 bits (CF, r/m16) left CL times
        #D3 /2 RCL r/m32, CL Rotate 33 bits (CF, r/m32) left CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x2:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f

                while tempcount:
                    tempcf = self.get_msb(op1value, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 17
                else:
                    tempcount = op2value & 0x1f

                while tempcount:
                    tempcf = self.get_msb(op1valuederef, size)
                    op1value = (op1value * 2) + self.CF
                    self.CF = tempcf
                    tempcount -= 1
                    
                if op2value == 1:
                    self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def RET(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #C3 RET Valid Valid Near return to calling procedure.
        if instruction.opcode == 0xc3:
            size = 4
            
            eip = self.get_memory32(self.get_register32("ESP"))
            esp = self.get_register32("ESP") + size
            
            self.set_register32("EIP", eip)
            self.set_register32("ESP", esp)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #CB RET Valid Valid Far return to calling procedure.
        elif instruction.opcode == 0xcb:
            print "[!] We dont support far cross segment returns!"
            return False
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C2 iw RET imm16 Valid Valid Near return to calling procedure and pop imm16 bytes from stack.
        elif instruction.opcode == 0xc2:
            size = 4
            
            op1value = op1.immediate & self.get_mask(2)
            
            eip = self.get_memory32(self.get_register32("ESP"))
            esp = self.get_register32("ESP") + op1value + size
            
            self.set_register32("EIP", eip)
            self.set_register32("ESP", esp)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #CA iw RET imm16 Valid Valid Far return to calling procedure and pop imm16 bytes from stack.
        elif instruction.opcode == 0xca:
            print "[!] We dont support far cross segment returns!"
            return False
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False
        
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
    
    def ROL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /0 ib ROL r/m8, imm8 Rotate 8 bits (CF, r/m8) left imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x0:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                tempcount = (op2value & 0x1f) % 8
                
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8
                
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /0 ib ROL r/m16, imm8 Rotate 16 bits (CF, r/m16) left imm8 times
        #C1 /0 ib ROL r/m32, imm8 Rotate 32 bits (CF, r/m32) left imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32
    
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /0 ROL r/m8, 1 Rotate 16 bits (CF, r/m16) left once
        elif instruction.opcode == 0xd0 and instruction.extindex == 0x0:
            size = 1
            
            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                tempcount = (op2value & 0x1f) % 8
 
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
               
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8
       
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
                
                self.set_memory(op1value, op1valuederef, size)
                         
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /0 ROL r/m16, 1 Rotate 16 bits (CF, r/m16) left once
        #D1 /0 ROL r/m32, 1 Rotate 32 bits (CF, r/m32) left once
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32
   
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /0 ROL r/m8, CL Rotate 8 bits (CF, r/m8) left CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x0:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                tempcount = (op2value & 0x1f) % 8

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /0 ROL r/m16, CL Rotate 16 bits (CF, r/m16) left CL times
        #D3 /0 ROL r/m32, CL Rotate 32 bits (CF, r/m32) left CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1value, size)
                        op1value = (op1value * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1value)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ self.CF
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_msb(op1valuederef, size)
                        op1value = (op1valuederef * 2) + tempcf
                        tempcount -= 1
                        
                    self.CF = self.get_lsb(op1valuederef)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1valuederef, size) ^ self.CF
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def ROR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /1 ib ROR r/m8, imm8 Rotate 8 bits (CF, r/m8) right imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x1:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                tempcount = (op2value & 0x1f) % 8
                
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8
                
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /1 ib ROR r/m16, imm8 Rotate 16 bits (CF, r/m16) right imm8 times
        #C1 /1 ib ROR r/m32, imm8 Rotate 32 bits (CF, r/m32) right imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32
    
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_memory(op1value, op1valuederef, size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /1 ROR r/m8, 1 Rotate 16 bits (CF, r/m16) right once
        elif instruction.opcode == 0xd0 and instruction.extindex == 0x1:
            size = 1
            
            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                tempcount = (op2value & 0x1f) % 8
 
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
               
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8
       
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_memory(op1value, op1valuederef, size)
                         
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /1 ROR r/m16, 1 Rotate 16 bits (CF, r/m16) right once
        #D1 /1 ROR r/m32, 1 Rotate 32 bits (CF, r/m32) right once
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32
   
                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /1 ROR r/m8, CL Rotate 8 bits (CF, r/m8) right CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x1:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                tempcount = (op2value & 0x1f) % 8

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                tempcount = (op2value & 0x1f) % 8

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /1 ROR r/m16, CL Rotate 16 bits (CF, r/m16) right CL times
        #D3 /1 ROR r/m32, CL Rotate 32 bits (CF, r/m32) right CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x1:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")

                # Do logic
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
                
                self.set_register(op1.reg, op1value, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                if size == 2:
                    tempcount = (op2value & 0x1f) % 16
                else:
                    tempcount = (op2value & 0x1f) % 32

                if tempcount > 0:
                    while tempcount:
                        tempcf = self.get_lsb(op2value)
                        op1value = (op1value / 2) + (tempcf * 2 ** size)
                        tempcount -= 1
                        
                    self.CF = self.get_msb(op1value, size)
                    
                    if op2value == 1:
                        self.OF = self.get_msb(op1value, size) ^ (self.get_msb(op1value, size) - 1)
             
                self.set_memory(op1value, op1valuederef, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SAL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /4 ib SAL r/m8,imm8 Signed multiply* r/m8 by 2, imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /4 ib SAL r/m16,imm8 Signed multiply* r/m16 by 2, imm8 times
        #C1 /4 ib SAL r/m32,imm8 Signed multiply* r/m32 by 2, imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /4 ib SAL r/m8,1 Signed multiply* r/m8 by 2, 1 time
        if instruction.opcode == 0xc0 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /4 SAL r/m16 Signed multiply* r/m16 by 2, 1 time
        #D1 /4 SAL r/m32 Signed multiply* r/m32 by 2, 1 time
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = 1
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /4 SAL r/m8,CL Signed multiply* r/m8 by 2, CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /4 SAL r/m16,CL Signed multiply* r/m16 by 2, CL times
        #D3 /4 SAL r/m32,CL Signed multiply* r/m32 by 2, CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1value, op2value, result, size)
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)
                
                self.set_flags("SAL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
                        
    def SAR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /7 ib SAR r/m8,imm8 Signed divide* r/m8 by 2, imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x7:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /7 ib SAR r/m16,imm8 Signed divide* r/m16 by 2, imm8 times
        #C1 /7 ib SAR r/m32,imm8 Signed divide* r/m32 by 2, imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /7 ib SAR r/m8,1 Signed divide* r/m8 by 2, 1 time
        elif instruction.opcode == 0xc0 and instruction.extindex == 0x7:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = 1

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /7 SAR r/m16 Signed divide* r/m16 by 2, 1 time
        #D1 /7 SAR r/m32 Signed divide* r/m32 by 2, 1 time
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = 1
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /7 SAR r/m8,CL Signed divide* r/m8 by 2, CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x7:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /7 SAR r/m16,CL Signed divide* r/m16 by 2, CL times
        #D3 /7 SAR r/m32,CL Signed divide* r/m32 by 2, CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x7:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SAR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
        
        return True

    def SBB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #18 /r SBB r/m8,r8 Subtract with borrow r8 from r/m8
        if instruction.opcode == 0x18:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1valuederef, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #19 /r SBB r/m16,r16 Subtract with borrow r16 from r/m16
        #19 /r SBB r/m32,r32 Subtract with borrow r32 from r/m32
        elif instruction.opcode == 0x19:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1valuederef, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #1B /r SBB r16,r/m16 Subtract with borrow r/m16 from r16
        #1B /r SBB r32,r/m32 Subtract with borrow r/m32 from r32
        elif instruction.opcode == 0x1b:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1valuederef, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                result = self.sanitize_value(result, size)
                
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #1C ib SBB AL,imm8 Subtract with borrow imm8 from AL
        elif instruction.opcode == 0x1c:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - (op2value + self.CF)
            oldcf = self.CF
            
            self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
            if oldcf == 0:
                self.CF = oldcf
                    
            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #1D id SBB EAX,imm32 Subtract with borrow imm32 from EAX
        #1D iw SBB AX,imm16 Subtract with borrow imm16 from AX
        elif instruction.opcode == 0x1d:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - (op2value + self.CF)
            oldcf = self.CF
            
            self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
            if oldcf == 0:
                self.CF = oldcf
                    
            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /3 id SBB r/m32,imm32 Subtract with borrow imm32 from r/m32
        #81 /3 iw SBB r/m16,imm16 Subtract with borrow imm16 from r/m16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1valuederef, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /3 ib SBB r/m16,imm8 Subtract with borrow sign-extended imm8 from r/m16
        #83 /3 ib SBB r/m32,imm8 Subtract with borrow sign-extended imm8 from r/m32
        elif instruction.opcode == 0x83 and instruction.extindex == 0x3:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1value, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                result = op1valuederef - (op2value + self.CF)
                oldcf = self.CF
                
                self.set_flags("SBB", op1valuederef, op2value + self.CF, result, size)
                
                if oldcf == 0:
                    self.CF = oldcf
                    
                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def SCAS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #AE SCAS m8 Compare AL with byte at ES:(E)DI and set status flags
        if instruction.opcode == 0xae:

            size = 1

            op1value = self.get_memory_address(instruction, 1, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #AF SCAS m16 Compare AX with word at ES:(E)DI and set status flags
        #AF SCAS m32 Compare EAX with doubleword at ES(E)DI and set status flags
        elif instruction.opcode == 0xaf:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_memory_address(instruction, 1, size)

            # Do logic
            return False

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SCASB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #AE SCASB Valid Valid Compare AL with byte at ES:(E)DI
        if instruction.opcode == 0xae:
            size = 1
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.DS + self.get_register16("DI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
          
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.get_register32("EDI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
             
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SCASW(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #AF SCASW Valid Valid Compare AX with byte at ES:(E)DI
        if instruction.opcode == 0xaf:
            size = 2
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.DS + self.get_register16("DI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
        
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.get_register32("EDI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
            
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SCASD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #AF SCASD Valid Valid Compare EAX with byte at ES:(E)DI
        if instruction.opcode == 0xaf:
            size = 4
            
            if ao:
                if instruction.repe():
                    repcount = self.get_register16("CX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register16("CX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.DS + self.get_register16("DI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                        
                        repcount -= 1

                    self.set_register16("CX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.DS + self.get_register16("DI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
                  
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.repe():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                elif instruction.repne():
                    repcount = self.get_register32("ECX")
                    
                    while repcount and not self.ZF:
                        op1value = self.get_register8("AL")
                        op2value = self.get_register32("EDI")
                        
                        op2valuederef = self.get_memory(op2value, size)
                        
                        result = op1value - op2valuederef

                        self.set_flags("CMP", op1value, op2valuederef, result, size)

                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                        
                        repcount -= 1

                    self.set_register32("ECX", repcount)
                    
                else:
                    op1value = self.get_register8("AL")
                    op2value = self.get_register32("EDI")

                    op2valuederef = self.get_memory(op2value, size)
                                        
                    result = op1value - op2value

                    self.set_flags("CMP", op1value, op2value, result, size)
               
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
                        
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETNA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 96 SETNA r/m8 Set byte if less or equal (ZF=1 or CF=1)
        if instruction.opcode == 0x96:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF or self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF or self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETLE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9e SETLE r/m8 Set byte if less or equal (ZF=1 or SF!=OF)
        if instruction.opcode == 0x9e:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF or self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF or self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETGE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9d SETG r/m8 Set byte if greater or equal (SF==OF)
        if instruction.opcode == 0x9d:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9f SETG r/m8 Set byte if greater (ZF=0 and SF==OF)
        if instruction.opcode == 0x9f:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF and self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF and self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 94 SETE r/m8 Set byte if carry (ZF=1)
        if instruction.opcode == 0x94:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 92 SETC r/m8 Set byte if carry (CF=1)
        if instruction.opcode == 0x92:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETBE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 96 SETBE r/m8 Set byte if above (CF=1 and ZF=1)
        if instruction.opcode == 0x96:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.CF and self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.CF and self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 92 SETB r/m8 Set byte if above (CF=1)
        if instruction.opcode == 0x92:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETAE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 93 SETAE r/m8 Set byte if above (CF=0)
        if instruction.opcode == 0x93:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETA(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 97 SETA r/m8 Set byte if above (CF=0 and ZF=0)
        if instruction.opcode == 0x97:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.CF and not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.CF and not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETPS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 98 SETS r/m8 Set byte if signed (SF=1)
        if instruction.opcode == 0x9b:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.SF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.SF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETPO(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9b SETPO r/m8 Set byte if parity (PF=0)
        if instruction.opcode == 0x9b:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETPE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9a SETPE r/m8 Set byte if parity (PF=1)
        if instruction.opcode == 0x9a:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9a SETP r/m8 Set byte if parity (PF=1)
        if instruction.opcode == 0x9a:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETO(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 90 SETO r/m8 Set byte if overflow (OF=1)
        if instruction.opcode == 0x90:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETNS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 99 SETNS r/m8 Set byte if not signed (SF=0)
        if instruction.opcode == 0x99:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.SF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.SF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETNP(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9b SETNO r/m8 Set byte if not parity (PF=0)
        if instruction.opcode == 0x9b:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.PF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETNO(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 91 SETNO r/m8 Set byte if not overflow (OF=0)
        if instruction.opcode == 0x9d:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
                
    def SETNL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9d SETNL r/m8 Set byte if not less (SF = OF)
        if instruction.opcode == 0x9d:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNGE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9c SETNGE r/m8 Set byte if not greater (SF!= OF)
        if instruction.opcode == 0x9c:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9e SETNG r/m8 Set byte if not greater (ZF=1 or SF!= OF)
        if instruction.opcode == 0x9e:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF or self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF or self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 95 SETNE r/m8 Set byte if not below (ZF=0)
        if instruction.opcode == 0x95:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNC(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 93 SETNC r/m8 Set byte if not below (CF=0)
        if instruction.opcode == 0x93:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNBE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 97 SETNB r/m8 Set byte if not below (CF=0, ZF=0)
        if instruction.opcode == 0x97:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.CF and not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.CF and not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 93 SETNB r/m8 Set byte if not below (CF=0)
        if instruction.opcode == 0x93:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
        
    def SETNAE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 92 SETNAE r/m8 Set byte if not above or equal (CF=1)
        if instruction.opcode == 0x92:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.CF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9C SETL r/m8 Set byte if less (SF<>OF)
        if instruction.opcode == 0x9c:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.SF != self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def SETNLE(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 9F SETNLE r/m8 Set byte if not less or equal (ZF=0 and SF=OF)
        if instruction.opcode == 0x9f:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF and self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF and self.SF == self.OF:
                    result = 0x1
                else:
                    result = 0x0
                
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETNZ(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 95 SETNZ r/m8 Set byte if not zero (ZF=0)
        if instruction.opcode == 0x95:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if not self.ZF:
                    result = 0x1
                else:
                    result = 0x0

                self.set_register(op1.reg, result, size)
                
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if not self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                    
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SETZ(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #0F 94 SETZ r/m8 Set byte if zero (ZF=1)
        if instruction.opcode == 0x94:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)

                # Do logic
                if self.ZF:
                    result = 0x1
                else:
                    result = 0x0

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)

                # Do logic
                if self.ZF:
                    result = 0x1
                else:
                    result = 0x0
                    
                self.set_memory(op1value, result, size)

            opcode = 0x0f << 7 | instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SHL(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /4 ib SHL r/m8,imm8 Multiply r/m8 by 2, imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /4 ib SHL r/m16,imm8 Multiply r/m16 by 2, imm8 times
        #C1 /4 ib SHL r/m32,imm8 Multiply r/m32 by 2, imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D0 /4 SHL r/m8 Multiple r/m8 by 2, 1 time
        elif instruction.opcode == 0xd0 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op1value = 1
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                    
        #D1 /4 SHL r/m16 Multiply r/m16 by 2, 1 time
        #D1 /4 SHL r/m32 Multiply r/m32 by 2, 1 time
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op1value = 1
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /4 SHL r/m8,CL Multiply r/m8 by 2, CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x4:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /4 SHL r/m16,CL Multiply r/m16 by 2, CL times
        #D3 /4 SHL r/m32,CL Multiply r/m32 by 2, CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x4:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1

                result = result & self.get_mask(size)
                
                self.set_flags("SHL", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_msb(result, size)
                    result = result * 2
                    tempcount -= 1
                
                result = result & self.get_mask(size)

                self.set_flags("SHL", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SHR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #C0 /5 ib SHR r/m8,imm8 Unsigned divide r/m8 by 2, imm8 times
        if instruction.opcode == 0xc0 and instruction.extindex == 0x5:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #C1 /5 ib SHR r/m16,imm8 Unsigned divide r/m16 by 2, imm8 times
        #C1 /5 ib SHR r/m32,imm8 Unsigned divide r/m32 by 2, imm8 times
        elif instruction.opcode == 0xc1 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D1 /5 SHR r/m16 Unsigned divide r/m16 by 2, 1 time
        #D1 /5 SHR r/m32 Unsigned divide r/m32 by 2, 1 time
        elif instruction.opcode == 0xd1 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = 1
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = 1
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D2 /5 SHR r/m8,CL Unsigned divide r/m8 by 2, CL times
        elif instruction.opcode == 0xd2 and instruction.extindex == 0x5:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #D3 /5 SHR r/m16,CL Unsigned divide r/m16 by 2, CL times
        #D3 /5 SHR r/m32,CL Unsigned divide r/m32 by 2, CL times
        elif instruction.opcode == 0xd3 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                countmask = 0x1f
                
                result = op1value
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register8("CL")
                
                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                countmask = 0x1f
                
                result = op1valuederef
                tempcount = op2value & countmask
                while tempcount:
                    self.CF = self.get_lsb(result)
                    result = result / 2
                    tempcount -= 1
                
                self.set_flags("SHR", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def STOS(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #AA STOS m8
        if instruction.opcode == 0xaa:
            return False
                
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #AB STOS m16 Valid Valid For legacy mode, store AX at address ES:(E)DI;
        #AB STOS m32 Valid Valid For legacy mode, store EAX at address ES:(E)DI;
        elif instruction.opcode == 0xab:
            if so:
                size = 2
            else:
                size = 4
            
            return False
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                        
        return False
    
    def STOSB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #AA STOSB
        if instruction.opcode == 0xaa:
            size = 1
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                    
                        
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                    
                        
                        repcount -= 1
                        
                    self.set_register32("CX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                 
        return True
    
    def STOSW(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2
        
        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #AB STOSW
        if instruction.opcode == 0xab:
            size = 2
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                    
                    
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                    
                    
                        repcount -= 1
                        
                    self.set_register32("CX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                 
        return True
    
    def STOSD(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        
        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None
        
        #AA MOVSB
        if instruction.opcode == 0xaa:
            size = 4
            
            if ao:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.ES + self.get_register16("DI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register16("DI", op1value + size)
                        else:
                            self.set_register16("DI", op1value - size)
                    
                        repcount -= 1
                        
                    self.set_register16("CX", repcount)
                else:
                    op1value = self.ES + self.get_register16("DI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register16("DI", op1value + size)
                    else:
                        self.set_register16("DI", op1value - size)
            
            else:
                if instruction.rep():
                    repcount = self.get_register16("CX")
                    
                    while repcount > 0:
                        op1value = self.get_register32("EDI")
                        op2value = self.get_register(0, size)
                        
                        self.set_memory(op1value, op2value, size)
                        
                        if not self.DF:
                            self.set_register32("EDI", op1value + size)
                        else:
                            self.set_register32("EDI", op1value - size)
                    
                        repcount -= 1
                        
                    self.set_register32("CX", repcount)
                else:
                    op1value = self.get_register32("EDI")
                    op2value = self.get_register(0, size)
                    
                    self.set_memory(op1value, op2value, size)
                    
                    if not self.DF:
                        self.set_register32("EDI", op1value + size)
                    else:
                        self.set_register32("EDI", op1value - size)
            
            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False
        
        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def SUB(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #28 /r SUB r/m8,r8 Subtract r8 from r/m8
        if instruction.opcode == 0x28:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("SUB", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - op2value

                self.set_flags("SUB", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #29 /r SUB r/m16,r16 Subtract r16 from r/m16
        #29 /r SUB r/m32,r32 Subtract r32 from r/m32
        elif instruction.opcode == 0x29:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("SUB", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - op2value

                self.set_flags("SUB", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #2B /r SUB r16,r/m16 Subtract r/m16 from r16
        #2B /r SUB r32,r/m32 Subtract r/m32 from r32
        elif instruction.opcode == 0x2b:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value - op2value

                self.set_flags("SUB", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)

                result = op1value - op2valuederef

                self.set_flags("SUB", op1value, op2valuederef, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #2C ib SUB AL,imm8 Subtract imm8 from AL
        elif instruction.opcode == 0x2c:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - op2value

            self.set_flags("SUB", op1value, op2value, result, size)

            result = self.sanitize_value(result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #2D id SUB EAX,imm32 Subtract imm32 from EAX
        #2D iw SUB AX,imm16 Subtract imm16 from AX
        elif instruction.opcode == 0x2d:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value - op2value

            self.set_flags("SUB", op1value, op2value, result, size)

            result = self.sanitize_value(result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #81 /5 id SUB r/m32,imm32 Subtract imm32 from r/m32
        #81 /5 iw SUB r/m16,imm16 Subtract imm16 from r/m16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - op2value

                self.set_flags("SUB", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - op2value

                self.set_flags("SUB", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /5 ib SUB r/m16,imm8 Subtract sign-extended imm8 from r/m16
        #83 /5 ib SUB r/m32,imm8 Subtract sign-extended imm8 from r/m32
        elif instruction.opcode == 0x83 and instruction.extindex == 0x5:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value - op2value

                self.set_flags("SUB", op1value, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef - op2value

                self.set_flags("SUB", op1valuederef, op2value, result, size)

                result = self.sanitize_value(result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def TEST(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #84 /r TEST r/m8,r8 AND r8 with r/m8; set SF, ZF, PF according to result
        if instruction.opcode == 0x84:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic

                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #85 /r TEST r/m16,r16 AND r16 with r/m16; set SF, ZF, PF according to result
        #85 /r TEST r/m32,r32 AND r32 with r/m32; set SF, ZF, PF according to result
        elif instruction.opcode == 0x85:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #A9 id TEST EAX,imm32 AND imm32 with EAX; set SF, ZF, PF according to result
        #A9 iw TEST AX,imm16 AND imm16 with AX; set SF, ZF, PF according to result
        elif instruction.opcode == 0xa9:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value & op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F6 /0 ib TEST r/m8,imm8 AND imm8 with r/m8; set SF, ZF, PF according to result
        elif instruction.opcode == 0xf6 and instruction.extindex == 0x0:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #F7 /0 id TEST r/m32,imm32 AND imm32 with r/m32; set SF, ZF, PF according to result
        #F7 /0 iw TEST r/m16,imm16 AND imm16 with r/m16; set SF, ZF, PF according to result
        elif instruction.opcode == 0xf7 and instruction.extindex == 0x0:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value & op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef & op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True

    def XCHG(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #86 /r XCHG r/m8, r8 Exchange r8 (byte register) with byte from r/m8
        #86 /r XCHG r8, r/m8 Exchange byte from r/m8 with r8 (byte register)
        if instruction.opcode == 0x86:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register(op2.reg, size)
        
                    # Do logic
                    self.set_register(op1.reg, op2value, size)
                    self.set_register(op2.reg, op1value, size)
                elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_memory_address(instruction, 2, size)
    
                    # Do logic
                    op2valuederef = self.get_memory(op2value, size)
                    
                    self.set_register(op1.reg, op2valuederef, size)
                    self.set_memory(op2value, op1value, size)
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                self.set_memory(op1value, op2value, size)
                self.set_register(op2.reg, op1valuederef, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #87 /r XCHG r/m16, r16 Exchange r16 with word from r/m16
        #87 /r XCHG r/m32, r32 Exchange r32 with doubleword from r/m32
        #87 /r XCHG r16, r/m16 Exchange word from r/m16 with r16
        #87 /r XCHG r32, r/m32 Exchange doubleword from r/m32 with r32
        elif instruction.opcode == 0x87:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_register(op2.reg, size)
        
                    # Do logic
                    self.set_register(op1.reg, op2value, size)
                    self.set_register(op2.reg, op1value, size)
                elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                    op1value = self.get_register(op1.reg, size)
                    op2value = self.get_memory_address(instruction, 2, size)
    
                    # Do logic
                    op2valuederef = self.get_memory(op2value, size)
                    
                    self.set_register(op1.reg, op2valuederef, size)
                    self.set_memory(op2value, op1value, size)
            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)
                
                self.set_memory(op1value, op2value, size)
                self.set_register(op2.reg, op1valuederef, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #90+rd XCHG EAX, r32 Exchange r32 with EAX
        #90+rd XCHG r32, EAX Exchange EAX with r32
        #90+rw XCHG AX, 16 Exchange r16 with AX
        #90+rw XCHG r16, AX Exchange AX with r16
        elif instruction.opcode >= 0x90 and instruction.opcode <= 0x97:
            
            if so:
                size = 2
            else:
                size = 4

            # No matter what its register to register
            op1value = self.get_register(op1.reg, size)
            op2value = self.get_register(op2.reg, size)

            # Do logic
            self.set_register(op1.reg, op2value, size)
            self.set_register(op2.reg, op1value, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True


    def XOR(self, instruction):
        op1 = instruction.op1
        op2 = instruction.op2

        so = instruction.operand_so()
        ao = instruction.address_so()
        

        op1value = ""
        op2value = ""
        op3value = ""
        op1valuederef = None
        op2valuederef = None

        #30 /r XOR r/m8,r8 r/m8  r8
        if instruction.opcode == 0x30:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef ^ op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #31 /r XOR r/m16,r16 r/m16  r16
        #31 /r XOR r/m32,r32 r/m32  r32
        elif instruction.opcode == 0x31:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = self.get_register(op2.reg, size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef ^ op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #33 /r XOR r16,r/m16 r8  r/m8
        #33 /r XOR r32,r/m32 r8  r/m8
        elif instruction.opcode == 0x33:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(op1.reg, size)

            if op2.type == pydasm.OPERAND_TYPE_REGISTER:
                op2value = self.get_register(op2.reg, size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op2.type == pydasm.OPERAND_TYPE_MEMORY:
                op2value = self.get_memory_address(instruction, 2, size)

                # Do logic
                op2valuederef = self.get_memory(op2value, size)

                result = op1value ^ op2valuederef

                self.set_flags("LOGIC", op1value, op2valuederef, result, size)

                self.set_register(op1.reg, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #34 ib XOR AL,imm8 AL  imm8
        elif instruction.opcode == 0x34:

            size = 1

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value ^ op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #35 id XOR EAX,imm32 EAX  imm32
        #35 iw XOR AX,imm16 AX  imm16
        elif instruction.opcode == 0x35:

            if so:
                size = 2
            else:
                size = 4

            op1value = self.get_register(0, size)
            op2value = op2.immediate & self.get_mask(size)

            # Do logic
            result = op1value ^ op2value

            self.set_flags("LOGIC", op1value, op2value, result, size)

            self.set_register(0, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #80 /6 ib XOR r/m8, imm8
        elif instruction.opcode == 0x80 and instruction.extindex == 0x6:

            size = 1

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef ^ op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)
                
        #81 /6 id XOR r/m32,imm32 r/m32  imm32
        #81 /6 iw XOR r/m16,imm16 r/m16  imm16
        elif instruction.opcode == 0x81 and instruction.extindex == 0x6:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef ^ op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        #83 /6 ib XOR r/m16,imm8 r/m16  imm8 (sign-extended)
        #83 /6 ib XOR r/m32,imm8 r/m32  imm8 (sign-extended)
        elif instruction.opcode == 0x83 and instruction.extindex == 0x6:

            if so:
                size = 2
            else:
                size = 4

            if op1.type == pydasm.OPERAND_TYPE_REGISTER:
                op1value = self.get_register(op1.reg, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                result = op1value ^ op2value

                self.set_flags("LOGIC", op1value, op2value, result, size)

                self.set_register(op1.reg, result, size)

            elif op1.type == pydasm.OPERAND_TYPE_MEMORY:
                op1value = self.get_memory_address(instruction, 1, size)
                op2value = op2.immediate & self.get_mask(size)

                # Do logic
                op1valuederef = self.get_memory(op1value, size)

                result = op1valuederef ^ op2value

                self.set_flags("LOGIC", op1valuederef, op2value, result, size)

                self.set_memory(op1value, result, size)

            opcode = instruction.opcode
            if opcode in self.emu.opcode_handlers:
                if op1valuederef != None and op2valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1valuederef, op2value, op3value)
                elif op2valuederef != None and op1valuederef == None:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2valuederef, op3value)
                else:
                    self.emu.opcode_handlers[opcode](self.emu, opcode, self.get_register32("EIP"), op1value, op2value, op3value)

        else:
            return False

        mnemonic = instruction.mnemonic.upper()
        if mnemonic in self.emu.mnemonic_handlers:
            if op1valuederef != None and op2valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1valuederef, op2value, op3value)
            elif op2valuederef != None and op1valuederef == None:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2valuederef, op3value)
            else:
                self.emu.mnemonic_handlers[mnemonic](self.emu, mnemonic, self.get_register32("EIP"), op1value, op2value, op3value)
                
        return True
