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

'''
    This is a new class for setting flags.  It is used by PyCPU to set
    flags per instruction.  This was shamelessly ripped from Bochs
    
    http://bochs.sourceforge.net/
'''

class PyFlags:
    parity_lookup_table = [1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
                           1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1]
        
    def __init__(self, mnemonic, op1, op2, result, size):
        assert isinstance(mnemonic, str)
        assert isinstance(op1, long) or isinstance(op1, int)
        assert isinstance(op2, long) or isinstance(op2, int)
        assert isinstance(result, long) or isinstance(result, int)
        assert isinstance(size, long) or isinstance(size, int)
        
        self.mnemonic = mnemonic
        self.op1 = op1
        self.op2 = op2
        self.result = result
        self.size = size
        self.bit_count = self.size * 8
        self.mask = (2 ** (self.bit_count) - 1)
        self.sign_mask = (self.mask + 1) / 2
        
    def get_CF(self):
        if self.mnemonic == "ADD":
            cf = int(self.result < self.op1)
        elif self.mnemonic == "ADC":
            # used only if CF = 1
            cf = int(self.result <= self.op1)
        elif self.mnemonic in ["SUB", "CMP"]:
            cf = int(self.op1 < self.op2)
        elif self.mnemonic == "SBB":
            # used only if CF = 1
            cf = int((self.op1 < self.result) or (self.op2 == self.mask))
        elif self.mnemonic == "NEG":
            cf = int(self.result != 0)
        elif self.mnemonic == "LOGIC":
            cf = 0
        elif self.mnemonic == "SAR":
            if self.op2 < self.bit_count:
                cf = int((self.op1 >> (self.op2 - 1)) & 0x01)
            else:
                cf = int((self.op1 & self.sign_mask) > 0)
        elif self.mnemonic in ["SHR", "SHRD"]:
            cf = int((self.op1 >> (self.op2 - 1)) & 0x01)
        elif self.mnemonic in ["SHL", "SAL"]:
            if self.op2 <= self.bit_count:
                cf = int((self.op1 >> (self.bit_count - self.op2)) & 0x01)
            else:
                cf = 0
        elif self.mnemonic == "IMUL":
            cf = int(not ((self.op1 < self.sign_mask and self.op2 == 0) or ((self.op1 & self.sign_mask) and self.op2 == self.mask)))

        elif self.mnemonic == "MUL":
            cf = int(self.op2 != 0)
        else:
            cf = None
        
        return cf

    def get_AF(self):
        if self.mnemonic in ["ADD", "ADC", "SUB", "CMP", "SBB"]:
            af = int(((self.op1 ^ self.op2) ^ self.result) & 0x10)
        elif self.mnemonic == "NEG":
            af = int((self.result & 0x0f) != 0)
        elif self.mnemonic == "INC":
            af = int((self.result & 0x0f) == 0)
        elif self.mnemonic == "DEC":
            af = int((self.result & 0x0f) == 0x0f)
        else:
            af = None
        
        return af
        
    def get_ZF(self):
        if self.mnemonic in ["LOGIC", "ADD", "ADC", "SUB", "CMP", "SBB", "NEG", "SAR", "SHR", "SHL", "SAR", "INC", "DEC"]:
            zf = int(self.result == 0)
        elif self.mnemonic in ["IMUL", "MUL"]:
            zf = int(self.op1 == 0)
        else:
            zf = None
        
        return zf
        
    def get_SF(self):
        if self.mnemonic in ["LOGIC", "ADD", "ADC", "SUB", "CMP", "SBB", "NEG", "SAR", "SHR", "SHL", "SAL", "INC", "DEC"]:
            sf = int(self.result >= self.sign_mask)
        elif self.mnemonic in ["IMUL", "MUL"]:
            sf = int(self.op1 >= self.sign_mask)
        else:
            sf = None
        
        return sf
    
    def get_OF_ADD(self):
        return int(((~((self.op1) ^ (self.op2)) & ((self.op2) ^ (self.result))) & (self.sign_mask)) != 0)
    
    def get_OF_SUB(self):
        return int(((((self.op1) ^ (self.op2)) & ((self.op1) ^ (self.result))) & (self.sign_mask)) != 0)
        
    def get_OF(self):
        if self.mnemonic in ["ADD", "ADC"]:
            of = self.get_OF_ADD()
        elif self.mnemonic in ["SUB", "CMP", "SBB"]:
            of = self.get_OF_SUB()
        elif self.mnemonic == "NEG":
            of = int(self.result == self.sign_mask)
        elif self.mnemonic in ["LOGIC", "SAR"]:
            of = 0
        elif self.mnemonic == "SHR":
            if self.op2 == 1:
                of = int(self.op1 >= self.sign_mask)
            else:
                of = 0
        elif self.mnemonic == "SHRD":
            of = int((((self.result << 1) ^ self.result) & self.sign_mask) > 0)
        elif self.mnemonic in ["SHL", "SAL"]:
            if self.op2 == 1:
                of = int(((self.op1 ^ self.result) & self.sign_mask) > 0)
            else:
                of = int((((self.op1 << (self.op2 - 1)) ^ self.result) & self.sign_mask) > 0)
        elif self.mnemonic == "IMUL":
            of = int(not ((self.op1 < self.sign_mask and self.op2 == 0) or ((self.op1 & self.sign_mask) and self.op2 == self.mask)))
        elif self.mnemonic == "MUL":
            of = int(self.op2 != 0)
        elif self.mnemonic == "INC":
            of = int(self.result == self.sign_mask)
        elif self.mnemonic == "DEC":
            of = int(self.result == self.sign_mask - 1)
        else:
            of = None
        
        return of
        
    def get_PF(self):
        if self.mnemonic in ["LOGIC", "ADD", "ADC", "SUB", "CMP", "SBB", "NEG", "SAR", "SHR", "SHL", "SAR", "INC", "DEC"]:
            pf = self.parity_lookup_table[self.result & 0xff]
        elif self.mnemonic in ["IMUL", "MUL"]:
            pf = self.parity_lookup_table[self.op1 & 0xff]
        else:
            pf = None
        
        return pf
    

# End PyFlags