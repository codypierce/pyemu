#!/usr/bin/env python

import sys

sys.path.append("..")

from PyFlags import *

def set_flags(mnemonic, op1, op2, result, size):
    flags = PyFlags(mnemonic, op1, op2, result, size)
    
    sys.stdout.write("Mnem: %s\n" % mnemonic)
    sys.stdout.write("Op1: %x\n" % op1)
    sys.stdout.write("Op2: %x\n" % op2)
    sys.stdout.write("Result: %x\n" % result)
    sys.stdout.write("Size: %d\n\n" % size)
    if flags.get_CF() == None:
        sys.stdout.write("CF: Undef ")
    else:
        sys.stdout.write("CF: %d " % flags.get_CF())        
    if flags.get_AF() == None:
        sys.stdout.write("AF: Undef ")
    else:
        sys.stdout.write("AF: %d " % flags.get_AF())
    if flags.get_SF() == None:
        sys.stdout.write("SF: Undef ")
    else:
        sys.stdout.write("SF: %d " % flags.get_SF())
    if flags.get_ZF() != None:
        sys.stdout.write("ZF: %d " % flags.get_ZF())
    else:
        sys.stdout.write("ZF: Undef ")
    if flags.get_OF() != None:
        sys.stdout.write("OF: %d " % flags.get_OF())
    else:
        sys.stdout.write("OF: Undef ")
    if flags.get_PF() != None:
        sys.stdout.write("PF: %d\n\n" % flags.get_PF())
    else:
        sys.stdout.write("PF: Undef\n\n")

def logic(op1, op2, size):
    result = op1 & op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("LOGIC", op1, op2, result, size)

def add(op1, op2, size):
    result = op1 + op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("ADD", op1, op2, result, size)

def adc(op1, op2, size):
    result = op1 & op2 + 1
    result &= (2 ** (size * 8) - 1)
    
    set_flags("ADC", op1, op2, result, size)

def sub(op1, op2, size):
    result = op1 - op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("SUB", op1, op2, result, size)

def sbb(op1, op2, size):
    result = op1 - op2 - 1
    result &= (2 ** (size * 8) - 1)
    
    set_flags("SBB", op1, op2, result, size)

def neg(op1, op2, size):
    result = -op1
    result &= (2 ** (size * 8) - 1)
    
    set_flags("NEG", op1, op2, result, size)

def sar(op1, op2, size):
    result = op1 >> op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("SAR", op1, op2, result, size)

def shr(op1, op2, size):
    result = op1 >> op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("SHR", op1, op2, result, size)

def shl(op1, op2, size):
    result = op1 << op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("SHL", op1, op2, result, size)

def inc(op1, op2, size):
    result = op1 + 1
    result &= (2 ** (size * 8) - 1)
    
    set_flags("INC", op1, op2, result, size)

def dec(op1, op2, size):
    result = op1 - 1
    result &= (2 ** (size * 8) - 1)
    
    set_flags("DEC", op1, op2, result, size)

def mul(op1, op2, size):
    result = op1 * op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("MUL", op1, op2, result, size)

def imul(op1, op2, size):
    result = op1 * op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("IMUL", op1, op2, result, size)

def bitscan(op1, op2, size):
    result = op1 & op2
    result &= (2 ** (size * 8) - 1)
    
    set_flags("BITSCAN", op1, op2, result, size)


op1 = int(sys.argv[1])
op2 = int(sys.argv[2])
size = int(sys.argv[3])

mask = (2 ** (size * 8) - 1)
op1 &= mask
op2 &= mask

def get_OF_ADD(op1, op2, result, size):
    mask = (2 ** (size * 8) - 1)
    sign_mask = (mask + 1) / 2
    
    op1 &= mask
    op2 &= mask
    result &= mask
    
    #print "mask: %x" % mask
    #print "sign: %x" % sign_mask
    #print "op1: %x" % op1
    #print "op2: %x" % op2
    #print "result: %x" % result
    #
    #print "op1 ^ op2: %x" % (op1 ^ op2)
    #print "op2 ^ result: %x" % (op2 ^ result)
    #print "1 & 2: %x\n" % ((op1 ^ op2) & (op2 ^ result))
    #
    #seg1 = op1 ^ op2 # check msb of op1/op2
    #seg2 = op2 ^ result # check msb of op2/result
    #seg3 = (~seg1) & seg2 # combine the 2 results
    #seg4 = seg3 & 0x80 # mask it
    #
    #print "seg1: %x" % seg1
    #print "seg2: %x" % seg2
    #print "seg3: %x" % seg3
    #print "seg4: %x" % seg4
    
    #if result < op1:
    #    return True
        
    return (((~((op1) ^ (op2)) & ((op2) ^ (result))) & sign_mask) != 0)

def eagle_OF(op1, op2, result, size):
    mask = (2 ** (size * 8) - 1)
    sign_mask = (mask + 1) / 2
    
    op1 &= mask
    op2 &= mask
    
    return (((op1 & op2 & ~result & sign_mask) or (~op1 & ~op2 & result & sign_mask)))
    
print get_OF_ADD(op1, op2, op1 + op2, size)
print eagle_OF(op1, op2, op1 + op2, size)

sys.exit(-1)
#logic(op1, op2, size)
add(op1, op2, size)
#adc(op1, op2, size)
#sub(op1, op2, size)
#sbb(op1, op2, size)
#neg(op1, op2, size)
#sar(op1, op2, size)
#shr(op1, op2, size)
#shl(op1, op2, size)
#inc(op1, op2, size)
#dec(op1, op2, size)
#mul(op1, op2, size)
#imul(op1, op2, size)
#bitscan(op1, op2, size)