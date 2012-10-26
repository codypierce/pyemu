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
PyDebug:

    This module allows us some helper debug functions for dumping
    instructions and other items.
'''

#
# DebugDumpFlags: nicely prints our current flags
#
def DebugDumpFlags(flags):
    eflags_map = {"CF": 0,
                  "PF": 2,
                  "AF": 4,
                  "ZF": 6,
                  "SF": 7,
                  "TF": 8,
                  "IF": 9,
                  "DF": 10,
                  "OF": 11,
                  "IOPL": 13,
                  "NT": 14,
                  "RF": 16,
                  "VM": 17,
                  "AC": 18,
                  "VIF": 19,
                  "VIP": 20,
                  "ID": 21 }
    
    for flag in eflags_map.keys():
        if (flags >> eflags_map[flag]) & 0x1:
            print flag,

#
# DebugInstruction: Nicely prints the full contents of an instruction
#
def DebugInstruction(instruction):
    print "[*] Length:       0x%x" % instruction.length
    print "[*] Type:         0x%x" % instruction.type
    print "[*] Mode:         0x%x" % instruction.mode
    print "[*] Opcode:       0x%x" % instruction.opcode
    print "[*] ModRM:        0x%x [0x%x 0x%x 0x%x]" % (instruction.modrm, instruction.get_mod(), instruction.get_reg_opcode(), instruction.get_rm())
    print "[*] SIB:          0x%x [0x%x 0x%x 0x%x]" % (instruction.sib, instruction.get_scale(), instruction.get_index(), instruction.get_base())
    print "[*] Extindex:     0x%x" % instruction.extindex
    print "[*] FPUindex:     0x%x" % instruction.fpuindex
    print "[*] Dispbytes:    0x%x" % instruction.dispbytes
    print "[*] Immbytes:     0x%x" % instruction.immbytes
    print "[*] Sectionbytes: 0x%x" % instruction.sectionbytes
    if instruction.op1:
        print "[*] Op1:\n"
        DebugOperand(instruction.op1)
    if instruction.op2:
        print "[*] Op2:\n"
        DebugOperand(instruction.op2)
    if instruction.op3:
        print "[*] Op3:\n"
        DebugOperand(instruction.op3)
    print "[*] Flags:        0x%x"  % instruction.flags,
    print "[",
    DebugDumpFlags(instruction.flags)
    print "]"

#
# DebugOperand: Nicely prints all the information for a single operand
#
def DebugOperand(operand):
    print "\tType:         0x%x" % operand.type
    print "\tReg:          0x%x" % operand.reg
    print "\tBaseReg:      0x%x" % operand.basereg
    print "\tIndexReg:     0x%x" % operand.indexreg
    print "\tScale:        0x%x" % operand.scale
    print "\tDispbytes:    0x%x" % operand.dispbytes
    print "\tDispoffset:   0x%x" % operand.dispoffset
    print "\tImmbytes:     0x%x" % operand.immbytes
    print "\tImmoffset:    0x%x" % operand.immoffset
    print "\tSectionbytes: 0x%x" % operand.sectionbytes
    print "\tSection:      0x%x" % operand.section
    print "\tDisplacement: 0x%x" % operand.displacement
    print "\tImmediate:    0x%x" % operand.immediate
    print "\tFlags:        0x%x" % operand.flags
