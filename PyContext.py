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
PyContext:

    A simple class that provides a method for passing full context
    information.
'''
class PyContext:
    def __init__(self):
        self.dr0 = 0x0
        self.dr1 = 0x0
        self.dr2 = 0x0
        self.dr3 = 0x0
        self.dr6 = 0x0
        self.dr7 = 0x0
        
        self.GS = 0x0
        self.FS = 0x0
        self.ES = 0x0
        self.DS = 0x0
        
        self.CS = 0x0
        self.SS = 0x0
        
        self.EAX = 0x0
        self.ECX = 0x0
        self.EDX = 0x0
        self.EBX = 0x0
        self.ESP = 0x0
        self.EBP = 0x0
        self.ESI = 0x0
        self.EDI = 0x0
        
        self.EFLAGS = 0x0
        self.EIP = 0x0