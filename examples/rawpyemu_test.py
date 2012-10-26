#!/usr/bin/env python

import sys, os, re, struct

sys.path.append(r'c:\code\python\pyemu')
sys.path.append(r'c:\code\python\pyemu\lib')

from PyEmu import *
import ia32

class RawMemory(PyMemory):
    def __init__(self, emu):
        PyMemory.__init__(self, emu)
    
    #
    # allocate_page: Allocates a page for addition into the cache
    #
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("A" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
        
    #
    # get_page: Handles unknown memory requests from the base class.
    #           This is where we return memory (or throw an exception)
    #
    def get_page(self, page):
        if self.fault:
            return False
            
        # Grab a new page object
        return self.allocate_page(page)

class RawPyEmu(PyEmu):
    def __init__(self, stack_base=0x0095f000, stack_size=0x1000, heap_base=0x000a0000, heap_size=0x2000, frame_pointer=True):

        PyEmu.__init__(self)
        
        # Store memory limit information
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.heap_base = heap_base
        self.heap_size = heap_size
        self.frame_pointer = frame_pointer

        # Get a memory manager object for IDA
        self.memory = RawMemory(self)

        # Load initial thread information
        self.setup_os()
        # Set up context information
        self.setup_context()
    
    #
    # setup_os: Adds a new thread based on which OS you are using
    #
    def setup_os(self):
        self.os.initialize(self, self.stack_base, self.stack_base - self.stack_size, self.heap_base, self.heap_base + self.heap_size)
    
    #
    # setup_context: Sets the needed stack pointers so we can execute
    #                properly
    #
    def setup_context(self):
        # Set the registers to a sane starting address
        self.cpu.set_register32("EBP", self.stack_base - self.stack_size / 2)
        
        # So heres the difference in starting at the FP save or after
        #self.cpu.set_register32("ESP", self.cpu.get_register32("EBP") - 4)
        self.cpu.set_register32("ESP", self.cpu.get_register32("EBP"))
        
        # Set some registers to dumb values
        self.cpu.EAX = 0x00000001
        self.cpu.ECX = 0x00000002
        self.cpu.EBX = 0x00000003
        self.cpu.EDX = 0x00000004
        self.cpu.ESI = 0x00000005
        self.cpu.EDI = 0x00000006
        
        # Set up segment registers
        self.cpu.CS = 0x001b
        self.cpu.SS = 0x0023
        self.cpu.DS = 0x0023
        self.cpu.ES = 0x0023
        self.cpu.FS = 0x003b
        self.cpu.GS = 0x0000
        
        return True


if __name__ == '__main__':
    emu = RawPyEmu()
    emu.debug(1)
    
    instructions = "\xeb\x08"
    textstart = 0x40001000
    print "[*] Loading text section bytes into memory"
    
    emu.set_memory(textstart, instructions)
    
    print "[*] Text section loaded into memory"
    
    emu.set_register("EIP", textstart)
    emu.set_register("ECX", 0x2)
    
    emu.execute()