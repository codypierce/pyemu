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
sys.path.append(r'C:\Program Files\IDA\python')

import pydasm

from PyCPU import PyCPU
from PyContext import PyContext
from PyMemory import *
from PyOS import *

'''
PyEmu:

    This main emulator class.  This class implements the public methods
    for controlling the emulator.  This includes handlers, and initialization.
'''
class PyEmu:
    DEBUG = 0
    
    def __init__(self):
        # Holds a instance of our PyCPU class
        self.cpu = None
        # Holds an instance of our PyOS class
        self.os = None
        
        # Tells the emulator whether we are emulating
        self.emulating = True
        # Whether to use a frame pointer for stack offsets
        self.frame_pointer = True
        
        # Class members to hold stack and heap limits
        self.stack_base = 0x0
        self.stack_size = 0x0
        self.heap_base = 0x0
        self.heap_size = 0x0
        
        # Holds an instance of our PyMemory class
        self.memory = ""
        
        # A list of names for public methods
        self.register_names = {}
        self.stack_variable_names = {}
        self.stack_argument_names = {}

        # A list of our user handlers for various aspects of emulation
        self.mnemonic_handlers = {}
        self.opcode_handlers = {}
        self.register_handlers = {}
        self.pc_handlers = {}
        self.exception_handlers = {}
        self.interrupt_handlers = {}
        self.library_handlers = {}
        self.memory_handlers = {}
        self.memory_read_handler = None
        self.memory_write_handler = None
        self.memory_access_handler = None
        
        self.stack_read_handler = None
        self.stack_write_handler = None
        self.stack_access_handler = None
        
        self.heap_read_handler = None
        self.heap_write_handler = None
        self.heap_access_handler = None
        
        # Instantiate a CPU for use in the emulator
        self.cpu = PyCPU(self)
        
        # Determine which os we are on to instantiate the proper PyOS
        if os.name == 'nt':
            self.os = PyWindows()
        elif os.name == 'posix':
            # Yea I realize
            self.os = PyLinux()

    #
    # raise_exception: This method gets called when an exception happens
    #                  Currently we only care about general protection
    #                  faults (invalid memory access).  We will throw a
    #                  Python exception when this occurs (I want to change
    #                  this).
    #
    def raise_exception(self, exception, address):
        # User must raise their own exception
        if exception in self.exception_handlers:
            self.exception_handlers[exception](self, exception, address, self.cpu.EIP)
        else:    
            print "\n"
            print "*" * 72
            print "* A %s fault has occured at 0x%08x" % (exception, address)
            print "*" * 72
            
            self.dump_regs()
            self.dump_stack()
            
            raise RuntimeError, "The memory requested was invalid"
        
        return False
        
    #
    # debug: A public method for setting global debug levels
    #
    def debug(self, level):
        self.DEBUG = level
     
        # Propigate the debug levels throughout   
        self.memory.set_debug(level)
        self.cpu.set_debug(level)
        self.os.set_debug(level)
    
    #
    # execute: A public method for executing instructions
    #
    def execute(self, steps=1, start=0x0, end=0x0):
        if not isinstance(steps, int) or not isinstance(start, int) or not isinstance(end, int):
            return False

        # If we are called we are emulating
        self.emulating = True
        
        # Set the instruction pointer to the user supplied address
        if start:
            self.cpu.set_register32("EIP", start)
        
        # Set a stopping point if supplied so we can break
        if end:
            if steps > 1:
                while self.cpu.get_register32("EIP") != end and steps:
                    if not self.emulating: return False
                    
                    if not self.cpu.execute():
                        print "[!] Problem executing"
                        
                        return False

                    steps -= 1
            else:
                while self.cpu.get_register32("EIP") != end:
                    if not self.emulating: return False
                    
                    if not self.cpu.execute():
                        print "[!] Problem executing"
                        
                        return False
        else:
            for x in range(steps):
                if not self.emulating: return False
                
                if not self.cpu.execute():
                    print "[!] Problem executing"
                    
                    return False

        return True
    
    #
    # get_register: A public method to retrieve a register for the user
    #    
    def get_register(self, register):
        register = register.upper()
        
        # We are smart about the requested register automatically
        # determining the proper register size
        
        # 32 bit registers
        if re.compile('^E[A-X]{2}$', re.IGNORECASE).match(register):
            result = self.cpu.get_register32(register)
            
        # 16 bit registers
        elif re.compile('^[ABCD]X$', re.IGNORECASE).match(register):
            result = self.cpu.get_register16(register)
            
        # 8 bit registers
        elif re.compile('^[ABCD]{1,}[LH]{1}$', re.IGNORECASE).match(register):
            result = self.cpu.get_register8(register)
            
        # Segment registers
        elif re.compile('^[CSDEFG]{1}S$', re.IGNORECASE).match(register):
            result = self.cpu.get_register16(register)
            
        # Flags
        elif re.compile('^[CPAZSTIDPR]{1}F$', re.IGNORECASE).match(register) or register in ["IOPL","NT","VM","AC","VIF","VIP","ID"]:
            result = self.cpu.get_register8(register)
            
        # Check to make sure the user isnt requesting by name
        else:
            if register in self.register_names:
                result = self.cpu.get_register(self.register_names[register]["name"], self.register_names[register]["size"])
                
            else:    
                print "[!] Couldnt determine register"
                
                return False
            
        return result
    
    #
    # set_register: A public method for setting a registers value
    #               from a script.
    #
    def set_register(self, register, value, name=""):
        # Make sure its a valid value
        if not isinstance(value, int) and not isinstance(value, long):
            print "[!] Dont know how to use non-int value %s" % type(value)
            
            return False
        
        register = register.upper()
        name = name.upper()
        
        # We are smart about the requested register automatically
        # determining the proper register size
        
        # 32 bit registers
        if re.compile('^E[A-X]{2}$', re.IGNORECASE).match(register):
            if name:
                self.register_names[name] = {"name": register, "size": 4}
            
            # Try and set the register
            if not self.cpu.set_register32(register, value):
                print "[!] Problem setting register"
                
                return False
        # 16 bit registers
        elif re.compile('^[ABCD]X$', re.IGNORECASE).match(register):
            if name:
                self.register_names[name] = {"name": register, "size": 2}
            
            # Try and set the register
            if not self.cpu.set_register16(register, value):
                print "[!] Problem setting register"
                
                return False
        # 8 bit registers
        elif re.compile('^[ABCD]{1,}[LH]{1}$', re.IGNORECASE).match(register):
            if name:
                self.register_names[name] = {"name": register, "size": 1}
            
            # Try and set the register
            if not self.cpu.set_register8(register, value):
                print "[!] Problem setting register"
                
                return False
        # Segment registers
        elif re.compile('^[CSDEFG]{1}S$', re.IGNORECASE).match(register):
            if name:
                self.register_names[name] = {"name": register, "size": 2}
            
            # Try and set the register
            if not self.cpu.set_register16(register, value):
                print "[!] Problem setting register"
                
                return False
        # Flags
        elif re.compile('^[CPAZSTIDPR]{1}F$', re.IGNORECASE).match(register) or register in ["IOPL","NT","VM","AC","VIF","VIP","ID"]:
            if name:
                self.register_names[name] = {"name": register, "size": 1}
            
            # Try and set the register
            if not self.cpu.set_register8(register, value):
                print "[!] Problem setting register"
                
                return False
        # Check to make sure the user isnt requesting by name
        else:
            if name in self.register_names:
                # Try and set the register
                if not self.cpu.set_register(self.register_names[name]["name"], self.register_names[name]["size"]):
                    print "[!] Problem setting register"
                
                    return False
            else:    
                print "[!] Couldnt determine register size"
                
                return False
            
        return True
    
    #
    # get_stack_variable: A public method for setting stack local variables
    #
    def get_stack_variable(self, offset, size=0):
        # Validate the type of argument to determine offset or name
        if isinstance(offset, str):
            offset = offset.upper()
            
            # Check if we have the name
            if offset not in self.stack_variable_names:
                print "[!] Couldnt find name %s" % offset
                
                return False
            else:
                # Retrieve the offset associated
                offset = self.stack_variable_names[offset]
        elif not isinstance(offset, int) and not isinstance(offset, long):
            print "[!] Dont understand %s type" % type(offset)
            
            return False
            
        # If we dont have a size default to a dword
        if not size:
            size = 4
        
        # Check if we are using frame pointers for offsets
        if self.frame_pointer:
            address = self.cpu.get_register32("EBP") - offset
        else:
            address = self.cpu.get_register32("ESP") + offset
        
        # Fetch the address requested from the memory manager
        result = self.memory.get_memory(address, size)
        
        # Return the value
        return result
    
    #
    # set_stack_variable: A public method for setting a local stack variable
    #
    def set_stack_variable(self, offset, value, size=0, name=""):
        # Make sure our offset is a valid type
        if not isinstance(offset, int) and not isinstance(offset, long):
            print "[!] Offset must be int not %s" % type(offset)
            
            return False
        
        # Automagically determine a size for the supplied string
        if isinstance(value, str):
            if not size:
                size = len(value)
            else:
                # Truncate the string if necessary
                value = value[:size]
        elif isinstance(value, int) or isinstance(value, long):
            if not size:
                size = 4
        
        # If we are setting a name store it in the names list
        if name:
            name = name.upper()
            self.stack_variable_names[name] = offset
        
        # Check for a frame pointer to get the proper offset
        if self.frame_pointer:
            address = self.cpu.get_register32("EBP") - offset
        else:
            address = self.cpu.get_register32("ESP") + offset
        
        # Set the value in memory via the memory manager
        if not self.set_memory(address, value, size):
            print "[!] Failed setting memory @ %x" % (address)
            
            return False
        
        return True
    
    #
    # get_stack_argument: A public method to get a functions stack argument
    #
    def get_stack_argument(self, offset, size=0):
        # If we are asking by name check it
        if isinstance(offset, str):
            offset = offset.upper()
            
            if offset not in self.stack_variable_names:
                print "[!] Couldnt find name %s" % offset
                return False
            else:
                # Return the offset associated
                offset = self.stack_variable_names[offset]
        elif not isinstance(offset, int) and not isinstance(offset, long):
            print "[!] Dont understand %s type" % type(offset)
            return False
        
        # We only handle dword arguments for now   
        size = 4
        
        # Check for frame pointer to get the proper stack address
        if self.frame_pointer:
            address = self.cpu.get_register32("EBP") + offset
        else:
            address = self.cpu.get_register32("ESP") + offset
        
        # Retrieve the value from memory via the memory manager
        result = self.memory.get_memory(address, size)
        
        return result
    
    #
    # set_stack_argument: A public method to set up a stack argument
    #
    def set_stack_argument(self, offset, value, name=""):
        # Ensure the offset is proper
        if not isinstance(offset, int) and not isinstance(offset, long):
            print "[!] Offset must be int not %s" % type(offset)
            
            return False
        
        # Only dword arguments for now
        size = 4
        
        # If we have a name we need to get the associated offset
        if name:
            name = name.upper()
            self.stack_variable_names[name] = offset
        
        # Check the frame pointer and get the proper address
        if self.frame_pointer:
            address = self.cpu.get_register32("EBP") + offset
        else:
            address = self.cpu.get_register32("ESP") + offset
            
        # Store the value on the stack
        if not self.set_memory(address, value, size):
            print "[!] Failed setting memory @ %x" % (address)
            
            return False
        
        return True
    
    #
    # get_memory: A public method for fetching arbitrary memory
    #
    def get_memory(self, address, size=0):
        if not size:
            size = 4
        
        # Fetch the value
        result = self.memory.get_memory(address, size)
        
        return result
    
    #
    # get_memory_string: A public method to fetch a string from memory
    #
    def get_memory_string(self, address):
        s = ""
        x = 0
        while True:
            b = self.get_memory(address + x, size=1)
            if b != 0x00:
                s += chr(b)
            else:
                break
            x += 1
        
        return s
            
    #
    # set_memory: A public method for setting arbitrary memory
    #
    def set_memory(self, address, value, size=0):
        # If we are using a string calculate the size
        if isinstance(value, str):
            if not size:
                size = len(value)
            else:
                value = value[:size]
        elif isinstance(value, int) or isinstance(value, long):
            if not size:
                size = 4
        else:
            print "[!] I dont know what this type is"
            
            return False
        
        # For right now we lower the fault so the user can set arbitraty memory
        self.memory.fault = False
        
        # Set the value into memory via the memory manager
        if not self.memory.set_memory(address, value, size):
            print "[!] Failed setting memory @ %x" % (address)
            
            return False
        
        self.memory.fault = True
        
        return True

    #
    # get_selector: A public method for fetching a selector from the LDT
    #
    def get_selector(self, selector):
        return self.os.get_selector(selector)

    #
    # set_register_handler: A public method for setting a custom register
    #                       handler.  This allows trapping register touches
    #
    def set_register_handler(self, register, handler):
        # We only allow names via this method
        if not isinstance(register, str):
            print "[!] Cant understand register of type %s" % type(register)
            return False
        
        # Store the handler
        register = register.upper()
        self.register_handlers[register] = handler
        
        return True
        
    #
    # set_mnemonic_handler: A public method for setting a custom mnemonic
    #                       handler.  This allows the user to trap on
    #                       execution of a specified mnemonic
    #
    def set_mnemonic_handler(self, mnemonic, handler):
        # We only allow the string representation of the mnemonic
        if not isinstance(mnemonic, str):
            print "[!] Cant understand mnemonic of type %s" % type(mnemonic)
            
            return False
        
        # Store the handler
        mnemonic = mnemonic.upper()
        self.mnemonic_handlers[mnemonic] = handler
        
        return True
    
    #
    # set_opcode_handler: A public method for setting a custom handler
    #                     for opcodes.  This allows a user to trap on
    #                     the specified opcode.
    #
    def set_opcode_handler(self, opcode, handler):
        # We only allow opcodes by integer
        if not isinstance(opcode, int) and not isinstance(opcode, long):
            print "[!] Cant understand opcode of type %s" % type(opcode)
            
            return False
        
        # Store the handler
        self.opcode_handlers[opcode] = handler
        
        return True
        
    #
    # set_pc_handler: A public method for setting a custom handler on
    #                 the instruction pointer.  A quasi breakpoint
    #                 returning execution to the user at a specified
    #                 address.
    #
    def set_pc_handler(self, address, handler):
        # We only allow integer addresses
        if not isinstance(address, int) and not isinstance(address, long):
            print "[!] Cant understand address of type %s" % type(address)
            
            return False
        
        # Store the handler    
        self.pc_handlers[address] = handler
    
    #
    # set_exception_handler: A public method for setting a custom
    #                        handler for any exceptions that may happen
    #                        currently we are only handling GP/DE faults
    #
    def set_exception_handler(self, exception, handler):
        # We only allow string values
        if not isinstance(exception, str):
            print "[!] Cant understand exception of type %s" % type(exception)
            
            return False
        
        # Store the handler
        self.exception_handlers[exception] = handler
    
    #
    # set_library_handler: A public method for setting a custom
    #                        handler for any import function that
    #                        gets called
    #
    def set_library_handler(self, function, handler):
        # We only allow string values
        if not isinstance(function, str):
            print "[!] Cant understand function of type %s" % type(function)
            
            return False
        
        # Store the handler
        self.library_handlers[function] = handler
    
    #
    # set_interrupt_handler: A public method for setting a custom
    #                        handler for any interrupts that may happen
    #
    def set_interrupt_handler(self, interrupt, handler):
        # We only allow int values
        if not isinstance(exception, int) and not isinstance(exception, long):
            print "[!] Cant understand interrupt of type %s" % type(interrupt)
            
            return False
        
        # Store the handler
        self.interrupt_handlers[interrupt] = handler
                            
    #
    # set_memory_handler: A public method for setting a custom handler
    #                     for specific memory access.  This allows a user
    #                     to receive execution when a specified address
    #                     is accessed.
    #
    def set_memory_handler(self, address, handler):
        # We only allow integer addresses
        if not isinstance(address, int) and not isinstance(address, long):
            print "[!] Cant understand address of type %s" % type(address)
            
            return False
                
        # Store the handler
        self.memory_handlers[address] = handler
    
    #
    # set_memory_read_handler: A public memory for setting a custom handler
    #                          for *any* read of memory.
    #    
    def set_memory_read_handler(self, handler):
        # Store the handler
        self.memory_read_handler = handler
        
        return True
    
    #
    # set_memory_write_handler: A public memory for setting a custom handler
    #                           for *any* write of memory.
    #      
    def set_memory_write_handler(self, handler):
        # Store the handler
        self.memory_write_handler = handler
        
        return True
    
    #
    # set_memory_access_handler: A public memory for setting a custom handler
    #                            for *any* read or write of memory.
    #  
    def set_memory_access_handler(self, handler):
        # Store the handler
        self.memory_access_handler = handler
        
        return True

    #
    # set_stack_read_handler: A public memory for setting a custom handler
    #                         for *any* stack read.
    #
    def set_stack_read_handler(self, handler):
        # Store the handler
        self.stack_read_handler = handler
        
        return True
    
    #
    # set_stack_write_handler: A public memory for setting a custom handler
    #                          for *any* stack write.
    #     
    def set_stack_write_handler(self, handler):
        # Store the handler
        self.stack_write_handler = handler
        
        return True
    
    #
    # set_stack_access_handler: A public memory for setting a custom handler
    #                           for *any* stack read or write.
    #
    def set_stack_access_handler(self, handler):
        # Store the handler
        self.stack_access_handler = handler
        
        return True
    
    #
    # set_heap_read_handler: A public memory for setting a custom handler
    #                        for *any* heap read.
    #
    def set_heap_read_handler(self, handler):
        # Store the handler
        self.heap_read_handler = handler
        
        return True
    
    #
    # set_heap_write_handler: A public memory for setting a custom handler
    #                         for *any* heap write.
    #    
    def set_heap_write_handler(self, handler):
        # Store the handler
        self.heap_write_handler = handler
        
        return True
    
    #
    # set_heap_access_handler: A public memory for setting a custom handler
    #                          for *any* heap read or write.
    #
    def set_heap_access_handler(self, handler):
        # Store the handler
        self.heap_access_handler = handler
        
        return True
    
    #
    # dump_regs: A public method to dump the regs from the CPU
    #
    def dump_regs(self):
        self.cpu.dump_regs()
    
    #
    # dump_stack: A public method to dump the stack from EBP
    #
    def dump_stack(self, count=64):
        self.cpu.dump_stack(count)
        
    #
    # get_disasm: A public method to get a pretty dump of the current
    #             instruction disassembly
    def get_disasm(self):
        return self.cpu.get_disasm()
             
'''
PyDbgPyEmu:

    The ugliest class name ever.  Really the PyEmu class for handling
    PyDbg operation.  It is responsible for talking between the
    emulator and the real process.  This is what the user would instantiate.
''' 
class PyDbgPyEmu(PyEmu):
    def __init__(self, dbg):
        
        PyEmu.__init__(self)
        
        # Store the pydbg instance
        self.dbg = dbg
        
        # Get the memory manager object
        self.memory = PyDbgMemory(self, self.dbg)
        
        # Set our context from the real process
        self.setup_context()
        
    def setup_context(self):
        pcontext = self.dbg.context
        
        emucontext = PyContext()
        
        emucontext.EAX = pcontext.Eax
        emucontext.ECX = pcontext.Ecx
        emucontext.EDX = pcontext.Edx
        emucontext.EBX = pcontext.Ebx
        emucontext.ESP = pcontext.Esp
        emucontext.EBP = pcontext.Ebp
        emucontext.ESI = pcontext.Esi
        emucontext.EDI = pcontext.Edi
        emucontext.EIP = pcontext.Eip
        
        emucontext.GS = pcontext.SegGs
        emucontext.FS = pcontext.SegFs
        emucontext.ES = pcontext.SegEs
        emucontext.DS = pcontext.SegDs
        
        emucontext.CS = pcontext.SegCs
        emucontext.SS = pcontext.SegSs
        
        emucontext.EFLAGS = pcontext.EFlags
        
        # Set up the context in the emulated CPU
        self.cpu.set_context(emucontext)
        
        return True
            
'''
IDAPyEmu:

    The purposed class for emulating in IDA Pro.  This has to set up
    some basic operating environments for the executable.  This is what
    the user will be instantiating.
'''
class IDAPyEmu(PyEmu):
    def __init__(self, stack_base=0x0095f000, stack_size=0x1000, heap_base=0x000a0000, heap_size=0x2000, frame_pointer=True):

        PyEmu.__init__(self)
        
        # Store memory limit information
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.heap_base = heap_base
        self.heap_size = heap_size
        self.frame_pointer = frame_pointer

        # Get a memory manager object for IDA
        self.memory = IDAMemory(self)

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

'''
PEPyEmu:

    The purposed class for emulating from a raw PE executable.  This has
    to set up some basic operating environments for the executable.
    This is what the user will be instantiating.
''' 
class PEPyEmu(PyEmu):
    def __init__(self, stack_base=0x0095f000, stack_size=0x1000, heap_base=0x000a0000, heap_size=0x2000, frame_pointer=True):
     
        PyEmu.__init__(self)
   
        # Store memory limit information
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.heap_base = heap_base
        self.heap_size = heap_size
        self.frame_pointer = frame_pointer

        # Get a memory manager object for the PE file
        self.memory = PEMemory(self)

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
