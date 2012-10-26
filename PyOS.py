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

import sys, struct

sys.path.append("lib")

from ctypes import *

'''
PyWindows:
    
    This is a class to handle any Win32 related system structures.  To the
    best of my abilities I have tried to load any relevant pieces of
    information.  This is not complete but enough for SEH and selector
    implementation.  The class includes the PEB, TEB/TIB, LDT.
'''
class PyWindows:
    DEBUG = 0
    
    def __init__(self):
        # We initialize a PEB structure
        self.PEB = self.__PEB()
        self.THREADS = []
        
        # This holds any libraries we may be interested in
        self.libraries = {}

    #
    # initialize: called from the emulator to set up the environment
    #
    def initialize(self, emu, stackbase, stacklimit, heapbase, heaplimit):
        self.PEB.ProcessHeap = heapbase

        # Grab the next TEB address
        if not len(self.THREADS):
            # Our first Thread
            tebaddress = self.PEB.Address - 0x1000
        else:
            # Get last TEB address
            tebaddress = self.THREADS[-1].TEB.Address - 0x1000
                
        # Create a new thread
        self.add_thread()
         
        self.THREADS[-1].load_teb(emu, tebaddress)
        self.THREADS[-1].load_stack(emu, stackbase, stacklimit)
        self.THREADS[-1].load_exceptions(emu)
        
        return True
    
    def set_debug(self, level):
        self.DEBUG = level
    
    #
    # add_thread: Handles creating a new thread/TEB/TIB and stores it
    #                 in the class THREAD list
    #
    def add_thread(self):
        # Instantiate a object with the TIB information
        new_thread = self.__THREAD()
        
        self.THREADS.append(new_thread)
        
        return True
    
    #
    # add_library: Handles addition of libraries to the OS.  This lets us
    #              call any user handlers when we call into this function
    #
    def add_library(self, dllname, function):
        for library in self.libraries:
            if function == self.libraries[library]['name']:
                return True

        handle  = windll.kernel32.LoadLibraryA(dllname)
        address = windll.kernel32.GetProcAddress(handle, function)
        windll.kernel32.FreeLibrary(handle)
        
        #if self.DEBUG >= 1:
        print "[*] Adding library %s address 0x%08x" % (function, address)
        
        self.libraries[address] = {'dll': dllname, 'address': address, 'name': function}
        
        return True
    
    #
    # get_library_address: Returns the address for the specified library
    #
    def get_library_address(self, function):
        for key in self.libraries.keys():
            if function == self.libraries[key]['name']:
                return key
        
        return False
            
    #
    # get_selector: Responsible for looking up the LDT offset requested
    #               Currently this is not very robust, in time it wll be
    #               cleaned up.
    #
    def get_selector(self, selector):
        return self.THREADS[-1].LDT.get_selector(selector)
    
    #
    # set_selector: Responsible for updating a selector values base address
    #
    def set_selector(self, selector, value):
        return self.THREADS[-1].LDT.set_selector(selector, value)
        
    '''
    __PEB:
    
        The PEB class implementation.  This is not complete as stated
        above.  It should contain a few values for fun.
    '''
    class __PEB:
        def __init__(self):
            self.Address = 0x00000000
            
            # *not complete*
            self.InheritedAddressSpace = 0x0
            self.ReadImageFileExecOptions = 0x0
            self.BeingDebugged = 0x0
            self.ImageBaseAddress = 0x00000000
            self.Ldr = self.__LDR()
            self.SubSystemData = 0x00000000
            self.ProcessHeap = 0x00000000
            self.ProcessParameters = 0x00000000
            self.WindowTitle = ""
            self.ImageFile = ""
            self.CommandLine = ""
            self.DllPath = ""
            self.Environment = 0x00000000
        
        #
        # get_packed: Packs all our values, since we are not using any
        #             nothing much goes on
        #
        def get_packed(self):
            packeddata = ""
            
            # NULL it out for now
            packeddata = "\x00" * 0x20c
            
            return packeddata
        
        '''
        __LDR:
        
            A LDR_DATA class for the future! and beyond!
        '''   
        class __LDR:
            def __init__(self):
                self.Address = 0x0000000
                
                # I need to add the LDR_DATA elements
                
            #
            # get_packed: Packs all our values, since we are not using any
            #             nothing much goes on
            #    
            def get_packed(self):
                packeddata = ""
                
                # NULL it out for now
                packeddata = "\x00" * 0x28
                
                return packeddata
    
    '''
    __THREAD:
    
        A THREAD class which contains our TEB and LDT.  This has been
        implemented to allow access to the SEH and selectors of the
        current thread.  This is not complete and simply a "good enough"
        implementation.
    '''
    class __THREAD:
        def __init__(self):
            
            # Initialize a TEB and LDT
            self.TEB = self.__TEB()
            self.LDT = self.__LDT()
        
        #
        # load_teb: Handles getting memory for the TEB and setting values
        #
        def load_teb(self, emu, address):
            self.TEB.Address = address
            
            emu.memory.allocate_page(self.TEB.Address)

            # Store our TEB in actual memory
            emu.set_memory(self.TEB.Address, self.TEB.get_packed())
            
            return True
        
        #
        # load_stack: Responsible for setting TIB stack values
        #
        def load_stack(self, emu, stackbase, stacklimit):
            # Fetch a page into cache for our stack
            emu.memory.allocate_page(stacklimit)
            
            self.TEB.TIB.StackBase = stackbase
            self.TEB.TIB.StackLimit = stacklimit
            
            return True
        
        #
        # load_exceptions: Responsible for setting TIB exception values
        #
        def load_exceptions(self, emu):
            # A generic address to get us started
            self.TEB.TIB.ExceptionList = self.TEB.TIB.StackBase - 0x24
            
            # Init a LDT entry four our TIB selector
            selector = self.LDT.get_selector(0x3b)
            selector.base = self.TEB.TIB.ExceptionList
            
            # Store the exception entry in actual memory
            emu.set_memory(self.TEB.TIB.ExceptionList, 0xffffffff)
            emu.set_memory(self.TEB.TIB.ExceptionList + 0x4, 0xdeadbeef)
            
            return True
        
        '''
        __TEB:
        
            A class to represent the TEB.  The only thing we are
            currently interested in is the TIB so the rest of the TEB
            is faked
        '''    
        class __TEB:
            def __init__(self):
                self.Address = 0x00000000
           
                # Initialize a new TIB (this is offset 0x0 in _TEB     
                self.TIB = self.__TIB()
                
                # Rest of the TEB would go here

            #
            # get_packed: Packs all our values, since we are not using any
            #             besides the TIB we do that then pad the rest
            #
            def get_packed(self):
                packeddata = ""
                
                # Pack and pad
                packeddata  = self.TIB.get_packed()
                packeddata += "\x00" * (0xfb6 - len(packeddata))
                
                return packeddata
            
            '''
            __TIB:
            
                A class to store the import TIB information.  This includes
                our stack boundaries and seh chain
            '''
            class __TIB:
                def __init__(self):
                    self.ExceptionList = 0x00000000
                    self.StackBase = 0x00000000
                    self.StackLimit = 0x00000000
                    self.SubSystemTib = 0x00000000
                    self.FiberData = 0x00000000
                    self.ArbitraryUserPointer = 0x00000000
                    self.Self = 0x00000000
                
                #
                # get_packed: Packs all our values, im sure there is a
                #             much better way to do this.
                # 
                def get_packed(self):
                    packeddata = ""
                    
                    packeddata  = struct.pack("<L", self.ExceptionList)
                    packeddata += struct.pack("<L", self.StackBase)
                    packeddata += struct.pack("<L", self.StackLimit)
                    packeddata += struct.pack("<L", self.SubSystemTib)
                    packeddata += struct.pack("<L", self.FiberData)
                    packeddata += struct.pack("<L", self.ArbitraryUserPointer)
                    packeddata += struct.pack("<L", self.Self)
                    
                    return packeddata
                
                '''
                __EXCEPTION_RECORD:
                
                    A class for handling exception records.  Currently
                    this is not used, but I like to type.
                '''
                class __EXCEPTION_RECORD:
                    def __init__(self):
                        self.Next = 0x00000000
                        self.Handler = 0x00000000
                    
                    def get_packed(self):
                        packeddata = ""
                        
                        packeddata  = struct.pack("<L", self.Next)
                        packeddata += struct.pack("<L", self.Handler)
                        
                        return packeddata
        
        '''
        __LDT:
        
            A local descriptor table per thread.  This is to allow us to
            access the TIB selector for exception handling.
        '''           
        class __LDT:
            def __init__(self):
                self.entries = {}
        
                # Load our initial entries    
                self.init_entries()
            
            #
            # init_entries: Loads selectors for various segments and the TIB
            #
            def init_entries(self):
                # Code, Data, TIB
                self.entries[0x0000] = self.__LDT_ENTRY(0x0000, 0x0000000, 0x00000000)
                self.entries[0x001b] = self.__LDT_ENTRY(0x001b, 0x0000000, 0xffffffff)
                self.entries[0x0023] = self.__LDT_ENTRY(0x0023, 0x0000000, 0xffffffff)
                self.entries[0x0038] = self.__LDT_ENTRY(0x0038, 0x0000000, 0x00000fff)
                self.entries[0x003b] = self.__LDT_ENTRY(0x003b, 0x0000000, 0x00000fff)

            #
            # get_selector: Returns the requested selector
            #
            def get_selector(self, selector):
                if selector not in self.entries:
                    print "[!] Couldnt get selector[%x]" % selector
                    
                    return False
                
                return self.entries[selector]
            
            #
            # set_selector: Sets the requested selector
            #
            def set_selector(self, selector, value):
                if selector not in self.entries:
                    print "[!] Couldnt get selector[%x]" % selector
                    
                    return False
                
                self.entries[selector].base = value
                
                return True
                
            '''
            __LDT_ENTRY:
            
                A class for storing the each LDT entries information
                including the selector offset, base, and limit.  We dont
                have support for getting at the other information yet
            '''    
            class __LDT_ENTRY:
                def __init__(self, selector, base, limit):
                    self.selector = selector
                    self.base = base
                    self.limit = limit
                    
'''
PyLinux:

    A class to handle process setup in Linux.  I dont have time to add
    this however I like at least mentioning it is possible.  PyEmu will
    choose this based on the internal os.name method.
'''
class PyLinux:
    DEBUG = 0
    
    def __init__(self):
        pass

    #
    # initialize: called from the emulator to set up the environment this
    #             wont do anything...yet :(
    #
    def initialize(self, stackbase, stacklimit, heapbase, heaplimit):
        
        return True
    
    def set_debug(self, level):
        self.DEBUG = level
