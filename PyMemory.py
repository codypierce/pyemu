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

import struct, sys, string

'''
PyMemoryPage:

    A class that allows us to define some properties and methods for each
    page of memory in our cache.  This could be used to further define
    permissions and attributes as needed
'''
class PyMemoryPage:
    DEBUG = 0
    PAGESIZE = 4096
    
    READ = 0x1
    WRITE = 0x2
    EXECUTE = 0x4
    
    def __init__(self, address, data="", permissions=0x0):
        self.address = address
        self.data = data
        self.permissions = permissions
        
    def get_data(self):
        return self.data
    
    def get_permissions(self):
        return self.permissions
    
    def set_data(self, data):
        self.data = data
    
    def set_permissions(self, permissions):
        self.permissions = permissions
    
    def set_debug(self, level):
        self.DEBUG = level
            
    def set_r(self):
        self.permissions |= self.READ
    
    def set_w(self):
        self.permissions |= self.WRITE
        
    def set_x(self):
        self.permissions |= self.EXECUTE
    
    def set_rw(self):
        self.permissions |= self.READ
        self.permissions |= self.WRITE
    
    def set_rx(self):
        self.permissions |= self.READ
        self.permissions |= self.EXECUTE
        
    def set_rwx(self):
        self.permissions |= self.READ
        self.permissions |= self.WRITE
        self.permissions |= self.EXECUTE
        
    def is_r(self):
        return self.permissions & self.READ
    
    def is_w(self):
        return self.permissions & self.WRITE
    
    def is_x(self):
        return self.permissions & self.WRITE
    
    def is_rx(self):
        if (self.permissions & self.READ) and (self.permissions & self.EXECUTE):
            return True
        else:
            return False
    
    def is_rwx(self):
        if (self.permissions & self.READ) and (self.permissions & self.WRITE) and (self.permissions & self.EXECUTE):
            return True
        else:
            return False
        
'''
PyMemory:
    
    The base class for handling memory requests from the PyCPU and PyEmu.
    This class should be extended by any custom memory managers.
'''
class PyMemory:
    DEBUG = 0
    PAGESIZE = 4096
    
    def __init__(self, emu):
        self.emu = emu
        self.pages = {}
        self.fault = True
    
    #
    # get_memory: Fetches memory first checking local cache, then
    #             calling the child memory allocator
    #
    def get_memory(self, address, size):
        page = address & 0xfffff000
        offset = address & 0x00000fff
        
        if self.DEBUG >= 2:
            print "[*] Trying to get memory @ %x" % (address)

        # I need to get the number of pages        
        (d, r) = divmod(offset + size, self.PAGESIZE)
        
        if r:
            d += 1

        oldsize = size
        rawbytes = ""
        for page in xrange(page, page + (d * self.PAGESIZE), self.PAGESIZE):
            # We must get our memory
            if page not in self.pages:
                if not self.get_page(page):
                    print "[!] Invalid memory"
                    
                    return self.emu.raise_exception("GP", page)
                
            for x in xrange(0, size):
                if address < (page + self.PAGESIZE):
                    # Do stuff on this page
                    try:
                        rawbytes += self.pages[page].data[address & 0x00000fff]
                    except IndexError:
                        print "%05x:%03x" % (page, address & 0x00000fff)
                        print "data %x" % (len(self.pages[page].data))
                        sys.exit()
                    address += 1
                else:
                    size -= x
                    break
        size = oldsize
        
        if size == 1:
            return struct.unpack("<B", rawbytes)[0]
        elif size == 2:
            return struct.unpack("<H", rawbytes)[0]
        elif size == 4:
            return struct.unpack("<L", rawbytes)[0]
        else:
            return rawbytes
                        
        return False
    
    #
    # set_memory: Set an address to a specific value.  This can be a
    #             integer or string.
    #
    def set_memory(self, address, value, size):
        page = address & 0xfffff000
        offset = address & 0x00000fff
        
        if self.DEBUG > 2:
            print "[*] Trying to set memory @ %x value %x size %d" % (address, value, size)
            
        if isinstance(value, int) or isinstance(value, long):
            if size == 1:
                packedvalue = struct.pack("<B", int(value))
            elif size == 2:
                packedvalue = struct.pack("<H", int(value))
            elif size == 4:
                packedvalue = struct.pack("<L", int(value))
            else:
                print "[!] Couldnt pack new value of size %d" % (size)
                
                return False
        elif isinstance(value, str):
            # We need to pack the values into native endian
            packedvalue = value[::-1]
        else:
            print "[!] Don't understand this value type %s" % type(value)
            
            return False
        
        # I need to get the number of pages        
        (d, r) = divmod(offset + size, self.PAGESIZE)
        
        if r:
            d += 1

        oldsize = size
        for page in xrange(page, page + (d * self.PAGESIZE), self.PAGESIZE):
            # We must get our memory
            if page not in self.pages:
                if not self.get_page(page):
                    print "[!] Invalid memory"
                    
                    return self.emu.raise_exception("GP", page)
  
            newdata = self.pages[page].data[:address & 0x00000fff]
            for x in xrange(0, size):
                if address < (page + self.PAGESIZE):
                    # Do stuff on this page
                    newdata += packedvalue[x]
                    address += 1
                else:
                    packedvalue = packedvalue[x:]
                    size -= x
                    break
            
            if address & 0x00000fff:    
                newdata += self.pages[page].data[(address & 0x00000fff):]
                    
            self.pages[page].set_data(newdata)
                
        return True
     
    #
    # get_available_page: Will return the next available page starting from address
    #
    def get_available_page(self, address):
        page = address & 0xfffff000
        
        while True:
            if page not in self.pages:
                break
            page += self.PAGESIZE
            
        return page
            
    #
    # is_valid: A helper function to check for a address in our cache
    #
    def is_valid(self, address):
        page = address & 0xfffff000
        
        if page not in self.pages:
            return False
        else:
            return True
            
    def get_page(self, page):
        print "[*] We dont know, this should be overloaded"
        
        return False
    
    def set_debug(self, level):
        self.DEBUG = level

    #
    # dump_memory: This dumps the data from memory optionally writing
    #              to a supplied file
    #
    def dump_memory(self, filename=None):
        if filename:
            handle = open(filename, "wb")
        else:
            handle = sys.stdout
        
        for addr in self.pages.keys():
            data = self.pages[addr].get_data()
            handle.write(data)
        
        if filename:
            handle.close()
            
        return True
        
    #
    # dump_pages: This will dump all the currently cached memory pages.
    #             This could potentially be a lot of data.
    #  
    def dump_pages(self, data=False):
        for addr in self.pages.keys():
            if data:
                print "[*] 0x%08x: size [%d] data [%s]" % (addr, len(self.pages[addr]), repr(self.pages[addr]))
            else:
                print "[*] 0x%08x: size [%d]" % (addr, len(self.pages[addr].data))
                
        return True

'''
PyDbgMemory:

    This is the pydbg memory manager.  It extends the base PyMemory class
    This is responsible for nothing more than handling requests for
    memory if needed.  In this case a fetch of unknown memory will make a
    call to ReadProcessMemory via the dbg instance.
'''
class PyDbgMemory(PyMemory):
    def __init__(self, emu, dbg):
        self.dbg = dbg
        
        PyMemory.__init__(self, emu)
   
    #
    # allocate_page: Allocates a page for addition into the cache
    # 
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("\x00" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
        
    #
    # get_page: This fetches the page from pydbg
    #
    def get_page(self, page):
        try:
            newpagedata = self.dbg.read_process_memory(page, self.PAGESIZE)
        except:
            print "[!] Couldnt read mem page @ 0x%08x" % page
            
            return False
        
        newpage = PyMemoryPage(page)
        newpage.set_data(newpagedata)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True

'''
IDAMemory:

    This is the ida memory manager. It extends the base PyMemory class
    and is responsible for handling any unknown memory requests.  In IDA
    this is a tricky call cause we can either throw an exception on invalid
    memory accesses or go ahead and fulfill them in case the user did not
    set everything up properly.  Its really a personal choice.
'''
class IDAMemory(PyMemory):
    def __init__(self, emu):
        PyMemory.__init__(self, emu)
    
    #
    # allocate_page: Allocates a page for addition into the cache
    #
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("\x00" * newpage.PAGESIZE)
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

'''
PEMemory:

    This is the raw PE file memory handler that is responsible for handling
    requests from the base class.  Like the others it requests memory when
    needed.
'''
class PEMemory(PyMemory):
    def __init__(self, emu):
        PyMemory.__init__(self, emu)

    #
    # allocate_page: Allocates a page for addition into the cache
    #
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("\x00" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
    
    #
    # allocate: Allocates a block of memory
    #
    def allocate(self, size):
        print "XXX - Doesnt work"
        sys.exit(-1)
        (num, rem) = divmod(size, self.PAGESIZE)
        if rem:
            num += 1
        pagenum = num
        
        page = self.get_available_page()
        if not self.allocate_page(page):
            print "[!] Error allocating page %x" % page
            return False
        
        return address
        
    #
    # get_page: Stores a page in the base class cache
    #
    def get_page(self, page):
        if self.fault:
            return False
            
        # Grab a new page object
        return self.allocate_page(page)
