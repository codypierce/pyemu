#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your paimei path plz2u !!!
sys.path.append("..")
sys.path.append("../lib")
sys.path.append("../../paimei/trunk")

from pydbg import *
from pydbg.defines import *

from PyEmu import *

###
#
# PyEmu handlers
#
###
def my_library_handler(library, address, dll):
    print "[*] Hit my_library_handler(%s, %x, %s)" % (library, address, dll)
    
    # I dont want to continue
    return True
    
###
#
# Pydbg stuff
#
###
def handler_breakpoint(dbg):
    # Initial module bp we need to process entries
    if dbg.first_breakpoint:
        print "[*] First bp hit setting emu address @ 0%08x" % dbg.emuaddress

        dbg.bp_set(dbg.emuaddress, handler=handler_emu_breakpoint, restore=False)
        
        return DBG_CONTINUE
    
    print "[!] Unknown bp caught @ 0%08x" % dbg.exception_address
    
    return DBG_CONTINUE

def handler_emu_breakpoint(dbg):
    if dbg.exception_address != dbg.emuaddress:
        print "[!] Emulator handler caught unknown bp @ 0x%08x" % (dbg.exception_address)
        
        return DBG_CONTINUE

    # Create a new emulator object
    emu = PyDbgPyEmu(dbg)
    
    emu.os.add_thread()
    print "%x %x" % (dbg.context.SegFs, dbg.tebs[dbg.dbg.dwThreadId])
    emu.os.set_selector(dbg.context.SegFs, dbg.tebs[dbg.dbg.dwThreadId])
    
    emu.debug(0)
    
    emu.os.add_library("kernel32", "LocalAlloc")
    emu.os.add_library("kernel32", "LocalFree")
    
    emu.set_library_handler("LocalAlloc", my_library_handler)
    
    c = None
    while c != "x":
        emu.dump_regs()

        if not emu.execute():
            return DBG_CONTINUE

        c = raw_input("emulator> ")
        
    return DBG_CONTINUE
    
#
# Attaches to procname if it finds it otherwise loads
#
def attach_target_proc(dbg, procname):
    imagename = procname.rsplit('\\')[-1]
    print "[*] Trying to attach to existing %s" % imagename
    for (pid, name) in dbg.enumerate_processes():
        if imagename in name:
            try:
                print "[*] Attaching to %s (%d)" % (name, pid)
                dbg.attach(pid)
            except:
                print "[!] Problem attaching to %s" % name
                
                return False
            
            return True
            
    try:
        print "[*] Trying to load %s" % (procname)
        dbg.load(procname, "")
    except:
        print "[!] Problem loading %s" % (procname)
        
        return False
    
    return True

# pydbgpyemu.py calc.exe 0x001001AF3
if len(sys.argv) < 3:
    print "Usage: %s <process name> <emulator start address>" % sys.argv[0]
    
    sys.exit(-1)

procname = sys.argv[1]
emuaddress = sys.argv[2]

if len(sys.argv) == 4:
    myinstruction = sys.argv[3]
else:
    myinstruction = None

dbg = pydbg()
dbg.procname = procname
dbg.emuaddress = string.atol(emuaddress, 16)
dbg.myinstruction = myinstruction

dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

if not attach_target_proc(dbg, procname):
    print "[!] Couldnt load/attach to %s" % procname
    
    sys.exit(-1)

dbg.debug_event_loop()