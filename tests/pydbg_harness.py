#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your paimei path plz2u !!!
sys.path.append("..")
sys.path.append("../lib")
sys.path.append("../../paimei/trunk")

from pydbg import *
from pydbg.defines import *

from PyEmu import *
from PyContext import *
from PyDebug import *

def get_context(dbg):
    pcontext = dbg.context
    
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

    return emucontext

def dump_context(contexta, contextb):
    sys.stdout.write("eax: 0x%08x    eax: 0x%08x\n" % (contexta.EAX, contextb.EAX))
    sys.stdout.write("ecx: 0x%08x    ecx: 0x%08x\n" % (contexta.ECX, contextb.ECX))
    sys.stdout.write("edx: 0x%08x    edx: 0x%08x\n" % (contexta.EDX, contextb.EDX))
    sys.stdout.write("ebx: 0x%08x    ebx: 0x%08x\n" % (contexta.EBX, contextb.EBX))
    sys.stdout.write("esp: 0x%08x    esp: 0x%08x\n" % (contexta.ESP, contextb.ESP))
    sys.stdout.write("ebp: 0x%08x    ebp: 0x%08x\n" % (contexta.EBP, contextb.EBP))
    sys.stdout.write("esi: 0x%08x    esi: 0x%08x\n" % (contexta.ESI, contextb.ESI))
    sys.stdout.write("edi: 0x%08x    edi: 0x%08x\n" % (contexta.EDI, contextb.EDI))
    sys.stdout.write("eip: 0x%08x    eip: 0x%08x\n\n" % (contexta.EIP, contextb.EIP))

    sys.stdout.write("efl:0x%08x [" % contexta.EFLAGS)
    DebugDumpFlags(contexta.EFLAGS)
    sys.stdout.write("]    ")
    sys.stdout.write("efl:0x%08x [" % contextb.EFLAGS)
    DebugDumpFlags(contextb.EFLAGS)
    sys.stdout.write("]\n\n")

    return

def error(message, pydbgcontext, emucontext):
    print message
        
    dump_context(pydbgcontext, emucontext)
    
def compare_context(pydbgcontext, emucontext):
    if pydbgcontext.EAX != emucontext.EAX: error("EAX", pydbgcontext, emucontext)
    elif pydbgcontext.ECX != emucontext.ECX: error("ECX", pydbgcontext, emucontext)
    elif pydbgcontext.EDX != emucontext.EDX: error("EDX", pydbgcontext, emucontext)
    elif pydbgcontext.EBX != emucontext.EBX: error("EBX", pydbgcontext, emucontext)
    elif pydbgcontext.ESP != emucontext.ESP: error("ESP", pydbgcontext, emucontext)
    elif pydbgcontext.EBP != emucontext.EBP: error("EBP", pydbgcontext, emucontext)
    elif pydbgcontext.ESI != emucontext.ESI: error("ESI", pydbgcontext, emucontext)
    elif pydbgcontext.EDI != emucontext.EDI: error("EDI", pydbgcontext, emucontext)
    elif pydbgcontext.EIP != emucontext.EIP: error("EIP", pydbgcontext, emucontext)
    
    #elif pydbgcontext.EFLAGS != emucontext.EFLAGS: error("EFL", pydbgcontext, emucontext)
    else:
        return True
    
    return False
    
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

    dbg.single_step(True)
    
    return DBG_CONTINUE

def handler_ss(dbg):
    dbg.single_step(True)
    
    # Create a new emulator object
    emu = PyDbgPyEmu(dbg)
    
    emu.os.add_thread()
    emu.os.set_selector(dbg.context.SegFs, dbg.tebs[dbg.dbg.dwThreadId])
    
    emu.debug(1)

    pydbgcontext = get_context(dbg)

    if dbg.emucontext:
        if not compare_context(pydbgcontext, dbg.emucontext):
            print "[!] Compare failed\n"
            
            dbg.terminate_process()
            
            return DBG_CONTINUE
    
    try:
        if not emu.execute():
            print "[!] Problem executing"
            dbg.terminate_process()    
    except:
        print "[!] Exception or something"
        dbg.terminate_process()
    
    dbg.emucontext = emu.cpu.get_context()
    
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
dbg.emucontext = None

dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP, handler_ss)
if not attach_target_proc(dbg, procname):
    print "[!] Couldnt load/attach to %s" % procname
    
    sys.exit(-1)

dbg.debug_event_loop()