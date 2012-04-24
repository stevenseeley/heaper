'''

   __                        
  / /  ___ ___ ____  ___ ____
 / _ \/ -_) _ `/ _ \/ -_) __/
/_//_/\__/\_,_/ .__/\__/_/   
             /_/             v0.01

Copyright (C) 2011  Steven Seeley

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Created on: Oct 4, 2011             
author: mr_me <steventhomasseeley@gmail.com>
Note: you will need pydot, pyparser and graphviz for the graphing functionality
'''

__VERSION__ = '0.01'
__IMM__ = '1.8'

DESC="""heaper - an advanced heap analysis plugin."""

import immlib
from immlib import LogBpHook
import immutils
import libdatatype
try:
    import pydot
except:
    pydot = False
import struct
import re
from hashlib import sha1
import urllib2
import inspect
from immlib import AccessViolationHook

# GLOBAL VARIABLES
# ================

# all available functions
# ========================
available_commands = ["dumppeb", "dp", "dumpheaps", "dh", "analyseheap", "ah", "dumpteb", "dt", 
                      "analysefrontend", "af", "analysebackend", "ab", "analysechunks", "ac", 
                      "dumpfunctionpointers", "dfp", "help", "-h", "analysesegments", "as", "-f", 
                      "-m", "-p", "freelistinuse", "fliu", "hook", "analyseheapcache", "ahc", "h",
                      "exploit","exp","u","update", "patch", "p"]

# graphiz engine needs this under windows 7
paths = {"dot":"C:\\Program Files\\Graphviz 2.28\\bin\\dot.exe",
         "twopi":"C:\\Program Files\\Graphviz 2.28\\bin\\twopi.exe",
         "neato":"C:\\Program Files\\Graphviz 2.28\\bin\\neato.exe",
         "circo":"C:\\Program Files\\Graphviz 2.28\\bin\\circo.exe",
         "fdp":"C:\\Program Files\\Graphviz 2.28\\bin\\fdp.exe"}
    
# 8 byte block
# ============
block = 8

# window management
# =================
opennewwindow = False

# graphic flag
# ============
graphic_structure = False

# heap restore
restore = False

# hook tags
# =========
tag             = "display_box"
ALLOCLABEL      = "RtlAllocateHeap Hook"
FREELABEL       = "RtlFreeHeap Hook"
CREATELABEL     = "RtlCreateHeap Hook"
DESTROYLABEL    = "RtlDestroyHeap Hook"
REALLOCLABEL    = "RtlReAllocateHeap Hook"
SIZELABEL       = "RtlSizeHeap Hook"
CREATECSLABEL   = "RtlInitializeCriticalSection Hook"
DELETECSLABEL   = "RtlDeleteCriticalSection Hook"
SETUEFLABEL     = "SetUnhandledExceptionFilter Hook"
VIRALLOCLABEL   = "VirtualAlloc Hook"
VIRFREELABEL    = "VirtualFree Hook"

# hook flags
# ==========
FilterHeap      = False
Disable         = False
AllocFlag       = False
FreeFlag        = False
CreateFlag      = False
DestroyFlag     = False
ReAllocFlag     = False
sizeFlag        = False
CreateCSFlag    = False
DeleteCSFlag    = False
setuefFlag      = False
setVAllocFlag   = False
setVFreeFlag    = False

# valid functions too hook
# ========================
valid_functions = ["alloc", "free", "create", "destroy", "realloc", "size", "createcs", "deletecs",
                   "all", "setuef", "va", "vf"]

# return heap for hooking
# =======================
rheap = False

# for hooking function pointers
# =============================
INDEXER    = 0xb4000000
INDEX_MASK = 0xFF000000
FNDX_MASK  = 0x00FFFFFF

# The OS version
# ==============
OS = None
##################################################################################


#  Utility functions
def to_hex(n):    
    """
    Converts a numeric value to hex (pointer to hex)

    Arguments:
    n - the value to convert

    Return:
    A string, representing the value in hex (8 characters long)
    """
    return "%08x" % n

def bin_to_dec(binary):
    """Converts a binary list to decimal number"""
    dec = 0
    binary_list = []
    for b in binary:
        binary_list.append(int(b))
    #reverse list:
    rev_bin = []
    for item in binary_list:
        rev_bin.insert(0,item)
    #calculate decimal
    for index in xrange(len(binary_list)):
        dec += rev_bin[index] * 2**index
    return dec

def to_hex_byte(n):
    """
    Converts a numeric value to a hex byte

    Arguments:
    n - the value to convert (max 255)

    Return:
    A string, representing the value in hex (1 byte)
    """
    return "%02x" % n

def chr_to_dword(n):
    """
    Converts a character variable to hex value

    Arguments:
    n - the value to convert

    Return:
    A string, representing the value in hex (8 characters long)
    """
    if len(n) == 4:
        myvalue = []
        for x in n:
            myvalue.append(hex(ord(x))[2:])
    else:
        return "(-) Value too big!"
    return "0x%s" % ("".join(myvalue))


def chr_to_pretty_hex(n):
    """
    Converts a character variable to hex value

    Arguments:
    n - the value to convert

    Return:
    A string, representing the value in hex (8 characters long)
    """
    myvalue = []
    for x in n:
        tempval = hex(ord(x)).replace("0x", "\\x")
        if len(tempval) <= 3:
            if tempval[2:3] != "0":
                tempval = "\\x" + tempval[2:3] + "0"
            else:
                tempval += "0"
        myvalue.append(tempval)
    return "".join(myvalue)

def chr_to_hex(n):
    """
    Converts a character variable to hex value

    Arguments:
    n - the value to convert

    Return:
    A string, representing the value in hex (8 characters long)
    """
    myvalue = []
    for x in n:
        tempval = hex(ord(x))[2:]
        if len(tempval) <= 1:
            if tempval != "0":
                tempval = "0" + tempval
            elif tempval == "0":
                tempval += "0"
        myvalue.append(tempval)
    return "".join(myvalue)

# just incase we will need this
def reverse(text):
    return ''.join([text[i] for i in range(len(text)-1,-1,-1)])

# patch the PEB
# thanks to BoB from Team PEiD
def patch_PEB(imm, window):
    peb_struct = imm.getPEB()
    if not peb_struct.BeingDebugged and not peb_struct.NtGlobalFlag:
        window.Log("(!) This process has already been patched!")
        window.Log("------------------------------------------")
        return False
    PEB = imm.getPEBAddress()
    # Just incase .. ;)
    if PEB == 0:
        window.Log("(-) No PEB to patch .. !?" )
        return

    window.Log("(+) Patching PEB.IsDebugged ..", address = PEB + 0x02 )
    imm.writeMemory(PEB + 0x02, imm.assemble( "db 0" ) )

    a = imm.readLong(PEB + 0x18)
    a += 0x10
    window.Log("(+) Patching PEB.ProcessHeap.Flag ..", address = a )
    imm.writeLong( a, 0 )

    window.Log("(+) Patching PEB.NtGlobalFlag ..", address = PEB + 0x68 )
    imm.writeLong(PEB + 0x68, 0)

    # Patch PEB_LDR_DATA 0xFEEEFEEE fill bytes ..  (about 3000 of them ..)
    a = imm.readLong(PEB + 0x0C)
    window.Log("(+) Patching PEB.LDR_DATA filling ..", address = a)
    while a != 0:
        a += 1
        try:
            b = imm.readLong(a)
            c = imm.readLong(a + 4)
            # Only patch the filling runs ..
            if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
                imm.writeLong(a, 0)
                imm.writeLong(a + 4, 0)
                a += 7
        except:
            break
    window.Log("----------------------------------------")
    return True
        

def githash(data):
    s = sha1()
    s.update("blob %u\0" % len(data))
    s.update(data)
    return s.hexdigest()

class set_command:
    """
    Class to call commands, show usage and parse arguments
    """
    def __init__(self, name, description, usage, parseProc, alias=""):
        self.name = name
        self.description = description
        self.usage = usage
        self.parseProc = parseProc
        self.alias = alias

# RtlFreeHeap Hook class
class function_hook(LogBpHook):
    """
    Class to get the particular functions arguments for a debug instance
    Return 
    """
    def __init__(self, window, function_name, heap=False):
        LogBpHook.__init__(self)
        self.window = window
        self.fname = function_name
        self.heap = heap
        self.rheap = None
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        
        # get the return address of the hooked function
        offset = 0x0
        if self.fname == "VirtualAllocEx":
            offset = 0x1c
        elif self.fname == "VirtualFreeEx":
            offset = 0x18
        elif self.fname == "RtlDestroyHeap" or self.fname == "RtlInitializeCriticalSection":
            offset = 0x0c
            
        ret = imm.readMemory( regs['ESP']+offset, 0x4)
        ret = struct.unpack("L", ret)
        
        # find the module with the ret address
        module_list = imm.getAllModules()
        for mod in module_list.iterkeys():
            find = False
            # make sure we cycle through the IAT (import database)
            for addy in range(module_list[mod].getCodebase(),module_list[mod].getIdatabase()):
                if int(ret[0]) == addy:
                    find = True
                    break
            if find: 
                break

        if self.fname == "RtlFreeHeap":
            res=imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("(-) RtlFreeHeap: the stack seems to broken, unable to get args")
                return 0x0
            (self.rheap, flags, size) = struct.unpack("LLL", res)
            if self.heap:
                if self.heap == self.rheap:
                    rheap = True
                    self.window.Log("(+) RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)" % (self.rheap, flags, size))
            else:
                self.window.Log("(+) RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)" % (self.rheap, flags, size))
            
        elif self.fname == "RtlAllocateHeap":
            res=imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("RtlAllocateHeap: ESP seems to broken, unable to get args")
                return 0x0
            (self.rheap, flags, size) = struct.unpack("LLL", res)
            if self.heap:
                if self.heap == self.rheap:
                    rheap = True
                    self.window.Log("(+) RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x)" % (self.rheap, flags, size))
            else:
                self.window.Log("(+) RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x)" % (self.rheap, flags, size))
            
        elif self.fname == "RtlCreateHeap":
            res=imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("(-) RtlCreateHeap: the stack seems to broken, unable to get args")
                return 0x0
            (flags, InitialSize, MaximumSize) = struct.unpack("LLL", res)
            self.window.Log("(+) RtlCreateHeap(0x%08x, 0x%08x, 0x%08x)" % (flags, InitialSize, MaximumSize)) 
            
        elif self.fname == "RtlDestroyHeap":
            res=imm.readMemory( regs['ESP'] + 4, 0x4)
            if len(res) != 0x4:
                self.window.Log("(-) RtlDestroyHeap: the stack seems to broken, unable to get args")
                return 0x0
            (heap) = struct.unpack("L", res)
            self.window.Log("(+) RtlDestroyHeap(0x%08x)" % (heap))
            
        elif self.fname == "RtlReAllocateHeap":    
            res=imm.readMemory( regs['ESP'] + 4, 0x10)
            if len(res) != 0x10:
                self.window.Log("(-) RtlReAllocateHeap: the stack seems to broken, unable to get args")
                return 0x0
            (heap, dwFlags, lpMem, dwBytes) = struct.unpack("LLLL", res)
            self.window.Log("(+) RtlReAllocateHeap(0x%08x, 0x%08x, 0x%08x, 0x%08x)" % (heap, dwFlags, lpMem, dwBytes)) 
                             
        elif self.fname == "RtlSizeHeap": 
            res=imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("(-) RtlSizeHeap: the stack seems to broken, unable to get args")
                return 0x0
            (heap, dwFlags, lpMem) = struct.unpack("LLL", res)
            self.window.Log("(+) RtlSizeHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, dwFlags, lpMem))
            
        elif self.fname == "RtlInitializeCriticalSection" or self.fname == "RtlDeleteCriticalSection":
            res=imm.readMemory( regs['ESP'] + 4, 0x4)
            if len(res) != 0x4:
                self.window.Log("(-) %s: the stack seems to broken, unable to get args" % self.fname)
                return 0x0
            (cs) = struct.unpack("L", res)
            self.window.Log("(+) %s(0x%08x)" % (self.fname,cs[0]))
            
        elif self.fname == "SetUnhandledExceptionFilter":
            res=imm.readMemory( regs['ESP'] + 4, 0x4)
            if len(res) != 0x4:
                self.window.Log("(-) SetUnhandledExceptionFilter: the stack seems to broken, unable to get args")
                return 0x0
            (pTopLevelFilter) = struct.unpack("L", res)
            self.window.Log("(+) SetUnhandledExceptionFilter(0x%08x)" % (pTopLevelFilter))
            
        elif self.fname == "VirtualAllocEx":
            res=imm.readMemory( regs['ESP'] + 0x8, 0x10)
            if len(res) != 0x10:
                self.window.Log("(-) VirtualAllocEx: the stack seems to broken, unable to get args")
                return 0x0
            (address, size, AllocationType, Protect) = struct.unpack("LLLL", res)
            self.window.Log("(+) VirtualAllocEx(0x%08x, 0x%08x, 0x%08x, 0x%08x)" % (address, size, AllocationType, Protect))
            
        elif self.fname == "VirtualFreeEx":
            res=imm.readMemory( regs['ESP'] + 0x8, 0x0c)
            if len(res) != 0x0c:
                self.window.Log("(-) VirtualFreeEx: the stack seems to broken, unable to get args")
                return 0x0
            (lpAddress, dwSize, dwFreeType) = struct.unpack("LLL", res)
            self.window.Log("(+) VirtualFreeEx(0x%08x, 0x%08x, 0x%08x)" % (lpAddress, dwSize, dwFreeType))
        
        if find:
            self.window.Log("(+) Called from 0x%08x - module: %s" % (ret[0],module_list[mod].getPath()),ret[0])
        elif not find:
            self.window.Log("(+) Called from 0x%08x - from an unknown module" % (ret[0]),ret[0])

    def is_heap_alloc_free_matching(self):
        return self.heap == self.rheap
            
class function_hook_return(LogBpHook):
    def __init__(self, window, function_name, heap=False):
        LogBpHook.__init__(self)
        self.window = window
        self.fname = function_name
        self.heap = heap
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        return_value = regs['EAX']
        self.window.Log("(+) %s() heapbase returned: 0x%08x" % (self.fname, return_value),return_value)
        border_len = len("(+) %s() heapbase returned: 0x%08x" % (self.fname, return_value))
        self.window.Log("=" * border_len)

class function_hook_seed(LogBpHook):
    def __init__(self, window, function_name, heap=False):
        LogBpHook.__init__(self)
        self.window = window
        self.fname = function_name
        self.heap = heap
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        # our flag is set for each call
        return_value = regs['EAX']
        self.window.Log("(+) %s() returned random seed value: 0x%08x" % (self.fname, return_value),return_value)
        self.window.Log("(!) To calculate the real heapbase, do: heapbase - random seed = x")
        

# Access Violation Hook class
# thanks to the immunity team
class FunctionTriggeredHook(AccessViolationHook):
    def __init__( self, fn_ptr, window):
        AccessViolationHook.__init__( self )
        self.fn_ptr = fn_ptr
        self.window = window

    # found the access violation we force by patching every function pointer. 
    def run(self, regs):
        imm  = immlib.Debugger()
        
        eip  = regs['EIP']
        # Checking if we are on the correct Access Violation
        if ( eip & INDEX_MASK ) != INDEXER:
            return ""
        fndx = eip & FNDX_MASK
        if fndx >= len( self.fn_ptr ) :
            return ""
        
        obj  = self.fn_ptr[ fndx ] # it shouldn't be out of index
        
        # Print info and Unhook
        self.window.Log("Found a pointer at 0x%08x that triggers: " % obj.address,  address = obj.address, focus =1 )
        self.window.Log("   %s: %s" % ( obj.name, obj.Print() ), address = obj.address)

        imm.setReg("EIP", int(obj.data) )
        imm.run()
        
# HeapHook_vals, HeapHook_ret,         
def hook_on(imm, LABEL, bp_address, function_name, bp_retaddress, Disable, window, heap=False, seed_address=False):
    """
    This function creates the hooks and adds/deletes them to the Debugger object depending on
    if they exist in immunities knowledge database
    
    @type  imm: Debugger Object
    @param imm: initialized debugger object 
    
    @type  LABEL: String
    @param LABEL: Hook label, depending on the operation
    
    @type  bp_address: long
    @param bp_address: The break point function entry address
    
    @type  function_name: String
    @param function_name: The function name to hook 
    
 
    """
    if not heap:
        heap = 0x00000000
        
    hook_values = imm.getKnowledge( LABEL + "%x_values" % heap)
    hook_ret_address = imm.getKnowledge( LABEL + "%x_ret" % heap)
    #if OS >= 6.0:
    if OS >= 6.0:
        hook_seed = imm.getKnowledge( LABEL + "%x_seed" % heap)
        
    if Disable:
        if not hook_values:
            window.Log("(-) Error %s, no hook to disable for the API" % (LABEL))
            #return "No hook to disable on"
        if not hook_ret_address:
            window.Log("(-) Error %s, no hook to disable for the return address!" % (LABEL))
            # if its debugged under windows xp, return from here
            #if imm.getOsVersion() != "7":
            if OS >= 6.0:
                return "No hook to disable on"
        #if OS >= 6.0 and not hook_seed:
        if OS >= 6.0 and not hook_seed:
            window.Log("(-) Error %s, no hook to disable for the random seed value!" % (LABEL))
            return "No hook to disable on"            
        
        elif hook_values or hook_ret_address or hook_seed:
            hook_values.UnHook()
            hook_ret_address.UnHook()
            window.Log("(+) Unhooked %s" % LABEL)
            imm.forgetKnowledge( LABEL + "%x_values" % heap)
            imm.forgetKnowledge( LABEL + "%x_ret" % heap)
            if OS >= 6.0 and hook_seed:
                imm.forgetKnowledge( LABEL + "%x_seed" % heap)
            return "Unhooked"
    # else we are not disabling...
    elif not Disable:
        if not hook_values:
            if heap != 0:
                hook_values= function_hook( window, function_name, heap)
            else:
                hook_values= function_hook( window, function_name)
            
            hook_values.add( LABEL + "%x_values" % heap, bp_address)
            window.Log("(+) Placed %s to retrieve the variables" % LABEL)
            imm.addKnowledge( LABEL + "%x_values" % heap, hook_values)
        elif hook_values:
            if heap != 0:
                window.Log("(!) %s for heap 0x%08x was ran previously, re-hooking" % (LABEL,heap))
                hook_values= function_hook( window, function_name, heap)
            else:
                window.Log("(!) %s was ran previously, re-hooking" % (LABEL))
                hook_values= function_hook( window, function_name)
            hook_values.add( LABEL + "%x_values" % heap, bp_address)
        
        if OS >= 6.0 and not hook_seed:
            if heap != 0:
                hook_seed = function_hook_seed( window, function_name, heap)
            else:
                hook_seed = function_hook_seed( window, function_name)
                
            hook_seed.add( LABEL + "%x_seed" % heap, seed_address)
            window.Log("(+) Placed %s to retrieve the seed value" % LABEL)
            imm.addKnowledge( LABEL + "%x_seed" % heap, hook_seed)
            
        elif OS >= 6.0 and hook_seed:
            if heap != 0:
                window.Log("(!) %s for the seed value on heap 0x%08x was ran previously, re-hooking" % (LABEL,heap))
                hook_seed = function_hook_seed( window, function_name, heap)
            else:
                window.Log("(!) %s for the seed value was ran previously, re-hooking" % (LABEL))
                hook_seed = function_hook_seed( window, function_name)
            hook_seed.add( LABEL + "%x_seed" % heap, seed_address)
        if not hook_ret_address:
            if heap != 0:
                hook_ret_address = function_hook_return( window, function_name, heap)
            else:
                hook_ret_address = function_hook_return( window, function_name)
            hook_ret_address.add( LABEL + "%x_ret" % heap, bp_retaddress)
            
            window.Log("(+) Placed %s to retrieve the return value" % LABEL)
            imm.addKnowledge( LABEL + "%x_ret" % heap, hook_ret_address )            
        else:
            if heap != 0:
                window.Log("(!) %s for the return address on heap 0x%08x was ran previously, re-hooking" % (LABEL,heap))
                hook_ret_address= function_hook_return( window, function_name, heap)
            elif heap == 0:
                window.Log("(!) %s for the return address was ran previously, re-hooking" % (LABEL))
                hook_ret_address= function_hook_return( window, function_name)
            hook_ret_address.add( LABEL + "%x_ret" % heap, bp_retaddress)
        return "Hooked"

# banner
# ======

def banner(win):
    win.Log("----------------------------------------") 
    win.Log("    __                         ")
    win.Log("   / /  ___ ___ ____  ___ ____ ")
    win.Log("  / _ \/ -_) _ `/ _ \/ -_) __/ ")
    win.Log(" /_//_/\__/\_,_/ .__/\__/_/    ")
    win.Log("              /_/              ")
    win.Log("----------------------------------------")
    win.Log("by mr_me :: steventhomasseeley@gmail.com")

# usage
# =====
def usage(window, imm):
    window.Log("")
    window.Log("****   available commands   ****")
    window.Log("")
    window.Log("dumppeb / dp                          : Dump the PEB pointers")
    window.Log("dumpteb / dt                          : Dump the TEB pointers")
    window.Log("dumpheaps / dh                        : Dump the heaps")
    window.Log("dumpfunctionpointers / dfp            : Dump all the processes function pointers")
    window.Log("analyseheap <heap> / ah <heap>        : Analyse a particular heap")
    window.Log("analysefrontend <heap> / af <heap>    : Analyse a particular heap's frontend data structure")
    window.Log("analysebackend <heap> / ab <heap>     : Analyse a particular heap's backend data structure")
    window.Log("analysesegments <heap> / as <heap>    : Analyse a particular heap's segments")
    window.Log("analysechunks <heap> / ac <heap>      : Analyse a particular heap's chunks")
    window.Log("analyseheapcache <heap> / ahc <heap>  : Analyse a particular heap's cache (FreeList[0])")
    window.Log("freelistinuse <heap> / fliu <heap>    : Analyse/patch the FreeListInUse structure")
    window.Log("hook <heap> / h -h <func>             : Hook various functions that create/destroy/manipulate a heap")
    window.Log("patch <function/data structure> / p   : Patch a function or datastructure")
    window.Log("update / u                            : Update to the latest version")
    window.Log("exploit <heap> / exp <heap>           : Perform heuristics against the FrontEnd and BackEnd allocators")
    window.Log("                                        to determine exploitable conditions")
    window.Log("")
    window.Log("Want more info about a given command? Run !heaper help <command>")
    window.Log("Detected the operating system to be windows %s, keep this in mind." % (imm.getOsVersion()))
    window.Log("")
    return "eg: !heaper al 00480000"

# runtime detection of avaliable functions
def get_extended_usage():
    extusage = {}
    extusage["freelistinuse"] = "\nfreelistinuse <heap> / fliu <heap> : analyse/patch the FreeListInUse structure\n"
    extusage["freelistinuse"] += "---------------------------------------------\n"
    extusage["freelistinuse"] += "Use -p <byte entry> to patch the FreeListInUse entry and set its bit\n"
    extusage["freelistinuse"] += "eg !heaper 0x00a80000 -p 0x7c\n"
    extusage["dumppeb"] = "\ndumppeb / dp : Return the PEB entry address\n"
    extusage["dumppeb"] += "---------------------------------------------\n"
    extusage["dumppeb"] += "Use -m to view the PEB management structure\n"
    extusage["hook"] = "\nhook <heap> / h : Hook various functions that create/destroy/manipulate a heap\n"
    extusage["hook"] += "------------------------------------------------------------------------------\n"
    extusage["hook"] += "Use -h to hook any function.\n"
    extusage["hook"] += "Use -u to unhook any function.\n"
    extusage["hook"] += "Available functions to hook are: \n"
    extusage["hook"] += "- RtlAllocateHeap()              [alloc]\n"
    extusage["hook"] += "- RtlFreeHeap()                  [free]\n"
    extusage["hook"] += "- RtlCreateHeap()                [create]\n"
    extusage["hook"] += "- RtlDestroyHeap()               [destroy]\n"
    extusage["hook"] += "- RtlReAllocateHeap()            [realloc]\n"
    extusage["hook"] += "- RtlSizeHeap()                  [size]\n"
    extusage["hook"] += "- RtlInitializeCriticalSection() [createcs]\n"
    extusage["hook"] += "- RtlDeleteCriticalSection()     [deletecs]\n"
    extusage["hook"] += "- SetUnhandledExceptionFilter()  [setuef]\n"
    extusage["hook"] += "- VirtualAllocEx()               [va]\n"
    extusage["hook"] += "- VirtualFreeEx()                [vf]\n"    
    extusage["hook"] += "- Hook all!                      [all]\n"
    extusage["hook"] += "Examples:\n"
    extusage["hook"] += "~~~~~~~~~\n"
    extusage["hook"] += "Hook RtlReAllocateHeap() on heap 0x00150000 '!heaper hook 0x00150000 -h realloc'\n"
    extusage["hook"] += "Hook all heap functions '!heaper hook -u all'\n"
    extusage["hook"] += "Hook RtlCreateHeap() '!heaper hook -h create'\n"
    extusage["dumpteb"] = "\ndumpteb / dt : List all of the TEB entry addresses\n"
    extusage["dumpteb"] += "--------------------------------------------------------\n"
    extusage["dumpheaps"] = "\ndumpheaps / dh : Dump all the heaps for a given process\n"
    extusage["dumpheaps"] += "-------------------------------------------------------\n"
    extusage["analyseheap"] = "\nanalyseheap <heap> / ah <heap> : Analyse a particular heap\n"
    extusage["analyseheap"] += "----------------------------------------------------------\n"
    extusage["analysesegments"] = "\nanalysesegments <heap> / as <heap> : Analyse a particular heap's segment stucture(s)\n"
    extusage["analysesegments"] += "------------------------------------------------------------------------------------\n"   
    extusage["analysesegments"] += "Use -g to view a graphical representation of the heap structure\n"
    extusage["analysefrontend"] = "\nanalysefrontend <heap> / af <heap> : Analyse a particular heap's frontend free structure\n"
    extusage["analysefrontend"] += "----------------------------------------------------------------------------------------\n"   
    
    if OS >= 6.0:
        extusage["analysefrontend"] += "Use -u to dump the UserBlocks that are activated in the LFH\n"
        extusage["analysefrontend"] += "Use -s to specify a sized bin to dump\n"
        extusage["analysefrontend"] += "Use -c to dump the UserBlockCache structure\n"
        extusage["analysefrontend"] += "Use -b to dump the buckets in the LFH\n"
        extusage["analysefrontend"] += "Use -g to view a graphical representation of the UserBlocks in the LFH\n"
        extusage["analysefrontend"] += "Use -o to specify a filename for the graph\n"
        extusage["analysefrontend"] += "Examples:\n"
        extusage["analysefrontend"] += "~~~~~~~~~\n"
        extusage["analysefrontend"] += "Dump the UserBlocks '!heaper af 0x00260000 -u'\n"
        extusage["analysefrontend"] += "Dump the UserBlocks for size 0x40 '!heaper af 0x00260000 -u -s 0x40'\n"
        extusage["analysefrontend"] += "Dump the UserBlockCache '!heaper af 0x00260000 -c'\n"
        extusage["analysefrontend"] += "Dump the buckets '!heaper af 0x00260000 -b'\n"
        extusage["analysefrontend"] += "Dump the UserBlocks and graph it '!heaper af 0x00260000 -u -g -o UserBlocks-example'\n"
    elif OS < 6.0:
        extusage["analysefrontend"] += "Use -l to dump the Lookaside Lists\n"
        extusage["analysefrontend"] += "Use -g to view a graphical representation of the Lookaside Lists\n"
        extusage["analysefrontend"] += "Use -o to specify a filename for the graph\n"
        extusage["analysefrontend"] += "Examples:\n"
        extusage["analysefrontend"] += "~~~~~~~~~\n"
        extusage["analysefrontend"] += "Dump the Lookaside Lists '!heaper af 0x00260000 -l'\n"
        extusage["analysefrontend"] += "Dump the Lookaside Lists and graph it '!heaper af 0x00260000 -l -g -o lookaside'\n"
        
    extusage["analysebackend"] = "\nanalysebackend <heap> / ab <heap> : Analyse a particular heap's backend free structure\n"
    extusage["analysebackend"] += "------------------------------------------------------------------------------------\n" 
    
    if OS >= 6.0:
        extusage["analysebackend"] += "Use -l to view the ListHints\n"
        extusage["analysebackend"] += "Use -f to view the FreeList chunks\n"  
        extusage["analysebackend"] += "Use -g to view a graphical representation of the ListHint/FreeList\n"
    elif OS < 6.0:
        extusage["analysebackend"] += "Use -h to view the HeapCache (if its activated)\n"
        extusage["analysebackend"] += "Use -f to view the FreeList chunks\n"  
        extusage["analysebackend"] += "Use -g to view a graphical representation of the FreeLists\n"
    extusage["analysebackend"] += "Use -o to specify a filename for the graph\n"        
    
    extusage["analysesegments"] = "\nanalysesegment(s) <heap> / as <heap> : Analyse a particular heap's segment structure(s)\n"
    extusage["analysesegments"] += "------------------------------------------------------------------------------------\n"   
    extusage["patch"] = "\npatch <function/data structures> / p <function/data structures> : patch memory for the heap\n"
    extusage["patch"] += "-------------------------------------------------------------------------------------------\n" 
    extusage["patch"] += "Use 'PEB' to patch the following areas:\n"
    extusage["patch"] += " - PEB.IsDebugged\n"
    extusage["patch"] += " - PEB.ProcessHeap.Flag\n"
    extusage["patch"] += " - PEB.NtGlobalFlag\n"
    extusage["patch"] += " - PEB.LDR_DATA\n"
    extusage["patch"] += "Example: '!heaper patch PEB'\n"
    extusage["analyseheapcache"] = "\nanalyseheapcache <heap> / ahc <heap> : Analyse a particular heap's cache (FreeList[0])\n"
    extusage["analyseheapcache"] += "------------------------------------------------------------------------------------\n"   
    extusage["analysechunks"] = "\nanalysechunks <heap> / ac <heap> : Analyse a particular heap's chunks\n"
    extusage["analysechunks"] += "---------------------------------------------------------------------\n"
    extusage["analysechunks"] += "Use -r <start address> <end address> to view all the chunks between those ranges\n"
    extusage["analysechunks"] += "Use -f to chunk_filter chunks by type (free/busy) eg: !heaper ac d20000 -f busy\n"
    extusage["analysechunks"] += "Use -v to view the first 16 bytes of each chunk\n"
    extusage["dumpfunctionpointers"] = "\ndumpfunctionpointers / dfp : Dump all the function pointers of the current process\n"
    extusage["dumpfunctionpointers"] += "-----------------------------------------------------------------------------------\n"
    extusage["dumpfunctionpointers"] += "Use -a <address> to specify where to start looking for function pointers\n"
    extusage["dumpfunctionpointers"] += "Use -s <size> to specify the amount of data to search from the address\n"
    extusage["dumpfunctionpointers"] += "Use -p <address/all> to patch a function pointer or all function pointers\n"
    extusage["dumpfunctionpointers"] += "Use -r <address/all> to restore a function pointer or all function pointers\n"
    extusage["dumpfunctionpointers"] += "Use -e <address,address,address> comma seperated list of addresses to exclude from patching/restoring\n"
    extusage["dumpfunctionpointers"] += "Examples:\n"
    extusage["dumpfunctionpointers"] += "~~~~~~~~~\n"
    extusage["dumpfunctionpointers"] += "locate pointers - '!heaper dfp -s 3000 -a 0x00c55000'\n"
    extusage["dumpfunctionpointers"] += "patch pointer - '!heaper dfp -p 0x00c56120'\n"
    extusage["dumpfunctionpointers"] += "patch all pointers - '!heaper dfp -s 2000 -a 6ed86000 -p all -e 6ed86290,6ed86294'\n"
    extusage["dumpfunctionpointers"] += "restore pointer - '!heaper dfp -r 0x00c56120'\n"
    extusage["dumpfunctionpointers"] += "restore all pointers - '!heaper dfp -s 3000 -a 0x00c55000 -r all'\n"
    extusage["exploit"] = "\nexploit / exp : Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions\n"
    extusage["exploit"] += "-----------------------------------------------------------------------------------\n"
    extusage["exploit"] += "Use -f to analyse the FrontEnd allocator\n"
    extusage["exploit"] += "Use -b to analyse the BackEnd allocator\n"
    extusage["exploit"] += "eg: !heaper exploit 00490000 -f\n"
    return extusage
    
def set_up_usage():
    cmds = {}
    cmds["dumppeb"] = set_command("dumppeb", "Dump the PEB pointers",get_extended_usage()["dumppeb"], "dp")
    cmds["dp"] = set_command("dumppeb", "Dump the PEB pointers",get_extended_usage()["dumppeb"], "dp")
    cmds["dumpteb"] = set_command("dumpteb", "Dump the TEB pointers",get_extended_usage()["dumpteb"], "dt")
    cmds["dt"] = set_command("dumpteb", "Dump the TEB pointers",get_extended_usage()["dumpteb"], "dt")
    cmds["dumpheaps"] = set_command("dumpheaps", "Dump all the heaps of a process",get_extended_usage()["dumpheaps"], "dh")
    cmds["dh"] = set_command("dumpheaps", "Dump all the heaps of a process",get_extended_usage()["dumpheaps"], "dh")
    cmds["dumpfunctionpointers"] = set_command("dumpfunctionpointers", "Dump all the function pointers of the current process",get_extended_usage()["dumpfunctionpointers"], "dfp")
    cmds["dfp"] = set_command("dumpfunctionpointers", "Dump all the function pointers of the current process",get_extended_usage()["dumpfunctionpointers"], "dfp")
    cmds["analyseheap"] = set_command("analyseheap", "analyse a particular heap",get_extended_usage()["analyseheap"], "ah")
    cmds["ah"] = set_command("analyseheap", "analyse a particular heap",get_extended_usage()["analyseheap"], "ah")
    cmds["analysefrontend"] = set_command("analysefrontend", "analyse a particular heap's frontend",get_extended_usage()["analysefrontend"], "af")
    cmds["af"] = set_command("analyselal", "analyse a particular heap's lookaside list",get_extended_usage()["analysefrontend"], "af")
    cmds["analysebackend"] = set_command("analysebackend", "analyse a particular heap's backend",get_extended_usage()["analysebackend"], "ab")
    cmds["ab"] = set_command("analysefreelist", "analyse a particular heap's freelist",get_extended_usage()["analysebackend"], "ab")
    cmds["analysechunks"] = set_command("analysechunks", "analyse a particular heap's list of chunks",get_extended_usage()["analysechunks"], "ac")
    cmds["ac"] = set_command("analysechunks", "analyse a particular heap's list of chunks",get_extended_usage()["analysechunks"], "ac")
    cmds["analysesegments"] = set_command("analysesegments", "analyse a particular heap's segment(s)",get_extended_usage()["analysesegments"], "as")
    cmds["as"] = set_command("analysesegments", "analyse a particular heap's segment(s)",get_extended_usage()["analysesegments"], "as")
    cmds["analyseheapcache"] = set_command("analyseheapcache", "analyse a particular heap's cache (FreeList[0])",get_extended_usage()["analyseheapcache"], "ahc")
    cmds["ahc"] = set_command("analyseheapcache", "analyse a particular heap's cache (FreeList[0])",get_extended_usage()["analyseheapcache"], "ahc")
    cmds["freelistinuse"] = set_command("freelistinuse", "analyse/patch the FreeListInUse structure",get_extended_usage()["freelistinuse"], "fliu")
    cmds["fliu"] = set_command("freelistinuse", "analyse/patch the FreeListInUse structure",get_extended_usage()["freelistinuse"], "fliu")
    cmds["hook"] = set_command("hook", "Hook various functions that create/destroy/manipulate a heap",get_extended_usage()["hook"], "h")
    cmds["h"] = set_command("hook", "Hook various functions that create/destroy/manipulate a heap",get_extended_usage()["hook"], "h")
    
    cmds["patch"] = set_command("patch", "Patch various data structures and functions",get_extended_usage()["patch"], "p")
    cmds["p"] = set_command("patch", "Patch various data structures and functions",get_extended_usage()["patch"], "p")
    
    cmds["exploit"] = set_command("exploit", "Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions",get_extended_usage()["exploit"], "exp")
    cmds["exp"] = set_command("exploit", "Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions",get_extended_usage()["exploit"], "exp")    
    return cmds

# detects exploitable conditions..
def freelist_and_lookaside_heuristics(window, chunk_data, pheap, imm, data_structure, vuln_chunks):

    # check for FreeList
    if data_structure == "freelistn" or data_structure == "freelist0":
        # extract the corrupt data
        corrupt_chunk_data = imm.getKnowledge(chunk_data)
        corrupt_chunk_size = corrupt_chunk_data[0]
        corrupt_chunk_address = corrupt_chunk_data[1]
        corrupt_chunk_blink = corrupt_chunk_data[2]
        corrupt_chunk_flink = corrupt_chunk_data[3]
        entry_offset = corrupt_chunk_data[4]
        # real values
        blink = corrupt_chunk_data[4]
        flink = corrupt_chunk_data[5]
        # ensure that we are dealing with FreeList[0]
        if corrupt_chunk_size == 0:
            # search all the chunks
            for index, chunk in enumerate(pheap.chunks):
                # compare chunk addresses and if the sizes are the same, 
                # i suspect at least a 4 byte overwrite..
                if (corrupt_chunk_address-0x8) == chunk.addr:
                    # if its the last chunk in the freelist[0] we can only check if we modify past
                    # 2 bytes, else we just have to check the 1st byte!
                    # this check can be inhanced further for freelist[n]
                    if ((flink == 1 and pheap.chunks[index-1].size != chunk.psize) 
                        or (flink != 1 and pheap.chunks[index+1].psize != chunk.size
                        and pheap.chunks[index-1].size != chunk.psize)):
                        
                        window.Log("")
                        window.Log("(+) Detected corrupted chunk in FreeList[0x%02x] chunk address 0x%08x" % (corrupt_chunk_size,corrupt_chunk_address-0x8))
                        window.Log("")
                        if flink == 1:
                            window.Log(" -> This chunk is the last entry in FreeList[0]")
                        elif flink != 1:
                            window.Log(" -> This chunk is number %d in FreeList[0]" % index)   
                        # 1st lets check for freelist insert attack vector
                        window.Log("")
                        window.Log(" > Freelist[0] insert attack:")
                        window.Log("    - Free a chunk of size > %d (0x%02x) < %d (0x%02x)" % 
                                   (pheap.chunks[index-1].size, pheap.chunks[index-1].size, pheap.chunks[index].size, pheap.chunks[index].size))
                        # blink checks
                        if corrupt_chunk_blink != blink:
                            window.Log("    - Blink was detected to be overwritten (0x%08x), try setting it to a lookaside[n] entry or a function pointer table" % corrupt_chunk_blink)
                        else:
                            window.Log("    - Try to overwrite the blink for this chunk so you can control what the address that points to the inserted chunk or try another attack")
                    
                        window.Log("")
                        window.Log(" > Freelist[0] search attack:")
                        window.Log("    - Overwrite with a size you can allocate. Current size: %d (0x%02x)" % (pheap.chunks[index].size, pheap.chunks[index].size))
                        # if flink == 0x1, its the last chunk in the list entry
                        if (flink == 0x1 and entry_offset != corrupt_chunk_flink) or (flink != 0x1 and flink != corrupt_chunk_flink):
                            window.Log("    - Flink was detected to be overwritten (0x%08x), try setting it to a fake chunk structure" % corrupt_chunk_flink)
                        else:
                            window.Log("    - Try to overwrite the flink for this chunk so you can point it to a fake chunk or try another attack")
                               
                        window.Log("")
                        window.Log(" > Freelist[0] relinking attack:")
                        window.Log("    - Overwrite with a size you can allocate. Current size: %d (0x%02x)" % (pheap.chunks[index].size, pheap.chunks[index].size))
                        # if flink == 0x1, its the last chunk in the list entry
                        if (flink == 0x1 and corrupt_chunk_address != corrupt_chunk_flink) or (flink != 0x1 and flink != corrupt_chunk_flink):
                            window.Log("    - Flink was detected to be overwritten (0x%08x), try setting it to a fake chunk structure (heapbase+0x057c)." % corrupt_chunk_flink)
                            
                        else:
                            window.Log("    - Try to overwrite the flink for this chunk so you can point it to a fake chunk structure (heapbase+0x057c).")
                        window.Log("    - This will allocate a pointer from the base and may allow you to take control by overwriting the heapbase using the RtlCommitRoutine")
                        # information for the user..
                        vuln_chunks += 1
                        
                    # Validate the HeapCache
                    # ====================== 
                    if pheap.HeapCache:
                        bit_list, chunk_dict = get_heapCache_bitmap(pheap, True)                   
                        if chunk.size in range (0x80, 0x400):
                            if bit_list[chunk.size] != 1:
                                window.Log("(+) Detected corrupted chunk in HeapCache bitmap[0x%04x] chunk address 0x%08x" % (chunk_dict[corrupt_chunk_address-0x8],corrupt_chunk_address-0x8),corrupt_chunk_address-0x8)
                                window.Log("")
                                # last chunk so we can get the size by 
                                if flink == 1:
                                    window.Log(" -> This chunk is the last entry in FreeList[0]")
                                elif flink != 1:
                                    window.Log(" -> This chunk is number %d in FreeList[0]" % index)
                                window.Log("")
                                window.Log(" > HeapCache de-synchronization attack:") 
                                if chunk.size > chunk_dict[corrupt_chunk_address-0x8]:
                                    window.Log("    - Size has been overwritten with a larger value! %d (0x%04x) try to overwrite the chunk with a size < %d (0x%04x)" % (chunk.size, chunk.size, chunk_dict[corrupt_chunk_address-0x8],chunk_dict[corrupt_chunk_address-0x8]))
                                elif chunk.size < chunk_dict[corrupt_chunk_address-0x8]:
                                    window.Log("    - Excellant! Size has been overwritten with a smaller value!  ")                       
                                # if the bitmask before our corrupted size is set, were fucked.
                                if bit_list[chunk_dict[corrupt_chunk_address-0x8]-0x1] == 1:
                                    window.Log("(-) HeapCache de-synchronization size attack will not work because there are no avalaible ")
                                    window.Log("    chunk sizes between the last set bucket entry and this chunks bucket entry!")
                                    window.Log("")
                                    window.Log("    -> bitmap[0x%04x] MUST be 0" % (chunk_dict[corrupt_chunk_address-0x8]-0x1))
                                
                                # else, we have a chance to exploit it...
                                else:
                                    window.Log("    - Allocate a chunk of size %d (0x%02x) or overwrite another size" % ((chunk.size-0x1 * 0x8), chunk.size))
                                    
                                    for size in range (chunk_dict[corrupt_chunk_address-0x8]-0x1, 0x7f, -1):
                                        if bit_list[size] == 1:
                                            break
                                    if size+0x1 < chunk_dict[corrupt_chunk_address-0x8]:
                                        window.Log("    -> Available chunk sizes to overwrite with:")
                                        window.Log("")
                                        for ow_size in range(size+0x1, chunk_dict[corrupt_chunk_address-0x8]):
                                            window.Log("        HEAP_CACHE[0x%04x]" % ow_size)                               
                                
                                vuln_chunks += 1
                        # else its overwritten with a value outside of FreeList[0] possible values
                        elif chunk.size not in range (0x80, 0x400):
                            window.Log("")
                            window.Log("(+) Detected corrupted chunk in HeapCache bitmap[0x%04x] chunk address 0x%08x" % (chunk_dict[corrupt_chunk_address-0x8],corrupt_chunk_address-0x8),corrupt_chunk_address-0x8)
                            window.Log("")
                            if flink == 1:
                                window.Log(" -> This chunk is the last entry in FreeList[0]")
                            elif flink != 1:
                                window.Log(" -> This chunk is number %d in FreeList[0]" % index)                 
                            window.Log("")
                            window.Log("(!) This chunk was overwritten with a size value (0x%04x) that is outside of the range of FreeList[0]" % chunk.size)
        
        elif corrupt_chunk_size != 0:
            for index, chunk in enumerate(pheap.chunks):
                if (corrupt_chunk_address-0x8) == chunk.addr:
                    # check on size only incase of an off by one
                    if (corrupt_chunk_size != chunk.size):

                        vuln_chunks += 1
                        window.Log("(!) Detected FreeList[0x%x] chunk (0x%08x) overwrite!" % (corrupt_chunk_size,chunk.addr), chunk.addr)
                        if chunk.size < 0x80:
                            window.Log("(+) Chunk is set to size 0x%04x so next allocation of size 0x%04x" % (chunk.size,pheap.chunks[index-1].size),chunk.addr)
                            window.Log("    will flip the FreeListInUse[0x%04x] entry" % (chunk.size),chunk.addr)
                        else:
                            window.Log("(+) Chunk is set to size 0x%04x, try setting it < 0x80" % (chunk.size))
                        if ((pheap.chunks[index-1].nextchunk == 0) and (pheap.chunks[index+1].prevchunk == 0)):
                            window.Log("(+) Detected the chunk to be lonely!",chunk.addr)
                        else:
                            window.Log("(-) This chunk is not lonely :( try overwriting blink and flink")                        
                        
        # remove the obj for next run
        imm.forgetKnowledge(chunk_data)
        return vuln_chunks

    elif data_structure == "lookaside":
        if pheap.Lookaside:
            for ndx in range(0, len(pheap.Lookaside)):
                entry = pheap.Lookaside[ndx]   
                        
                if not entry.isEmpty():
                    #window.Log("Lookaside[0x%03x] No. of chunks: %d, ListEntry: 0x%08x, Size: (%d+8=%d)" % 
                    #(ndx, entry.Depth, entry.addr, (ndx*8), (ndx*8+8)), address = entry.addr) 
                    no_chunk = 0              
                    for a in entry.getList():
                        no_chunk += 1 
                        chunk_size = ""
                        try:
                            # size
                            chunk_size = imm.readMemory(a, 0x2)
                            chunk_size = struct.unpack("H", chunk_size)[0]
                            # flink
                            chunk_flink = imm.readMemory(a+0x8, 0x4)
                            chunk_flink = struct.unpack("L", chunk_flink)[0]
                        except:
                            window.Log("(-) Cannot read chunk address: 0x%08x" % a)
                            pass
                        lookaside_chunk_list = entry.getList()
                        try:
                            next_chunk = lookaside_chunk_list[lookaside_chunk_list.index(a)+1]
                        except:
                            next_chunk = 0
                            
                        try:
                            prev_chunk = lookaside_chunk_list[lookaside_chunk_list.index(a)-1]
                        except:
                            prev_chunk = 0
                        # first lets check the size
                        if chunk_size != ndx and (next_chunk == 0 or next_chunk == (chunk_flink-0x8)):
                            vuln_chunks += 1 
                            window.Log("")    
                            window.Log("(!) Size has not been set for chunk 0x%08x, possibly because it doesnt exist" % a)
                            window.Log("(+) This is likley the previous chunks flink! (0x%08x)" % prev_chunk, prev_chunk)
                            alloc_size = (ndx-0x01)*0x8
                            window.Log("(+) Try to set the address to a controlled pointer and make %d allocations using size %d (0x%04x)" % (no_chunk,alloc_size,alloc_size))
                            window.Log("(!) This will set the allocation pointer to the function pointer and allow you to overwrite its value.. ")
                            window.Log("")
                        # overwrite the size, but not the flink..    
                        elif chunk_size != ndx and (next_chunk != (chunk_flink-0x8) or next_chunk != 0):
                            vuln_chunks += 1
                            window.Log("")
                            window.Log("(!) Size has been overwritten for chunk 0x%08x" % a)
                            window.Log("(+) Try to overwrite the flink for this chunk")                            
                            window.Log("")
             
        # remove the obj for next run
        imm.forgetKnowledge(chunk_data)
        return vuln_chunks
    
def dump_heap(imm, window):
    window.Log("Listing available heaps: ")
    window.Log("")
    for hndx in imm.getHeapsAddress():
        window.Log("Heap: 0x%08x" % hndx, address = hndx, focus = 1)
    window.Log("----------------")
    return "(+) Dumped all heaps for the debugged process"      
        
        
def dump_peb(imm, window, dump_management=False):
    """
    dump the PEB structure using mostly immunities API
    
    arguments:
    - obj imm
    - obj window
    - boolean dump_management flag
    
    return:
    - PEB structure if flag is set
    - The PEB address if flag is NOT set
    """
    peb = imm.getPEBAddress()
    window.Log("")
    
    if dump_management:
        peb_struct = imm.getPEB()
        # some PEB members are not in immlib API
        AtlThunkSListPtr32 = imm.readMemory(peb+0x34, 4)
        (AtlThunkSListPtr32) = struct.unpack("L", AtlThunkSListPtr32)[0]
        
        # only need em if we are running win7's PEB structure
        if OS >= 6.0:
            AtlThunkSListPtr = imm.readMemory(peb+0x20, 4)
            (AtlThunkSListPtr) = struct.unpack("L", AtlThunkSListPtr)[0]
            IFEOKey = imm.readMemory(peb+0x24, 4)
            (IFEOKey) = struct.unpack("L", IFEOKey)[0]
            ApiSetMap = imm.readMemory(peb+0x38, 4)
            (ApiSetMap) = struct.unpack("L", ApiSetMap)[0]  
            FlsBitmapBits = imm.readMemory(peb+0x21c, 8)
            (FlsBitmapBits) = struct.unpack("d", FlsBitmapBits)[0]
            FlsBitmapBits2 = imm.readMemory(peb+0x21c+0x8, 8)
            (FlsBitmapBits2) = struct.unpack("d", FlsBitmapBits2)[0]
            FlsBitmap = imm.readMemory(peb+0x218, 4)
            (FlsBitmap) = struct.unpack("L", FlsBitmap)[0] 
            FlsListHead = imm.readMemory(peb+0x210, 4)
            (FlsListHead) = struct.unpack("L", FlsListHead)[0] 
            FlsCallback = imm.readMemory(peb+0x20c, 4)
            (FlsCallback) = struct.unpack("L", FlsCallback)[0]
            FlsHighIndex = imm.readMemory(peb+0x22c, 4)
            (FlsHighIndex) = struct.unpack("L", FlsHighIndex)[0]  
            WerRegistrationData = imm.readMemory(peb+0x230, 4)
            (WerRegistrationData) = struct.unpack("L", WerRegistrationData)[0]             
            WerShipAssertPtr = imm.readMemory(peb+0x234, 4)
            (WerShipAssertPtr) = struct.unpack("L", WerShipAssertPtr)[0]    
            pContextData = imm.readMemory(peb+0x238, 4)
            (pContextData) = struct.unpack("L", pContextData)[0]   
            pImageHeaderHash = imm.readMemory(peb+0x23c, 4)
            (pImageHeaderHash) = struct.unpack("L", pImageHeaderHash)[0]               
            offset_three = imm.readMemory(peb+0x03, 1)
            (offset_three) = struct.unpack("B", offset_three)[0] 
            # get the binary 0/1 representation
            binary_three = bin(offset_three)[2:].rjust(8, '0')
            CrossProcessFlags = imm.readMemory(peb+0x28, 4)
            (CrossProcessFlags) = struct.unpack("L", CrossProcessFlags)[0]
            # 4 bytes instead of 1 so we expand to 32 bits
            binary_twenty_eight = bin(CrossProcessFlags)[2:].rjust(32, '0')
            
        AppCompatFlags = imm.readMemory(peb+0x1d8, 8)
        (AppCompatFlags) = struct.unpack("LL", AppCompatFlags)[0] 
        AppCompatFlagsUser = imm.readMemory(peb+0x1e0, 8)
        (AppCompatFlagsUser) = struct.unpack("LL", AppCompatFlagsUser)[0] 
        pShimData = imm.readMemory(peb+0x1e8, 4)
        (pShimData) = struct.unpack("L", pShimData)[0]
        ActivationContextData = imm.readMemory(peb+0x1f8, 4)
        (ActivationContextData) = struct.unpack("L", ActivationContextData)[0]
        ProcessAssemblyStorageMap = imm.readMemory(peb+0x1fc, 4)
        (ProcessAssemblyStorageMap) = struct.unpack("L", ProcessAssemblyStorageMap)[0]
        SystemDefaultActivationContextData = imm.readMemory(peb+0x200, 4)
        (SystemDefaultActivationContextData) = struct.unpack("L", SystemDefaultActivationContextData)[0]
        SystemAssemblyStorageMap = imm.readMemory(peb+0x204, 4)
        (SystemAssemblyStorageMap) = struct.unpack("L", SystemAssemblyStorageMap)[0]
        MinimumStackCommit = imm.readMemory(peb+0x208, 4)
        (MinimumStackCommit) = struct.unpack("L", MinimumStackCommit)[0]

        window.Log("---------------------------------------------------------")
        window.Log("PEB Management Structure @ 0x%08x" % peb,peb)
        window.Log("---------------------------------------------------------")
        window.Log("+0x000 InheritedAddressSpace                 : 0x%08x" % peb_struct.InheritedAddressSpace, peb_struct.InheritedAddressSpace)
        window.Log("+0x001 ReadImageFileExecOptions              : 0x%08x" % peb_struct.ReadImageFileExecOptions, peb_struct.ReadImageFileExecOptions)
        window.Log("+0x002 BeingDebugged                         : 0x%08x" % peb_struct.BeingDebugged, peb_struct.BeingDebugged) 
        if OS < 6.0:
            window.Log("+0x003 SpareBool                             : 0x%08x" % peb_struct.SpareBool, peb_struct.SpareBool)
        elif OS >= 6.0:
            # according the wingdbg symbols
            window.Log("+0x003 BitField                              : 0x%x" % offset_three,offset_three)
            window.Log("+0x003 ImageUsesLargePages                   : bit: %s" % binary_three[1])
            window.Log("+0x003 IsProtectedProcess                    : bit: %s" % binary_three[2])
            window.Log("+0x003 IsLegacyProcess                       : bit: %s" % binary_three[3])
            window.Log("+0x003 IsImageDynamicallyRelocated           : bit: %s" % binary_three[4])
            window.Log("+0x003 SkipPatchingUser32Forwarders          : bit: %s" % binary_three[5])
            window.Log("+0x003 SpareBits                             : bits 6-8: %s" % binary_three[-3:len(binary_three)])
        window.Log("+0x004 Mutant                                : 0x%08x" % peb_struct.Mutant, peb_struct.Mutant)
        window.Log("+0x008 ImageBaseAddress                      : 0x%08x" % peb_struct.ImageBaseAddress, peb_struct.ImageBaseAddress)
        window.Log("+0x00c Ldr                                   : 0x%08x" % peb_struct.Ldr, peb_struct.Ldr)
        window.Log("+0x010 ProcessParameters                     : 0x%08x" % peb_struct.ProcessParameters, peb_struct.ProcessParameters)
        window.Log("+0x014 SubSystemData                         : 0x%08x" % peb_struct.SubSystemData, peb_struct.SubSystemData)
        window.Log("+0x018 ProcessHeap                           : 0x%08x" % peb_struct.ProcessHeap, peb_struct.ProcessHeap)
        window.Log("+0x01c FastPebLock                           : 0x%08x" % peb_struct.FastPebLock, peb_struct.FastPebLock)
        if OS < 6.0:
            window.Log("+0x020 FastPebLockRoutine                    : 0x%08x" % peb_struct.FastPebLockRoutine, peb_struct.FastPebLockRoutine)
            window.Log("+0x024 FastPebUnLockRoutine                  : 0x%08x" % peb_struct.FastPebUnlockRoutine, peb_struct.FastPebUnlockRoutine)
            window.Log("+0x028 EnvironmentUpdateCount                : 0x%08x" % peb_struct.EnviromentUpdateCount, peb_struct.EnviromentUpdateCount)
        elif OS >= 6.0:
            window.Log("+0x020 AtlThunkSListPtr                      : 0x%08x" % AtlThunkSListPtr,AtlThunkSListPtr)
            window.Log("+0x024 IFEOKey                               : 0x%08x" % IFEOKey, IFEOKey)
            # according the wingdbg symbols
            window.Log("+0x028 CrossProcessFlags                     : 0x%08x" % CrossProcessFlags,CrossProcessFlags)
            window.Log("+0x028 ProcessInJob                          : bit: %s" % binary_twenty_eight[1])
            window.Log("+0x028 ProcessInitializing                   : bit: %s" % binary_twenty_eight[2])
            window.Log("+0x028 ProcessUsingVEH                       : bit: %s" % binary_twenty_eight[3])
            window.Log("+0x028 ProcessUsingVCH                       : bit: %s" % binary_twenty_eight[4])
            window.Log("+0x028 ProcessUsingFTH                       : bit: %s" % binary_twenty_eight[5])
            window.Log("+0x028 ReservedBits0                         : bits 6-32: %s" % binary_twenty_eight[-27:len(binary_twenty_eight)])
        window.Log("+0x02c KernelCallbackTable                   : 0x%08x" % peb_struct.KernelCallbackTable, peb_struct.KernelCallbackTable)
        if OS >= 6.0:
            window.Log("+0x02c UserSharedInfoPtr                     : 0x%08x" % peb_struct.KernelCallbackTable, peb_struct.KernelCallbackTable)
        for sysResv in peb_struct.SystemReserved:
            window.Log("    +0x030 SystemReserved                    : 0x%08x" % sysResv, sysResv) 
        window.Log("+0x034 AtlThunkSListPtr32                    : 0x%08x" % AtlThunkSListPtr32, AtlThunkSListPtr32)
        if OS < 6.0: 
            window.Log("+0x038 FreeList                              : 0x%08x" % peb_struct.FreeList, peb_struct.FreeList)
        elif OS >= 6.0:
            window.Log("+0x038 ApiSetMap                             : 0x%08x" % ApiSetMap, ApiSetMap)
        window.Log("+0x03c TlsExpansionCounter                   : 0x%08x" % peb_struct.TlsExpansionCounter, peb_struct.TlsExpansionCounter)
        window.Log("+0x040 TlsBitmap                             : 0x%08x" % peb_struct.TlsBitmap, peb_struct.TlsBitmap)
        for bits in peb_struct.TlsBitmapBits:
            window.Log("    +0x044 TlsBitmapBits                     : 0x%08x" % bits, bits)
        window.Log("+0x04c ReadOnlySharedMemoryBase              : 0x%08x" % peb_struct.ReadOnlySharedMemoryBase, peb_struct.ReadOnlySharedMemoryBase)
        if OS < 6.0:
            window.Log("+0x050 ReadOnlySharedMemoryHeap              : 0x%08x" % peb_struct.ReadOnlySharedMemoryheap, peb_struct.ReadOnlySharedMemoryheap)
        elif OS >= 6.0:
            # ReadOnlySharedMemoryheap == HotpatchInformation
            window.Log("+0x050 HotpatchInformation                   : 0x%08x" % peb_struct.ReadOnlySharedMemoryheap, peb_struct.ReadOnlySharedMemoryheap)
        window.Log("+0x054 ReadOnlyStaticServerData              : 0x%08x" % peb_struct.ReadOnlyStaticServerData, peb_struct.ReadOnlyStaticServerData)
        window.Log("+0x058 AnsiCodePageData                      : 0x%08x" % peb_struct.AnsiCodePageData, peb_struct.AnsiCodePageData)
        window.Log("+0x05c OemCodePageData                       : 0x%08x" % peb_struct.OemCodePageData, peb_struct.OemCodePageData)
        window.Log("+0x060 UnicodeCaseTableData                  : 0x%08x" % peb_struct.UnicodeCaseTableData, peb_struct.UnicodeCaseTableData)
        window.Log("+0x064 NumberOfProcessors                    : 0x%08x" % peb_struct.NumberOfProcessors, peb_struct.NumberOfProcessors)
        window.Log("+0x068 NtGlobalFlag                          : 0x%08x" % peb_struct.NtGlobalFlag, peb_struct.NtGlobalFlag)
        window.Log("+0x070 CriticalSectionTimeout (high)         : 0x%08x" % peb_struct.CriticalSectionTimeout_HighPart, peb_struct.CriticalSectionTimeout_HighPart)
        window.Log("+0x070 CriticalSectionTimeout (low)          : 0x%08x" % peb_struct.CriticalSectionTimeout_LowPart, peb_struct.CriticalSectionTimeout_LowPart)
        window.Log("+0x078 HeapSegmentReserve                    : 0x%08x" % peb_struct.HeapSegmentReserve, peb_struct.HeapSegmentReserve)
        window.Log("+0x07c HeapSegmentCommit                     : 0x%08x" % peb_struct.HeapSegmentCommit, peb_struct.HeapSegmentCommit)
        window.Log("+0x080 HeapDeCommitTotalFreeThreshold        : 0x%08x" % peb_struct.HeapDeCommitTotalFreeThreshold, peb_struct.HeapDeCommitTotalFreeThreshold)
        window.Log("+0x084 HeapDeCommitFreeBlockThreshold        : 0x%08x" % peb_struct.HeapDeCommitFreeBlockThreshold, peb_struct.HeapDeCommitFreeBlockThreshold)
        window.Log("+0x088 NumberOfHeaps                         : 0x%08x" % peb_struct.NumberOfHeaps, peb_struct.NumberOfHeaps)
        window.Log("+0x08c MaximumNumberOfHeaps                  : 0x%08x" % peb_struct.MaximumNumberOfHeaps, peb_struct.MaximumNumberOfHeaps)
        window.Log("+0x090 ProcessHeaps                          : 0x%08x" % peb_struct.ProcessHeaps, peb_struct.ProcessHeaps)
        window.Log("+0x094 GdiSharedHandleTable                  : 0x%08x" % peb_struct.GdiSharedHandleTable, peb_struct.GdiSharedHandleTable)
        window.Log("+0x098 ProcessStarterHelper                  : 0x%08x" % peb_struct.ProcessStarterHelper, peb_struct.ProcessStarterHelper)
        window.Log("+0x09c GdiDCAttributeList                    : 0x%08x" % peb_struct.GdiDCAttributeList, peb_struct.GdiDCAttributeList)
        window.Log("+0x0a0 LoaderLock                            : 0x%08x" % peb_struct.LoaderLock, peb_struct.LoaderLock)
        window.Log("+0x0a4 OSMajorVersion                        : 0x%08x" % peb_struct.OSMajorVersion, peb_struct.OSMajorVersion) 
        window.Log("+0x0a8 OSMinorVersion                        : 0x%08x" % peb_struct.OSMinorVersion, peb_struct.OSMinorVersion) 
        window.Log("+0x0ac OSBuildNumber                         : 0x%08x" % peb_struct.OSBuildNumber, peb_struct.OSBuildNumber) 
        window.Log("+0x0ae OSCSDVersion                          : 0x%08x" % peb_struct.OSCSDVersion, peb_struct.OSCSDVersion) 
        window.Log("+0x0b0 OSPlatformId                          : 0x%08x" % peb_struct.OSPlatformId, peb_struct.OSPlatformId) 
        window.Log("+0x0b4 ImageSubsystem                        : 0x%08x" % peb_struct.ImageSubsystem, peb_struct.ImageSubsystem) 
        window.Log("+0x0b8 ImageSubsystemMajorVersion            : 0x%08x" % peb_struct.ImageSubsystemMajorVersion, peb_struct.ImageSubsystemMajorVersion) 
        window.Log("+0x0bc ImageSubsystemMinorVersion            : 0x%08x" % peb_struct.ImageSubsystemMinorVersion, peb_struct.ImageSubsystemMinorVersion) 
        if OS < 6.0:
            # ImageProcessAffinityMask == ActiveProcessAffinityMask 
            window.Log("+0x0c0 ImageProcessAffinityMask              : 0x%08x" % peb_struct.ImageProcessAffinityMask, peb_struct.ImageProcessAffinityMask) 
        elif OS >= 6.0:
            window.Log("+0x0c0 ActiveProcessAffinityMask             : 0x%08x" % peb_struct.ImageProcessAffinityMask, peb_struct.ImageProcessAffinityMask) 
        for buff in peb_struct.GdiHandleBuffer:
            window.Log("    +0x0c4 GdiHandleBuffer                   : 0x%08x" % buff, buff) 
        window.Log("+0x14c PostProcessInitRoutine                : 0x%08x" % peb_struct.PostProcessInitRoutine, peb_struct.PostProcessInitRoutine) 
        window.Log("+0x150 TlsExpansionBitmap                    : 0x%08x" % peb_struct.TlsExpansionBitmap, peb_struct.TlsExpansionBitmap) 
        for bitmapbits in peb_struct.TlsExpansionBitmapBits:
            window.Log("    +0x154 TlsExpansionBitmapBits            : 0x%08x" % bitmapbits, bitmapbits) 
        window.Log("+0x1d4 SessionId                             : 0x%08x" % peb_struct.SessionId, peb_struct.SessionId) 
        window.Log("+0x1d8 AppCompatFlags                        : 0x%08x" % AppCompatFlags, AppCompatFlags) 
        window.Log("+0x1e0 AppCompatFlagsUser                    : 0x%08x" % AppCompatFlagsUser, AppCompatFlagsUser) 
        window.Log("+0x1e8 pShimData                             : 0x%08x" % pShimData, pShimData) 
        window.Log("+0x1ec AppCompatInfo                         : 0x%08x" % peb_struct.AppCompatInfo, peb_struct.AppCompatInfo) 
        window.Log("+0x1f0 CSDVersion                            : 0x%08x" % peb_struct.CSDVersion_Buffer, peb_struct.CSDVersion_Buffer) 
        window.Log("+0x1f8 ActivationContextData                 : 0x%08x" % ActivationContextData, ActivationContextData) 
        window.Log("+0x1fc ProcessAssemblyStorageMap             : 0x%08x" % ProcessAssemblyStorageMap, ProcessAssemblyStorageMap) 
        window.Log("+0x200 SystemDefaultActivationContextData    : 0x%08x" % SystemDefaultActivationContextData, SystemDefaultActivationContextData) 
        window.Log("+0x204 SystemAssemblyStorageMap              : 0x%08x" % SystemAssemblyStorageMap, SystemAssemblyStorageMap) 
        window.Log("+0x208 MinimumStackCommit                    : 0x%08x" % MinimumStackCommit, MinimumStackCommit) 
        if OS >= 6.0:
            window.Log("+0x20c FlsCallback                       : 0x%08x" % FlsCallback,FlsCallback)
            window.Log("+0x210 FlsListHead                       : 0x%08x" % FlsListHead,FlsListHead)
            window.Log("+0x218 FlsBitmap                         : 0x%08x" % FlsBitmap,FlsBitmap)
            window.Log("+0x21c FlsBitmapBits                     : 0x%08x%08x" % (FlsBitmapBits,FlsBitmapBits2))
            window.Log("+0x22c FlsHighIndex                      : 0x%08x" % FlsHighIndex,FlsHighIndex)
            window.Log("+0x230 WerRegistrationData               : 0x%08x" % WerRegistrationData,WerRegistrationData)
            window.Log("+0x234 WerShipAssertPtr                  : 0x%08x" % WerShipAssertPtr,WerShipAssertPtr)
            window.Log("+0x238 pContextData                      : 0x%08x" % pContextData,pContextData)
            window.Log("+0x23c pImageHeaderHash                  : 0x%08x" % pImageHeaderHash,pImageHeaderHash)
        
        window.Log("---------------------------------------------------------")
        window.Log("")
        return "Dumped PEB successfully"
    
    else: 
        window.Log("(+) The PEB is located at 0x%08x" % peb,peb)
        peb_struct = imm.getPEB()
        # check at least to locations where the PEB might be patched..
        if peb_struct.BeingDebugged and peb_struct.NtGlobalFlag:
            window.Log("(!) Beaware! the PEB is not patched and heap operations may detect a debugger!")
        elif peb_struct.BeingDebugged == 0 and peb_struct.NtGlobalFlag == 0:
            window.Log("(+) Excellent, the PEB appears to be patched")
        return "PEB is located at 0x%08x" % peb

def dump_teb(imm, window):
    """
    dump Thread environment block - dumps the listed TEB's in the current process 
    (multi-threaded application)
    
    arguments:
    - obj imm
    - obj window
    
    return:
    - printed TEB addresses
    """
    currenttid = imm.getThreadId()
    threads = imm.getAllThreads()
    window.Log("")
    try:
        currentTEB = threads[currenttid].getTEB()
        window.Log("(+) The current TEB id is: %s and is located at: 0x%08x" % (currenttid,currentTEB),currentTEB)
    except:
        window.Log("(-) The current TEB id is: %s and is located at an unknown address" % (currenttid))
    
    tebArray = {}
    
    for key in threads:
        teb = key.getTEB()
        tid = key.getId()
        tebArray[teb] = tid
        
    valuelist = tebArray.keys()
    valuelist.sort()
    valuelist.reverse()
    if len(valuelist) == 1:
        window.Log("(!) There is only 1 thread running (the current TEB)")
    else:
        window.Log("(+) There are %d number of threads in this process" % len(valuelist))
        window.Log("(+) Other TEB's in this process:")
        for key in valuelist:
            window.Log("(+) ID: %s is located at: 0x%08x" % (tebArray[key],key), key)
    return "Dumped TEB successfully"

# LFH dumping function
# ====================
def dump_lfh(imm, pheap, graphic_structure, window, switch, filename="lfh_graph"):
      
    def dump_UserBlocks(UserBlocksIndex, chunk_nodes=False):
        # validate the chunks havent had there offsets overwritten..
        chunk_validation_list = []
        free_chunk_validation_list = []
        for chunk in subseg.chunks:
            chunk_validation_list.append(chunk.addr)
            if chunk.freeorder != -1:
                    free_chunk_validation_list.append(chunk.freeorder)
        free_chunk_validation_list.sort()
        window.Log("")
        window.Log("(+) Dumping UserBlocks from =>")
        window.Log("        _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->_HEAP_LOCAL_DATA(0x%08x)" % (pheap.address,pheap.LFH.address,pheap.LFH.LocalData.address),pheap.LFH.LocalData.address)
        try:
            window.Log("            ->_HEAP_LOCAL_SEGMENT_INFO[0x%x]->_HEAP_SUBSEGMENT(0x%08x)->_HEAP_USERDATA_HEADER(0x%08x):" % (subseg.BlockSize, subseg.UserDataHeader.SubSegment, subseg.UserDataHeader.address),subseg.UserBlocks)
        except:
            window.Log("            ->_HEAP_LOCAL_SEGMENT_INFO[?]->_HEAP_SUBSEGMENT(?)->_HEAP_USERDATA_HEADER(?):") 
        window.Log("")                 
        window.Log("(+) UserBlocks(0x%08x) => Size: 0x%04x %-8segment: 0x%08x FreeEntryOffset: 0x%04x Depth: %d" % (subseg.UserBlocks, subseg.BlockSize, subseg.type, subseg.UserBlocks, subseg.Offset, subseg.Depth), address = subseg.UserBlocks)
        try:
            window.Log("(+) Header => SubSegment: 0x%08x Reserved: 0x%08x SizeIndex: 0x%x Signature: 0x%08x" % (subseg.UserDataHeader.SubSegment, subseg.UserDataHeader.Reserved, subseg.UserDataHeader.SizeIndex, subseg.UserDataHeader.Signature),subseg.UserDataHeader.SubSegment)
        except:
            window.Log("(+) Header => SubSegment: ? Reserved: ? SizeIndex: ? Signature: ?")
        window.Log("(+) Current UserBlocks pointer => UserBlocks + FreeEntryOffset => 0x%08x + 0x%04x = 0x%08x" % (subseg.UserBlocks, subseg.Offset, (subseg.UserBlocks+subseg.Offset)))
        window.Log("")
        i = 0
        if graphic_structure:
            UserBlocks_data = "UserBlocks 0x%08x\nSize:0x%x" % (subseg.UserBlocks,subseg.BlockSize)
            Userblocks_nodes.append(pydot.Node(UserBlocks_data, style="filled", shape="rectangle", label=UserBlocks_data, fillcolor="#00eeaa"))
        
        for chk in subseg.chunks:
            if chk.isLFH:
                i += 1
                s = "B"
                if chk.freeorder != -1:
                    s = "F(%02x)" % chk.freeorder     
                    NextOffset = imm.readMemory(chk.addr+0x8,2)
                    (NextOffset) = struct.unpack("H", NextOffset)[0]
                    window.Log("-" * 111)
                    window.Log("%04d: Chunk(0x%08x) -> Size: 0x%x LFHflag: 0x%x %s " % ( i, chk.addr, chk.psize,  chk.lfhflags, s),chk.addr)
                    window.Log("%04d: Chunk(0x%08x) -> NextOffset: 0x%04x NextVirtualAddress -> UserBlocks + (NextOffset * 0x8): 0x%08x" % (i, chk.addr, NextOffset, (subseg.UserBlocks+(NextOffset*0x8))), chk.addr)
                    if (subseg.chunks.index(chk)+1) < len(subseg.chunks):
                        offset_next_chunk = subseg.UserBlocks+(NextOffset*0x8)
                        next_chunk = subseg.chunks[subseg.chunks.index(chk)+1].addr
                        if offset_next_chunk == next_chunk:
                            window.Log("%04d: Chunk(0x%08x) ** This chunk has been validated against the next chunk **" % (i, chk.addr))
                        elif offset_next_chunk in chunk_validation_list:
                            window.Log("%04d: Chunk(0x%08x) ** This chunk has been validated **" % (i, chk.addr))
                        elif chk.freeorder == free_chunk_validation_list[len(free_chunk_validation_list) -1]:
                            encoded_header = imm.readMemory(chk.addr-0x8,2)
                            (encoded_header) = struct.unpack("H", encoded_header)[0]
                            if NextOffset == 0xffff:
                                # shits gone funky y0! - bcoles :0)
                                # if its the last chunk and the nextoffset is 0xffff, then double check
                                # the rest of the header to ensure you havent overwritten it...
                                if encoded_header == NextOffset:
                                    window.Log("    --> **********************************************************************************************")
                                    window.Log("    --> ** %04d: Chunk(0x%08x) ** The EntryOffset (0x%04x) for this chunk has been overwritten! **" % (i, chk.addr, NextOffset))
                                    window.Log("    --> **********************************************************************************************")                                    
                                else:
                                    window.Log("%04d: Chunk(0x%08x) ** This chunk has been validated as the last chunk **" % (i, chk.addr))
                            elif NextOffset != 0xffff:
                                window.Log("    --> **********************************************************************************************")
                                window.Log("    --> ** %04d: Chunk(0x%08x) ** The EntryOffset (0x%04x) for this chunk has been overwritten! **" % (i, chk.addr, NextOffset))
                                window.Log("    --> **********************************************************************************************")
                        elif offset_next_chunk not in chunk_validation_list:
                            window.Log("    --> **********************************************************************************************")
                            window.Log("    --> ** %04d: Chunk(0x%08x) ** The EntryOffset (0x%04x) for this chunk has been overwritten! **" % (i, chk.addr, NextOffset))
                            window.Log("    --> **********************************************************************************************")
                elif chk.freeorder == -1:
                    # dont worry about the NextVirtualAddress
                    window.Log("%04d: Chunk(0x%08x) -> Size: 0x%x LFHflag: 0x%x %s" % ( i, chk.addr, chk.psize,  chk.lfhflags, s ),chk.addr)

            if graphic_structure:
                chunk_data = "(%d) chunk 0x%08x" % (i, chk.addr)
                if chk.freeorder == -1:
                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data+"\nBUSY CHUNK", fillcolor="#0055ee"))
                elif chk.freeorder != -1:
                    NextOffset = imm.readMemory(chk.addr+0x8,2)
                    (NextOffset) = struct.unpack("H", NextOffset)[0]
                                
                    if (subseg.chunks.index(chk)+1) < len(subseg.chunks):
                        offset_next_chunk = subseg.UserBlocks+(NextOffset*0x8)
                        next_chunk = subseg.chunks[subseg.chunks.index(chk)+1].addr
                        
                        # 1st check to see if the calculated NextOffset matches the next chunk address
                        # 2nd check that it is not the last free chunk
                        # 3rd check to see if the NextOffset is 0xffff
                        # 4th check to see if part of the encoded header matches the NextOffset
                        
                        if offset_next_chunk == next_chunk:
                            chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%08x" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                        elif offset_next_chunk in chunk_validation_list:
                            chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%08x" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                        elif chk.freeorder == free_chunk_validation_list[len(free_chunk_validation_list) -1]:
                            encoded_header = imm.readMemory(chk.addr-0x8,2)
                            (encoded_header) = struct.unpack("H", encoded_header)[0]
                            if NextOffset == 0xffff:
                                encoded_header = imm.readMemory(chk.addr-0x8,2)
                                (encoded_header) = struct.unpack("H", encoded_header)[0]
                                
                                # if its the last chunk and the nextoffset is 0xffff, then double check
                                # the rest of the header to ensure you havent overwritten it...
                                if encoded_header == NextOffset:
                                    chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%08x\nEntryOffset overwritten!" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="red"))
                                else:
                                    chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%08x" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                            elif NextOffset != 0xffff:
                                chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%08x\nEntryOffset overwritten!" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                                chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="red"))
                        
                        # the only case when we have an entry overwrite
                        elif offset_next_chunk not in chunk_validation_list:
                            chunk_data = "(%d) chunk 0x%08x\nFREE CHUNK\nNextVA: 0x%x\nEntryOffset overwritten!" % (i, chk.addr,(subseg.UserBlocks+(NextOffset*0x8)))
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="red")) 

        window.Log("-" * 111)
        return chunk_nodes               
        
    # if the user wants, print out all this information
    if switch["bucket_flag"]:
        window.Log("")
        window.Log("(+) Dumping buckets from _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->Buckets(+0x110):" % (pheap.address,pheap.LFH.address))
        window.Log("")
        if pheap.LFH.Buckets:    
            for bucket in pheap.LFH.Buckets:
                if switch["Bin_size"]:
                    if bucket.SizeIndex == int(switch["Bin_size"],16):
                        window.Log("bucket[%x] (0x%08x) -> BlockUnits: 0x%x UseAffinity: %x DebugFlags: %x" % (bucket.SizeIndex, bucket.address, bucket.BlockUnits, bucket.UseAffinity, bucket.DebugFlags),bucket.address)
                else:
                    window.Log("bucket[%x] (0x%08x) -> BlockUnits: 0x%x UseAffinity: %x DebugFlags: %x" % (bucket.SizeIndex, bucket.address, bucket.BlockUnits, bucket.UseAffinity, bucket.DebugFlags),bucket.address)
        window.Log("-" * 83)
        
    if switch["UserBlockCache_flag"]:
        window.Log("")
        window.Log("(+) Dumping UserBlockCache from _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->UserBlockCache(+0x50):" % (pheap.address,pheap.LFH.address))
        window.Log("")
        if pheap.LFH.UserBlockCache:
            for cache in pheap.LFH.UserBlockCache:           
                window.Log("Cache: 0x%08x Next: 0x%08x Depth: 0x%x Sequence: 0x%x AvailableBlocks: %d Reserved: 0x%x" % (cache.address, cache.Next, cache.Depth, cache.Sequence, cache.AvailableBlocks, cache.Reserved))
        window.Log("-" * 96)
         
    if switch["UserBlocks_flag"]:
       
        if pheap.LFH.LocalData:
            for seginfo in pheap.LFH.LocalData.SegmentInfo:
                subseg_management_list = seginfo.SubSegment
                if graphic_structure:
                    Userblocks_nodes = []
                UserBlocksIndex = 0
                for subseg in subseg_management_list:
                    UserBlocksIndex += 1
                    if graphic_structure:
                        chunk_nodes = []
                    else:
                        chunk_nodes = False
                    if switch["Bin_size"]:
                        if subseg.BlockSize == int(switch["Bin_size"],16):
                            chunk_nodes = dump_UserBlocks(UserBlocksIndex, chunk_nodes)
                    else:
                        chunk_nodes = dump_UserBlocks(UserBlocksIndex, chunk_nodes)
               
                    
                    if graphic_structure:
                        lfhgraph = pydot.Dot(graph_type='digraph')
                        lfhgraph.add_node(pydot.Node("free", style="filled", shape="rectangle", label="free chunk", fillcolor="#33ccff"))
                        lfhgraph.add_node(pydot.Node("busy", style="filled", shape="rectangle", label="busy chunk", fillcolor="#0055ee"))
          
                        UserBlocks_data = "UserBlocks 0x%08x\nSize:0x%x" % (subseg.UserBlocks,subseg.BlockSize)
                        lfhgraph.add_node(pydot.Node(UserBlocks_data, style="filled", shape="rectangle", label=UserBlocks_data, fillcolor="#00eeaa"))

                        for node in chunk_nodes:
                            lfhgraph.add_node(node)
                            if (chunk_nodes.index(node)+1) < len(chunk_nodes):                        
                                next_chunk_label = node.__get_attribute__("label")
                                if not re.search("FREE CHUNK", next_chunk_label):
                                    lfhgraph.add_edge(pydot.Edge(node, chunk_nodes[chunk_nodes.index(node)+1]))
                                else:
                                    lfhgraph.add_edge(pydot.Edge(node, chunk_nodes[chunk_nodes.index(node)+1], label="  NextOffset"))                               
                                            
                        if switch["Bin_size"]:
                            if subseg.BlockSize == int(switch["Bin_size"],16):
                                lfhgraph.write_png(filename+"-bin-%02d-%02d.png" % (subseg.BlockSize,UserBlocksIndex))
                        else:
                            lfhgraph.write_png(filename+"-bin-%02d-%02d.png" % (subseg.BlockSize,UserBlocksIndex))

# Lookaside list dumping function
# ===============================
def dump_lal(imm, pheap, graphic_structure, window, filename="lal_graph"):
    """
    Dump the lookaside list structure
    
    arguments:
    - obj imm
    - obj pheap
    - boolean graphic_structure (no need?)
    - obj window
    - string graph filename
    
    return:
    - dumps the lookaside list entry
    """
    exploitable_conditions = ["flink_overwrite", "size_overwrite"]
    if graphic_structure:
        lalgraph = pydot.Dot(graph_type='digraph')
        ndx_nodes = []
        chunk_dict = {}
    # we use the api where we can ;)
    if pheap.Lookaside:
        no_chunks = 0
        for ndx in range(0, len(pheap.Lookaside)):
            entry = pheap.Lookaside[ndx]
            chunk_nodes = []    
                    
            if not entry.isEmpty():
                b = 0
                window.Log("Lookaside[0x%03x] No. of chunks: %d, ListEntry: 0x%08x, Size: (%d+8=%d)" % 
        (ndx, entry.Depth, entry.addr, (ndx*8), (ndx*8+8)), address = entry.addr)
                window.Log("")
                window.Log("    List structure:")
                window.Log("    ~~~~~~~~~~~~~~~")
                window.Log("    +0x00 Pointer to first chunk                              : 0x%08x" % entry.ListHead, entry.ListHead)
                window.Log("    +0x04 Depth                                               : 0x%08x" % entry.Depth, entry.Depth)
                window.Log("    +0x06 Max Depth                                           : 0x%08x" % entry.MaxDepth, entry.MaxDepth)
                window.Log("")
                window.Log("    Chunks:")
                window.Log("    ~~~~~~~")                
                for a in entry.getList():
                    # get the chunks self size
                    chunk_read_self_size = ""
                    try:
                        chunk_read_self_size = imm.readMemory(a, 0x2)
                        chunk_read_self_size = struct.unpack("H", chunk_read_self_size)[0]
                    except:
                        pass
                        
                    # get the chunks cookie
                    chunkCookie = ""
                    try:
                        chunkCookie = imm.readMemory(a+0x4, 0x1)
                        (chunkCookie) = struct.unpack("B", chunkCookie)
                    except:
                        pass
                    
                    # validate the flink!
                    chunk_overwrite = False
                    try:
                        flink = imm.readMemory(a+0x8, 0x4)
                        flink = struct.unpack("L", flink)[0]
                    except:
                        chunk_overwrite = True
                    if not chunk_overwrite:
                        chunk_data = ("chunk (%d) 0x%08x \nFlink 0x%08x-0x08" % (b, a, (flink)))
                    elif chunk_overwrite:
                        chunk_data = ("chunk (%d) 0x%08x \nFlink ??0x%08x??" % (b, a, (a + 0x8)))

                    # else the expected chunk size is not the same as the read in chunk..
                    if (chunk_read_self_size * block) != (ndx * block):
                        # if the size has been overwritten.....
                        if chunk_read_self_size != "":
                            if graphic_structure:
                                chunk_nodes.append(pydot.Node("size_overwrite_%x" % 
                                (a), style="filled", shape="rectangle", label=chunk_data+"\nSize overwritten..", fillcolor="red"))
                            if not chunk_overwrite:
                                window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x, Size: %d (0x%03x)" % 
                                (b, a, flink, chunk_read_self_size, chunk_read_self_size), address = a) 
                                window.Log("        -> chunk size should have been %d (0x%04x)! We have a possible chunk overwrite.." % 
                                (ndx * block, ndx * block), focus=1)
                            elif chunk_overwrite:
                                # we cant read what flink is so its a ??
                                window.Log("    chunk [%d]: 0x%08x, Flink: ??0x%08x??, Size: ? " % (b, a, (a + 0x8)), address = a) 
                                window.Log("        -> failed to read chunk @ 0x%08x!" % a, address = a)
                        # else if the chunk address has been overwrtten and we couldnt read the chunks size due
                        # to a dodgy chunk header. This is generally because the previous chunks flink was clobbered..
                        elif chunk_read_self_size == "":
                            # just to ensure the flink was owned...
                            if not chunk_overwrite:
                                window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x, Size: %d (0x%03x)" % 
                                (b, a, (flink), chunk_read_self_size, chunk_read_self_size), address = a)                           
                            if chunk_overwrite:
                                window.Log("    chunk [%d]: 0x%08x, Flink: ??0x%08x??, Size: ? " % (b, a, (a + 0x8)), address = a) 
                                window.Log("        -> failed to read chunk @ 0x%08x!" % a, address = a)
                                if graphic_structure:
                                    chunk_nodes.append(pydot.Node("chunk_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nFlink overwrite...", fillcolor="red"))
                    elif (chunk_read_self_size * block) == (ndx * block):
                        b += 1
                        if graphic_structure:
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                        if not chunk_overwrite:
                            window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x-0x8, Size: %d (0x%03x), Cookie: 0x%01x" % 
                                       (b, a, (flink), (ndx * block), (ndx * block), chunkCookie[0]), address = a) 
                        elif chunk_overwrite:
                            window.Log("    chunk [%d]: 0x%08x, Flink: ??0x%08x??, Size: %d (0x%03x), Cookie: 0x%01x" % 
                                       (b, a, (a+0x8), (ndx * block), (ndx * block), chunkCookie), address = a)   
                            window.Log("        -> failed to read chunk @ 0x%08x!" % a, address = a)              
                window.Log("-" * 77)  

            elif entry.isEmpty(): 
                no_chunks +=1
                                 
            if graphic_structure:
                chunk_dict[ndx] = chunk_nodes
                ndx_nodes.append(pydot.Node("Lookaside[%s]" % ndx, style="filled", shape="rectangle", fillcolor="#66FF66")) 

    else:
        window.Log("Cannot find lookaside list for this heap")
        imm.log( "Cannot find lookaside list for this heap" )

    if graphic_structure:
        for node in ndx_nodes: 
            lalgraph.add_node(node)
            try:
                lalgraph.add_edge(pydot.Edge(node, ndx_nodes[ndx_nodes.index(node)+1]))
            except:
                pass

            # traverse through our dict so we can find some chunks?
            for key,value in chunk_dict.iteritems():
                # if we have got the correct entry
                if key == ndx_nodes.index(node):
                    # if we have chunks in the particular lookaside list..
                    if len(value) != 0: 
                        for v in value:
                            lalgraph.add_node(v)
                            if value.index(v) == 0:
                                if re.match(exploitable_conditions[0], v.get_name().strip('"')):
                                    lalgraph.add_edge(pydot.Edge(ndx_nodes[key], v, label="exploitable condition?"))
                                elif re.match(exploitable_conditions[1], v.get_name().strip('"')):
                                    lalgraph.add_edge(pydot.Edge(ndx_nodes[key], v, label="exploitable condition?"))
                                else:
                                    lalgraph.add_edge(pydot.Edge(ndx_nodes[key], v))
                            
                            try:
                                if re.match(exploitable_conditions[0], v.get_name().strip('"')):
                                    lalgraph.add_edge(pydot.Edge(v, value[value.index(v)+1], label="exploitable condition?"))
                                elif re.match(exploitable_conditions[1], v.get_name().strip('"')):                                
                                    lalgraph.add_edge(pydot.Edge(v, value[value.index(v)+1], label="exploitable condition?"))
                                else:
                                    lalgraph.add_edge(pydot.Edge(v, value[value.index(v)+1]))
                            except:
                                pass
        
        lalgraph.write_png(filename+".png")
    #if the number of emtpy chunks is 128, we have no lookaside..
    if no_chunks == 128:  
        window.Log("(-) Lookaside not in use..")

# yes this is technically cheating, but much more realistic
def get_heapCache_bitmap(pheap, get_chunk_dict=False):
    bit_list = {}
    chunk_dict = {}
    for a in range(0, len(pheap.HeapCache.Buckets)):
        if pheap.HeapCache.Buckets[a]:
            bit_list[a+0x80] = 1
            if get_chunk_dict:
                chunk_dict[pheap.HeapCache.Buckets[a]] = a+0x80 # ;)
        else:
            bit_list[a+0x80] = 0
    if get_chunk_dict:
        return bit_list, chunk_dict
    else:
        return bit_list

# get the bits for each freelist[n] entry
def get_FreeListInUse(pHeap):
    # ensure we are dealing with 32 bit integers only, lose the LSB
    bitblocks = "%s%s%s%s" % (pHeap.decimal2binary(pHeap.FreeListInUseLong[0])[0:32],
                              pHeap.decimal2binary(pHeap.FreeListInUseLong[1])[0:32],
                              pHeap.decimal2binary(pHeap.FreeListInUseLong[2])[0:32],
                              pHeap.decimal2binary(pHeap.FreeListInUseLong[3])[0:32])
    bits = []
    for bit in bitblocks:
        bits.append(int(bit))
    return bits

# here we can patch FreeListInUse depending on what
# values the user sets
def set_FreeListInUse(value,win,pHeap,imm,heapbase):
    
    fliu_0 = list(pHeap.decimal2binary(pHeap.FreeListInUseLong[0]))
    fliu_1 = list(pHeap.decimal2binary(pHeap.FreeListInUseLong[1]))
    fliu_2 = list(pHeap.decimal2binary(pHeap.FreeListInUseLong[2]))
    fliu_3 = list(pHeap.decimal2binary(pHeap.FreeListInUseLong[3]))
    
    # check in which long our value is in..
    if value in range(0x00,0x20):
        # if the bit is not set, set it
        if fliu_0[(value - 0x00)] != "1":
            fliu_0[(value - 0x00)] = "1"
        # else just unset the bit
        else:
            fliu_0[(value - 0x00)] = "0"
    if value in range(0x20,0x40):
        if fliu_1[(value - 0x20)] != "1":
            fliu_1[(value - 0x20)] = "1"
        else:
            fliu_1[(value - 0x20)] = "0"
    if value in range(0x40,0x60):
        if fliu_2[(value - 0x40)] != "1":
            fliu_2[(value - 0x40)] = "1"
        else:
            fliu_2[(value - 0x40)] = "0"
    if value in range(0x60,0x80):
        if fliu_3[(value - 0x60)] != "1":
            fliu_3[(value - 0x60)] = "1"
        else:
            fliu_3[(value - 0x60)] = "0"
    
    # pack up the bit list into a decimal
    fliu_0 = bin_to_dec(fliu_0[::-1])
    fliu_1 = bin_to_dec(fliu_1[::-1])
    fliu_2 = bin_to_dec(fliu_2[::-1])
    fliu_3 = bin_to_dec(fliu_3[::-1])
    
    # patch memory
    imm.writeLong( heapbase+0x158+0x00, fliu_0 )
    imm.writeLong( heapbase+0x158+0x04, fliu_1 )
    imm.writeLong( heapbase+0x158+0x08, fliu_2 )
    imm.writeLong( heapbase+0x158+0x0c, fliu_3 )
    
    
def dump_HeapCache_bitmap(pheap, window):
    bit_list = get_heapCache_bitmap(pheap)
    
    for k,v in bit_list.items():
        window.Log("bucket[0x%03x] = %d" % (k,v))

def dump_HeapCache_struc(pheap, window):
    window.Log("-" * 45)
    window.Log("HeapCache structure @ 0x%08x (unofficial)" % (pheap.HeapCache.addr),pheap.HeapCache.addr)
    window.Log("-" * 45)
    window.Log("")
    window.Log("+0x000 NumBuckets            : 0x%08x" % pheap.HeapCache.NumBuckets, pheap.HeapCache.NumBuckets)                       
    window.Log("+0x004 CommittedSize         : 0x%08x" % pheap.HeapCache.CommittedSize, pheap.HeapCache.CommittedSize)
    window.Log("+0x008 CounterFrequency      : 0x%08x" % pheap.HeapCache.CounterFrequency, pheap.HeapCache.CounterFrequency)
    window.Log("+0x010 AverageAllocTime      : 0x%08x" % pheap.HeapCache.AverageAllocTime, pheap.HeapCache.AverageAllocTime)
    window.Log("+0x018 AverageFreeTime       : 0x%08x" % pheap.HeapCache.AverageFreeTime, pheap.HeapCache.AverageFreeTime)
    window.Log("+0x020 SampleCounter         : 0x%08x" % pheap.HeapCache.SampleCounter, pheap.HeapCache.SampleCounter)
    window.Log("+0x024 field_24              : 0x%08x" % pheap.HeapCache.field_24, pheap.HeapCache.field_24)
    window.Log("+0x028 AllocTimeRunningTotal : 0x%08x" % pheap.HeapCache.AllocTimeRunningTotal, pheap.HeapCache.AllocTimeRunningTotal)
    window.Log("+0x030 FreeTimeRunningTotal  : 0x%08x" % pheap.HeapCache.FreeTimeRunningTotal, pheap.HeapCache.FreeTimeRunningTotal)
    window.Log("+0x038 AllocTimeCount        : 0x%08x" % pheap.HeapCache.AllocTimeCount, pheap.HeapCache.AllocTimeCount)
    window.Log("+0x03c FreeTimeCount         : 0x%08x" % pheap.HeapCache.FreeTimeCount, pheap.HeapCache.FreeTimeCount)
    window.Log("+0x040 Depth                 : 0x%08x" % pheap.HeapCache.Depth, pheap.HeapCache.Depth)
    window.Log("+0x044 HighDepth             : 0x%08x" % pheap.HeapCache.HighDepth, pheap.HeapCache.HighDepth)
    window.Log("+0x048 LowDepth              : 0x%08x" % pheap.HeapCache.LowDepth, pheap.HeapCache.LowDepth)
    window.Log("+0x04c Sequence              : 0x%08x" % pheap.HeapCache.Sequence, pheap.HeapCache.Sequence)
    window.Log("+0x050 ExtendCount           : 0x%08x" % pheap.HeapCache.ExtendCount, pheap.HeapCache.ExtendCount)
    window.Log("+0x054 CreateUCRCount        : 0x%08x" % pheap.HeapCache.CreateUCRCount, pheap.HeapCache.CreateUCRCount)
    window.Log("+0x058 LargestHighDepth      : 0x%08x" % pheap.HeapCache.LargestHighDepth, pheap.HeapCache.LargestHighDepth)
    window.Log("+0x05c HighLowDifference     : 0x%08x" % pheap.HeapCache.HighLowDifference, pheap.HeapCache.HighLowDifference)
    window.Log("+0x060 pBitmap               : 0x00%14x" % pheap.HeapCache.pBitmap, pheap.HeapCache.pBitmap)
                        
# dump the HeapCache
def dump_HeapCache(pheap,window,imm):
    for a in range(0, pheap.HeapCache.NumBuckets):
        if pheap.HeapCache.Buckets[a]:
            # assumed size
            size = (a+0x80-0x1) * block
            try:
                flink = imm.readMemory(pheap.HeapCache.Buckets[a]+0x8,0x4)
                (flink) = struct.unpack("L", flink)
            except:
                flink = None
            try:
                blink = imm.readMemory(pheap.HeapCache.Buckets[a]+0xc,0x4)
                (blink) = struct.unpack("L", blink)
            except:
                blink = None
            if flink != None and blink != None:
                window.Log("HEAP_CACHE[0x%03x] = 0x%08x (flink: 0x%08x, blink: 0x%08x, size: 0x%x - %d)" % 
                (a+0x80, pheap.HeapCache.Buckets[a], flink[0], blink[0], size, size), address = pheap.HeapCache.Buckets[a])
            else:
                # tell the user something is funky with flink/blink
                window.Log("HEAP_CACHE[0x%03x] = 0x%08x (size: 0x%x - %d)" % 
                (a+0x80, pheap.HeapCache.Buckets[a], size, size), address = pheap.HeapCache.Buckets[a])                    
    
# need a better way to do this..
# this will do for now.
def get_heap_instance(heap, imm):
    try:
        heap = int(heap,16)
    except:
        return "(-) Invalid heap address"
    try:
        pheap = imm.getHeap( heap, restore )
    except:
        return "(-) Invalid heap address"
    return pheap, heap

def dump_FreeListInUse(pheap, window):
    bits = get_FreeListInUse(pheap)
    i = 0
    window.Log("")
    window.Log("FreeListInUse:")
    window.Log("--------------")
    for b in bits:
        if i == 0:
            window.Log("FreeList[0x%x] = NA" % (i))
        else:
            window.Log("FreeList[0x%x] = %d" % (i,b))
        i+= 1

# Save the Lookaside chunks for analysing exploitable conditions
def set_Lookaside_chunks(imm, pheap, heap):
    if pheap.Lookaside:
        for ndx in range(0, len(pheap.Lookaside)):
            entry = pheap.Lookaside[ndx]
                    
            if not entry.isEmpty():
                
                for a in entry.getList():
                    lookaside_list = entry.getList()
                    
                    # get the previous chunk address
                    prev_chunk = lookaside_list[lookaside_list.index(a)-1]-0x8
                    
                    chunk_address = a
                    
                    # validate the flink!
                    flink_overwrite = False
                    try:
                        flink = imm.readMemory(a+0x8, 0x4)
                        flink = struct.unpack("L", flink)
                    except:
                        flink_overwrite = True                    
                    
                    # before we fudge it..
                    if flink_overwrite:
                        break                     
                    imm.addKnowledge("Lookasiden_chunk_%x" % chunk_address, [chunk_address, flink, prev_chunk], force_add = 1)
       
# Save the LFH chunks for analysing exploitable conditions
def perform_LFH_heuristics(imm, pheap, heap, window):
    
    """
    perform LFH heuristics when using the 'exploit' command
    
    @type  imm: Debugger Object
    @param imm: initialized debugger object
    
    @type  pheap: Heap Object
    @param param: initialised heap object

    @type  heap: DWORD
    @param heap: heap address only    
    
    @type  window: Windows Object
    @param window: initialized window object
     
    @rtype: None    
    
    """
    
    vuln_chunks = 0
    if pheap.LFH.LocalData:
        for seginfo in pheap.LFH.LocalData.SegmentInfo:
            subseg_management_list = seginfo.SubSegment
            for subseg in subseg_management_list:
                
                # validate the chunks havent had there offsets overwritten..
                chunk_validation_list = []
                free_chunk_validation_list = []
                for chunk in subseg.chunks:
                    chunk_validation_list.append(chunk.addr)
                    if chunk.freeorder != -1:
                        free_chunk_validation_list.append(chunk.freeorder)
                free_chunk_validation_list.sort()
                for chk in subseg.chunks:
                    
                    # only validate free chunks
                    if chk.freeorder != -1:
                        NextOffset = imm.readMemory(chk.addr+0x8,2)
                        (NextOffset) = struct.unpack("H", NextOffset)[0]
                        
                        if (subseg.chunks.index(chk)+1) < len(subseg.chunks):
                            # calculate the next address using the NextOffset
                            offset_next_chunk = subseg.UserBlocks+(NextOffset*0x8)
                            
                            # if the current chunks freeorder is the same as the last freeorder for the UserBlocks, its ok
                            if chk.freeorder == free_chunk_validation_list[len(free_chunk_validation_list) -1]:
                                encoded_header = imm.readMemory(chk.addr-0x8,2)
                                (encoded_header) = struct.unpack("H", encoded_header)[0]
                                if NextOffset == 0xffff:
                                    # if its the last chunk and the nextoffset is 0xffff, then double check
                                    # the rest of the header to ensure you havent overwritten it...
                                    if encoded_header == NextOffset:
                                        vuln_chunks += 1
                                        window.Log("")
                                        window.Log("(!) Detected chunk overwrite!")
                                        window.Log("-" * 40)
                                        window.Log("UserBlocks: 0x%08x" % (subseg.UserBlocks),subseg.UserBlocks) 
                                        window.Log("-" * 40)
                                        window.Log("    --> Chunk(0x%08x) ** The EntryOffset for this chunk has been overwritten! **" % (chk.addr),chk.addr)
                                        window.Log("    --> Size: 0x%x" % chk.psize)
                                        window.Log("    --> NextOffset: 0x%x" % NextOffset)
                                        window.Log("(!) 1. You will need %d allocations to overwrite the FreeEntryOffset" % len(free_chunk_validation_list))
                                        window.Log("(!) 2. Using NextOffset: 0x%x, your next controlled allocation will be at 0x%08x" % 
                                                   (NextOffset, subseg.UserBlocks + (NextOffset * 0x8)),subseg.UserBlocks + (NextOffset * 0x8))
                                elif NextOffset != 0xffff:
                                    vuln_chunks += 1
                                    window.Log("")
                                    window.Log("(!) Detected chunk overwrite!")
                                    window.Log("-" * 40)
                                    window.Log("UserBlocks: 0x%08x" % (subseg.UserBlocks),subseg.UserBlocks) 
                                    window.Log("-" * 40)
                                    window.Log("    --> Chunk(0x%08x) ** The EntryOffset for this chunk has been overwritten! **" % (chk.addr),chk.addr)
                                    window.Log("    --> Size: 0x%x" % chk.psize)
                                    window.Log("    --> NextOffset: 0x%x" % NextOffset)
                                    window.Log("(!) 1. You will need %d allocations to overwrite the FreeEntryOffset" % len(free_chunk_validation_list))
                                    window.Log("(!) 2. Using NextOffset: 0x%x, your next controlled allocation will be at 0x%08x" % 
                                               (NextOffset, subseg.UserBlocks + (NextOffset * 0x8)),subseg.UserBlocks + (NextOffset * 0x8))     
                            elif offset_next_chunk not in chunk_validation_list:
                                vuln_chunks += 1
                                window.Log("")
                                window.Log("(!) Detected chunk overwrite!")
                                window.Log("-" * 40)
                                window.Log("UserBlocks: 0x%08x" % (subseg.UserBlocks),subseg.UserBlocks) 
                                window.Log("-" * 40)
                                window.Log("    --> Chunk(0x%08x) ** The EntryOffset for this chunk has been overwritten! **" % (chk.addr),chk.addr)
                                window.Log("    --> Size: 0x%x" % chk.psize)
                                window.Log("    --> NextOffset: 0x%x" % NextOffset)
                                window.Log("(!) 1. You will need %d allocations to overwrite the FreeEntryOffset" % len(free_chunk_validation_list))
                                window.Log("(!) 2. Using NextOffset: 0x%x, your next controlled allocation will be at 0x%08x" % 
                                           (NextOffset, subseg.UserBlocks + (NextOffset * 0x8)),subseg.UserBlocks + (NextOffset * 0x8))
    # return the number of chunks overwritten
    window.Log("")
    window.Log("(!) Found %d overwritten chunks" % vuln_chunks)
    window.Log("")
    return "(!) Found %d number of Overwritten chunks" % vuln_chunks

# save freelist[n] chunks for auditing later
# ==========================================
def set_FreeList_chunks(imm, pheap, heap):
    
    """
    Save the FreeList chunks into immunities memory (NT-5.x)
    
    @type  imm: Debugger Object
    @param imm: initialized debugger object
    
    @type  pheap: Heap Object
    @param param: initialised heap object
    
    @type  heap: DWORD
    @param heap: heap address only    
    
    @rtype: None
    
    """
    
    for a in range(0, 128):
        entry = pheap.FreeList[a]
        e = entry[0]
        if e[0]:
            if len(entry[1:]) >= 1:
                for fc in entry[1:]:
                    # anti-confusion, setup the needed chunks
                    if len(entry[1:]) == 1:
                        prevchunk_address = e[0]
                    else:
                        prevchunk_address = entry[1:][entry[1:].index(fc)-1][0]
                    try:
                        nextchunk_address = entry[1:][entry[1:].index(fc)+1][0]
                    except:
                        nextchunk_address = 1
                    chunk_address  = fc[0]
                    chunk_blink = fc[1]
                    chunk_flink = fc[2]
                    # distinwish from freelist[0] and freelist[n] 
                    if a != 0:
                        imm.addKnowledge("FreeListn_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                    elif a == 0:
                        imm.addKnowledge("FreeList0_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
    
def perform_heuristics(window, imm, pheap, allocator):
    window.Log("")
    if allocator == "BackEnd":
        header_line_sz = 51
    elif allocator == "FrontEnd":
        header_line_sz = 52
    window.Log("-" * header_line_sz)
    window.Log("Performing heuristics against the %s allocator" % allocator)
    window.Log("-" * header_line_sz)
    window.Log("")
    vuln_freelistchunks = 0 
    vuln_lookasidelistchunks = 0
    vuln_freelistnchunks = 0
    for knowledge in imm.listKnowledge():
        # match on all the freelist[0] chunks we added earlier 
        if allocator == "BackEnd":
            if re.match("FreeList0_chunk_",knowledge):
                vuln_freelistchunks += freelist_and_lookaside_heuristics(window, knowledge, pheap, imm, "freelist0", vuln_freelistchunks)
            elif re.match("FreeListn_chunk_",knowledge):
                vuln_freelistnchunks += freelist_and_lookaside_heuristics(window, knowledge, pheap, imm, "freelistn", vuln_freelistchunks)
        # match on Lookaside
        elif allocator == "FrontEnd":
            if re.match("Lookasiden_chunk_",knowledge):
                vuln_lookasidelistchunks += freelist_and_lookaside_heuristics(window, knowledge, pheap, imm, "lookaside", vuln_lookasidelistchunks)
        # if we have vulnerable chunks... dont keep looping
        if vuln_lookasidelistchunks >= 1:
            break
            
    window.Log("")
    if vuln_freelistchunks > 0:
        window.Log("")
        window.Log("Information regarding FreeList[0] attacks")
        window.Log("=" * 41)
        window.Log("")                      
        window.Log("1. Freelist[0] insert attack:")
        window.Log("-" * 29)
        window.Log("The idea here is overwrite a chunks blink and set it to a lookaside[n] entry or function pointer table")
        window.Log("1. Overwriten chunk's blink will be set to the Lookaside[n] list entry")
        window.Log("2. Free chunk is inserted BEFORE the overwritten chunk write the address of the free chunk into blinks address (blink->inserted_chunk)")            
        window.Log("3. Now lookaside[n]->inserted_chunk->overwritten_chunk->controlled_flink")
        window.Log("4. Now pop 3 chunks off the lookaside[n] to get the controlled flink returned from RtlAllocateHeap")
        window.Log("5. Overwrite a function pointer")
        window.Log("")
        window.Log("2. Freelist[0] search attack:")
        window.Log("-" * 29)
        window.Log("The idea here is overwrite a chunks flink and set it to a fake chunk.")
        window.Log("1. Set the flink to an address at the base of the heap (eg: heapbase+0x188)")
        window.Log("2. When a size that is bigger than the overwritten chunk is requested, it will return the fake chunk address-0x8 (heapbase+0x180)")                   
        window.Log(" - You can set it to FreeList[0x41] or FreeList[0x42] and overwrite the RtlCommitRoutine pointer at offset heapbase+0x578")
        window.Log(" - Or you could overwrite the blink/flink of a FreeList[n] entry itself..?")
        window.Log("")
        window.Log("3. Freelist[0] relinking attack:")
        window.Log("-" * 32)
        window.Log("The idea here is to control flink, so that you can indirectly control address that WILL point to the blink of the fake chunk")
        window.Log("1. The chunk gets split and the relink chunk is inserted BEFORE the fake chunk")
        window.Log("2. The address of the relink chunk is written to the fake chunks blink")
        window.Log("3. The idea is to overwrite the pointer to the Lookaside (heapbase+0x580) with a pointer to the fake chunk")
        window.Log(" - set the flink to be heapbase+0x57c")
        window.Log(" - set the fake chunk to be heapbase+0x574")
        window.Log(" - flink of fake chunk will be at heapbase+0x57c")
        window.Log(" - blink of fake chunk will be heapbase+0x580, thus overwriting heapbase+0x688 with the relink chunk address")                        
        window.Log("")
        window.Log("(!) Heuristics check completed")
    
    elif allocator == "BackEnd" and vuln_freelistchunks <= 0:
        window.Log("(!) No exploitable cases were identified for FreeList[0]")
    elif allocator == "FrontEnd" and vuln_lookasidelistchunks <= 0:
        window.Log("(!) No vulnerable cases were identified")
    elif allocator == "BackEnd" and vuln_freelistnchunks <= 0:
        window.Log("(!) No exploitable cases were identified for FreeList[n]")
                                   

def dump_ListHint_and_FreeList(args, pheap, window, heap, imm, graphic_structure=False, filename="listhint_graph"):
    if graphic_structure:
        listhintgraph = pydot.Dot(graph_type='digraph')
        listhintgraph.set("ranksep", "0.75")
        ListHint_nodes = {}
        list_hint_dict = {}
        
    chunk_nodes = []
    node_list = []
    for i in range(0, len(pheap.blocks)):

        block = pheap.blocks[i]
        num_of_freelists = block.ArraySize - block.BaseIndex
        window.Log("")
        window.Log("HeapBase->BlocksIndex")
        window.Log("~~~~~~~~~~~~~~~~~~~~~")
        window.Log("(+) BlocksIndex information for 0x%08x->0x%08x" % (heap+0xb8,block.address),block.address)
        window.Log("(+) ExtendedLookup => 0x%08x" % block.ExtendedLookup)
        window.Log("(+) ArraySize [max permitted in blocks] => 0x%08x" % block.ArraySize)
        window.Log("(+) BaseIndex => 0x%08x" % block.BaseIndex)
        window.Log("(+) End Block information for 0x%08x" % block.address)
        window.Log("(+) Block has [0x%x] FreeLists starting at 0x%08x"  % (num_of_freelists, block.ListHints))
        window.Log("")
        
        if "-l" in args or "-L" in args: 
            window.Log("(+) ListHints:")
            window.Log("-------------")
            memory = imm.readMemory( block.ListHints, num_of_freelists * 8 )
            allocations_needed = {}
                     
            for a in range(0, num_of_freelists):
                # Previous and Next Chunk of the head of the double linked list
                (flink, heap_bucket) = struct.unpack("LL", memory[a * 0x8 : a * 0x8 + 0x8] )
                bin_entry = a + block.BaseIndex
                freelist_addr = block.ListHints + (bin_entry - block.BaseIndex) * 8
                allocations = heap_bucket & 0x0000FFFF
                allocations = allocations / 2
                # if we have had a allocation, then there should only be 17 to go
                if allocations > 0:
                    lfhthreshold = 0x11
                else:
                    lfhthreshold = 0x12
                amount_needed = lfhthreshold - allocations
    
                if heap_bucket != 0:
                    if amount_needed in range (0x01,0x12):
                        allocations_needed[bin_entry] = amount_needed
                    else:
                        allocations_needed[bin_entry] = 0 
                    if heap_bucket & 1:
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: Enabled | Bucket => 0x%08x" % (bin_entry, flink, heap_bucket - 1), address = freelist_addr)
                    elif (heap_bucket & 0x0000FFFF) >= 0x22: #there appears to be a case where the LFH isn't activated when it should be...
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: ??????? | Bucket => 0x%08x" % (bin_entry, flink, heap_bucket), address = freelist_addr)
                    else:
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: Has had %d allocations | Needs %d more" % (bin_entry, flink, allocations, amount_needed), address = freelist_addr)
                elif heap_bucket == 0:
                        
                    if bin_entry != 0x1 and bin_entry != 0x0 and flink == 0:
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: Bin is Empty!" % (bin_entry, flink), address = freelist_addr)
                    elif bin_entry != 0x1 and bin_entry != 0x0 and bin_entry == (block.ArraySize-0x1) and flink != 0:
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: last entry contains large chunks!" % (bin_entry, flink), address = freelist_addr)
                    elif flink != 0 and bin_entry != 0x1 and bin_entry != 0x0:
                        window.Log("Bin[0x%04x] | Flink => 0x%08x :: Has had %d allocations | Needs %d more" % (bin_entry, flink, allocations, amount_needed), address = freelist_addr)
                        allocations_needed[bin_entry] = 0
                    # amount needed should always be between 0-18
                    if amount_needed in range (0x01,0x12):
                        allocations_needed[bin_entry] = amount_needed
                        
                if flink != 0:
                    window.Log("    -> Bin contains chunks")
                          
        if "-f" in args or "-F" in args: 
                                 
            window.Log("")
            window.Log("(+) FreeList:")
            window.Log("-------------")
            for a in range(block.BaseIndex, num_of_freelists): # num_of_freelists
                entry= block.FreeList[a]
                e=entry[0]
                first_entry = entry[0]
                nodes = []
                overwrite_flink_blink = False
                overwrite_size = False
                if e[0]:
                    window.Log("Bin[0x%04x]    0x%08x -> [ Flink: 0x%08x | Blink: 0x%08x ] " % (a+block.BaseIndex, e[0], e[1], e[2]), address = e[0])
                    # logic to detect overwrite via the size (decode the header on the fly)
                    encoded_header = imm.readMemory(e[0]-0x8,0x4)
                    (encoded_header) = struct.unpack("L", encoded_header) 
                    result = "%x" % (encoded_header[0] ^ pheap.EncodingKey)
                    # chunks of size 0x7f or 0x7ff (FreeList[0] will NOT have their size validated for obvious reasons...)
                    if (int(result[len(result)-4:len(result)],16) != a+block.BaseIndex and (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff):
                        window.Log("               -> Detected chunk size overwrite!")
                        overwrite_size = True
                        if e[1] == e[2]:
                            overwrite_flink_blink = True
                            window.Log("               -> Detected the flink/blink to be overwritten as well!") 
                    elif (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff:
                        window.Log("Chunk:         0x%08x has had its size validated correctly" % e[0])
                        if e[1] == e[2]:
                            overwrite_flink_blink = True
                            window.Log("               -> Detected flink/blink overwrite without overewriting the size!? Do you have a 4-n byte write!?")                    
    
                    if (int(a+block.BaseIndex) != 0x7f and int(a+block.BaseIndex) != 0x7ff):
                        chunk_data = "Chunk: 0x%08x\nFlink: 0x%08x\nBlink: 0x%08x\nSize: 0x%x" % (e[0],e[1], e[2],a+block.BaseIndex)  
     
                    # we have to get the calculated size if its like FreeList[0]...
                    elif (int(a+block.BaseIndex) == 0x7f or int(a+block.BaseIndex) == 0x7ff):      
                        chunk_data = "Chunk: 0x%08x\nFlink: 0x%08x\nBlink: 0x%08x\nSize: 0x%x" % (e[0],e[1], e[2],int(result[len(result)-4:len(result)],16))
                    
                    if graphic_structure:
                        if overwrite_flink_blink and not overwrite_size:
                            nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data+"\nflink/blink are owned!", fillcolor="red"))
                        elif overwrite_flink_blink and overwrite_size:
                            nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data+"\nsize and flink/blink are owned!", fillcolor="red"))
                        elif not overwrite_flink_blink and not overwrite_size:
                            nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                        
                    # if more than one entries exists, loop over them and add them...
                    if len(entry[1:]) > 1:
                        for e in entry[1:]:
                            # logic to detect overwrite via the size (decode the header on the fly)
                            encoded_header = imm.readMemory(e[0]-0x8,0x4)
                            (encoded_header) = struct.unpack("L", encoded_header) 
                            result = "%x" % (encoded_header[0] ^ pheap.EncodingKey)
                            if (int(result[len(result)-4:len(result)],16) != a+block.BaseIndex and (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff):
                                window.Log("    -> Detected chunk size overwrite!")
                                overwrite_size = True
                                if e[1] == e[2]:
                                    window.Log("               -> Detected the flink/blink to be overwritten as well!")
                                    overwrite_flink_blink = True
                            elif (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff:
                                window.Log("Chunk:         0x%08x has had its size validated correctly" % e[0])
                                if e[1] == e[2]:
                                    window.Log("    -> Detected flink/blink overwrite without overewriting the size!? Do you have a 4-n byte write!?")                         
                                    overwrite_flink_blink = True
                            if (int(a+block.BaseIndex) != 0x7f and (int(a+block.BaseIndex)) != 0x7ff):
                                chunk_data = "Chunk: 0x%08x\nFlink: 0x%08x\nBlink: 0x%08x\nSize: 0x%x" % (e[0],e[1], e[2],a+block.BaseIndex)    
                            # we have to get the calculated size if its like FreeList[0]...
                            elif (int(a+block.BaseIndex) == 0x7f and int(a+block.BaseIndex) == 0x7ff):
                                chunk_data = "Chunk: 0x%08x\nFlink: 0x%08x\nBlink: 0x%08x\nSize: 0x%x" % (e[0],e[1], e[2],int(result[len(result)-4:len(result)],16))
                            window.Log("               0x%08x -> [ Flink: 0x%08x | Blink: 0x%08x ] " % (e[0], e[1], e[2]), address= e[0])                          
                                         
                            if graphic_structure:
                                # as long as the first entry is not the same as the already added node..
                                if first_entry[0] != e[0]:
                                    if overwrite_flink_blink and not overwrite_size:
                                        nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data+"\nflink/blink are owned!", fillcolor="red"))
                                    elif overwrite_flink_blink and overwrite_size:
                                        nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data+"\nsize and flink/blink are owned!", fillcolor="red"))
                                    elif not overwrite_size and not overwrite_flink_blink:
                                        nodes.append(pydot.Node("chunk 0x%08x" % e[0], style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))    
                if graphic_structure:
                    if a not in list_hint_dict:
                        list_hint_dict[a] = nodes
                    # no matter how many allocations, you will never trigger LFH
                    if a == 127:
                        list_data = "ListHint[0x%x]\nNo amount of allocations will\ntrigger LFH for this bin" % (a) 
                    elif a in allocations_needed and allocations_needed[a] == 0:
                        list_data = "ListHint[0x%x]\nNo. of allocations to LFH is unknown" % (a)
                    elif a in allocations_needed:
                        list_data = "ListHint[0x%x]\nNo. of allocations to LFH: %d" % (a,allocations_needed[a])
                    else:
                        list_data = "ListHint[0x%x]" % (a)
                    ListHint_nodes[a] = pydot.Node("ListHint[0x%x]" % a, style="filled", shape="rectangle", label=list_data, fillcolor="#66FF66")
            
            
        
            if graphic_structure:
                k = 0
                for listhintnode in ListHint_nodes.keys():
                    
                    nodes_to_add = list_hint_dict[k]
                    if len(nodes_to_add) > 0:
                        
                        if k not in chunk_nodes:
                            chunk_nodes.append(k)
                            
                        listhintgraph.add_node(ListHint_nodes[listhintnode])
                        # link to the first chunk in the Bin
                        # if statement not working, not sure why.... alternate fix is using used_nodes array
                        if not listhintgraph.get_edge(ListHint_nodes[listhintnode], nodes_to_add[0]):   
                            edge = pydot.Edge(ListHint_nodes[listhintnode], nodes_to_add[0])
                            # needs to be check against multiple FreeList's
                            # checks to see if the ListHint Entry and the first chunk have been added to the node_list
                            # if then have, then they already have an edge, so dont add a second edge (needed for multiple BlocksIndex)
                            if (node_list.count(ListHint_nodes[listhintnode]) < 1 and node_list.count(nodes_to_add[0]) < 1):
                                listhintgraph.add_edge(edge)
                                node_list.append(ListHint_nodes[listhintnode])
                                node_list.append(nodes_to_add[0])
                        j = 0
                        for node in nodes_to_add:
                            listhintgraph.add_node(node)
                            
                            if j+1 <= len(nodes_to_add)-1:
                                edge = pydot.Edge(node, nodes_to_add[j+1])
                                node_list.append(node)
                                if not node_list.count(node) == 2 and not node_list.count(nodes_to_add[j+1]) == 2:
                                    listhintgraph.add_edge(edge)
                                
                            if ((chunk_nodes.index(k)-1) >= 0):
                                prev_nodes_to_link = list_hint_dict[chunk_nodes[chunk_nodes.index(k)-1]]
                                # check the previous node to see if there is an edge, if not, add it
                                if not listhintgraph.get_edge(prev_nodes_to_link[-1],node) and nodes_to_add.index(node) == 0:     
                                    edge = pydot.Edge(prev_nodes_to_link[-1],node)
                                    node_list.append(prev_nodes_to_link[-1])
                                    if not node_list.count(prev_nodes_to_link[-1]) >= 2:
                                        listhintgraph.add_edge(edge)
                            j+=1
                    k+=1
            if graphic_structure:
                listhintgraph.set_graphviz_executables(paths)
                listhintgraph.write_png(filename+".png")
                
    if graphic_structure and not "-l" in args and not "-f" in args:
        window.Log("(-) You must specify argument -l/-L or -f/-F to graph the ListHints or FreeList")
    
        
def dump_freelist(imm, pheap, window, heap, graphic_structure=False, filename="freelist_graph"):
    if graphic_structure:
        freelistgraph = pydot.Dot(graph_type='digraph')
        freelist_nodes = []
        chunk_dict = {}
    for a in range(0, 128):
        entry= pheap.FreeList[a]
        e=entry[0]
        chunk_nodes = []
        if e[0]:
            expected_size_freelist0 = ">1016"
            expected_size = a * block
            result_of_expected_size = expected_size - block
            window.Log("")
            if len(entry[1:]) >= 1:
                chunkNum = 0

                # if we are not FreeList[0] and yet we have chunks
                if a != 0:
                    window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s-8=%s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size, result_of_expected_size), address = e[0])
                    window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
                else:
                    window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size_freelist0), address = e[0])
                    window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
                         
                # for each avaliable chunk in the freelist[] entry            
                for fc in entry[1:]:
                    # anti-confusion, setup the needed chunks
                    if len(entry[1:]) == 1:
                        prevchunk_address = e[0]
                    else:
                        prevchunk_address = entry[1:][entry[1:].index(fc)-1][0]
                    try:
                        nextchunk_address = entry[1:][entry[1:].index(fc)+1][0]
                    except:
                        nextchunk_address = 1
                    chunk_address  = fc[0]
                    chunk_blink = fc[1]
                    chunk_flink = fc[2]
                    try:
                        sz = pheap.get_chunk( chunk_address - block ).size
                        # avoid freelist[0] as it can be anything > 1016
                        if a != 0:
                            calc_sz = (sz * block) - block
                        else:
                            calc_sz = 0
                    except:
                        calc_sz = 0
                        sz = 0
                    # win32heapchunk API does not accommodate for the cookie, so lets do it manually 
                    # header [0x2 - size][0x2 - previous size][0x1 - cookie][0x1 - flag][0x1 - unused][0x1 - segment index]
                    chunkCookie = imm.readMemory(chunk_address-0x4, 1) # chunk_address includes header
                    (chunkCookie) = struct.unpack("B", chunkCookie)
                                    
                    chunk_data = "Chunk (%d) 0x%08x\nBlink (0x%08x)\nFlink (0x%08x)" % (chunkNum, chunk_address, chunk_blink, chunk_flink)
                    chunkNum += 1
                    window.Log("         * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x] " % (chunkNum, chunk_address, chunk_blink, chunk_flink), address = chunk_address) 
                    window.Log("                 [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x" % (chunkNum, sz, calc_sz, calc_sz, chunkCookie[0]), address = chunk_address) 
                    if graphic_structure:
                        chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))
                    
                    if a != 0:
                        # now lets validate the integrity of the linked list using safe unlinking checks
                        # Not the last chunk in the entry..
                        if sz != a and nextchunk_address != 1:
                            if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                window.Log("           --> Size, Flink and Blink appear to be overwritten, code execution maybe possible")
                            else:
                                window.Log("           --> Size appears to be overwritten, code execution maybe possible")                            
                            # something is dodgy, lets save it for performing heuristics later..
                            imm.addKnowledge("FreeListn_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                            if graphic_structure:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size, Flink and Blink\n are overwritten...", fillcolor="red"))
                                else:
                                    chunk_nodes.append(pydot.Node("size_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size is overwritten...", fillcolor="red"))                   
                        
                        # now lets validate the integrity of the linked list using safe unlinking checks and size validation
                        # Last chunk in the entry..
                        elif sz != a and nextchunk_address == 1:
                            if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                window.Log("           --> Size, Flink and Blink appear to be overwritten, code execution maybe possible")
                            else:
                                window.Log("           --> Size appears to be overwritten, code execution maybe possible")
                            # something is dodgy, lets save it for performing heuristics later..   
                            imm.addKnowledge("FreeListn_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                            if graphic_structure:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size, Flink and Blink\n are overwritten...", fillcolor="red"))
                                else:
                                    chunk_nodes.append(pydot.Node("size_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size is overwritten...", fillcolor="red"))

                    # FreeList[0]
                    # huertistic validation of corrupted chunk is done at freelist0_heuristics()
                    elif a == 0:
                        
                        # check if this chunk is not the last chunk in the entry
                        if nextchunk_address != 1:
                            if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                window.Log("           --> Size, Flink and Blink appear to be overwritten, code execution maybe possible")                          
                            
                            # lets save it for performing heuristics later..
                            # only on FreeList[0] we validate the integrity of the chunk in freelist0_heuristics()
                            imm.addKnowledge("FreeList0_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                            if graphic_structure:
                                window.Log("graph structure 1")
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size, Flink and Blink\n are overwritten...", fillcolor="red"))    
                                    
                        # last chunk
                        elif nextchunk_address == 1:            
                            if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                window.Log("           --> Size, Flink and Blink appear to be overwritten, code execution maybe possible")                         
                            # lets save it for performing heuristics later..
                            # only on FreeList[0] we validate the integrity of the chunk in freelist0_heuristics()
                            imm.addKnowledge("FreeList0_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                            if graphic_structure:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nThe Size, Flink and Blink\n are overwritten...", fillcolor="red"))                                     
 
                        # else just check blink
                        # code probably never lands here... will check and remove soon
                        else:
                            if prevchunk_address != chunk_blink:
                                window.Log("           --> Flink and Blink appear to be overwritten, code execution maybe possible")
                                # lets save it for performing heuristics later..
                                # only on FreeList[0] is there no way to check for dodgy chunk here..
                                imm.addKnowledge("FreeList[0]_chunk_%x" % chunk_address, [a, chunk_address, chunk_blink, chunk_flink, prevchunk_address, nextchunk_address, e[0]], force_add = 1)
                                if graphic_structure:
                                    chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nFlink/Blink overwrite...", fillcolor="red"))
                
            # if they have no chunks, print them anyway, prooves useful when performing certain attacks 
            elif len(entry[1:]) < 1:
                window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s-8=%s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size, result_of_expected_size), address = e[0])
                window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x]].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
            window.Log("")   
            window.Log("-" * 94)
                
        if graphic_structure:
            chunk_dict[a] = chunk_nodes
            freelist_nodes.append(pydot.Node("Freelist[0x%x]" % a, style="filled", shape="rectangle", fillcolor="#66FF66"))
    
    if graphic_structure:
        for node in freelist_nodes:
            freelistgraph.add_node(node)
            try:
                freelistgraph.add_edge(pydot.Edge(node, freelist_nodes[freelist_nodes.index(node)+1]))
            except:
                pass

            # traverse through our dict so we can find some chunks?
            for key,value in chunk_dict.iteritems():
                # if we have got the correct entry
                if key == freelist_nodes.index(node):
                    # if we have chunks in the particular lookaside list..
                    if len(value) != 0: 
                        for v in value:
                            freelistgraph.add_node(v)
                            if value.index(v) == 0:
                                if re.match("flink_blink_overwrite", v.get_name().strip('"')):
                                    freelistgraph.add_edge(pydot.Edge(freelist_nodes[key], v, label="exploitable condition?"))
                                else:
                                    freelistgraph.add_edge(pydot.Edge(freelist_nodes[key], v))
                            
                            try:
                                if re.match("flink_blink_overwrite", v.get_name().strip('"')):
                                    freelistgraph.add_edge(pydot.Edge(v, value[value.index(v)+1], label="exploitable condition?"))
                                else:
                                    freelistgraph.add_edge(pydot.Edge(v, value[value.index(v)+1]))
                            except:
                                pass                                
            
        freelistgraph.write_png(filename+".png") 

# display chunk info my way
def dumpchunk_info(chunk, show_detail, window):
    if chunk.getflags(chunk.flags) == "B$":
        window.Log("(+) Chunk on the Lookaside @ 0x%08x" % chunk.addr,chunk.addr)
    elif chunk.getflags(chunk.flags) == "F$":
        window.Log("(+) Chunk on the Lookaside @ 0x%08x" % chunk.addr,chunk.addr)
    elif chunk.getflags(chunk.flags) == "F":
        window.Log("(+) Chunk on the Freelist @ 0x%08x+0x08 (0x%08x)" % (chunk.addr,(chunk.addr+0x08)), chunk.addr)
    elif chunk.getflags(chunk.flags) == "B":
        window.Log("(+) BUSY chunk @ 0x%08x" % chunk.addr,chunk.addr)
    elif chunk.getflags(chunk.flags) == "B|T":
        window.Log("(+) Last BUSY chunk @ 0x%08x" % chunk.addr,chunk.addr)
    else:
        window.Log("(+) chunk @ 0x%08x" % chunk.addr,chunk.addr)
        
    window.Log("")
    window.Log("    -> size: 0x%08x  (8 * 0x%04x = 0x%04x, decimal: %d)" % (chunk.usize, chunk.size, chunk.usize, chunk.usize) )
    window.Log("    -> prevsize: 0x%08x (%04x)" % (chunk.upsize, chunk.psize))
    window.Log("    -> flags: 0x%04x (%s)" % (chunk.flags, chunk.getflags(chunk.flags)))
    
    # chunks on the lookaside will "appear" busy
    if chunk.getflags(chunk.flags) == "B$":
        window.Log("    -> Lookaside[0x%02x] entry" % chunk.size)
        window.Log("        -> Flink: 0x%08x" % (chunk.addr+0x8))
    elif chunk.getflags(chunk.flags) == "F":
        window.Log("    -> Freelist[0x%02x] entry" % chunk.size)
        window.Log("        -> Flink: 0x%08x" % chunk.nextchunk) 
        window.Log("        -> Blink: 0x%08x" % chunk.prevchunk)
        

    if show_detail:
        dump = immutils.hexdump(chunk.sample)
        for a in range(0, len(dump)):
            if not a:
                window.Log("    -> First 16 bytes of data:")
                window.Log("        -> hex: \\x%s" % dump[a][0].rstrip().replace(" ", "\\x")) 
                window.Log("        -> ascii: %s" % (dump[a][1]))

def analyse_function_pointers(args, window, imm, patch=False, patch_val=False, restore=False, restore_val=False):

    fn_ptr = []
    exclude = []
    ndx = INDEXER  
    # create the datatype object    
    dt = libdatatype.DataTypes(imm)
                
    # get the address and size
    if (patch_val == "all" or restore_val == "all") or (not patch_val and not restore_val):
        try:
            addr = int(args[args.index("-a")+1],16)
            size = int(args[args.index("-s")+1],16)
            mem = imm.readMemory( addr, size )
            if not mem:
                return "(-) Error: Couldn't read any memory at address: 0x%08x" % addr
            ret = dt.Discover( mem, addr, what = 'pointers' )
        except:
            window.Log("")
            window.Log("(-) You need to specify the address and size using -a and -s")
            return "(-) You need to specify the address and size using -a and -s"

    # we are discovering..
    if not patch and not restore:
        fp=0
        for obj in ret:
            if obj.isFunctionPointer():
                fp+=1
                            
        window.Log("")
        window.Log( "(+) Found %d function pointers" % fp )
        window.Log("")
                    
        for obj in ret:
            if obj.isFunctionPointer():
                msg = "0x%08x -> 0x%08x in %s at the %s section" % (obj.address, obj.data, obj.mem.getOwner(), obj.mem.section)
                window.Log( "%s" % ( msg ), address = obj.address)
                
        window.Log("-" * 60)
        return "(+) Dumped function pointers!"
    # we are patching...
    elif patch and not restore:
                    
        # lets save all of the function pointers in case we have to restore..
        memory_dict = {}
                     
        # we are patching all pointers
        if patch_val == "all":
            if "-e" in args:
                exclude = []
                exclude_addresses = args[args.index("-e")+1]
                exclude_list = exclude_addresses.split(",")
            for e in exclude_list:
                exclude.append(int(e,16))
                
            window.Log("%s" % exclude)           
            if ret:
                window.Log("")
                for obj in ret:
                    if obj.isFunctionPointer() and obj.address not in exclude:
                        # remember what we are modifying
                        memory_dict[obj.address] = obj.data
                        window.Log( "(+) Modifying pointer: 0x%08x to 0x%08x" % (obj.address, ndx), obj.address)
                        imm.writeLong( obj.address, ndx )
                        ndx += 1
                        fn_ptr.append( obj )
                            
                # save the function pointers
                imm.addKnowledge("fps_%s" % addr, memory_dict, force_add = 1)
                hook = FunctionTriggeredHook( fn_ptr, window )
                hook.add( "modptr_%08x" % addr )
                window.Log("-" * 47)
                return "(+) Hooking on %d Functions" % len( fn_ptr )
            else:
                return "(-) No Function pointers found at address 0x%08x" % patch_val
                        
        # we are patching a specific pointer
        elif patch_val != "all": 
            patch_val = int(patch_val,16)                      
            mem = imm.readMemory( patch_val, 4 )
            if not mem:
                return "(-) Error: Couldn't read any memory at address: 0x%08x" % addr
            ret = dt.Discover( mem, patch_val, what = 'pointers' )
            if ret:
                for obj in ret:
                    if obj.isFunctionPointer() and obj.address == patch_val:
                        memory_dict[obj.address] = obj.data
                        window.Log("")
                        window.Log( "(+) Modifying pointer: 0x%08x to 0x%08x" % (obj.address, ndx), obj.address)
                        imm.writeLong( obj.address, ndx )
                        ndx += 1
                        fn_ptr.append( obj )
                                    
                # save the function pointer we are patching
                imm.addKnowledge("fp_%x" % patch_val, memory_dict, force_add = 1)
                hook = FunctionTriggeredHook( fn_ptr, window )
                hook.add( "modptr_%08x" % patch_val )
                window.Log("-" * 47)
                return "Hooking on function pointer 0x%08x" % obj.address
            else:
                window.Log("")
                window.Log("(-) No Function pointer found at address 0x%08x" % patch_val)
                window.Log("")
                return "(-) No Function pointer found at address 0x%08x" % patch_val
                        
    # we are restoring...
    elif restore and not patch:
                    
        restore_dict = False
        for knowledge in imm.listKnowledge():
            if re.match("fp", knowledge):
                restore_dict = imm.getKnowledge(knowledge)
                imm.forgetKnowledge(knowledge)
                    
        if restore_dict:
            for faddy, pointer in restore_dict.iteritems():
                imm.writeLong( faddy, pointer )
            window.Log("")   
            window.Log("(+) Restored function pointer(s)...")
            window.Log("-" * 40)
            return "(+) Restored function pointer(s)..."
        else:
            window.Log("")
            window.Log("(!) Function pointer already restored...")
            window.Log("-" * 40)
            return "(!) Function pointer already restored..."


def dump_segment_structure(pheap, window, imm, heap):
    """
    allows the user to dump the segment structure(s) from a heap
    
    arguments:
    - obj heap
    - obj window
    - obj imm
    - int heap
    
    return:
    - string showing the segment is dumped
    """
    for segment in pheap.Segments:
        window.Log("")
        window.Log("-" * 19)
        window.Log("Segment: 0x%08x" % segment.BaseAddress)
        window.Log("-" * 19)
        window.Log("")
        entry_0 = imm.readMemory(segment.BaseAddress, 4)
        entry_0 = struct.unpack("L", entry_0)[0]
        entry_1 = imm.readMemory(segment.BaseAddress+0x4, 4)
        entry_1 = struct.unpack("L", entry_1)[0]
        signature = imm.readMemory(segment.BaseAddress+0x8, 4)
        signature = struct.unpack("L", signature)[0]
        flags = imm.readMemory(segment.BaseAddress+0xc, 4)
        flags = struct.unpack("L", flags)[0]
        heap_ = imm.readMemory(segment.BaseAddress+0x10, 4)
        heap_ = struct.unpack("L", heap_)[0]
        LargestUncommitedRange = imm.readMemory(segment.BaseAddress+0x14, 4)
        LargestUncommitedRange = struct.unpack("L", LargestUncommitedRange)[0]
        BaseAddress = imm.readMemory(segment.BaseAddress+0x18, 4)
        BaseAddress = struct.unpack("L", BaseAddress)[0] 
        NumberOfPages = imm.readMemory(segment.BaseAddress+0x1c, 4)
        NumberOfPages = struct.unpack("L", NumberOfPages)[0]
        FirstEntry = imm.readMemory(segment.BaseAddress+0x20, 4)
        FirstEntry = struct.unpack("L", FirstEntry)[0]
        LastValidEntry = imm.readMemory(segment.BaseAddress+0x24, 4)
        LastValidEntry = struct.unpack("L", LastValidEntry)[0]
        NumberOfUncommitedPages = imm.readMemory(segment.BaseAddress+0x28, 4)
        NumberOfUncommitedPages = struct.unpack("L", NumberOfUncommitedPages)[0]
        NumberOfUncommitedRanges = imm.readMemory(segment.BaseAddress+0x2c, 4)
        NumberOfUncommitedRanges = struct.unpack("L", NumberOfUncommitedRanges)[0]
        UnCommitedRanges = imm.readMemory(segment.BaseAddress+0x30, 4)
        UnCommitedRanges = struct.unpack("L", UnCommitedRanges)[0]
        AllocatorBackTraceIndex = imm.readMemory(segment.BaseAddress+0x34, 2)
        AllocatorBackTraceIndex = struct.unpack("H", AllocatorBackTraceIndex)[0]
        Reserved = imm.readMemory(segment.BaseAddress+0x36, 2)
        Reserved = struct.unpack("H", Reserved)[0]
        LastEntryInSegment = imm.readMemory(segment.BaseAddress+0x38, 4)
        LastEntryInSegment = struct.unpack("L", LastEntryInSegment)[0]                                      
        window.Log("+0x000 Entry  (high)            : 0x%08x" % entry_0,entry_0)
        window.Log("+0x000 Entry  (low)             : 0x%08x" % entry_1,entry_1)
        window.Log("+0x008 Signature                : 0x%08x" % signature,signature)
        window.Log("+0x00c Flags                    : 0x%08x" % flags,flags)
        window.Log("+0x010 heap                     : 0x%08x" % heap_,heap_)
        window.Log("+0x014 LargestUncommitedRange   : 0x%08x" % LargestUncommitedRange,LargestUncommitedRange)
        window.Log("+0x018 BaseAddress              : 0x%08x" % BaseAddress,BaseAddress)
        window.Log("+0x01c NumberOfPages            : 0x%08x" % NumberOfPages,NumberOfPages)
        window.Log("+0x020 FirstEntry               : 0x%08x" % FirstEntry,FirstEntry)
        window.Log("+0x024 LastValidEntry           : 0x%08x" % LastValidEntry,LastValidEntry)
        window.Log("+0x028 NumberOfUncommitedPages  : 0x%08x" % NumberOfUncommitedPages,NumberOfUncommitedPages)
        window.Log("+0x02c NumberOfUncommitedRanges : 0x%08x" % NumberOfUncommitedRanges,NumberOfUncommitedRanges)
        window.Log("+0x030 UnCommitedRanges         : 0x%08x" % UnCommitedRanges,UnCommitedRanges)
        window.Log("+0x034 AllocatorBackTraceIndex  : 0x%08x" % AllocatorBackTraceIndex,AllocatorBackTraceIndex)
        window.Log("+0x036 Reserved                 : 0x%08x" % Reserved,Reserved)
        window.Log("+0x038 LastEntryInSegment       : 0x%08x" % LastEntryInSegment,LastEntryInSegment)
    return "(+) Dumped all Heap Segmements in heap 0x%08x" % heap

def analyse_heap(heap, imm, window):
    """
    allows you to dump the _heap structure
    
    arguments: 
    - int heap
    - obj imm
    - obj window
    
    return:
    - string showing the heap is dumped
    """
    if heap and ( heap in imm.getHeapsAddress() ):
        i = 0 
        v = 0
        pheap = imm.getHeap( heap )
        window.Log("--------------------------------------------------")
        window.Log("Heap structure @ 0x%08x" % heap)
        window.Log("--------------------------------------------------")
        window.Log("+0x000 Entry                          : 0x%08x" % heap, heap)

        if OS < 6.0:
            window.Log("+0x008 Signature                      : 0x%08x" % pheap.Signature, pheap.Signature)
            window.Log("+0x00c Flags                          : 0x%08x" % pheap.Flags, pheap.Flags)
            window.Log("+0x010 Forceflags                     : 0x%08x" % pheap.ForceFlags, pheap.ForceFlags)
            window.Log("+0x014 VirtualMemoryThreshold         : 0x%08x" % pheap.VirtualMemoryThreshold, pheap.VirtualMemoryThreshold) 
            window.Log("+0x018 SegmentReserve                 : 0x%08x" % pheap.SegmentReserve, pheap.SegmentReserve)
            window.Log("+0x01C SegmentCommit                  : 0x%08x" % pheap.SegmentCommit, pheap.SegmentCommit)
        elif OS >= 6.0:
            window.Log("+0x008 SegmentSignature               : 0x%08x" % pheap.Signature, pheap.Signature)
            window.Log("+0x00c SegmentFlags                   : 0x%08x" % pheap.Flags, pheap.Flags)
            SegmentListEntry = imm.readMemory(heap+0x14, 4)
            SegmentListEntry = struct.unpack("L", SegmentListEntry)[0]
            #window.Log("+0x010 SegmentListEntry               : 0x%08x" % pheap.ForceFlags, pheap.ForceFlags)
            window.Log("+0x010 SegmentListEntry               : 0x%08x" % SegmentListEntry, SegmentListEntry)
            window.Log("+0x018 Heap                           : 0x%08x" % pheap.SegmentReserve, pheap.SegmentReserve)
            window.Log("+0x01C BaseAddress                    : 0x%08x" % pheap.SegmentCommit, pheap.SegmentCommit)
        if OS < 6.0:
            window.Log("+0x020 DeCommitFreeBlockThreshold     : 0x%08x" % pheap.DeCommitFreeBlockThreshold, pheap.DeCommitFreeBlockThreshold)
            window.Log("+0x024 DeCommitTotalBlockThreshold    : 0x%08x" % pheap.DeCommitTotalBlockThreshold, pheap.DeCommitTotalBlockThreshold)
            window.Log("+0x028 TotalFreeSize                  : 0x%08x" % pheap.TotalFreeSize, pheap.TotalFreeSize)
        elif OS >= 6.0:
            window.Log("+0x020 NumberOfPages                  : 0x%08x" % pheap.NumberOfPages, pheap.NumberOfPages)
            window.Log("+0x024 FirstEntry                     : 0x%08x" % pheap.FirstEntry, pheap.FirstEntry)
            window.Log("+0x028 LastValidEntry                 : 0x%08x" % pheap.TotalFreeSize, pheap.TotalFreeSize)
            
        if OS < 6.0:
            window.Log("+0x02c MaximumAllocationSize          : 0x%08x" % pheap.MaximumAllocationSize, pheap.MaximumAllocationSize)
        elif OS >= 6.0:
            NumberOfUnCommittedPages = imm.readMemory(heap+0x2c, 4)
            NumberOfUnCommittedPages = struct.unpack("L", NumberOfUnCommittedPages)[0]
            window.Log("+0x02c NumberOfUnCommittedPages       : 0x%08x" % NumberOfUnCommittedPages, NumberOfUnCommittedPages)
        
        # libheap does not have some members, so we are on our own
        ProcessHeapsListIndex = imm.readMemory(heap+0x30, 2)
        ProcessHeapsListIndex = struct.unpack("H", ProcessHeapsListIndex)[0]
        if OS < 6.0:            
            window.Log("+0x030 ProcessHeapsListIndex          : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)
        elif OS >= 6.0:
            window.Log("+0x030 NumberOfUnCommittedRanges      : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)
            # libheap does not have some members, so we are on our own
            SegmentAllocatorBackTraceIndex = imm.readMemory(heap+0x34, 2)
            SegmentAllocatorBackTraceIndex = struct.unpack("H", SegmentAllocatorBackTraceIndex)[0]

            Reserved = imm.readMemory(heap+0x36, 2)
            Reserved = struct.unpack("H", Reserved)[0]

            UCRSegmentList = imm.readMemory(heap+0x38, 4)
            UCRSegmentList = struct.unpack("L", UCRSegmentList)[0]
            
            UCRSegmentList1 = imm.readMemory(heap+0x3c, 4)
            UCRSegmentList1 = struct.unpack("L", UCRSegmentList1)[0]
                                    
            window.Log("+0x034 SegmentAllocatorBackTraceIndex : 0x%08x" % SegmentAllocatorBackTraceIndex, SegmentAllocatorBackTraceIndex)
            window.Log("+0x036 Reserved                       : 0x%08x" % Reserved, Reserved)
            window.Log("+0x038 UCRSegmentList                 : 0x%08x%08x" % (UCRSegmentList,UCRSegmentList1))
        # uncommited range segments
        if OS < 6.0:
            window.Log("+0x032 HeaderValidateLength           : 0x%08x" % pheap.HeaderValidateLength, pheap.HeaderValidateLength)
            window.Log("+0x034 HeaderValidateCopy             : 0x%08x" % pheap.HeaderValidateCopy, pheap.HeaderValidateCopy)
            window.Log("+0x038 NextAvailableTagIndex          : 0x%08x" % pheap.NextAvailableTagIndex, pheap.NextAvailableTagIndex)
            window.Log("+0x03a MaximumTagIndex                : 0x%08x" % pheap.MaximumTagIndex, pheap.MaximumTagIndex)
            window.Log("+0x03c TagEntries                     : 0x%08x" % pheap.TagEntries, pheap.TagEntries)
            
            window.Log("+0x040 UCRSegments                    : 0x%08x" % pheap.UCRSegments, pheap.UCRSegments)
            window.Log("+0x044 UnusedUncommittedRanges        : 0x%08x" % pheap.UnusedUnCommittedRanges, pheap.UnusedUnCommittedRanges)
            window.Log("+0x048 AlignRound                     : 0x%08x" % pheap.AlignRound, pheap.AlignRound)
            window.Log("+0x04c AlignMask                      : 0x%08x" % pheap.AlignMask, pheap.AlignMask)
        elif OS >= 6.0:
            window.Log("+0x040 Flags                          : 0x%08x" % pheap.Flags, pheap.Flags)
            window.Log("+0x044 ForceFlags                     : 0x%08x" % pheap.ForceFlags, pheap.ForceFlags)
            window.Log("+0x048 CompatibilityFlags             : 0x%08x" % pheap.AlignRound, pheap.AlignRound)
            window.Log("+0x04c EncodeFlagMask                 : 0x%08x" % pheap.AlignMask, pheap.AlignMask)
                    
        # lots of blocks..
        if OS < 6.0:
            window.Log("+0x050 VirtualAllocedBlocks            ")
            for block in pheap.VirtualAllocedBlock:
                v += 1
                window.Log("       VirtualAllocedBlock %d          : 0x%08x" % (v,block), block)
            window.Log("+0x058 Segments")
            for segment in pheap.Segments:
                i += 1
                window.Log("       Segment %d                      : 0x%08x" % (i,segment.BaseAddress), segment.BaseAddress)                                      
        
            FreelistBitmap = imm.readMemory(heap+0x158, 4)
            FreelistBitmap = struct.unpack("L", FreelistBitmap)[0]
            window.Log("+0x158 FreelistBitmap                 : 0x%08x" % FreelistBitmap, FreelistBitmap)
            window.Log("+0x16a AllocatorBackTraceIndex        : 0x%08x" % pheap.AllocatorBackTraceIndex, pheap.AllocatorBackTraceIndex)
            NonDedicatedListLength = imm.readMemory(heap+0x16c, 4)
            NonDedicatedListLength = struct.unpack("L", NonDedicatedListLength)[0]
            window.Log("+0x16c NonDedicatedListLength         : 0x%08x" % NonDedicatedListLength, NonDedicatedListLength)
            if OS < 6.0:
                window.Log("+0x170 LargeBlocksIndex               : 0x%08x" % pheap.LargeBlocksIndex, pheap.LargeBlocksIndex)
            window.Log("+0x174 PseudoTagEntries               : 0x%08x" % pheap.PseudoTagEntries)
            window.Log("+0x178 Freelist[0]                    : 0x%08x" % (heap+0x178), (heap+0x178))
            window.Log("+0x578 LockVariable                   : 0x%08x" % pheap.LockVariable, pheap.LockVariable)
            window.Log("+0x57c CommitRoutine                  : 0x%08x" % pheap.CommitRoutine, pheap.CommitRoutine)
                        
            FrontEndHeap = imm.readMemory(heap+0x580, 4)
            FrontEndHeap = struct.unpack("L", FrontEndHeap)[0]
            
            FrontHeapLockCount = imm.readMemory(heap+0x584, 2)
            FrontHeapLockCount = struct.unpack("H", FrontHeapLockCount)[0]
                        
            FrontEndHeapType = imm.readMemory(heap+0x586, 1)
            FrontEndHeapType = struct.unpack("B", FrontEndHeapType)[0]
                        
            LastSegmentIndex = imm.readMemory(heap+0x587, 1)
            LastSegmentIndex = struct.unpack("B", LastSegmentIndex)[0]
                        
            window.Log("+0x580 FrontEndHeap                   : 0x%08x" % FrontEndHeap, FrontEndHeap)
            window.Log("+0x584 FrontHeapLockCount             : 0x%08x" % FrontHeapLockCount, FrontHeapLockCount)
            window.Log("+0x586 FrontEndHeapType               : 0x%08x" % FrontEndHeapType, FrontEndHeapType)
            window.Log("+0x587 LastSegmentIndex               : 0x%08x" % LastSegmentIndex, LastSegmentIndex)         
        
        elif OS >= 6.0:
            Encoding = imm.readMemory(heap+0x50, 4)
            Encoding = struct.unpack("L", Encoding)[0]            
            window.Log("+0x050 Encoding                       : 0x%08x" % Encoding, Encoding)
            window.Log("+0x058 PointerKey                     : 0x%08x" % pheap.PointerKey, pheap.PointerKey)
            Interceptor = imm.readMemory(heap+0x5c, 4)
            Interceptor = struct.unpack("L", Interceptor)[0]            
            window.Log("+0x05c Interceptor                    : 0x%08x" % Interceptor, Interceptor)
            window.Log("+0x060 VirtualMemoryThreshold         : 0x%08x" % pheap.VirtualMemoryThreshold, pheap.VirtualMemoryThreshold)          
            window.Log("+0x064 Signature                      : 0x%08x" % pheap.Signature, pheap.Signature)
            window.Log("+0x068 SegmentReserve                 : 0x%08x" % pheap.SegmentReserve, pheap.SegmentReserve)
            window.Log("+0x06c SegmentCommit                  : 0x%08x" % pheap.SegmentCommit, pheap.SegmentCommit)
            DeCommitFreeBlockThreshold = imm.readMemory(heap+0x70, 4)
            DeCommitFreeBlockThreshold = struct.unpack("L", DeCommitFreeBlockThreshold)[0]  
            DeCommitTotalFreeThreshold = imm.readMemory(heap+0x74, 4)
            DeCommitTotalFreeThreshold = struct.unpack("L", DeCommitTotalFreeThreshold)[0]  
            window.Log("+0x070 DeCommitFreeBlockThreshold     : 0x%08x" % DeCommitFreeBlockThreshold, DeCommitFreeBlockThreshold)
            window.Log("+0x074 DeCommitTotalFreeThreshold     : 0x%08x" % DeCommitTotalFreeThreshold, DeCommitTotalFreeThreshold)
            window.Log("+0x078 TotalFreeSize                  : 0x%08x" % pheap.TotalFreeSize, pheap.TotalFreeSize)
            MaximumAllocationSize = imm.readMemory(heap+0x7c, 4)
            MaximumAllocationSize = struct.unpack("L", MaximumAllocationSize)[0]              
            window.Log("+0x07c MaximumAllocationSize          : 0x%08x" % MaximumAllocationSize, MaximumAllocationSize)
            window.Log("+0x080 ProcessHeapsListIndex          : 0x%08x" % pheap.ProcessHeapsListIndex, pheap.ProcessHeapsListIndex)
            window.Log("+0x082 HeaderValidateLength           : 0x%08x" % pheap.HeaderValidateLength, pheap.HeaderValidateLength)
            window.Log("+0x084 HeaderValidateCopy             : 0x%08x" % pheap.HeaderValidateCopy, pheap.HeaderValidateCopy)
            window.Log("+0x088 NextAvailableTagIndex          : 0x%08x" % pheap.NextAvailableTagIndex, pheap.NextAvailableTagIndex)
            window.Log("+0x08a MaximumTagIndex                : 0x%08x" % pheap.MaximumTagIndex, pheap.MaximumTagIndex)
            window.Log("+0x08c TagEntries                     : 0x%08x" % pheap.TagEntries, pheap.TagEntries)
            UCRList1 = imm.readMemory(heap+0x90, 4)
            UCRList1 = struct.unpack("L", UCRList1)[0]
            UCRList2 = imm.readMemory(heap+0x94, 4)
            UCRList2 = struct.unpack("L", UCRList2)[0]      
            window.Log("+0x090 UCRList                        : 0x%08x%08x" % (UCRList1, UCRList2))
            window.Log("+0x098 AlignRound                     : 0x%08x" % pheap.AlignRound, pheap.AlignRound)
            window.Log("+0x09c AlignMask                      : 0x%08x" % pheap.AlignMask, pheap.AlignMask)
            VirtualAllocdBlocks1 = imm.readMemory(heap+0x0a0, 4)
            VirtualAllocdBlocks1 = struct.unpack("L", VirtualAllocdBlocks1)[0]
            VirtualAllocdBlocks2 = imm.readMemory(heap+0x0a4, 4)
            VirtualAllocdBlocks2 = struct.unpack("L", VirtualAllocdBlocks2)[0]  
            window.Log("+0x0a0 VirtualAllocdBlocks            : 0x%08x%08x" % (VirtualAllocdBlocks1, VirtualAllocdBlocks2))
            SegmentList1 = imm.readMemory(heap+0x0a8, 4)
            SegmentList1 = struct.unpack("L", SegmentList1)[0]
            SegmentList2 = imm.readMemory(heap+0x0ac, 4)
            SegmentList2 = struct.unpack("L", SegmentList2)[0]
            window.Log("+0x0a8 SegmentList                    : 0x%08x%08x" % (SegmentList1, SegmentList2))            
            window.Log("+0x0b0 AllocatorBackTraceIndex        : 0x%08x" % pheap.AllocatorBackTraceIndex, pheap.AllocatorBackTraceIndex)
            NonDedicatedListLength = imm.readMemory(heap+0x0b4, 4)
            NonDedicatedListLength = struct.unpack("L", NonDedicatedListLength)[0]
            BlocksIndex = imm.readMemory(heap+0x0b8, 4)
            BlocksIndex = struct.unpack("L", BlocksIndex)[0]            
            UCRIndex = imm.readMemory(heap+0x0bc, 4)
            UCRIndex = struct.unpack("L", UCRIndex)[0] 
            FreeLists = imm.readMemory(heap+0x0c4, 4)
            FreeLists = struct.unpack("L", FreeLists)[0]
            window.Log("+0x0b4 NonDedicatedListLength         : 0x%08x" % NonDedicatedListLength, NonDedicatedListLength) 
            window.Log("+0x0b8 BlocksIndex                    : 0x%08x" % BlocksIndex, BlocksIndex)   
            window.Log("+0x0bc UCRIndex                       : 0x%08x" % UCRIndex, UCRIndex)      
            window.Log("+0x0c0 PseudoTagEntries               : 0x%08x" % pheap.PseudoTagEntries, pheap.PseudoTagEntries)
            window.Log("+0x0c4 FreeLists                      : 0x%08x" % FreeLists, FreeLists)      
            window.Log("+0x0cc LockVariable                   : 0x%08x" % pheap.LockVariable, pheap.LockVariable)
            window.Log("+0x0d0 CommitRoutine                  : 0x%08x" % pheap.CommitRoutine, pheap.CommitRoutine)
            FrontEndHeap = imm.readMemory(heap+0x0d4, 4)
            FrontEndHeap = struct.unpack("L", FrontEndHeap)[0]
            FrontHeapLockCount = imm.readMemory(heap+0x0d8, 2)
            FrontHeapLockCount = struct.unpack("H", FrontHeapLockCount)[0]
            FrontEndHeapType = imm.readMemory(heap+0x0da, 2)
            FrontEndHeapType = struct.unpack("H", FrontEndHeapType)[0]
            Counters = imm.readMemory(heap+0x0dc, 4)
            Counters = struct.unpack("L", Counters)[0]
            TuningParameters = imm.readMemory(heap+0x0d8, 4)
            TuningParameters = struct.unpack("L", TuningParameters)[0]
            window.Log("+0x0d4 FrontEndHeap                   : 0x%08x" % FrontEndHeap, FrontEndHeap) 
            window.Log("+0x0d8 FrontHeapLockCount             : 0x%04x" % FrontHeapLockCount, FrontHeapLockCount)   
            window.Log("+0x0da FrontEndHeapType               : 0x%04x" % FrontEndHeapType, FrontEndHeapType)              
            window.Log("+0x0dc Counters                       : 0x%08x" % Counters, Counters)  
            window.Log("+0x130 TuningParameters               : 0x%08x" % TuningParameters, TuningParameters)
    return "(+) Dumped the heap structure 0x%08x" % heap

# main entry
# ==========
# TODO: complete refactoring of code.
# - Graphing engine Class
# - FrontEnd/BackEnd Classes
# - any other ideas ??
def main(args):
    imm = immlib.Debugger()
    
    # set the global OS version
    global OS
    OS = imm.getOsRelease()
    
    # custom window
    if not opennewwindow:            
        window = imm.getKnowledge(tag)
        if window and not window.isValidHandle():
            imm.forgetKnowledge(tag)
            del window
            window = None
        
        if not window:
            window = imm.createTable("Heaper - by mr_me", ["Address", "Information"])
            imm.addKnowledge(tag, window, force_add = 1)

    if not args:
        banner(window)
        return usage(window, imm)
    banner(window)
    
    if len(args) > 1:
        cmds = set_up_usage()
        
        # show the user how to do things
        # ==============================
        if args[0].lower().strip() == "help":
            if args[1].lower().strip() in available_commands:
                usageText = cmds[args[1].lower().strip()].usage.split("\n")
                for line in usageText:
                    window.Log(line)
                return "(+) Good luck!"
            else:
                usage(window, imm)
                return "(-) Invalid command specified!"
        
    # commands that only require one argument
    # =======================================
    if len(args) == 1:
        if args[0].lower().strip() in available_commands:
            if args[0].lower().strip() == "dumpheaps" or args[0].lower().strip() == "dh":
                return dump_heap(imm, window)
            elif args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
                return dump_peb(imm,window)
            elif args[0].lower().strip() == "dumpteb" or args[0].lower().strip() == "dt":
                return dump_teb(imm,window)
            elif args[0].lower().strip() == "help" or args[0].lower().strip() == "-h":
                return usage(window, imm)
            # update functionality
            elif args[0].lower().strip() == "update" or args[0].lower().strip() == "u":
                
                try:
                    f = urllib2.urlopen("https://raw.github.com/mrmee/heaper/master/heaper.py")
                    latest_build = f.read()
                    latest_build2 = latest_build.split("\r")
                    f.close()
                except:
                    window.Log("(-) Please check your internet connection")
                    return "(-) Please check your internet connection"
                
                window.Log("")
                f = open(inspect.getfile(inspect.currentframe()),"r")
                current_build = f.read()
                current_build2 = current_build.split("\r")
                f.close()
                
                if githash("".join(latest_build2)) != githash("".join(current_build2)):
                    window.Log("(!) Detected older version...")
                    window.Log("(!) Updating...")
                    write_new_file = open(inspect.getfile(inspect.currentframe()),'w')
                    for lines in latest_build2:
                        write_new_file.write(lines)
                    write_new_file.close()
                    window.Log("(!) Update complete!")
                    return "(!) Update complete!" 
                else:
                    window.Log("(+) This version is the latest version...")
                    return "(!) This version is the latest version..."
                
            else:
                window.Log("")
                window.Log("(-) Invalid number of arguments!")
                window.Log("(!) Try '!heaper help %s'" % args[0].lower().strip())
                window.Log("-" * 32)
                return "(-) Invalid number of arguments"
        else:
            usage(imm)
            return "(-) Invalid command specified!"
    
    # the main entry into the arguments
    # =================================
    elif len(args) >= 2:
        graphic_structure = False
        custfilename = False
        if args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
                if args[1] == "-m":
                    dump_peb(imm,window,True)
                    
        elif args[0].lower().strip() == "patch" or args[0].lower().strip() == "p":
            if args[1].lower().strip() == "peb":
                window.Log("")
                if patch_PEB(imm,window):
                    return "(+) Patching complete!"
                else:
                    return "(-) This processes PEB has already been patched!"
                    
        # commands that require use of a heap
        # ===================================
        if (args[0].lower().strip() in available_commands and args[0].lower().rstrip() != "help" 
            and args[0].lower().rstrip() != "-h"):
                        
            # check if we are graphing, if so, do we have a custom filename?
            if "-g" in args:
                if not pydot:
                    window.Log("(-) Please ensure pydot, pyparser and graphviz are installed")
                    window.Log("    when using the graphing functionaility.")
                    return "(-) Please ensure pydot, pyparser and graphviz are installed!"
                graphic_structure = True
                if "-o" in args:
                    try:
                        custfilename = True
                        filename = args[args.index("-o")+1]
                    except:
                        return "no filename specified"   

            # analyse a heap structure
            # ========================
            if args[0].lower().strip() == "analyseheap" or args[0].lower().strip() == "ah":
                try:
                    heap = args[1].lower().strip()
                    heap = int(heap,16)
                except:
                    return "Invalid heap address"
                
                analyse_heap(heap, imm, window)
                window.Log("=" * 50)    
                
            # analyse the frontend
            # ====================
            elif args[0].lower().strip() == "analysefrontend" or args[0].lower().strip() == "af":

                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    # special case, incase we have a overwrite in a userblock
                    # waiting on immunity to patch their code see: http://pastie.org/3551958
                    for heap_handle in imm.getHeapsAddress():
                        if heap_handle == int(args[1].lower().strip(),16):
                            window.Log("") 
                            window.Log("(!) The heap address supplied is valid, but the heap has a chunk overwrite", address = heap_handle, focus = 1)
                            return "(!) Cannot analyse the heap if there is a chunk overwrite"
                        
                    window.Log("")
                    window.Log("(-) Invalid heap address or cannot read address!")
                    return "(-) Invalid heap address or cannot read address!"
        
                if OS < 6.0:
                    FrontEndHeap = imm.readMemory(heap+0x580, 4)
                    (FrontEndHeap) = struct.unpack("L", FrontEndHeap)                    
                    window.Log("-" * 77)
                    window.Log("Lookaside List structure @ 0x%08x" % FrontEndHeap)
                    window.Log("-" * 77)
                    if custfilename:
                        dump_lal(imm, pheap, graphic_structure, window, filename)
                    else:
                        dump_lal(imm, pheap, graphic_structure, window)
                        
                elif OS >= 6.0:
                    if pheap.FrontEndHeapType == 0x2:
                        switch = {}
                        switch["bucket_flag"] = False
                        switch["UserBlockCache_flag"] = False
                        switch["UserBlocks_flag"] = False
                        switch["Bin_size"] = False
                        
                        if "-s" in args:
                            switch["Bin_size"] = args[args.index("-s")+1]
                            
                        if "-b" in args:
                            switch["bucket_flag"] = True
                        if "-c" in args:
                            switch["UserBlockCache_flag"] = True
                        if "-u" in args:
                            switch["UserBlocks_flag"] = True
                        if "-b" not in args and "-c" not in args and "-u" not in args:
                            usageText = cmds["analysefrontend"].usage.split("\n")
                            for line in usageText:
                                window.Log(line)
                            window.Log("=" * 59)
                            return "(!) Please specify a correct option"
                        
                        window.Log("")
                        window.Log("-" * 28)
                        window.Log("LFH information @ 0x%08x" % (pheap.LFH.address),pheap.LFH.address)
                        window.Log("-" * 28)
                        if custfilename:
                            dump_lfh(imm, pheap, graphic_structure, window, switch, filename)
                        else:
                            dump_lfh(imm, pheap, graphic_structure, window, switch)
                    elif pheap.FrontEndHeapType == 0x1:
                        window.Log("(?) You are running windows 7 yet the Lookaside list is being used?")
                        return "(?) You are running windows 7 yet the Lookaside list is being used?"
            
            # analyse the backend
            # ===================
            elif args[0].lower().strip() == "analysebackend" or args[0].lower().strip() == "ab":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("")
                    window.Log("(-) Invalid heap address! Try '!heaper help ab'")
                    window.Log("-" * 47)
                    return "Invalid heap address! Try '!heaper help ab'"
                
                if OS < 6.0:
                    
                    if pheap.HeapCache:
                        window.Log("-" * 62)
                        window.Log("FreeList structure @ 0x%08x (HeapCache active)" % (heap+0x178))
                        window.Log("- use '!heaper ahc 0x%08x' to dump the HeapCache separately" % (heap+0x178))
                        window.Log("-" * 62)
                    else:
                        window.Log("-" * 50)
                        window.Log("FreeList structure @ 0x%08x (HeapCache inactive)" % (heap+0x178))
                        window.Log("-" * 50)
                    if graphic_structure:
                        if custfilename:
                            dump_freelist(imm, pheap, window, heap, graphic_structure, filename)
                        else:
                            dump_freelist(imm, pheap, window, heap, graphic_structure)
                    else:
                        dump_freelist(imm, pheap, window, heap, graphic_structure)
                        
                    dump_FreeListInUse(pheap, window)
                    
                    # HeapCache analysis
                    # ==================
                    if pheap.HeapCache:
                        window.Log("")
                        window.Log("HeapCache")
                        window.Log("-----------------")
                        dump_HeapCache(pheap,window,imm)
                        window.Log("")
                        window.Log("HeapCache Bitmap:")
                        window.Log("-----------------")
                        dump_HeapCache_bitmap(pheap, window)

                else:
                    if graphic_structure:
                        if custfilename:
                            dump_ListHint_and_FreeList(args, pheap, window, heap, imm, graphic_structure, filename)
                        else:
                            dump_ListHint_and_FreeList(args, pheap, window, heap, imm, graphic_structure)
                    else:
                        dump_ListHint_and_FreeList(args, pheap, window, heap, imm)
                
                window.Log("-" * 76)

            # analyse heap cache if it exists
            # ===============================
            elif args[0].lower().strip() == "analyseheapcache" or args[0].lower().strip() == "ahc":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                if OS < 6.0:
                    if pheap.HeapCache:
                        dump_HeapCache_struc(pheap, window)
                        window.Log("")
                        window.Log("HeapCache:")
                        window.Log("----------")
                        dump_HeapCache(pheap,window,imm)
                        window.Log("")
                        window.Log("HeapCache Bitmap:")
                        window.Log("-----------------")
                        dump_HeapCache_bitmap(pheap, window)
                    else:
                        window.Log("")
                        window.Log("(!) The HeapCache is inactive for this heap!")
                        window.Log("(+) You can activate it by:")
                        window.Log("    1. Freeing 32 blocks into FreeList[0] simultaneously")
                        window.Log("    2. De-commiting 256 blocks")
                        return "(-) The HeapCache is inactive for this heap!"
                elif OS >= 6.0:
                    return "(-) HeapCache not supported under windows 7"
                                               
            # perform hueristics
            # ==================
            elif args[0].lower().strip() == "exploit" or args[0].lower().strip() == "exp":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                if OS < 6.0:
                    if "-f" in args:
                        set_Lookaside_chunks(imm, pheap, heap)
                        perform_heuristics(window, imm, pheap, "FrontEnd")
                    elif "-b" in args:
                        set_FreeList_chunks(imm, pheap, heap)
                        perform_heuristics(window, imm, pheap, "BackEnd")
                    else:
                        window.Log("")
                        window.Log("(-) Please provide the correct arguments. Run !heaper help <command> for help")           
                        return "(-) Please provide the correct arguments. Run !heaper help <command> for help"
                elif OS >= 6.0:
                    if "-f" in args:
                        perform_LFH_heuristics(imm, pheap, heap,window)
                    elif "-b" in args:
                        window.Log("")
                        window.Log("(!) No known exploitable techniques in the NT 6.x ListHint/FreeList :(")
                        window.Log("")
                        return "(!) No known exploitable techniques in the NT 6.x ListHint/FreeList :("
                                             
            
            # analyse FreelistInUse
            # =====================
            # TODO: change to detect xp or win7
            # check to see if this works under win7
            elif args[0].lower().strip() == "freelistinuse" or args[0].lower().strip() == "fliu":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                window.Log("")
                
                if len(args) > 2:
                    if args[2] == "-p":
                        window.Log("")
                        if args[3] and int(args[3],16) in range(0x00,0x7f): 
                            set_FreeListInUse(int(args[3],16),window,pheap,imm,heap)
                            window.Log("(+) Patched FreeList[%x]'s FreeListInUse entry!" % int(args[3],16))
                            window.Log("(+) Just run: '!heaper fliu 0x%08x' to see the changes" % heap)
                        else:
                            window.Log("(-) Failed to patch FreeListInUse for heap 0x%08x" % heap)
                      
                else:
                    window.Log("(+) Dumping the FreeListInUse for heap 0x%08x" % heap)
                    dump_FreeListInUse(pheap, window)
                
            # analyse segment chunks
            # ======================
            elif args[0].lower().strip() == "analysechunks" or args[0].lower().strip() == "ac":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"              
                show_detail = False
                start_block = 0
                finish_block = 0
                chunk_filter = 0
                for ar in args:
                    if ar == "-v":
                        show_detail = True
                    if ar == "-r":
                        try:
                            start_block = int(args[args.index(ar)+1], 16)
                            finish_block = int(args[args.index(ar)+2], 16)
                        except:
                            return "(-) Address range invalid.."
                    if ar == "-f":
                        if len(args) > 3:
                            if (args[args.index(ar)+1].lower() != "free" or args[args.index(ar)+1].lower() != "busy"):
                                chunk_filter = args[args.index(ar)+1].lower()
                            else:
                                return "(-) Invalid chunk_filter option! use free/busy only"
                        else:
                            return "(-) Invalid chunk_filter option! use free/busy only"
                window.Log("-" * 62)
                window.Log("Dumping chunks @ heap address: 0x%08x" % (heap))
                window.Log("Analyzing %d segments" % len(pheap.Segments))
                for segment in pheap.Segments:
                        window.Log("- 0x%08x" % segment.BaseAddress)
                window.Log("-" * 62)
                window.Log("Note: chunks on the lookaside will appear BUSY")
                window.Log("~" * 46)

                for chunk in pheap.chunks:
                    if start_block and finish_block:
                        if chunk.addr <= finish_block and chunk.addr >= start_block:
                            window.Log("-" * 62)
                            dumpchunk_info(chunk, show_detail, window)
                    elif chunk_filter == "busy":
                        # if they are busy and NOT on the lookaside..
                        if chunk.flags == 0x1 and not chunk.getflags(chunk.flags) == "B$":
                            window.Log("-" * 62)
                            dumpchunk_info(chunk, show_detail, window)
                    elif chunk_filter == "free":
                        # if they are free and 'busy' but are on the lookaside..
                        if chunk.flags == 0x0 or chunk.getflags(chunk.flags) == "B$":
                            window.Log("-" * 62)
                            dumpchunk_info(chunk, show_detail, window) 
                    else:
                        window.Log("-" * 62)
                        dumpchunk_info(chunk, show_detail, window)

            # dump function pointers
            # ======================
            elif args[0].lower().strip() == "dumpfunctionpointer" or args[0].lower().strip() == "dfp":
                # some checks
                patch = False
                restore = False
                if "-p" in args and "-r" not in args:
                    patch = True
                    try:
                        patch_val = args[args.index("-p")+1].lower().strip()
                    except:
                        return "(-) You must provide a argument to -p <address/all>"

                    return analyse_function_pointers(args, window, imm, True, patch_val, False, False)
                    
                elif "-r" in args and "-p" not in args:
                    restore = True
                    try:
                        restore_val = args[args.index("-r")+1].lower().strip()
                    except:
                        return "(-) You must provide a argument to -r <address/all>"
                    
                    return analyse_function_pointers(args, window, imm, False, False, True, restore_val)
                    
                elif "-r" in args and "-p" in args:
                    window.Log("")
                    window.Log("(-) You cannot patch and restore at the same time!")
                    window.Log("(!) Try '!heaper help %s'" %  args[0].lower().strip())
                    window.Log("-" * 30)
                    return "(-) You cannot patch and restore at the same time!"
            
                # if at any time we dont have the size or address (besides patching and restoring).. fail.
                if ("-s" not in args or "-a" not in args) and not patch and not restore:
                    window.Log("")
                    window.Log("(-) Need the address and size to dump function pointers")
                    window.Log("(!) Try '!heaper help %s'" %  args[0].lower().strip())
                    window.Log("-" * 30)
                    return "(-) Need the address and size to dump function pointers"
                # else just view the function pointers
                elif not patch and not restore:
                    return analyse_function_pointers(args, window, imm, False, False, False, False)
            
            # analyse segments
            # ================
            elif args[0].lower().strip() == "analysesegments" or args[0].lower().strip() == "as":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                dump_segment_structure(pheap, window, imm, heap)
            
            # hook heap API
            # =============
            elif args[0].lower().strip() == "hook" or args[0].lower().strip() == "h":
                window.Log("")
                valid_functions = ["alloc", "free", "create","destroy","realloc","size","createcs","deletecs","all","setuef"]
                # set the flags
                FilterHeap      = False
                Disable         = False
                AllocFlag       = False
                FreeFlag        = False
                CreateFlag      = False
                DestroyFlag     = False
                ReAllocFlag     = False
                sizeFlag        = False
                CreateCSFlag    = False
                DeleteCSFlag    = False
                setuefFlag      = False
                setVAllocFlag   = False
                setVFreeFlag    = False
                if len(args) > 2:
                    # !heaper command <heap> -h <func>
                    if (args[2].lower().strip() == "-h" or args[2].lower().strip() == "-u"):
                        FilterHeap = True
                        try:
                            pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                        except:
                            window.Log("(-) Invalid heap address!")
                            return "(-) Invalid heap address!"
                        if args[3].lower().strip() in valid_functions:
                            if args[3].lower().strip() == "alloc":
                                AllocFlag = True
                            elif args[3].lower().strip() == "free":
                                FreeFlag = True
                            elif args[3].lower().strip() == "all":
                                # hook everything!
                                AllocFlag       = True
                                FreeFlag        = True
                                CreateFlag      = True
                                DestroyFlag     = True
                                ReAllocFlag     = True
                                sizeFlag        = True
                                CreateCSFlag    = True
                                DeleteCSFlag    = True
                                setuefFlag      = True 
                                setVAllocFlag   = True
                                setVFreeFlag    = True  
                                                                                       
                    # !heaper command -h <func>                    
                    elif (args[1].lower().strip() == "-h" or args[1].lower().strip() == "-u"):
                        # just set it on the default heap if the user fails
                        # to supply a heap address
                        if args[1].lower().strip() == "-u":
                            Disable = True
                        
                        if args[2].lower().strip() not in valid_functions:
                            window.Log("(-) Please include a valid function to hook that doesnt require a heap")
                            return "(-) Please include a valid function to hook that doesnt require a heap"   
                                                                      
                        elif args[2].lower().strip() == "create":
                            CreateFlag      = True
                        elif args[2].lower().strip() == "destroy":
                            DestroyFlag     = True
                        elif args[2].lower().strip() == "alloc":
                            AllocFlag       = True
                        elif args[2].lower().strip() == "free":
                            FreeFlag        = True
                        elif args[2].lower().strip() == "realloc":
                            ReAllocFlag     = True                            
                        elif args[2].lower().strip() == "setuef":
                            setuefFlag      = True
                        elif args[2].lower().strip() == "va":
                            setVAllocFlag   = True
                        elif args[2].lower().strip() == "vf":
                            setVFreeFlag    = True
                        elif args[2].lower().strip() == "size":
                            sizeFlag        = True
                        elif args[2].lower().strip() == "createcs":
                            CreateCSFlag    = True
                        elif args[2].lower().strip() == "deletecs":
                            DeleteCSFlag    = True
                          
                        elif args[2].lower().strip() == "all":
                                    AllocFlag       = True
                                    FreeFlag        = True
                                    CreateFlag      = True
                                    DestroyFlag     = True
                                    ReAllocFlag     = True
                                    sizeFlag        = True
                                    CreateCSFlag    = True
                                    DeleteCSFlag    = True
                                    setuefFlag      = True 
                                    setVAllocFlag   = True
                                    setVFreeFlag    = True
                        else:
                            window.Log("(-) Please include a valid heap for this hook!")
                            return "(-) Please include a valid heap for this hook!"
                    else:
                        window.Log("(-) Please specify a function to hook/unhook using -h/-u")
                        return "(-) Please specify a function to hook/unhook using -h/-u"
                
                # display the hooks..
                # try and find a API that will automatically get the last opcode of a function..
                window.Log("-" * 30)
                if AllocFlag:
                    allocaddr = imm.getAddress("ntdll.RtlAllocateHeap" )
                    if OS < 6.0:
                        retaddr = allocaddr+0x117
                    elif OS >= 6.0:
                        retaddr = allocaddr+0xe6
                    if FilterHeap:
                        hook_output = ("(+) %s RtlAllocateHeap() for heap 0x%08x" % 
                        (hook_on(imm, ALLOCLABEL, allocaddr, "RtlAllocateHeap", retaddr, Disable, window, heap), heap))
                    else:
                        hook_output = ("(+) %s RtlAllocateHeap()" %  
                        (hook_on(imm, ALLOCLABEL, allocaddr, "RtlAllocateHeap", retaddr, Disable, window)))                      
                if FreeFlag:
                    freeaddr = imm.getAddress("ntdll.RtlFreeHeap" )
                    if OS < 6.0:
                        retaddr = freeaddr+0x130
                    elif OS >= 6.0:
                        retaddr = freeaddr+0x99
                    if FilterHeap:
                        hook_output = ("(+) %s RtlFreeHeap() for heap 0x%08x" % 
                        (hook_on(imm, FREELABEL, freeaddr, "RtlFreeHeap", retaddr, Disable, window, heap), heap))
                    else:
                        hook_output = ("(+) %s RtlFreeHeap()" % 
                        (hook_on(imm, FREELABEL, freeaddr, "RtlFreeHeap", retaddr, Disable, window)))                        
                
                # I suppose I could tidy this up in the future
                if CreateFlag:
                    # basically, I use both the wrapper function and core api so I can easily
                    # determine the 'caller', a bit lazy I know, but hell. You aint paying for this.
                    createaddr = imm.getAddress("kernel32.HeapCreate" )
                    ret_address = imm.getAddress("ntdll.RtlCreateHeap" )
                    
                    if OS < 6.0:
                        retaddr = ret_address+0x42e
                        hook_output = ("(+) %s HeapCreate()" % 
                        (hook_on(imm, CREATELABEL, createaddr, "RtlCreateHeap", retaddr, Disable, window)))
                    # if using winodws 7, lets get the ntdll!RtlpHeapGenerateRandomValue64 calculated value
                    # and set the ret offset correctly
                    elif OS >= 6.0:
                        retaddr = ret_address+0x536
                        
                        # 77be2a69 e819feffff      call    ntdll!RtlpHeapGenerateRandomValue64 (77be2887)
                        # 77be2a6e 83e01f          and     eax,1Fh
                        # 77be2a71 c1e010          shl     eax,10h
                        seed_address_hook = imm.getAddress("ntdll.RtlCreateHeap") + 0x1b0
                        hook_output = ("(+) %s HeapCreate()" % 
                        (hook_on(imm, CREATELABEL, createaddr, "RtlCreateHeap", retaddr, Disable, window, False, seed_address_hook)))                   
                
                if DestroyFlag:
                    destoryaddr = imm.getAddress("ntdll.RtlDestroyHeap")
                    if OS < 6.0:
                        retaddr = destoryaddr+0xd9
                    elif OS >= 6.0:
                        retaddr = destoryaddr+0xdc
                    hook_output = ("(+) %s RtlDestroyHeap() for heap 0x%08x" % 
                    (hook_on(imm, DESTROYLABEL, destoryaddr, "RtlDestroyHeap", retaddr, Disable, window), 0))
                if ReAllocFlag:
                    reallocaddr = imm.getAddress("ntdll.RtlReAllocateHeap")
                    if OS < 6.0:
                        retaddr = reallocaddr+0x20a
                    elif OS >= 6.0:
                        retaddr = reallocaddr+0x98
                    hook_output = ("(+) %s RtlReAllocateHeap() for heap 0x%08x" % 
                    (hook_on(imm, REALLOCLABEL, reallocaddr, "RtlReAllocateHeap", retaddr, Disable, window), 0))
                if sizeFlag:
                    sizeaddr = imm.getAddress("ntdll.RtlSizeHeap")
                    if OS < 6.0:
                        retaddr = sizeaddr+0x62
                    elif OS >= 6.0:
                        retaddr = sizeaddr+0xae
                    hook_output = ("(+) %s RtlSizeHeap() for heap 0x%08x" % 
                    (hook_on(imm, SIZELABEL, sizeaddr, "RtlSizeHeap", retaddr, Disable, window), 0))
                if CreateCSFlag:
                    create_cs_addr = imm.getAddress("ntdll.RtlInitializeCriticalSection")
                    if OS < 6.0:
                        retaddr = create_cs_addr+0x10
                    elif OS >= 6.0:
                        retaddr = create_cs_addr+0x13
                    hook_output = ("(+) %s RtlInitializeCriticalSection() for heap 0x%08x" % 
                    (hook_on(imm, CREATECSLABEL, create_cs_addr, "RtlInitializeCriticalSection", retaddr, Disable, window), 0))
                if DeleteCSFlag:
                    delete_cs_addr = imm.getAddress("ntdll.RtlDeleteCriticalSection")
                    if OS < 6.0:
                        retaddr = delete_cs_addr+0x78
                    elif OS >= 6.0:
                        retaddr = delete_cs_addr+0xef
                    hook_output = ("(+) %s RtlDeleteCriticalSection() for heap 0x%08x" % 
                    (hook_on(imm, DELETECSLABEL, delete_cs_addr, "RtlDeleteCriticalSection", retaddr, Disable, window), 0))                    
                if setuefFlag:
                    setuef_addr = imm.getAddress("kernel32.SetUnhandledExceptionFilter")
                    # no worries if you dont return here, it just wont log the return address
                    # no use under windows 7 atm
                    if OS < 6.0:
                        retaddr = setuef_addr-0x34707
                        hook_output = ("(+) %s SetUnhandledExceptionFilter() for heap 0x%08x" % 
                        (hook_on(imm, SETUEFLABEL, setuef_addr, "SetUnhandledExceptionFilter", retaddr, Disable, window), 0))                      
                    elif OS >= 6.0:
                        window.Log("(-) Hooking SetUnhandledExceptionFilter is unsupported under windows 7")
                        return "(-) Hooking SetUnhandledExceptionFilter is unsupported under windows 7"
                
                if setVAllocFlag:
                    setva_addr = imm.getAddress("kernel32.VirtualAllocEx")
                    # no worries if you dont return here, it just wont log the return address
                    if OS < 6.0:
                        retaddr = setva_addr+0x47
                    elif OS >= 6.0:
                        retaddr = setva_addr+0x101
                    hook_output = ("(+) %s VirtualAllocEx() for heap 0x%08x" % 
                    (hook_on(imm, VIRALLOCLABEL, setva_addr, "VirtualAllocEx", retaddr, Disable, window), 0))                      
                if setVFreeFlag:
                    setvf_addr = imm.getAddress("kernel32.VirtualFreeEx")
                    # no worries if you dont return here, it just wont log the return address
                    if OS < 6.0:
                        retaddr = setvf_addr+0x3d
                    elif OS >= 6.0:
                        retaddr = setvf_addr+0xd9
                    hook_output = ("(+) %s VirtualFreeEx() for heap 0x%08x" % 
                    (hook_on(imm, VIRFREELABEL, setvf_addr, "VirtualFreeEx", retaddr, Disable, window), 0))                      
                try:            
                    window.Log(hook_output)
                    window.Log("-" * 30)
                    return hook_output
                except:
                    usageText = cmds["hook"].usage.split("\n")
                    for line in usageText:
                        window.Log(line)
        # more than one command and that we cant understand
        # =================================================
        else:
            return usage(window,imm)