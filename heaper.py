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

DESC="""!heaper - a tool to analyse heap structures."""

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
paths = {"dot":"C:\\Program Files\\Graphviz 2.28\\bin\\dot.exe","twopi":"C:\\Program Files\\Graphviz 2.28\\bin\\twopi.exe",
        "neato":"C:\\Program Files\\Graphviz 2.28\\bin\\neato.exe","circo":"C:\\Program Files\\Graphviz 2.28\\bin\\circo.exe",
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

# lookaside heuristic flag
lookaside_corrupt = False

# heap restore
restore = False

# emptybins flag
emptybins = False

# hook tags
# =========
tag = "display_box"
ALLOCLABEL = "RtlAllocateHeap Hook"
FREELABEL = "RtlFreeHeap Hook"
CREATELABEL = "RtlCreateHeap Hook"
DESTROYLABEL = "RtlDestroyHeap Hook"
REALLOCLABEL = "RtlReAllocateHeap Hook"
SIZELABEL = "RtlSizeHeap Hook"
CREATECSLABEL = "RtlInitializeCriticalSection Hook"
DELETECSLABEL = "RtlDeleteCriticalSection Hook"
SETUEFLABEL = "SetUnhandledExceptionFilter Hook"
VIRALLOCLABEL = "VirtualAlloc Hook"
VIRFREELABEL = "VirtualFree Hook"

# hook flags
# ==========
FilterHeap = False
Disable = False
AllocFlag = False
FreeFlag = False
CreateFlag = False
DestroyFlag = False
ReAllocFlag = False
sizeFlag = False
CreateCSFlag = False
DeleteCSFlag = False
setuefFlag = False
setVAllocFlag = False
setVFreeFlag = False

# valid functions too hook
# ========================
valid_functions = ["alloc", "free", "create", "destroy", "realloc", "size", "createcs", "deletecs",
                   "all", "setuef", "va", "vf"]

# return heap for hooking
# =======================
rheap = False
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
    # lulz nice trick /mr_me
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
# update for WIN7 heap (rendomized)
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
            for addy in range(module_list[mod].getCodebase(),(module_list[mod].getCodebase()+module_list[mod].getCodesize())):
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
                self.window.Log("(-) RtlFreeHeap: the stack seems to broken, unable to get args")
                return 0x0
            (flags, InitialSize, MaximumSize) = struct.unpack("LLL", res)
            self.window.Log("(+) RtlCreate(0x%08x, 0x%08x, 0x%08x)" % (flags, InitialSize, MaximumSize))
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
        if self.heap:
            if self.heap == self.rheap:    
                self.window.Log("(+) Called from 0x%08x - module: %s" % (ret[0],module_list[mod].getPath()))
        else:
            self.window.Log("(+) Called from 0x%08x - module: %s" % (ret[0],module_list[mod].getPath()))

    def is_heap_alloc_free_matching(self):
        return self.heap == self.rheap
            
class function_hook_ret(LogBpHook):
    def __init__(self, window, function_name, heap=False):
        LogBpHook.__init__(self)
        self.window = window
        self.fname = function_name
        self.heap = heap
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        # our flag is set for each call
        if rheap:
            return_value = regs['EAX']
            self.window.Log("(+) %s() returned: 0x%08x" % (self.fname, return_value)) 
        else:
            self.window.Log("(+) Detected alternate %s() call" % (self.fname))
        
        self.window.Log("-" * 30)

# HeapHook_vals, HeapHook_ret,         
def hook_on(imm, LABEL, bp_address, function_name, bp_retaddress, Disable, window, heap=False):
    """
    this function creates the hooks and adds/deletes them to the instance of immdbg depending on
    if they exist in immunities knowledge database
    
    arguments:
    - obj imm
    - constant LABEL
    - obj HeapHook_vals (hooking class)
    - obj HeapHook_ret (hooking class)
    - int bp_address (function entry address)
    - int bp_retaddress (function exit address)
    - boolean Disable (disable hook or not)
    - obj window
    
    return:
    - String showing if hook succeeded or not  
    """
    if not heap:
        heap = 0x00000000
        
    hook_values = imm.getKnowledge( LABEL + "%x_values" % heap)
    hook_ret_address = imm.getKnowledge( LABEL + "%x_ret" % heap)
    if Disable:
        if not hook_values:
            window.Log("(-) Error %s: No hook to disable!" % (LABEL))
            return "(-) No hook to disable on"
        elif not hook_ret_address:
            window.Log("(-) Error %s: No hook to disable!" % (LABEL))
            return "(-) No hook to disable on"
        else:
            hook_values.UnHook()
            hook_ret_address.UnHook()
            window.Log("(+) UnHooked %s" % LABEL)
            imm.forgetKnowledge( LABEL + "%x_values" % heap)
            imm.forgetKnowledge( LABEL + "%x_ret" % heap)
            return "Unhooked"
    else:
        if not hook_values:
            if heap != 0:
                hook_values= function_hook( window, function_name, heap)
            else:
                hook_values= function_hook( window, function_name)
                
            #window.Log("match? %s" % hook_values.is_heap_alloc_free_matching())
            
            hook_values.add( LABEL + "%x_values" % heap, bp_address)
            window.Log("(+) Placed %s to retrieve the variables" % LABEL)
            
            imm.addKnowledge( LABEL + "%x_values" % heap, hook_values)
        else:
            window.Log("(?) HookAlloc for heap 0x%08x is already running")
        if not hook_ret_address:
            if heap != 0:   
                hook_ret_address= function_hook_ret( window, function_name, heap)
            else:
                hook_ret_address= function_hook_ret( window, function_name)
            hook_ret_address.add( LABEL + "_ret", bp_retaddress)
            
            window.Log("(+) Placed %s to retrieve the return value" % LABEL)
            imm.addKnowledge( LABEL + "%x_ret" % heap, hook_ret_address )            
        else:
            window.Log("(?) HookAlloc is already running")
        return "Hooked"

# banner
# ======

def win_banner(win):
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
    window.Log("update / u                            : Update to the latest version")
    window.Log("patch <function/data structure> / p   : Patch a function or datastructure")
    window.Log("exploit <heap> / exp <heap>           : Perform heuristics against the FrontEnd and BackEnd allocators")
    window.Log("                                        to determine exploitable conditions")
    window.Log("")
    window.Log("Want more info about a given command? Run !heaper help <command>")
    window.Log("Detected the operating system to be windows %s, keep this in mind." % (imm.getOsVersion()))
    window.Log("")
    return "eg: !heaper al 00480000"

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
    extusage["hook"] += "eg: !heaper hook 0x00150000 -h realloc\n"
    extusage["hook"] += "eg: !heaper hook -u all\n"
    extusage["hook"] += "eg: !heaper hook -h create\n"
    extusage["dumpteb"] = "\ndumpteb / dt : List all of the TEB entry addresses\n"
    extusage["dumpteb"] += "--------------------------------------------------------\n"
    extusage["dumpheaps"] = "\ndumpheaps / dh : Dump all the heaps for a given process\n"
    extusage["dumpheaps"] += "-------------------------------------------------------\n"
    extusage["analyseheap"] = "\nanalyseheap <heap> / ah <heap> : Analyse a particular heap\n"
    extusage["analyseheap"] += "----------------------------------------------------------\n"
    extusage["analyseheap"] += "Use -s to view the segments within that heap\n"
    extusage["analyseheap"] += "Use -l to show the lookaside list\n"
    extusage["analyseheap"] += "Use -f to show the freelist chunks available\n"
    extusage["analyseheap"] += "Use -b to show the freelist bitmap\n"
    extusage["analyseheap"] += "Use -v to show verbose information such as data structure headers\n"
    extusage["analysesegments"] = "\nanalysesegments <heap> / as <heap> : Analyse a particular heap's segment stucture(s)\n"
    extusage["analysesegments"] += "------------------------------------------------------------------------------------\n"   
    extusage["analysesegments"] += "Use -g to view a graphical representation of the heap structure\n"
    extusage["analyselal"] = "\nanalyselal <heap> / al <heap> : Analyse a particular heap's lookaside list structure\n"
    extusage["analyselal"] += "------------------------------------------------------------------------------------\n"   
    extusage["analyselal"] += "Use -g to view a graphical representation of the lookaside\n"
    extusage["analyselal"] += "Use -f to specify a filename for the graph\n"
    extusage["analysefreelist"] = "\nanalysefreelist <heap> / af <heap> : Analyse a particular heap's freelist structure\n"
    extusage["analysefreelist"] += "------------------------------------------------------------------------------------\n"   
    extusage["analysefreelist"] += "Use -g to view a graphical representation of the freelist\n"
    extusage["analysefreelist"] += "Use -f to specify a filename for the graph\n"
    extusage["analysesegments"] = "\nanalysesegment(s) <heap> / as <heap> : Analyse a particular heap's segment structure(s)\n"
    extusage["analysesegments"] += "------------------------------------------------------------------------------------\n"   
    
    extusage["patch"] = "\npatch <function/data structures> / p <function/data structures> : patch memory for the heap\n"
    extusage["patch"] += "-------------------------------------------------------------------------------------------\n" 
    extusage["patch"] += "Use 'PEB' to patch the following areas:\n"
    extusage["patch"] += " - PEB.IsDebugged\n"
    extusage["patch"] += " - PEB.ProcessHeap.Flag\n"
    extusage["patch"] += " - PEB.NtGlobalFlag\n"
    extusage["patch"] += " - PEB.LDR_DATA\n"
    extusage["patch"] += "example: !heaper patch PEB\n"
    
    extusage["analyseheapcache"] = "\nanalyseheapcache <heap> / ahc <heap> : Analyse a particular heap's cache (FreeList[0])\n"
    extusage["analyseheapcache"] += "------------------------------------------------------------------------------------\n"   
    #extusage["analyseheapcache"] += "Use -g to view a graphical representation of the heap cache (dev)\n"
    
    extusage["analysechunks"] = "\nanalysechunks <heap> / ac <heap> : Analyse a particular heap's chunks\n"
    extusage["analysechunks"] += "---------------------------------------------------------------------\n"
    extusage["analysechunks"] += "Use -r <start address> <end address> to view all the chunks between those ranges\n"
    extusage["analysechunks"] += "Use -f to chunk_filter chunks by type (free/busy) eg: !heaper ac d20000 -f busy\n"
    extusage["analysechunks"] += "Use -v to view the first 16 bytes of each chunk\n"
    extusage["dumpfunctionpointers"] = "\ndumpfunctionpointers / dfp : Dump all the function pointers of the current process\n"
    extusage["dumpfunctionpointers"] += "-----------------------------------------------------------------------------------\n"
    extusage["dumpfunctionpointers"] += "Use -p <addr/all> to patch a function pointer or all function pointers in the .data segment\n"
    extusage["dumpfunctionpointers"] += "Use -r <addr/all> to restore a function pointer or all function pointers in the .data segment\n"
    extusage["dumpfunctionpointers"] += "eg: !heaper dfp -r 005000f0\n"
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
    cmds["analyselal"] = set_command("analyselal", "analyse a particular heap's lookaside list",get_extended_usage()["analyselal"], "al")
    cmds["al"] = set_command("analyselal", "analyse a particular heap's lookaside list",get_extended_usage()["analyselal"], "al")
    cmds["analysefreelist"] = set_command("analysefreelist", "analyse a particular heap's freelist",get_extended_usage()["analysefreelist"], "af")
    cmds["af"] = set_command("analysefreelist", "analyse a particular heap's freelist",get_extended_usage()["analysefreelist"], "af")
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
                        #window.Log("len: %d vs ndx: %d" % (len(pheap.Lookaside),ndx))
                        #window.Log("chunk: %x, flink: %x, sflink: %x" % (a,next_chunk, chunk_flink-0x8))
                        # first lets check the size
                        
                        if chunk_size != ndx and (next_chunk == 0 or next_chunk == (chunk_flink-0x8)):
                            #lookaside_corrupt = True
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
                            #lookaside_corrupt = True
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
        if imm.getOsVersion() == "7":
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
        if imm.getOsVersion() == "xp":
            window.Log("+0x003 SpareBool                             : 0x%08x" % peb_struct.SpareBool, peb_struct.SpareBool)
        elif imm.getOsVersion() == "7":
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
        if imm.getOsVersion() == "xp":
            window.Log("+0x020 FastPebLockRoutine                    : 0x%08x" % peb_struct.FastPebLockRoutine, peb_struct.FastPebLockRoutine)
            window.Log("+0x024 FastPebUnLockRoutine                  : 0x%08x" % peb_struct.FastPebUnlockRoutine, peb_struct.FastPebUnlockRoutine)
            window.Log("+0x028 EnvironmentUpdateCount                : 0x%08x" % peb_struct.EnviromentUpdateCount, peb_struct.EnviromentUpdateCount)
        elif imm.getOsVersion() == "7":
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
        if imm.getOsVersion() == "7":
            window.Log("+0x02c UserSharedInfoPtr                     : 0x%08x" % peb_struct.KernelCallbackTable, peb_struct.KernelCallbackTable)
        for sysResv in peb_struct.SystemReserved:
            window.Log("    +0x030 SystemReserved                    : 0x%08x" % sysResv, sysResv) 
        window.Log("+0x034 AtlThunkSListPtr32                    : 0x%08x" % AtlThunkSListPtr32, AtlThunkSListPtr32)
        if imm.getOsVersion() == "xp": 
            window.Log("+0x038 FreeList                              : 0x%08x" % peb_struct.FreeList, peb_struct.FreeList)
        elif imm.getOsVersion() == "7":
            window.Log("+0x038 ApiSetMap                             : 0x%08x" % ApiSetMap, ApiSetMap)
        window.Log("+0x03c TlsExpansionCounter                   : 0x%08x" % peb_struct.TlsExpansionCounter, peb_struct.TlsExpansionCounter)
        window.Log("+0x040 TlsBitmap                             : 0x%08x" % peb_struct.TlsBitmap, peb_struct.TlsBitmap)
        for bits in peb_struct.TlsBitmapBits:
            window.Log("    +0x044 TlsBitmapBits                     : 0x%08x" % bits, bits)
        window.Log("+0x04c ReadOnlySharedMemoryBase              : 0x%08x" % peb_struct.ReadOnlySharedMemoryBase, peb_struct.ReadOnlySharedMemoryBase)
        if imm.getOsVersion() == "xp":
            window.Log("+0x050 ReadOnlySharedMemoryHeap              : 0x%08x" % peb_struct.ReadOnlySharedMemoryheap, peb_struct.ReadOnlySharedMemoryheap)
        elif imm.getOsVersion() == "7":
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
        if imm.getOsVersion() == "XP":
            # ImageProcessAffinityMask == ActiveProcessAffinityMask 
            window.Log("+0x0c0 ImageProcessAffinityMask              : 0x%08x" % peb_struct.ImageProcessAffinityMask, peb_struct.ImageProcessAffinityMask) 
        elif imm.getOsVersion() == "7":
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
        if imm.getOsVersion() == "7":
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
                        #chunk_read_self_size = chunk_read_self_size*8
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
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#3366ff"))
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

def set_Lookaside_chunks(imm, pheap, heap):
    if pheap.Lookaside:
        for ndx in range(0, len(pheap.Lookaside)):
            entry = pheap.Lookaside[ndx]
                    
            if not entry.isEmpty():
                
                for a in entry.getList():
                    lookaside_list = entry.getList()
                    # get the chunk address so that we point to the header
                    prev_chunk = lookaside_list[lookaside_list.index(a)-1]-0x8
                    
                    chunk_address = a
                    # get the chunks self size
                    
                    try:
                        chunk_size = imm.readMemory(a, 0x2)
                        chunk_size = struct.unpack("H", chunk_size)[0]
                        chunk_size = chunk_size*8
                    except:
                        chunk_size = ""
                    try:
                        chunk_psize = imm.readMemory(a+0x2, 0x2)
                        chunk_psize = struct.unpack("H", chunk_psize)[0]
                        chunk_psize = chunk_psize*8  
                    except:
                        chunk_psize = ""
                                          
                        
                    # get the chunks cookie
                    
                    try:
                        chunkCookie = imm.readMemory(a+0x4, 0x1)
                        chunkCookie = struct.unpack("B", chunkCookie)[0]
                    except:
                        chunkCookie = ""
                    
                    # validate the flink!
                    flink_overwrite = False
                    try:
                        flink = imm.readMemory(a+0x8, 0x4)
                        flink = struct.unpack("L", flink)
                        #next_chunk = flink-0x8
                    except:
                        flink_overwrite = True                    
                    
                    # before we fudge it..
                    if flink_overwrite:
                        break                     
                    imm.addKnowledge("Lookasiden_chunk_%x" % chunk_address, [chunk_address, flink, prev_chunk], force_add = 1)
       

# set the freelist[n] for auditing
# ================================
def set_FreeList_chunks(imm, pheap, heap):
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
        #window.Log(knowledge)
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
        
        #elif re.match("FreeListn_chunk_",knowledge):
            
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
                                   

def dump_ListHint_and_freelist(pheap, window, heap, imm, graphic_structure=False, filename="listhint_graph"):
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
                    
                if emptybins and bin_entry != 0x1 and bin_entry != 0x0 and flink == 0:
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
                #chunk_data = "Chunk: 0x%08x\nFlink: 0x%08x\nBlink: 0x%08x\nSize: 0x%x" % (e[0],e[1], e[2],a+block.BaseIndex)
 
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
                window.Log("Bin[0x%04x]    0x%08x -> [ Flink: 0x%08x | Blink: 0x%08x ] " % (a+block.BaseIndex, e[0], e[1], e[2]), address = e[0])

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
                        chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#3366ff"))
                    
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

def dump_function_pointers(window, imm, writable_segment, patch=False, restore=False, address_to_patch=False):
    j = 0
    g = 0
    memory_dict = {}
    # patch the memory in the .data segment
    if patch and address_to_patch:
        if address_to_patch != "all":
            # patch with 0x41's
            imm.writeLong( address_to_patch, 0x41414141 )
            return "(+) Patched address %s with 0x%x" % (address_to_patch, 0x41414141)
    elif restore and address_to_patch:
        restore_dict = imm.getKnowledge("function_pointers")
        if address_to_patch == "all":
            for k,v in restore_dict.iteritems():
                g += 1
                window.Log("-" * 60)
                window.Log("(%04d) Pointer      : 0x%08x" % (g,k),k)
                window.Log("       Function     : 0x%08x" % (v),v)
                window.Log("       Module Name  : %s" % imm.getModuleByAddress(v).getName())
                window.Log("       First Opcode : %s" % imm.disasm(v).getDisasm())
                imm.writeLong( k, v )
            return "(+) Restored all function pointer(s) to there original values"
        elif address_to_patch != "all":
            for k,v in restore_dict.iteritems():
                
                if k == address_to_patch:
                    imm.writeLong( address_to_patch, v )
            return "(+) Restored 0x%08x function pointer to its original value" % address_to_patch
    
    page = imm.getMemoryPageByAddress( writable_segment )
    addr = page.getBaseAddress()
    mem = imm.readMemory( page.getBaseAddress(), page.getSize() )
    # Discovering Function Pointers (taken from immunity's code)
    dt = libdatatype.DataTypes( imm )
    ret = dt.Discover( mem, addr, what = 'pointers' )
    if ret:
        for obj in ret: 
            if obj.isFunctionPointer() and obj.address:
                j += 1
                window.Log("-" * 60)
                window.Log("(%04d) Pointer      :  0x%08x" % (j, obj.address),obj.address)
                function = imm.readMemory(obj.address, 4)
                (function) = struct.unpack("L", function)
                
                window.Log("       Function     : 0x%08x" % (function),function)
                window.Log("       Module Name  : %s" % imm.getModuleByAddress(function).getName())
                window.Log("       First Opcode : %s" % imm.disasm(function).getDisasm())
                # store it into a dict object
                memory_dict[obj.address]= function 
                if address_to_patch:
                    imm.writeLong( obj.address, 0x41414141 )
                    window.Log("       pointer patched!")
                    
        # save it so we can restore it later
        imm.addKnowledge("function_pointers", memory_dict, force_add = 1)
        return "(+) Patched %s addresses with 0x%x" % (address_to_patch, 0x41414141)
        
    return "(+) Dumped all IAT pointers from %s" % imm.getDebuggedName()    

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
        window.Log("+0x008 Signature                      : 0x%08x" % pheap.Signature, pheap.Signature)
        window.Log("+0x00c Flags                          : 0x%08x" % pheap.Flags, pheap.Flags)
        window.Log("+0x010 Forceflags                     : 0x%08x" % pheap.ForceFlags, pheap.ForceFlags)
        window.Log("+0x014 VirtualMemoryThreshold         : 0x%08x" % pheap.VirtualMemoryThreshold, pheap.VirtualMemoryThreshold) 
        window.Log("+0x018 SegmentReserve                 : 0x%08x" % pheap.SegmentReserve, pheap.SegmentReserve)
        window.Log("+0x01C SegmentCommit                  : 0x%08x" % pheap.SegmentCommit, pheap.SegmentCommit)
        window.Log("+0x020 DeCommitFreeBlockThreshold     : 0x%08x" % pheap.DeCommitFreeBlockThreshold, pheap.DeCommitFreeBlockThreshold)
        window.Log("+0x024 DeCommitTotalBlockThreshold    : 0x%08x" % pheap.DeCommitTotalBlockThreshold, pheap.DeCommitTotalBlockThreshold)
        window.Log("+0x028 Total Free Size                : 0x%08x" % pheap.TotalFreeSize, pheap.TotalFreeSize)
        window.Log("+0x02c MaximumAllocationSize          : 0x%08x" % pheap.MaximumAllocationSize, pheap.MaximumAllocationSize)
                    
        # libheap does not have some members, so we are on our own
        ProcessHeapsListIndex = imm.readMemory(heap+0x30, 2)
        ProcessHeapsListIndex = struct.unpack("H", ProcessHeapsListIndex)[0]
                    
        window.Log("+0x030 ProcessHeapsListIndex          : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)
        window.Log("+0x032 HeaderValidateLength           : 0x%08x" % pheap.HeaderValidateLength, pheap.HeaderValidateLength)
        window.Log("+0x034 HeaderValidateCopy             : 0x%08x" % pheap.HeaderValidateCopy, pheap.HeaderValidateCopy)
        window.Log("+0x038 NextAvailableTagIndex          : 0x%08x" % pheap.NextAvailableTagIndex, pheap.NextAvailableTagIndex)
        window.Log("+0x03a MaximumTagIndex                : 0x%08x" % pheap.MaximumTagIndex, pheap.MaximumTagIndex)
        window.Log("+0x03c TagEntries                     : 0x%08x" % pheap.TagEntries, pheap.TagEntries)
        # uncommited range segments
        window.Log("+0x040 UCRSegments                    : 0x%08x" % pheap.UCRSegments, pheap.UCRSegments)
        window.Log("+0x044 UnusedUncommittedRanges        : 0x%08x" % pheap.UnusedUnCommittedRanges, pheap.UnusedUnCommittedRanges)
        window.Log("+0x048 AlignRound                     : 0x%08x" % pheap.AlignRound, pheap.AlignRound)
        window.Log("+0x04c AlignMask                      : 0x%08x" % pheap.AlignMask, pheap.AlignMask)
                    
        # lots of blocks..
        window.Log("+0x050 VirtualAllocedBlocks            ")
        for block in pheap.VirtualAllocedBlock:
            v += 1
            window.Log("       VirtualAllocedBlock %d          : 0x%08x" % (v,block), block)
            imm.log("+0x058 Segments                       ")
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
    return "(+) Dumped the heap structure 0x%08x" % heap

# main entry
# ==========
def main(args):
    imm = immlib.Debugger()
    
    if not opennewwindow:            
        window = imm.getKnowledge(tag)
        if window and not window.isValidHandle():
            imm.forgetKnowledge(tag)
            del window
            window = None
        
        if not window:
            window = imm.createTable("Heaper - by mr_me", ["Address", "Information"])
            imm.addKnowledge(tag, window, force_add = 1)
        #win_banner(window)
        
    if not args:
        win_banner(window)
        return usage(window, imm)
    win_banner(window)
         
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
  
            # dump function pointers from the parent processes .data segment
            # TODO: dump function pointers from dlls too
            elif args[0].lower().strip() == "dumpfunctionpointers" or args[0].lower().strip() == "dfp":
                writable_segment = 0x00000000
                writable_segment_size = 0x0
                for addr in imm.getMemoryPageByOwner(imm.getDebuggedName()):
                    if addr.section == ".data":
                        writable_segment = addr.baseaddress
                        writable_segment_size = addr.size
                
                if not writable_segment and not writable_segment_size:
                    return ".data segment not found"
                
                window.Log("-" * 60)
                window.Log("Dumping function pointers from the %s process" % imm.getDebuggedName())
                window.Log("-" * 60)
                dump_function_pointers(window, imm, writable_segment)
                
            else:
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
                if "-f" in args:
                    try:
                        custfilename = True
                        filename = args[args.index("-f")+1]
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
                if imm.getOsVersion() == "xp":
                    analyse_heap(heap, imm, window)
                elif imm.getOsVersion() == "7":
                    window.Log("TODO: dump the heap structure under win7")
                    window.Log("also add support to dump _LFH_HEAP and a few other structures")
                    
            # analyse the lookaside list
            # ==========================
            # TODO: change to analyse front end
            # runtime to detect if we are using LFH or lookaside
            
            elif args[0].lower().strip() == "analysefrontend" or args[0].lower().strip() == "af":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                if imm.getOsVersion() == "xp":
                    FrontEndHeap = imm.readMemory(heap+0x580, 4)
                    (FrontEndHeap) = struct.unpack("L", FrontEndHeap)                    
                    window.Log("-" * 77)
                    window.Log("Lookaside List structure @ 0x%08x" % FrontEndHeap)
                    window.Log("-" * 77)
                    if custfilename:
                        dump_lal(imm, pheap, graphic_structure, window, filename)
                    else:
                        dump_lal(imm, pheap, graphic_structure, window)
                elif imm.getOsVersion() == "7":
                    window.Log("Lookaside list analyse not supported under Windows Vista and above")
            
            # analyse freelists
            # =================
            # TODO: change to analyse back end
            # runtime to detect the ListHint or FreeList
            
            elif args[0].lower().strip() == "analysebackend" or args[0].lower().strip() == "ab":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                
                if imm.getOsVersion() == "xp":
                    
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
                    
                    # HeapCache
                    if pheap.HeapCache:
                        window.Log("")
                        window.Log("HeapCache")
                        window.Log("-----------------")
                        dump_HeapCache(pheap,window,imm)
                        window.Log("")
                        window.Log("HeapCache Bitmap:")
                        window.Log("-----------------")
                        dump_HeapCache_bitmap(pheap, window)

                # do vista and windows 7 freelist analyse?
                else:
                    if graphic_structure:
                        if custfilename:
                            dump_ListHint_and_freelist(pheap, window, heap, imm, graphic_structure, filename)
                        else:
                            dump_ListHint_and_freelist(pheap, window, heap, imm, graphic_structure)
                    else:
                        dump_ListHint_and_freelist(pheap, window, heap, imm)
                    

            # analyse heap cache if it exists
            # ===============================
            elif args[0].lower().strip() == "analyseheapcache" or args[0].lower().strip() == "ahc":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
                if imm.getOsVersion() == "xp":
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
                                               
            # perform hueristics
            # ==================
            # TODO: hueristics additions for LFH
            elif args[0].lower().strip() == "exploit" or args[0].lower().strip() == "exp":
                try:
                    pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                except:
                    window.Log("Invalid heap address!")
                    return "Invalid heap address!"
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
            
            # analyse FreelistInUse
            # =====================
            # TODO: change to detect xp or win7
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
            # TODO: find out if this still works on win7?
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
                writable_segment = 0x00000000
                writable_segment_size = 0x0
                restore = False
                patch = False
                address_to_patch = False
                for addr in imm.getMemoryPageByOwner(imm.getDebuggedName()):
                    if addr.section == ".data":
                        writable_segment = addr.baseaddress
                        writable_segment_size = addr.size
                
                if not writable_segment and not writable_segment_size:
                    return ".data segment not found"

                if "-p" in args:
                    patch = True
                elif "-r" in args:
                    restore = True

                if patch:
                    if len(args) == 3:
                        if args[2].lower() != "all":
                            try:
                                address_to_patch = int(args[2].lower(),16)
                            except:
                                return "(-) Please specficy which pointer to patch... eg: all / 00514450"
                        else:
                            address_to_patch = args[2].lower()
                    else:
                        return "(-) Please specify which pointer to patch... eg: all / 0x00514450"
                  
                    window.Log("-" * 60)
                    if args[2].lower() != "all":
                        window.Log("Patching 0x%08x function pointer(s) " % address_to_patch)
                    else:
                        window.Log("Patching %s function pointer(s) " % address_to_patch)
                    window.Log("-" * 60)
                elif restore:
                    if len(args) == 3:
                        if args[2].lower() != "all":
                            try:
                                address_to_patch = int(args[2].lower(),16)
                            except:
                                return "(-) Please specify which pointer to restore... eg: all / 00514450"
                        else:
                            address_to_patch = args[2].lower()
                    else:
                        return "(-) Please specify which pointer to restore... eg: all / 00514450"
                    
                    window.Log("-" * 60)
                    if args[2].lower() != "all":
                        window.Log("Restoring function pointer 0x%08x" % address_to_patch)
                    else:
                        window.Log("Restoring %s function pointer(s) " % address_to_patch)
                    window.Log("-" * 60)  
                return dump_function_pointers(window, imm, writable_segment, patch, restore, address_to_patch)
            
            # analyse segments
            # ================
            elif args[0].lower().strip() == "analysesegments" or args[0].lower().strip() == "as":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                dump_segment_structure(pheap, window, imm, heap)
                
            elif args[0].lower().strip() == "hook" or args[0].lower().strip() == "h":
                window.Log("")
                valid_functions = ["alloc", "free", "create","destroy","realloc","size","createcs","deletecs","all","setuef"]

                
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
                                AllocFlag = True
                                FreeFlag = True
                                CreateFlag = True
                                DestroyFlag = True
                                ReAllocFlag = True
                                sizeFlag = True
                                CreateCSFlag = True
                                DeleteCSFlag = True
                                setuefFlag = True 
                                setVAllocFlag = True
                                setVFreeFlag = True  
                                                                                       
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
                            CreateFlag = True
                        elif args[2].lower().strip() == "destroy":
                            DestroyFlag = True
                        elif args[2].lower().strip() == "alloc":
                            AllocFlag = True
                        elif args[2].lower().strip() == "free":
                            FreeFlag = True
                        elif args[2].lower().strip() == "realloc":
                            ReAllocFlag = True                            
                        elif args[2].lower().strip() == "setuef":
                            setuefFlag = True
                        elif args[2].lower().strip() == "va":
                            setVAllocFlag = True
                        elif args[2].lower().strip() == "vf":
                            setVFreeFlag = True
                        elif args[2].lower().strip() == "size":
                            sizeFlag = True
                        elif args[2].lower().strip() == "createcs":
                            CreateCSFlag = True
                        elif args[2].lower().strip() == "deletecs":
                            DeleteCSFlag = True
                          
                        # zmfg you didnt just hook all did you!?
                        elif args[2].lower().strip() == "all":
                                    AllocFlag = True
                                    FreeFlag = True
                                    CreateFlag = True
                                    DestroyFlag = True
                                    ReAllocFlag = True
                                    sizeFlag = True
                                    CreateCSFlag = True
                                    DeleteCSFlag = True
                                    setuefFlag = True 
                                    setVAllocFlag = True
                                    setVFreeFlag = True
                        else:
                            window.Log("(-) Please include a valid heap for this hook!")
                            return "(-) Please include a valid heap for this hook!"
                    else:
                        window.Log("%d" % len(args))
                        window.Log("(-) Please specify a function to hook/unhook using -h/-u")
                        return "(-) Please specify a function to hook/unhook using -h/-u"
                
                # display the hook..
                window.Log("-" * 30)
                if AllocFlag:
                    allocaddr = imm.getAddress("ntdll.RtlAllocateHeap" )
                    retaddr = allocaddr+0x117
                    if FilterHeap:
                        hook_output = ("(+) %s RtlAllocateHeap() for heap 0x%08x" % 
                        (hook_on(imm, ALLOCLABEL, allocaddr, "RtlAllocateHeap", retaddr, Disable, window, heap), heap))
                    else:
                        hook_output = ("(+) %s RtlAllocateHeap()" %  
                        (hook_on(imm, ALLOCLABEL, allocaddr, "RtlAllocateHeap", retaddr, Disable, window)))                      
                if FreeFlag:
                    freeaddr = imm.getAddress("ntdll.RtlFreeHeap" )
                    retaddr = freeaddr+0x130
                    if FilterHeap:
                        hook_output = ("(+) %s RtlFreeHeap() for heap 0x%08x" % 
                        (hook_on(imm, FREELABEL, freeaddr, "RtlFreeHeap", retaddr, Disable, window, heap), heap))
                    else:
                        hook_output = ("(+) %s RtlFreeHeap()" % 
                        (hook_on(imm, FREELABEL, freeaddr, "RtlFreeHeap", retaddr, Disable, window)))                        
                if CreateFlag:
                    # we dont hook ntdll.RtlCreateHeap because its not simply a wrapper...
                    createaddr = imm.getAddress("kernel32.HeapCreate" )
                    retaddr = createaddr+0x57
                    hook_output = ("(+) %s HeapCreate() for heap 0x%08x" % 
                    (hook_on(imm, CREATELABEL, createaddr, "RtlCreateHeap", retaddr, Disable, window), 0))
                if DestroyFlag:
                    destoryaddr = imm.getAddress("ntdll.RtlDestroyHeap")
                    retaddr = destoryaddr+0xd9
                    hook_output = ("(+) %s RtlDestroyHeap() for heap 0x%08x" % 
                    (hook_on(imm, DESTROYLABEL, destoryaddr, "RtlDestroyHeap", retaddr, Disable, window), 0))
                if ReAllocFlag:
                    reallocaddr = imm.getAddress("ntdll.RtlReAllocateHeap")
                    retaddr = reallocaddr+0x20a
                    hook_output = ("(+) %s RtlReAllocateHeap() for heap 0x%08x" % 
                    (hook_on(imm, REALLOCLABEL, reallocaddr, "RtlReAllocateHeap", retaddr, Disable, window), 0))
                if sizeFlag:
                    sizeaddr = imm.getAddress("ntdll.RtlSizeHeap")
                    retaddr = sizeaddr+0x62
                    hook_output = ("(+) %s RtlSizeHeap() for heap 0x%08x" % 
                    (hook_on(imm, SIZELABEL, sizeaddr, "RtlSizeHeap", retaddr, Disable, window), 0))
                if CreateCSFlag:
                    create_cs_addr = imm.getAddress("ntdll.RtlInitializeCriticalSection")
                    retaddr = create_cs_addr+0x10
                    hook_output = ("(+) %s RtlInitializeCriticalSection() for heap 0x%08x" % 
                    (hook_on(imm, CREATECSLABEL, create_cs_addr, "RtlInitializeCriticalSection", retaddr, Disable, window), 0))
                if DeleteCSFlag:
                    delete_cs_addr = imm.getAddress("ntdll.RtlDeleteCriticalSection")
                    retaddr = delete_cs_addr+0x78
                    hook_output = ("(+) %s RtlDeleteCriticalSection() for heap 0x%08x" % 
                    (hook_on(imm, DELETECSLABEL, delete_cs_addr, "RtlDeleteCriticalSection", retaddr, Disable, window), 0))                    
                if setuefFlag:
                    setuef_addr = imm.getAddress("kernel32.SetUnhandledExceptionFilter")
                    # no worries if you dont return here, it just wont log the return address
                    retaddr = setuef_addr-0x34707
                    hook_output = ("(+) %s SetUnhandledExceptionFilter() for heap 0x%08x" % 
                    (hook_on(imm, SETUEFLABEL, setuef_addr, "SetUnhandledExceptionFilter", retaddr, Disable, window), 0))                      
                if setVAllocFlag:
                    setva_addr = imm.getAddress("kernel32.VirtualAllocEx")
                    # no worries if you dont return here, it just wont log the return address
                    retaddr = setva_addr+0x47
                    hook_output = ("(+) %s VirtualAllocEx() for heap 0x%08x" % 
                    (hook_on(imm, VIRALLOCLABEL, setva_addr, "VirtualAllocEx", retaddr, Disable, window), 0))                      
                if setVFreeFlag:
                    setvf_addr = imm.getAddress("kernel32.VirtualFreeEx")
                    # no worries if you dont return here, it just wont log the return address
                    retaddr = setvf_addr+0x3d
                    hook_output = ("(+) %s VirtualFreeEx() for heap 0x%08x" % 
                    (hook_on(imm, VIRFREELABEL, setvf_addr, "VirtualFreeEx", retaddr, Disable, window), 0))                      
                                
                window.Log(hook_output)
                window.Log("-" * 30)                    
                return hook_output                    
                            
        # more than one command and that we cant understand
        # =================================================
        else:
            return usage(imm)