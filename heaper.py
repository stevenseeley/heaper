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

DESC="""!heaper - a tool to analyse heap structures."""

import immlib
import immutils
import libdatatype
import binascii
import pydot
import re

##################################################################################
# GLOBALS VARS                                                                       #
##################################################################################
available_commands = [
"dumppeb", "dp", "dumpheaps", "dh", "analyseheap", "ah", "dumpteb", "dt", "analyselal", "al", 
"analysefreelist", "af", "analysechunks", "ac", "dumpfunctionpointers", "dfp", "help", "-h", 
"analysesegments", "as", "-f", "-m", "-p", "freelistinuse", "fliu"]

block = 8 # a block will always be 8 bytes
opennewwindow = False
graphic_structure = False
tag = "display_box" 
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

def reverse(text):
    return ''.join([text[i] for i in range(len(text)-1,-1,-1)])

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

# banners, i know huh pretty lame
def banner(imm):
    imm.log("----------------------------------------",highlight=1) 
    imm.log("    __                         ",highlight=1)
    imm.log("   / /  ___ ___ ____  ___ ____ ",highlight=1)
    imm.log("  / _ \/ -_) _ `/ _ \/ -_) __/ ",highlight=1)
    imm.log(" /_//_/\__/\_,_/ .__/\__/_/    ",highlight=1)
    imm.log("              /_/              ",highlight=1)
    imm.log("----------------------------------------",highlight=1)
    imm.log("by mr_me :: steventhomasseeley@gmail.com",highlight=1)

def win_banner(win):
    win.Log("----------------------------------------") 
    win.Log("    __                         ")
    win.Log("   / /  ___ ___ ____  ___ ____ ")
    win.Log("  / _ \/ -_) _ `/ _ \/ -_) __/ ")
    win.Log(" /_//_/\__/\_,_/ .__/\__/_/    ")
    win.Log("              /_/              ")
    win.Log("----------------------------------------")
    win.Log("by mr_me :: steventhomasseeley@gmail.com")

def usage(imm):
    imm.log("")
    imm.log("****   available commands   ****")
    imm.log("")
    imm.log("dumppeb / dp                          : dump the PEB pointers")
    imm.log("dumpteb / dt                          : dump the TEB pointers")
    imm.log("dumpheaps / dh                        : dump the heaps")
    imm.log("dumpfunctionpointers / dfp            : dump all the processes function pointers")
    imm.log("analyseheap <heap> / ah <heap>        : analyse a particular heap")
    imm.log("analyselal <heap> / al <heap>         : analyse a particular heap's Lookaside list")
    imm.log("analysefreelist <heap> / af <heap>    : analyse a particular heap's freelist")
    imm.log("analysesegments <heap> / as <heap>    : analyse a particular heap's segments")
    imm.log("analysechunks <heap> / ac <heap>      : analyse a particular heap's chunks")
    imm.log("freelistinuse <heap> / fliu <heap>    : analyse/patch the FreeListInUse structure")
    imm.log("")
    imm.log("Want more info about a given command? Run !heaper help <command>",highlight=1)
    imm.log("")
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
    extusage["analysesegments"] += "Use -g to view a graphical representation of the freelist\n"
    extusage["analysechunks"] = "\nanalysechunks <heap> / ac <heap> : Analyse a particular heap's chunks\n"
    extusage["analysechunks"] += "---------------------------------------------------------------------\n"
    extusage["analysechunks"] += "Use -r <start address> <end address> to view all the chunks between those ranges\n"
    extusage["analysechunks"] += "Use -f to chunk_filter chunks by type (free/busy) eg: !heaper ac d20000 -f busy\n"
    extusage["analysechunks"] += "Use -v to view the first 16 bytes of each chunk\n"
    extusage["dumpfunctionpointers"] = "\ndumpfunctionpointers /  dfp : Dump all the function pointers of the current process\n"
    extusage["dumpfunctionpointers"] += "-----------------------------------------------------------------------------------\n"
    extusage["dumpfunctionpointers"] += "Use -p <addr/all> to patch a function pointer or all function pointers in the .data segment\n"
    extusage["dumpfunctionpointers"] += "Use -r <addr/all> to restore a function pointer or all function pointers in the .data segment\n"
    extusage["dumpfunctionpointers"] += "eg: !heaper dfp -r 005000f0\n"
    return extusage
    
def setUpArgs():
    cmds = {}
    cmds["dumppeb"] = set_command("dumppeb", "Dump the PEB pointers",get_extended_usage()["dumppeb"], "dp")
    cmds["dumpteb"] = set_command("dumpteb", "Dump the TEB pointers",get_extended_usage()["dumpteb"], "dt")
    cmds["dumpheaps"] = set_command("dumpheaps", "Dump all the heaps of a process",get_extended_usage()["dumpheaps"], "dh")
    cmds["dumpfunctionpointers"] = set_command("dumpfunctionpointers", "Dump all the function pointers of the current process",get_extended_usage()["dumpfunctionpointers"], "dfp")
    cmds["analyseheap"] = set_command("analyseheap", "analyse a particular heap",get_extended_usage()["analyseheap"], "ah")
    cmds["analyselal"] = set_command("analyselal", "analyse a particular heap's lookaside list",get_extended_usage()["analyselal"], "al")
    cmds["analysefreelist"] = set_command("analysefreelist", "analyse a particular heap's freelist",get_extended_usage()["analysefreelist"], "af")
    cmds["analysechunks"] = set_command("analysechunks", "analyse a particular heap's list of chunks",get_extended_usage()["analysechunks"], "ac")
    cmds["analysesegments"] = set_command("analysesegments", "analyse a particular heap's segment(s)",get_extended_usage()["analysesegments"], "as")
    cmds["freelistinuse"] = set_command("freelistinuse", "aanalyse/patch the FreeListInUse structure",get_extended_usage()["freelistinuse"], "fliu")
    return cmds

# TODO: build heuristics to detect exploitable paths...
# exploit heuristics
def do_heuristics(window, structure, chunk_number, list_number):
    if structure == "freelist":
        window.Log("        (+) Checking heuristics for chunk (%d) in freelist[%03d]" % (chunk_number,list_number))
        # 1st lets check for freelist insert attack vector
    
def dump_heap(imm):
    imm.log("Listing available heaps: ")
    imm.log("")
    for hndx in imm.getHeapsAddress():
        imm.log("Heap: 0x%08x" % hndx, address = hndx, focus = 1)
    return "Heap command successful"      
        
def dump_peb(imm, window, dump_management=False):
    peb = imm.getPEBAddress()
    window.Log("")
    
    if dump_management:
        
        # dont know why, but some of this isnt in the api?
        AtlThunkSListPtr32 = imm.readMemory(peb+0x34, 4)
        AtlThunkSListPtr32 = reverse(AtlThunkSListPtr32)
        AtlThunkSListPtr32 = int(binascii.hexlify(AtlThunkSListPtr32),16)   
          
        AppCompatFlags = imm.readMemory(peb+0x1d8, 8)
        AppCompatFlags = reverse(AppCompatFlags)
        AppCompatFlags = int(binascii.hexlify(AppCompatFlags),16)  
    
        AppCompatFlagsUser = imm.readMemory(peb+0x1e0, 8)
        AppCompatFlagsUser = reverse(AppCompatFlagsUser)
        AppCompatFlagsUser = int(binascii.hexlify(AppCompatFlagsUser),16) 
        
        pShimData = imm.readMemory(peb+0x1e8, 4)
        pShimData = reverse(pShimData)
        pShimData = int(binascii.hexlify(pShimData),16) 
        
        ActivationContextData = imm.readMemory(peb+0x1f8, 4)
        ActivationContextData = reverse(ActivationContextData)
        ActivationContextData = int(binascii.hexlify(ActivationContextData),16) 
        
        ProcessAssemblyStorageMap = imm.readMemory(peb+0x1fc, 4)
        ProcessAssemblyStorageMap = reverse(ProcessAssemblyStorageMap)
        ProcessAssemblyStorageMap = int(binascii.hexlify(ProcessAssemblyStorageMap),16) 
        
        SystemDefaultActivationContextData = imm.readMemory(peb+0x200, 4)
        SystemDefaultActivationContextData = reverse(SystemDefaultActivationContextData)
        SystemDefaultActivationContextData = int(binascii.hexlify(SystemDefaultActivationContextData),16)
    
        SystemAssemblyStorageMap = imm.readMemory(peb+0x204, 4)
        SystemAssemblyStorageMap = reverse(SystemAssemblyStorageMap)
        SystemAssemblyStorageMap = int(binascii.hexlify(SystemAssemblyStorageMap),16)
        
        MinimumStackCommit = imm.readMemory(peb+0x208, 4)
        MinimumStackCommit = reverse(MinimumStackCommit)
        MinimumStackCommit = int(binascii.hexlify(MinimumStackCommit),16)
           
        peb_struct = imm.getPEB()
        window.Log("---------------------------------------------------------")
        window.Log("PEB Management Structure @ 0x%08x" % peb,peb)
        window.Log("---------------------------------------------------------")
        window.Log("+0x000 InheritedAddressSpace                 : 0x%08x" % peb_struct.InheritedAddressSpace, peb_struct.InheritedAddressSpace)
        window.Log("+0x001 ReadImageFileExecOptions              : 0x%08x" % peb_struct.ReadImageFileExecOptions, peb_struct.ReadImageFileExecOptions)
        window.Log("+0x002 BeingDebugged                         : 0x%08x" % peb_struct.BeingDebugged, peb_struct.BeingDebugged) 
        window.Log("+0x003 SpareBool                             : 0x%08x" % peb_struct.SpareBool, peb_struct.SpareBool)
        window.Log("+0x004 Mutant                                : 0x%08x" % peb_struct.Mutant, peb_struct.Mutant)
        window.Log("+0x008 ImageBaseAddress                      : 0x%08x" % peb_struct.ImageBaseAddress, peb_struct.ImageBaseAddress)
        window.Log("+0x00c Ldr                                   : 0x%08x" % peb_struct.Ldr, peb_struct.Ldr)
        window.Log("+0x010 ProcessParameters                     : 0x%08x" % peb_struct.ProcessParameters, peb_struct.ProcessParameters)
        window.Log("+0x014 SubSystemData                         : 0x%08x" % peb_struct.SubSystemData, peb_struct.SubSystemData)
        window.Log("+0x018 ProcessHeap                           : 0x%08x" % peb_struct.ProcessHeap, peb_struct.ProcessHeap)
        window.Log("+0x01c FastPebLock                           : 0x%08x" % peb_struct.FastPebLock, peb_struct.FastPebLock)
        window.Log("+0x020 FastPebLockRoutine                    : 0x%08x" % peb_struct.FastPebLockRoutine, peb_struct.FastPebLockRoutine)
        window.Log("+0x024 FastPebUnLockRoutine                  : 0x%08x" % peb_struct.FastPebUnlockRoutine, peb_struct.FastPebUnlockRoutine)
        window.Log("+0x028 EnvironmentUpdateCount                : 0x%08x" % peb_struct.EnviromentUpdateCount, peb_struct.EnviromentUpdateCount)
        window.Log("+0x02c KernelCallbackTable                   : 0x%08x" % peb_struct.KernelCallbackTable, peb_struct.KernelCallbackTable)
        for sysResv in peb_struct.SystemReserved:
            window.Log("+0x030 SystemReserved                        : 0x%08x" % sysResv, sysResv)
        window.Log("+0x034 AtlThunkSListPtr32                    : 0x%08x" % AtlThunkSListPtr32, AtlThunkSListPtr32)
        window.Log("+0x038 FreeList                              : 0x%08x" % peb_struct.FreeList, peb_struct.FreeList)
        window.Log("+0x03c TlsExpansionCounter                   : 0x%08x" % peb_struct.TlsExpansionCounter, peb_struct.TlsExpansionCounter)
        window.Log("+0x040 TlsBitmap                             : 0x%08x" % peb_struct.TlsBitmap, peb_struct.TlsBitmap)
        for bits in peb_struct.TlsBitmapBits:
            window.Log("+0x044 TlsBitmapBits                         : 0x%08x" % bits, bits)
        window.Log("+0x04c ReadOnlySharedMemoryBase              : 0x%08x" % peb_struct.ReadOnlySharedMemoryBase, peb_struct.ReadOnlySharedMemoryBase)
        window.Log("+0x050 ReadOnlySharedMemoryHeap              : 0x%08x" % peb_struct.ReadOnlySharedMemoryheap, peb_struct.ReadOnlySharedMemoryheap)
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
        window.Log("+0x0c0 ImageProcessAffinityMask              : 0x%08x" % peb_struct.ImageProcessAffinityMask, peb_struct.ImageProcessAffinityMask) 
        for buff in peb_struct.GdiHandleBuffer:
            window.Log("+0x0c4 GdiHandleBuffer                       : 0x%08x" % buff, buff) 
        window.Log("+0x14c PostProcessInitRoutine                : 0x%08x" % peb_struct.PostProcessInitRoutine, peb_struct.PostProcessInitRoutine) 
        window.Log("+0x150 TlsExpansionBitmap                    : 0x%08x" % peb_struct.TlsExpansionBitmap, peb_struct.TlsExpansionBitmap) 
        for bitmapbits in peb_struct.TlsExpansionBitmapBits:
            window.Log("+0x154 TlsExpansionBitmapBits                : 0x%08x" % bitmapbits, bitmapbits) 
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
        window.Log("---------------------------------------------------------")
        window.Log("")
        return "Dumped PEB successfully"
    else:
        window.Log("PEB is located at 0x%08x" % peb,peb)
        return "PEB is located at 0x%08x" % peb

def dump_teb(imm, window):
    currenttid = imm.getThreadId()
    threads = imm.getAllThreads()
    window.Log("")
    try:
        currentTEB = threads[currenttid].getTEB()
        window.Log("The current TEB id is: %s and is located at: 0x%08x" % (currenttid,currentTEB),currentTEB)
    except:
        window.Log("The current TEB id is: %s and is located at an unknown address" % (currenttid))
    
    window.Log("Other TEB's in this process:")
    tebArray = {}
    
    for key in threads:
        teb = key.getTEB()
        tid = key.getId()
        tebArray[teb] = tid
        
    valuelist = tebArray.keys()
    valuelist.sort()
    valuelist.reverse()
    for key in valuelist:
        window.Log("id: %s is located at: 0x%08x" % (tebArray[key],key), key)
    return "Dumped TEB successfully"
    
# ripped from immunity inc, greetz
def dump_lal(imm, pheap, graphic_structure, window, filename="lal_graph"):
    exploitable_conditions = ["flink_overwrite", "size_overwrite"]
    if graphic_structure:
        lalgraph = pydot.Dot(graph_type='digraph')
        ndx_nodes = []
        chunk_dict = {}
    # we use the api where we can ;)
    if pheap.Lookaside:
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
                    chunkSelfSize = ""
                    try:
                        chunkSelfSize = imm.readMemory(a, 0x2)
                        chunkSelfSize = reverse(chunkSelfSize)
                        chunkSelfSize = int(binascii.hexlify(chunkSelfSize),16)
                        chunkSelfSize = chunkSelfSize*8
                    except:
                        pass
                        
                    # get the chunks cookie
                    chunkCookie = ""
                    try:
                        chunkCookie = imm.readMemory(a+0x4, 0x1)
                        chunkCookie = reverse(chunkCookie)
                        chunkCookie = int(binascii.hexlify(chunkCookie),16)
                    except:
                        pass
                    
                    # validate the flink!
                    flink_overwrite = False
                    try:
                        flink = imm.readMemory(a+0x8, 0x4)
                        flink = reverse(flink)
                        flink = int(binascii.hexlify(flink),16)
                    except:
                        flink_overwrite = True
                    chunk_data = ("chunk (%d) 0x%08x \nFlink 0x%08x" % (b, a, (a + 0x8)))

                    # else the expected chunk size is not the same as the read in chunk..
                    if chunkSelfSize != (ndx * block):
                        # if the size has been overwritten.....
                        if chunkSelfSize != "":
                            if graphic_structure:
                                chunk_nodes.append(pydot.Node("size_overwrite_%x" % 
                                (a), style="filled", shape="rectangle", label=chunk_data+"\nSize overwritten..", fillcolor="red"))
                            window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x, Size: %d (0x%03x)" % 
                            (b, a, (a + 0x8), chunkSelfSize, chunkSelfSize), address = a) 
                            window.Log("        -> chunk size should have been %d (0x%04x)! We have a possible chunk overwrite.." % 
                            (ndx * block, ndx * block), focus=1)
                        # else if the chunk address has been overwrtten and we couldnt read the chunks size...
                        # generally because the previous chunks flink was clobbered..
                        elif chunkSelfSize == "":
                            # just to ensure the flink was owned...
                            if flink_overwrite:
                                window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x, Size: ? " % (b, a, (a + 0x8)), address = a) 
                                window.Log("        -> failed to read chunk @ 0x%08x!" % a, address = a)
                                if graphic_structure:
                                    chunk_nodes.append(pydot.Node("flink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nFlink overwrite...", fillcolor="red"))
                    elif chunkSelfSize == (ndx * block):
                        b += 1
                        if graphic_structure:
                            chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#3366ff"))
                        window.Log("    chunk [%d]: 0x%08x, Flink: 0x%08x, Size: %d (0x%03x), Cookie: 0x%01x" % 
                        (b, a, (a + 0x8), (ndx * block), (ndx * block), chunkCookie), address = a) 
                window.Log("-" * 77)        
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
    
    
def get_heap_instance(heap, imm):
    try:
        heap = int(heap,16)
    except:
        return "(-) Invalid heap address"
    try:
        pheap = imm.getHeap( heap )
    except:
        return "(-) Invalid heap address"
    return pheap, heap

def dump_FreeListInUse(pheap, window):
    bits = get_FreeListInUse(pheap)
    i = 0
    window.Log("")
    window.Log("FreeListInUse:")
    window.Log("--------------")
    window.Log("")
    for b in bits:
        if i == 0:
            window.Log("FreeList[0x%x] = NA" % (i))
        else:
            window.Log("FreeList[0x%x] = %d" % (i,b))
        i+= 1
           
# for <= XP only
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
                # 
                if a != 0:
                    window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s-8=%s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size, result_of_expected_size), address = e[0])
                    window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[%03d].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
                else:
                    window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size_freelist0), address = e[0])
                    window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[%03d].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
                         
                # for each avaliable chunk in the freelist[] entry            
                for fc in entry[1:]:
                    # anti-confusion, setup the needed chunks
                    if len(entry[1:]) == 1:
                        prevChunkAddr = e[0]
                    else:
                        prevChunkAddr = entry[1:][entry[1:].index(fc)-1][0]
                    try:
                        nextChunkAddr = entry[1:][entry[1:].index(fc)+1][0]
                    except:
                        nextChunkAddr = 1
                    chunkAddr  = fc[0]
                    chunkBlink = fc[1]
                    chunkFlink = fc[2]
                    # read the chunks size
                    
                    try:
                        sz = pheap.get_chunk( chunkAddr - block ).size
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
                    chunkCookie = imm.readMemory(chunkAddr-0x4, 1) # chunkAddr includes header
                    chunkCookie = reverse(chunkCookie)
                    chunkCookie = int(binascii.hexlify(chunkCookie),16)                    
                    chunk_data = "Chunk (%d) 0x%08x\nBlink (0x%08x)\nFlink (0x%08x)" % (chunkNum, chunkAddr, chunkBlink, chunkFlink)
                    chunkNum += 1
                    window.Log("         * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x] " % (chunkNum, chunkAddr, chunkBlink, chunkFlink), address = chunkAddr) 
                    window.Log("                 [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x" % (chunkNum, sz, calc_sz, calc_sz, chunkCookie), address = chunkAddr) 
                    if graphic_structure:
                        chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#3366ff"))
                    # safe unlinking, or at least the best ill get ;)
                    # if there is a valid next chunk, do the check
                    if nextChunkAddr != 1:
                        if prevChunkAddr != chunkBlink and chunkFlink != nextChunkAddr:
                            window.Log("           --> Flink and Blink appear to be overwritten, code execution maybe possible")
                            
                            # window, strucure, chunk number, freelist entry id
                            do_heuristics(window, "freelist", chunkNum, a)
                            
                            if graphic_structure:
                                chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nFlink/Blink overwrite...", fillcolor="red"))
                    # else just check blink
                    else:
                        if prevChunkAddr != chunkBlink:
                            window.Log("           --> Flink and Blink appear to be overwritten, code execution maybe possible")
                            do_heuristics(window, "freelist", chunkNum, a)
                            if graphic_structure:
                                chunk_nodes.append(pydot.Node("flink_blink_overwrite", style="filled", shape="rectangle", label=chunk_data+"\nFlink/Blink overwrite...", fillcolor="red"))
            
            # if they have no chunks, print them anyway, prooves useful when performing certain attacks 
            elif len(entry[1:]) < 1:
                window.Log("FreeList[0x%02x] - 0x%08x | +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: %s-8=%s]" % (a, e[0],(e[0]+0x4), (e[0]-0x4), expected_size, result_of_expected_size), address = e[0])
                window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[%03d].flink : 0x%08x]" % (a, e[1], a, e[2]), address = e[1])
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
    # if we have a free chunk
    
    # chunks on the lookaside will "appear" busy
    if chunk.getflags(chunk.flags) == "B$":
        window.Log("    -> Lookaside[%d] entry" % chunk.size)
        window.Log("        -> Flink: 0x%08x" % (chunk.addr+0x8))
    elif chunk.getflags(chunk.flags) == "F":
        window.Log("    -> Freelist[%d] entry" % chunk.size)
        window.Log("        -> Flink: 0x%08x" % chunk.nextchunk) 
        window.Log("        -> Blink: 0x%08x" % chunk.prevchunk)

    if show_detail:
        dump = immutils.hexdump(chunk.sample)
        for a in range(0, len(dump)):
            if not a:
                window.Log("    -> First 16 bytes of data:")
                window.Log("        -> hex: \\x%s" % dump[a][0].rstrip().replace(" ", "\\x")) 
                window.Log("        -> ascii: %s" % (dump[a][1]))

# TODO: detect where the function pointer was called from
# may require a new function.

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
                function = reverse(function)
                function = int(binascii.hexlify(function),16)
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
    for segment in pheap.Segments:
        window.Log("")
        window.Log("-" * 19)
        window.Log("Segment: 0x%08x" % segment.BaseAddress)
        window.Log("-" * 19)
        window.Log("")
        entry_0 = imm.readMemory(segment.BaseAddress, 4)
        entry_0 = reverse(entry_0)
        entry_0 = int(binascii.hexlify(entry_0),16)
        entry_1 = imm.readMemory(segment.BaseAddress+0x4, 4)
        entry_1 = reverse(entry_1)
        entry_1 = int(binascii.hexlify(entry_1),16)                   
        signature = imm.readMemory(segment.BaseAddress+0x8, 4)
        signature = reverse(signature)
        signature = int(binascii.hexlify(signature),16)  
        flags = imm.readMemory(segment.BaseAddress+0xc, 4)
        flags = reverse(flags)
        flags = int(binascii.hexlify(flags),16)  
        heap_ = imm.readMemory(segment.BaseAddress+0x10, 4)
        heap_ = reverse(heap_)
        heap_ = int(binascii.hexlify(heap_),16)      
                                    
        LargestUncommitedRange = imm.readMemory(segment.BaseAddress+0x14, 4)
        LargestUncommitedRange = reverse(LargestUncommitedRange)
        LargestUncommitedRange = int(binascii.hexlify(LargestUncommitedRange),16)
                    
        BaseAddress = imm.readMemory(segment.BaseAddress+0x18, 4)
        BaseAddress = reverse(BaseAddress)
        BaseAddress = int(binascii.hexlify(BaseAddress),16) 
                    
        NumberOfPages = imm.readMemory(segment.BaseAddress+0x1c, 4)
        NumberOfPages = reverse(NumberOfPages)
        NumberOfPages = int(binascii.hexlify(NumberOfPages),16) 
                    
        FirstEntry = imm.readMemory(segment.BaseAddress+0x20, 4)
        FirstEntry = reverse(FirstEntry)
        FirstEntry = int(binascii.hexlify(FirstEntry),16) 
                    
        LastValidEntry = imm.readMemory(segment.BaseAddress+0x24, 4)
        LastValidEntry = reverse(LastValidEntry)
        LastValidEntry = int(binascii.hexlify(LastValidEntry),16) 

        NumberOfUncommitedPages = imm.readMemory(segment.BaseAddress+0x28, 4)
        NumberOfUncommitedPages = reverse(NumberOfUncommitedPages)
        NumberOfUncommitedPages = int(binascii.hexlify(NumberOfUncommitedPages),16)                    

        NumberOfUncommitedRanges = imm.readMemory(segment.BaseAddress+0x2c, 4)
        NumberOfUncommitedRanges = reverse(NumberOfUncommitedRanges)
        NumberOfUncommitedRanges = int(binascii.hexlify(NumberOfUncommitedRanges),16)  
                    
        UnCommitedRanges = imm.readMemory(segment.BaseAddress+0x30, 4)
        UnCommitedRanges = reverse(UnCommitedRanges)
        UnCommitedRanges = int(binascii.hexlify(UnCommitedRanges),16) 
                    
        AllocatorBackTraceIndex = imm.readMemory(segment.BaseAddress+0x34, 2)
        AllocatorBackTraceIndex = reverse(AllocatorBackTraceIndex)
        AllocatorBackTraceIndex = int(binascii.hexlify(AllocatorBackTraceIndex),16)                     

        Reserved = imm.readMemory(segment.BaseAddress+0x36, 2)
        Reserved = reverse(Reserved)
        Reserved = int(binascii.hexlify(Reserved),16) 

        LastEntryInSegment = imm.readMemory(segment.BaseAddress+0x38, 4)
        LastEntryInSegment = reverse(LastEntryInSegment)
        LastEntryInSegment = int(binascii.hexlify(LastEntryInSegment),16) 
                                                                                                                     
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
                    
        # libheap do not have this member, so we do it manually..
        ProcessHeapsListIndex = imm.readMemory(heap+0x30, 2)
        ProcessHeapsListIndex = reverse(ProcessHeapsListIndex)
        ProcessHeapsListIndex = int(binascii.hexlify(ProcessHeapsListIndex),16)
                    
        window.Log("+0x030 ProcessHeapsListIndex          : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)
        window.Log("+0x032 HeaderValidateLength           : 0x%08x" % pheap.HeaderValidateLength, pheap.HeaderValidateLength)
        window.Log("+0x034 HeaderValidateCopy             : 0x%08x" % pheap.HeaderValidateCopy, pheap.HeaderValidateCopy)
        window.Log("+0x038 NextAvailableTagIndex          : 0x%08x" % pheap.NextAvailableTagIndex, pheap.NextAvailableTagIndex)
        window.Log("+0x03a MaximumTagIndex                : 0x%08x" % pheap.MaximumTagIndex, pheap.MaximumTagIndex)
        window.Log("+0x03c TagEntries                     : 0x%08x" % pheap.TagEntries, pheap.TagEntries)
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
                    
        # libheap does not have this member, so we do it manually..
        FreelistBitmap = imm.readMemory(heap+0x158, 4)
        FreelistBitmap = reverse(FreelistBitmap)
        FreelistBitmap = int(binascii.hexlify(FreelistBitmap),16)  
                        
        window.Log("+0x158 FreelistBitmap                 : 0x%08x" % FreelistBitmap, FreelistBitmap)
        window.Log("+0x16a AllocatorBackTraceIndex        : 0x%08x" % pheap.AllocatorBackTraceIndex, pheap.AllocatorBackTraceIndex)

        NonDedicatedListLength = imm.readMemory(heap+0x16c, 4)
        NonDedicatedListLength = reverse(NonDedicatedListLength)
        NonDedicatedListLength = int(binascii.hexlify(NonDedicatedListLength),16)
                    
        window.Log("+0x16c NonDedicatedListLength         : 0x%08x" % NonDedicatedListLength, NonDedicatedListLength)
        window.Log("+0x170 LargeBlocksIndex               : 0x%08x" % pheap.LargeBlocksIndex, pheap.LargeBlocksIndex)
        window.Log("+0x174 PseudoTagEntries               : 0x%08x" % pheap.PseudoTagEntries)
        window.Log("+0x178 Freelist[0]                    : 0x%08x" % (heap+0x178), (heap+0x178))
        window.Log("+0x578 LockVariable                   : 0x%08x" % pheap.LockVariable, pheap.LockVariable)
        window.Log("+0x57c CommitRoutine                  : 0x%08x" % pheap.CommitRoutine, pheap.CommitRoutine)
                    
        # and the rest..
        FrontEndHeap = imm.readMemory(heap+0x580, 4)
        FrontEndHeap = reverse(FrontEndHeap)
        FrontEndHeap = int(binascii.hexlify(FrontEndHeap),16)
                    
        FrontHeapLockCount = imm.readMemory(heap+0x584, 2)
        FrontHeapLockCount = reverse(FrontHeapLockCount)
        FrontHeapLockCount = int(binascii.hexlify(FrontHeapLockCount),16)
                    
        FrontEndHeapType = imm.readMemory(heap+0x586, 1)
        FrontEndHeapType = reverse(FrontEndHeapType)
        FrontEndHeapType = int(binascii.hexlify(FrontEndHeapType),16)
                    
        LastSegmentIndex = imm.readMemory(heap+0x587, 1)
        LastSegmentIndex = reverse(LastSegmentIndex)
        LastSegmentIndex = int(binascii.hexlify(LastSegmentIndex),16)
                    
        window.Log("+0x580 FrontEndHeap                   : 0x%08x" % FrontEndHeap, FrontEndHeap)
        window.Log("+0x584 FrontHeapLockCount             : 0x%08x" % FrontHeapLockCount, FrontHeapLockCount)
        window.Log("+0x586 FrontEndHeapType               : 0x%08x" % FrontEndHeapType, FrontEndHeapType)
        window.Log("+0x587 LastSegmentIndex               : 0x%08x" % LastSegmentIndex, LastSegmentIndex)    

def main(args):
    imm = immlib.Debugger()
    if not args:
        banner(imm)
        return usage(imm)
    banner(imm)
    
    if len(args) > 1:
        cmds = setUpArgs()
        if args[0].lower().strip() == "help":
            if args[1].lower().strip() in available_commands:
                # teach them how to do stuff
                if args[1].lower().strip() == "dumppeb" or args[1].lower().strip() == "dp":
                    usageText = cmds["dumppeb"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "dumpteb" or args[1].lower().strip() == "dt":
                    usageText = cmds["dumpteb"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "dumpheaps" or args[1].lower().strip() == "dh":
                    usageText = cmds["dumpheaps"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "dumpfunctionpointers" or args[1].lower().strip() == "dfp":
                    usageText = cmds["dumpfunctionpointers"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "analyseheap" or args[1].lower().strip() == "ah":
                    usageText = cmds["analyseheap"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "analysefreelist" or args[1].lower().strip() == "af":
                    usageText = cmds["analysefreelist"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "analyselal" or args[1].lower().strip() == "al":
                    usageText = cmds["analyselal"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "analysechunks" or args[1].lower().strip() == "ac":
                    usageText = cmds["analysechunks"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "analysesegments" or args[1].lower().strip() == "as":
                    usageText = cmds["analysesegments"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                elif args[1].lower().strip() == "freelistinuse" or args[1].lower().strip() == "fliu":
                    usageText = cmds["freelistinuse"].usage.split("\n")
                    for line in usageText:
                        imm.log(line)
                return "(+) Good luck!"
            else:
                usage(imm)
                return "Invalid command specified!"
    
    if len(args) >= 1:
        # ensure we dont keep opening windows
        if not opennewwindow:            
            window = imm.getKnowledge(tag)
            if window and not window.isValidHandle():
                imm.forgetKnowledge(tag)
                del window
                window = None
        
            if not window:
                window = imm.createTable("Heaper - by mr_me", ["Address", "Information"])
                imm.addKnowledge(tag, window, force_add = 1)
        win_banner(window)
        
    if len(args) == 1:
        if args[0].lower().strip() in available_commands:
            if args[0].lower().strip() == "dumpheaps" or args[0].lower().strip() == "dh":
                return dump_heap(imm)
            elif args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
                return dump_peb(imm,window)
            elif args[0].lower().strip() == "dumpteb" or args[0].lower().strip() == "dt":
                return dump_teb(imm,window)
            elif args[0].lower().strip() == "help" or args[0].lower().strip() == "-h":
                return usage(imm)
            elif args[0].lower().strip() == "dumpfunctionpointers" or args[0].lower().strip() == "dfp":
                # default debugged processes .data segment
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
                return "Invalid number of arguments"
        else:
            usage(imm)
            return "Invalid command specified!"
    
    # the main entry into the arguments...
    elif len(args) >= 2:
        graphic_structure = False
        custfilename = False
        if args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
                if args[1] == "-m":
                    dump_peb(imm,window,True)
                    
        # assume its a heap address the second arg
        if (args[0].lower().strip() in available_commands and args[0].lower().rstrip() != "help" 
            and args[0].lower().rstrip() != "-h"):
                        
            # check if we are graphing, if so, do we have a custom filename?
            if "-g" in args:
                graphic_structure = True
                if "-f" in args:
                    try:
                        custfilename = True
                        filename = args[args.index("-f")+1]
                    except:
                        return "no filename specified"   

            # analyse a heap (heap structure)
            if args[0].lower().strip() == "analyseheap" or args[0].lower().strip() == "ah":
                try:
                    heap = args[1].lower().strip()
                    heap = int(heap,16)
                except:
                    return "Invalid heap address"
                
                analyse_heap(heap, imm, window)
            
            # analyse the lookaside list
            elif args[0].lower().strip() == "analyselal" or args[0].lower().strip() == "al":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                if imm.getOsVersion() == "xp":
                    FrontEndHeap = imm.readMemory(heap+0x580, 4)
                    FrontEndHeap = reverse(FrontEndHeap)
                    FrontEndHeap = int(binascii.hexlify(FrontEndHeap),16) 
                    window.Log("-" * 77)
                    window.Log("Lookaside List structure @ 0x%08x" % FrontEndHeap)
                    window.Log("-" * 77)
                    if custfilename:
                        dump_lal(imm, pheap, graphic_structure, window, filename)
                    else:
                        dump_lal(imm, pheap, graphic_structure, window)
                else:
                    window.Log("Lookaside list analyse not supported under Windows Vista and above")
            
            # analyse freelists
            elif args[0].lower().strip() == "analysefreelist" or args[0].lower().strip() == "af":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                if imm.getOsVersion() == "xp":
                    window.Log("-" * 62)
                    window.Log("FreeList structure @ 0x%08x" % (heap+0x178))
                    window.Log("-" * 62)
                    if graphic_structure:
                        if custfilename:
                                
                            dump_freelist(imm, pheap, window, heap, graphic_structure, filename)
                        else:
                            dump_freelist(imm, pheap, window, heap, graphic_structure)
                    else:
                        dump_freelist(imm, pheap, window, heap, graphic_structure)
                    dump_FreeListInUse(pheap, window)
                    # do vista and windows 7 freelist analyse?
                else:
                    window.Log("(-) Freelist analyse not supported under Vista and above")
                        
            # analyse FreelistInUse
            elif args[0].lower().strip() == "freelistinuse" or args[0].lower().strip() == "fliu":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                window.Log("")
                window.Log("(+) Dumping the FreeListInUse for heap 0x%08x" % heap)
                if len(args) > 2:
                    if args[2] == "-p":
                        window.Log("")
                        if args[3] and int(args[3],16) in range(0x00,0x7f): 
                            set_FreeListInUse(int(args[3],16),window,pheap,imm,heap)
                            window.Log("(+) Patched FreeList[%x]'s FreeListInUse!" % int(args[3],16))
                        else:
                            window.Log("(-) Failed to patch FreeListInUse for heap 0x%08x" % heap)
                    
                dump_FreeListInUse(pheap, window)
                
            # analyse segment chunks
            elif args[0].lower().strip() == "analysechunks" or args[0].lower().strip() == "ac":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)               
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

                for ar in args:
                    if ar == "-p":
                        patch = True
                    if ar == "-r":
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
                        return "(-) Please specficy which pointer to patch... eg: all / 00514450"
                  
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
            elif args[0].lower().strip() == "analysesegments" or args[0].lower().strip() == "as":
                pheap, heap = get_heap_instance(args[1].lower().strip(), imm)
                dump_segment_structure(pheap, window, imm, heap)
                

        # more than one command and that we cant understand
        else:
            return usage(imm)