'''
Created on Apr 24, 2012

@author:  mr_me
@contact: steventhomasseeley@gmail.com
@version: 0.02
'''

__VERSION__ = '0.02'
__IMM__ = '1.8'

DESC="""heaper - an advanced heap analysis plugin for Immunity Debugger."""

import immlib
from immlib import LogBpHook, FastLogHook
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
import os

###########
# Globals #
###########

# for hooking function pointers
# =============================
INDEXER      = 0xb4000000
INDEX_MASK   = 0xFF000000
FNDX_MASK    = 0x00FFFFFF

# window management
# =================
opennewwindow = False
windowtag     = "display_box"

# The Heaper class
class Heaper:

    """ 
    The main heaper class that handles generic heap analysis
    """
    def __init__(self, imm, window):
        self.imm                = imm
        self.window             = window
        self.opennewwindow      = False
        self.os                 = ""
        self.heap               = ""
        self.pheap              = ""
        self.config_settings    = []
        self.block              = 0x8

        # all available commands '!heaper <command>'
        self.available_commands = ["dumppeb", "dp", "dumpheaps", "dh", "analyseheap", "ah", 
        "dumpteb", "dt", "analysefrontend", "af", "analysebackend", "ab", "analysechunks", "ac", 
        "dumpfunctionpointers", "dfp", "help", "-h", "analysesegments", "as", "-f", "-m", "-p",
        "freelistinuse", "fliu", "analyseheapcache", "ahc", "exploit", "exp", "u",
        "update", "patch", "p", "config", "cnf", "hardhook", "hh", "softhook", "sh", "findwptrs",
        "findwritablepointers"]

    def run(self):
        self.os         = int(self.imm.getOsRelease().split('.')[0])
        self.peb        = self.imm.getPEBAddress()
        self.peb_struct = self.imm.getPEB()
        self.config_settings.append("workingdir")
        self.set_config()

    # operational methods
    # ===================
    def banner(self):
        self.window.Log("----------------------------------------") 
        self.window.Log("    __                         ")
        self.window.Log("   / /  ___ ___ ____  ___ ____ ")
        self.window.Log("  / _ \/ -_) _ `/ _ \/ -_) __/ ")
        self.window.Log(" /_//_/\__/\_,_/ .__/\__/_/    ")
        self.window.Log("              /_/              ")
        self.window.Log("----------------------------------------")
        self.window.Log("by mr_me :: steventhomasseeley@gmail.com")

    def usage(self):
        self.window.Log("")
        self.window.Log("****   available commands   ****")
        self.window.Log("")
        self.window.Log("dumppeb / dp                          : Dump the PEB pointers")
        self.window.Log("dumpteb / dt                          : Dump the TEB pointers")
        self.window.Log("dumpheaps / dh                        : Dump the heaps")
        self.window.Log("dumpfunctionpointers / dfp            : Dump all the processes function pointers")
        self.window.Log("findwritablepointers / findwptrs      : Dump all the called, writable function pointers")
        self.window.Log("analyseheap <heap> / ah <heap>        : Analyse a particular heap")
        self.window.Log("analysefrontend <heap> / af <heap>    : Analyse a particular heap's frontend data structure")
        self.window.Log("analysebackend <heap> / ab <heap>     : Analyse a particular heap's backend data structure")
        self.window.Log("analysesegments <heap> / as <heap>    : Analyse a particular heap's segments")
        self.window.Log("analysechunks <heap> / ac <heap>      : Analyse a particular heap's chunks")
        self.window.Log("analyseheapcache <heap> / ahc <heap>  : Analyse a particular heap's cache (FreeList[0])")
        self.window.Log("freelistinuse <heap> / fliu <heap>    : Analyse/patch the FreeListInUse structure")
        self.window.Log("hardhook <heap> / hh <heap> -f <func> : Hook various functions that manipulate a heap by injecting assembly")
        self.window.Log("softhook <heap> / sh <heap> -f <func> : Hook various functions that manipulate a heap by using software breakpoints ")
        self.window.Log("patch <function/data structure> / p   : Patch a function or datastructure")
        self.window.Log("update / u                            : Update to the latest version")
        self.window.Log("config <options> / cnf <options>      : Display or set the current context configurations")
        self.window.Log("exploit <heap> / exp <heap>           : Perform heuristics against the FrontEnd and BackEnd allocators")
        self.window.Log("                                        to determine exploitable conditions")
        self.window.Log("")
        self.window.Log("Want more info about a given command? Run !heaper help <command>")
        self.window.Log("Detected the operating system to be windows %s, keep this in mind." % (self.imm.getOsVersion()))
        self.window.Log("")
        return "Example: !heaper al 00480000 -l"

    def get_config(self):
        config_settings = []
        for knowledge in self.imm.listKnowledge():
            if re.match("config", knowledge):
                config_settings.append(knowledge)
        return config_settings

    # runtime detection of avaliable functions
    def get_extended_usage(self):
        extusage = {}
        extusage["freelistinuse"] = "\nfreelistinuse <heap> / fliu <heap> : analyse/patch the FreeListInUse structure\n"
        extusage["freelistinuse"] += "---------------------------------------------\n"
        extusage["freelistinuse"] += "Use -p <byte entry> to patch the FreeListInUse entry and set its bit\n"
        extusage["freelistinuse"] += "eg !heaper 0x00a80000 -p 0x7c\n"
        extusage["dumppeb"] = "\ndumppeb / dp : Return the PEB entry address\n"
        extusage["dumppeb"] += "---------------------------------------------\n"
        extusage["dumppeb"] += "Use -m to view the PEB management structure\n"
        extusage["softhook"] = "\nsofthook <heap> / sh : Hook various functions that create/destroy/manipulate a heap\n"
        extusage["softhook"] += "------------------------------------------------------------------------------\n"
        extusage["softhook"] += "Use -f to hook available function(s).\n"
        extusage["softhook"] += "Use -u to unhook previously hooked function(s).\n"
        extusage["softhook"] += "Available functions to hook are: \n"
        extusage["softhook"] += "- RtlAllocateHeap()              [alloc]\n"
        extusage["softhook"] += "- RtlFreeHeap()                  [free]\n"   
        extusage["softhook"] += "- Hook all functions!            [all]\n"
        extusage["softhook"] += "Examples:\n"
        extusage["softhook"] += "~~~~~~~~~\n"
        extusage["softhook"] += "Hard hook RtlAllocateHeap() on heap 0x00150000 '!heaper softhook 0x00150000 -h alloc'\n"
        extusage["softhook"] += "Unhook all heap functions '!heaper softhook 0x00150000 -u all'\n"
        extusage["softhook"] += "Hard hook RtlFreeHeap() '!heaper sh 0x00150000 -f free'\n"
        extusage["hardhook"] = "\nhardhook <heap> / hh : Hook various functions that create/destroy/manipulate a heap\n"
        extusage["hardhook"] += "------------------------------------------------------------------------------\n"
        extusage["hardhook"] += "Use -h to hook RtlAllocateHeap and RtlFreeHeap.\n"
        extusage["hardhook"] += "Use -u to unhook previously hooked functions.\n"
        extusage["hardhook"] += "Available options to use: \n"
        extusage["hardhook"] += "-a                 : filter by chunk address\n"
        extusage["hardhook"] += "-h                 : enable the hook on\n"   
        extusage["hardhook"] += "-d                 : disable the hooks\n"
        extusage["hardhook"] += "-c                 : clear the hooks\n"
        extusage["hardhook"] += "-p                 : pause hook execution\n"
        extusage["hardhook"] += "-C                 : Continue hook execution\n"
        extusage["hardhook"] += "Examples:\n"
        extusage["hardhook"] += "~~~~~~~~~\n"
        extusage["hardhook"] += "'!heaper hardhook 0x00150000 -h'\n"
        extusage["hardhook"] += "'!heaper hardhook 0x00150000 -u'\n"
        extusage["hardhook"] += "'!heaper hh 0x00150000 -h -a 0x1503e848'\n"
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
        if self.os >= 6.0:
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
        elif self.os < 6.0:
            extusage["analysefrontend"] += "Use -l to dump the Lookaside Lists\n"
            extusage["analysefrontend"] += "Use -v to verbosely dump the Lookaside Lists\n"
            extusage["analysefrontend"] += "Use -g to view a graphical representation of the Lookaside Lists\n"
            extusage["analysefrontend"] += "Use -o to specify a filename for the graph\n"
            extusage["analysefrontend"] += "Examples:\n"
            extusage["analysefrontend"] += "~~~~~~~~~\n"
            extusage["analysefrontend"] += "Dump the Lookaside Lists '!heaper af 0x00260000 -l'\n"
            extusage["analysefrontend"] += "Dump the Lookaside Lists and graph it '!heaper af 0x00260000 -l -g -o lookaside'\n"
        extusage["analysebackend"] = "\nanalysebackend <heap> / ab <heap> : Analyse a particular heap's backend free structure\n"
        extusage["analysebackend"] += "------------------------------------------------------------------------------------\n" 
        if self.os >= 6.0:
            extusage["analysebackend"] += "Use -l to view the ListHints\n"
            extusage["analysebackend"] += "Use -f to view the FreeList chunks\n"  
            extusage["analysebackend"] += "Use -g to view a graphical representation of the ListHint/FreeList\n"
            extusage["analysebackend"] += "Use -o to specify a filename for the graph\n"
            extusage["analysebackend"] += "Examples:\n"
            extusage["analysebackend"] += "~~~~~~~~~\n"
            extusage["analysebackend"] += "Analyse the ListHints '!heaper ab 00150000 -l'\n"

        # verbose mode only supported in windows NT v5.x for now
        elif self.os < 6.0:
            extusage["analysebackend"] += "Use -h to dump the HeapCache (if its activated)\n"
            extusage["analysebackend"] += "Use -f to dump the FreeList chunks\n"
            extusage["analysebackend"] += "Use -v to verbosely dump the FreeList chunks\n"
            extusage["analysebackend"] += "Use -g to view a graphical representation of the FreeLists\n"
            extusage["analysebackend"] += "Use -o to specify a filename for the graph\n"
            extusage["analysebackend"] += "Examples:\n"
            extusage["analysebackend"] += "~~~~~~~~~\n"
            extusage["analysebackend"] += "Analyse the FreeList '!heaper ab 00150000 -f'\n"
            extusage["analysebackend"] += "Analyse the FreeList verbosly '!heaper ab 00150000 -f -v'\n"
        extusage["analysebackend"] += "Analyse and graph the FreeList '!heaper ab 00150000 -f -g'\n"
        extusage["analysebackend"] += "Analyse and graph the FreeList verbosly setting a filename '!heaper ab 00150000 -f -g -v -o ie8_freelist'\n"
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
        extusage["config"] = "\nconfig / cnf : Display the current configuration settings or set them accordingly\n"
        extusage["config"] += "---------------------------------------------------------------------------------\n"
        extusage["config"] += "Use -d to display the current settings\n"
        extusage["config"] += "Use -s to set any setting\n"
        extusage["config"] += "Examples:\n"
        extusage["config"] += "~~~~~~~~~\n"
        extusage["config"] += "Display the settings '!heaper cnf -d'\n"
        extusage["config"] += "Set the workingdir option '!heaper cnf -s workingdir c:\output'\n"
        extusage["exploit"] = "\nexploit <heap> / exp <heap>: Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions\n"
        extusage["exploit"] += "-----------------------------------------------------------------------------------\n"
        extusage["exploit"] += "Use -f to analyse the FrontEnd allocator\n"
        extusage["exploit"] += "Use -b to analyse the BackEnd allocator\n"
        extusage["exploit"] += "Example: !heaper exploit 00490000 -f\n"
        extusage["findwritablepointers"] = "\nfindwritablepointers / findwptrs : Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions\n"
        extusage["findwritablepointers"] += "-------------------------------------------------------------------------------------------------------------------------------------\n"
        extusage["findwritablepointers"] += "Use -m to filter by module (use 'all' for all modules in the address space)\n"
        extusage["findwritablepointers"] += "!! Warning: using the 'all' option will take a long time. Go get a 0xc00ffee !!\n"
        extusage["findwritablepointers"] += "Examples:\n"
        extusage["findwritablepointers"] += "~~~~~~~~~\n"
        extusage["findwritablepointers"] += "find calls/jmps in ntdll.dll - '!heaper findwptrs -m ntdll.dll'\n"
        extusage["findwritablepointers"] += "find calls/jmps in all modules - '!heaper findwptrs -m all'\n"
        return extusage

    # taken from mona.py, thanks peter
    def get_modules_iat(self, module):
        themod = module
        syms = themod.getSymbols()
        IAT = []
        for sym in syms:
            if syms[sym].getType().startswith("Import"):
                theaddress = syms[sym].getAddress()
                if not theaddress in IAT:
                    IAT.append(theaddress)
        return IAT
    
    def set_usage(self):
        self.cmds = {}
        self.cmds["dumppeb"] = Setcommand("dumppeb", "Dump the PEB pointers",self.get_extended_usage()["dumppeb"], "dp")
        self.cmds["dp"] = Setcommand("dumppeb", "Dump the PEB pointers",self.get_extended_usage()["dumppeb"], "dp")
        self.cmds["dumpteb"] = Setcommand("dumpteb", "Dump the TEB pointers",self.get_extended_usage()["dumpteb"], "dt")
        self.cmds["dt"] = Setcommand("dumpteb", "Dump the TEB pointers",self.get_extended_usage()["dumpteb"], "dt")
        self.cmds["dumpheaps"] = Setcommand("dumpheaps", "Dump all the heaps of a process",self.get_extended_usage()["dumpheaps"], "dh")
        self.cmds["dh"] = Setcommand("dumpheaps", "Dump all the heaps of a process",self.get_extended_usage()["dumpheaps"], "dh")
        self.cmds["dumpfunctionpointers"] = Setcommand("dumpfunctionpointers", "Dump all the function pointers of the current process",self.get_extended_usage()["dumpfunctionpointers"], "dfp")
        self.cmds["dfp"] = Setcommand("dumpfunctionpointers", "Dump all the function pointers of the current process",self.get_extended_usage()["dumpfunctionpointers"], "dfp")
        self.cmds["analyseheap"] = Setcommand("analyseheap", "analyse a particular heap",self.get_extended_usage()["analyseheap"], "ah")
        self.cmds["ah"] = Setcommand("analyseheap", "analyse a particular heap",self.get_extended_usage()["analyseheap"], "ah")
        self.cmds["analysefrontend"] = Setcommand("analysefrontend", "analyse a particular heap's frontend",self.get_extended_usage()["analysefrontend"], "af")
        self.cmds["af"] = Setcommand("analyselal", "analyse a particular heap's lookaside list",self.get_extended_usage()["analysefrontend"], "af")
        self.cmds["analysebackend"] = Setcommand("analysebackend", "analyse a particular heap's backend",self.get_extended_usage()["analysebackend"], "ab")
        self.cmds["ab"] = Setcommand("analysefreelist", "analyse a particular heap's freelist",self.get_extended_usage()["analysebackend"], "ab")
        self.cmds["analysechunks"] = Setcommand("analysechunks", "analyse a particular heap's list of chunks",self.get_extended_usage()["analysechunks"], "ac")
        self.cmds["ac"] = Setcommand("analysechunks", "analyse a particular heap's list of chunks",self.get_extended_usage()["analysechunks"], "ac")
        self.cmds["analysesegments"] = Setcommand("analysesegments", "analyse a particular heap's segment(s)",self.get_extended_usage()["analysesegments"], "as")
        self.cmds["as"] = Setcommand("analysesegments", "analyse a particular heap's segment(s)",self.get_extended_usage()["analysesegments"], "as")
        self.cmds["analyseheapcache"] = Setcommand("analyseheapcache", "analyse a particular heap's cache (FreeList[0])",self.get_extended_usage()["analyseheapcache"], "ahc")
        self.cmds["ahc"] = Setcommand("analyseheapcache", "analyse a particular heap's cache (FreeList[0])",self.get_extended_usage()["analyseheapcache"], "ahc")
        self.cmds["freelistinuse"] = Setcommand("freelistinuse", "analyse/patch the FreeListInUse structure",self.get_extended_usage()["freelistinuse"], "fliu")
        self.cmds["fliu"] = Setcommand("freelistinuse", "analyse/patch the FreeListInUse structure",self.get_extended_usage()["freelistinuse"], "fliu")
        self.cmds["hardhook"] = Setcommand("hook", "Hard hook various functions that manipulate a heap",self.get_extended_usage()["hardhook"], "hh")
        self.cmds["hh"] = Setcommand("hook", "Hard hook various functions that manipulate a heap",self.get_extended_usage()["hardhook"], "hh")
        self.cmds["softhook"] = Setcommand("hook", "Soft hook various functions that manipulate a heap",self.get_extended_usage()["softhook"], "sh")
        self.cmds["sh"] = Setcommand("hook", "Soft hook various functions that manipulate a heap",self.get_extended_usage()["softhook"], "sh")
        self.cmds["patch"] = Setcommand("patch", "Patch various data structures and functions",self.get_extended_usage()["patch"], "p")
        self.cmds["p"] = Setcommand("patch", "Patch various data structures and functions",self.get_extended_usage()["patch"], "p")
        self.cmds["exploit"] = Setcommand("exploit", "Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions",self.get_extended_usage()["exploit"], "exp")
        self.cmds["exp"] = Setcommand("exploit", "Perform heuristics against the FrontEnd and BackEnd allocators to determine exploitable conditions",self.get_extended_usage()["exploit"], "exp")    
        self.cmds["config"] = Setcommand("config", "Display or set the current configuration",self.get_extended_usage()["config"], "cnf")
        self.cmds["cnf"] = Setcommand("config", "Display or set the current configuration",self.get_extended_usage()["config"], "cnf")
        self.cmds["findwritablepointers"] = Setcommand("findwritablepointers", "List all the called, hardcoded, writable function pointers for a given module or modules",self.get_extended_usage()["findwritablepointers"], "findwptrs")
        self.cmds["findwptrs"] = Setcommand("findwritablepointers", "List all the called, hardcoded, writable function pointers for a given module or modules",self.get_extended_usage()["findwritablepointers"], "findwptrs") 

    def set_config(self):
        self.imm.addKnowledge("config_workingdir","C:\\Program Files\\Immunity Inc\\Immunity Debugger\\heaper")

    # print methods
    def print_heaps(self):
        self.window.Log("-" * 24)
        self.window.Log("Listing available heaps: ")
        self.window.Log("")
        for hndx in self.imm.getHeapsAddress():
            self.window.Log("Heap: 0x%08x" % hndx, address = hndx, focus = 1)
        self.window.Log("-" * 16)
        return "(+) Dumped all heaps for the debugged process"

    def print_peb_struct(self, dump_management=False):
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
        self.window.Log("")
        if dump_management:

            # some PEB members are not in immlib API
            AtlThunkSListPtr32 = self.imm.readMemory(self.peb+0x34, 4)
            (AtlThunkSListPtr32) = struct.unpack("L", AtlThunkSListPtr32)[0]

            # we only need them if we are running win7's PEB structure
            if self.os >= 6.0:
                AtlThunkSListPtr    = self.imm.readMemory(self.peb+0x20, 4)
                AtlThunkSListPtr    = struct.unpack("L", AtlThunkSListPtr)[0]
                IFEOKey             = self.imm.readMemory(self.peb+0x24, 4)
                IFEOKey             = struct.unpack("L", IFEOKey)[0]
                ApiSetMap           = self.imm.readMemory(self.peb+0x38, 4)
                ApiSetMap           = struct.unpack("L", ApiSetMap)[0]  
                FlsBitmapBits       = self.imm.readMemory(self.peb+0x21c, 8)
                FlsBitmapBits       = struct.unpack("d", FlsBitmapBits)[0]
                FlsBitmapBits2      = self.imm.readMemory(self.peb+0x21c+0x8, 8)
                FlsBitmapBits2      = struct.unpack("d", FlsBitmapBits2)[0]
                FlsBitmap           = self.imm.readMemory(self.peb+0x218, 4)
                FlsBitmap           = struct.unpack("L", FlsBitmap)[0] 
                FlsListHead         = self.imm.readMemory(self.peb+0x210, 4)
                FlsListHead         = struct.unpack("L", FlsListHead)[0] 
                FlsCallback         = self.imm.readMemory(self.peb+0x20c, 4)
                FlsCallback         = struct.unpack("L", FlsCallback)[0]
                FlsHighIndex        = self.imm.readMemory(self.peb+0x22c, 4)
                FlsHighIndex        = struct.unpack("L", FlsHighIndex)[0]  
                WerRegistrationData = self.imm.readMemory(self.peb+0x230, 4)
                WerRegistrationData = struct.unpack("L", WerRegistrationData)[0]             
                WerShipAssertPtr    = self.imm.readMemory(self.peb+0x234, 4)
                WerShipAssertPtr    = struct.unpack("L", WerShipAssertPtr)[0]    
                pContextData        = self.imm.readMemory(self.peb+0x238, 4)
                pContextData        = struct.unpack("L", pContextData)[0]   
                pImageHeaderHash    = self.imm.readMemory(self.peb+0x23c, 4)
                pImageHeaderHash    = struct.unpack("L", pImageHeaderHash)[0]           
                offset_three        = self.imm.readMemory(self.peb+0x03, 1)
                offset_three        = struct.unpack("B", offset_three)[0]

                # get the binary 0/1 representation
                binary_three = bin(offset_three)[2:].rjust(8, '0')
                CrossProcessFlags   = self.imm.readMemory(self.peb+0x28, 4)
                CrossProcessFlags   = struct.unpack("L", CrossProcessFlags)[0]

                # 4 bytes instead of 1 so we expand to 32 bits
                binary_twenty_eight = bin(CrossProcessFlags)[2:].rjust(32, '0')
            AppCompatFlags                      = self.imm.readMemory(self.peb+0x1d8, 8)
            AppCompatFlags                      = struct.unpack("LL", AppCompatFlags)[0] 
            AppCompatFlagsUser                  = self.imm.readMemory(self.peb+0x1e0, 8)
            AppCompatFlagsUser                  = struct.unpack("LL", AppCompatFlagsUser)[0] 
            pShimData                           = self.imm.readMemory(self.peb+0x1e8, 4)
            pShimData                           = struct.unpack("L", pShimData)[0]
            ActivationContextData               = self.imm.readMemory(self.peb+0x1f8, 4)
            ActivationContextData               = struct.unpack("L", ActivationContextData)[0]
            ProcessAssemblyStorageMap           = self.imm.readMemory(self.peb+0x1fc, 4)
            ProcessAssemblyStorageMap           = struct.unpack("L", ProcessAssemblyStorageMap)[0]
            SystemDefaultActivationContextData  = self.imm.readMemory(self.peb+0x200, 4)
            SystemDefaultActivationContextData  = struct.unpack("L", SystemDefaultActivationContextData)[0]
            SystemAssemblyStorageMap            = self.imm.readMemory(self.peb+0x204, 4)
            SystemAssemblyStorageMap            = struct.unpack("L", SystemAssemblyStorageMap)[0]
            MinimumStackCommit                  = self.imm.readMemory(self.peb+0x208, 4)
            MinimumStackCommit                  = struct.unpack("L", MinimumStackCommit)[0]
            self.window.Log("---------------------------------------------------------")
            self.window.Log("PEB Management Structure @ 0x%08x" % self.peb,self.peb)
            self.window.Log("---------------------------------------------------------")
            self.window.Log("+0x000 InheritedAddressSpace                 : 0x%08x" % self.peb_struct.InheritedAddressSpace, self.peb_struct.InheritedAddressSpace)
            self.window.Log("+0x001 ReadImageFileExecOptions              : 0x%08x" % self.peb_struct.ReadImageFileExecOptions, self.peb_struct.ReadImageFileExecOptions)
            self.window.Log("+0x002 BeingDebugged                         : 0x%08x" % self.peb_struct.BeingDebugged, self.peb_struct.BeingDebugged) 
            if self.os < 6.0:
                self.window.Log("+0x003 SpareBool                             : 0x%08x" % self.peb_struct.SpareBool, self.peb_struct.SpareBool)
            elif self.os >= 6.0:

                # according the wingdbg symbols
                self.window.Log("+0x003 BitField                              : 0x%x" % offset_three,offset_three)
                self.window.Log("+0x003 ImageUsesLargePages                   : bit: %s" % binary_three[1])
                self.window.Log("+0x003 IsProtectedProcess                    : bit: %s" % binary_three[2])
                self.window.Log("+0x003 IsLegacyProcess                       : bit: %s" % binary_three[3])
                self.window.Log("+0x003 IsImageDynamicallyRelocated           : bit: %s" % binary_three[4])
                self.window.Log("+0x003 SkipPatchingUser32Forwarders          : bit: %s" % binary_three[5])
                self.window.Log("+0x003 SpareBits                             : bits 6-8: %s" % binary_three[-3:len(binary_three)])
            self.window.Log("+0x004 Mutant                                : 0x%08x" % self.peb_struct.Mutant, self.peb_struct.Mutant)
            self.window.Log("+0x008 ImageBaseAddress                      : 0x%08x" % self.peb_struct.ImageBaseAddress, self.peb_struct.ImageBaseAddress)
            self.window.Log("+0x00c Ldr                                   : 0x%08x" % self.peb_struct.Ldr, self.peb_struct.Ldr)
            self.window.Log("+0x010 ProcessParameters                     : 0x%08x" % self.peb_struct.ProcessParameters, self.peb_struct.ProcessParameters)
            self.window.Log("+0x014 SubSystemData                         : 0x%08x" % self.peb_struct.SubSystemData, self.peb_struct.SubSystemData)
            self.window.Log("+0x018 ProcessHeap                           : 0x%08x" % self.peb_struct.ProcessHeap, self.peb_struct.ProcessHeap)
            self.window.Log("+0x01c FastPebLock                           : 0x%08x" % self.peb_struct.FastPebLock, self.peb_struct.FastPebLock)
            if self.os < 6.0:
                self.window.Log("+0x020 FastPebLockRoutine                    : 0x%08x" % self.peb_struct.FastPebLockRoutine, self.peb_struct.FastPebLockRoutine)
                self.window.Log("+0x024 FastPebUnLockRoutine                  : 0x%08x" % self.peb_struct.FastPebUnlockRoutine, self.peb_struct.FastPebUnlockRoutine)
                self.window.Log("+0x028 EnvironmentUpdateCount                : 0x%08x" % self.peb_struct.EnviromentUpdateCount, self.peb_struct.EnviromentUpdateCount)
            elif self.os >= 6.0:
                self.window.Log("+0x020 AtlThunkSListPtr                      : 0x%08x" % AtlThunkSListPtr,AtlThunkSListPtr)
                self.window.Log("+0x024 IFEOKey                               : 0x%08x" % IFEOKey, IFEOKey)

                # according the wingdbg symbols
                self.window.Log("+0x028 CrossProcessFlags                     : 0x%08x" % CrossProcessFlags,CrossProcessFlags)
                self.window.Log("+0x028 ProcessInJob                          : bit: %s" % binary_twenty_eight[1])
                self.window.Log("+0x028 ProcessInitializing                   : bit: %s" % binary_twenty_eight[2])
                self.window.Log("+0x028 ProcessUsingVEH                       : bit: %s" % binary_twenty_eight[3])
                self.window.Log("+0x028 ProcessUsingVCH                       : bit: %s" % binary_twenty_eight[4])
                self.window.Log("+0x028 ProcessUsingFTH                       : bit: %s" % binary_twenty_eight[5])
                self.window.Log("+0x028 ReservedBits0                         : bits 6-32: %s" % binary_twenty_eight[-27:len(binary_twenty_eight)])
            self.window.Log("+0x02c KernelCallbackTable                   : 0x%08x" % self.peb_struct.KernelCallbackTable, self.peb_struct.KernelCallbackTable)
            if self.os >= 6.0:
                self.window.Log("+0x02c UserSharedInfoPtr                     : 0x%08x" % self.peb_struct.KernelCallbackTable, self.peb_struct.KernelCallbackTable)
            for sysResv in self.peb_struct.SystemReserved:
                self.window.Log("    +0x030 SystemReserved                    : 0x%08x" % sysResv, sysResv) 
            self.window.Log("+0x034 AtlThunkSListPtr32                    : 0x%08x" % AtlThunkSListPtr32, AtlThunkSListPtr32)
            if self.os < 6.0: 
                self.window.Log("+0x038 FreeList                              : 0x%08x" % self.peb_struct.FreeList, self.peb_struct.FreeList)
            elif self.os >= 6.0:
                self.window.Log("+0x038 ApiSetMap                             : 0x%08x" % ApiSetMap, ApiSetMap)
            self.window.Log("+0x03c TlsExpansionCounter                   : 0x%08x" % self.peb_struct.TlsExpansionCounter, self.peb_struct.TlsExpansionCounter)
            self.window.Log("+0x040 TlsBitmap                             : 0x%08x" % self.peb_struct.TlsBitmap, self.peb_struct.TlsBitmap)
            for bits in self.peb_struct.TlsBitmapBits:
                self.window.Log("    +0x044 TlsBitmapBits                     : 0x%08x" % bits, bits)
            self.window.Log("+0x04c ReadOnlySharedMemoryBase              : 0x%08x" % self.peb_struct.ReadOnlySharedMemoryBase, self.peb_struct.ReadOnlySharedMemoryBase)
            if self.os < 6.0:
                self.window.Log("+0x050 ReadOnlySharedMemoryHeap              : 0x%08x" % self.peb_struct.ReadOnlySharedMemoryheap, self.peb_struct.ReadOnlySharedMemoryheap)
            elif self.os >= 6.0:

                # ReadOnlySharedMemoryheap == HotpatchInformation
                self.window.Log("+0x050 HotpatchInformation                   : 0x%08x" % self.peb_struct.ReadOnlySharedMemoryheap, self.peb_struct.ReadOnlySharedMemoryheap)
            self.window.Log("+0x054 ReadOnlyStaticServerData              : 0x%08x" % self.peb_struct.ReadOnlyStaticServerData, self.peb_struct.ReadOnlyStaticServerData)
            self.window.Log("+0x058 AnsiCodePageData                      : 0x%08x" % self.peb_struct.AnsiCodePageData, self.peb_struct.AnsiCodePageData)
            self.window.Log("+0x05c OemCodePageData                       : 0x%08x" % self.peb_struct.OemCodePageData, self.peb_struct.OemCodePageData)
            self.window.Log("+0x060 UnicodeCaseTableData                  : 0x%08x" % self.peb_struct.UnicodeCaseTableData, self.peb_struct.UnicodeCaseTableData)
            self.window.Log("+0x064 NumberOfProcessors                    : 0x%08x" % self.peb_struct.NumberOfProcessors, self.peb_struct.NumberOfProcessors)
            self.window.Log("+0x068 NtGlobalFlag                          : 0x%08x" % self.peb_struct.NtGlobalFlag, self.peb_struct.NtGlobalFlag)
            self.window.Log("+0x070 CriticalSectionTimeout (high)         : 0x%08x" % self.peb_struct.CriticalSectionTimeout_HighPart, self.peb_struct.CriticalSectionTimeout_HighPart)
            self.window.Log("+0x070 CriticalSectionTimeout (low)          : 0x%08x" % self.peb_struct.CriticalSectionTimeout_LowPart, self.peb_struct.CriticalSectionTimeout_LowPart)
            self.window.Log("+0x078 HeapSegmentReserve                    : 0x%08x" % self.peb_struct.HeapSegmentReserve, self.peb_struct.HeapSegmentReserve)
            self.window.Log("+0x07c HeapSegmentCommit                     : 0x%08x" % self.peb_struct.HeapSegmentCommit, self.peb_struct.HeapSegmentCommit)
            self.window.Log("+0x080 HeapDeCommitTotalFreeThreshold        : 0x%08x" % self.peb_struct.HeapDeCommitTotalFreeThreshold, self.peb_struct.HeapDeCommitTotalFreeThreshold)
            self.window.Log("+0x084 HeapDeCommitFreeBlockThreshold        : 0x%08x" % self.peb_struct.HeapDeCommitFreeBlockThreshold, self.peb_struct.HeapDeCommitFreeBlockThreshold)
            self.window.Log("+0x088 NumberOfHeaps                         : 0x%08x" % self.peb_struct.NumberOfHeaps, self.peb_struct.NumberOfHeaps)
            self.window.Log("+0x08c MaximumNumberOfHeaps                  : 0x%08x" % self.peb_struct.MaximumNumberOfHeaps, self.peb_struct.MaximumNumberOfHeaps)
            self.window.Log("+0x090 ProcessHeaps                          : 0x%08x" % self.peb_struct.ProcessHeaps, self.peb_struct.ProcessHeaps)
            self.window.Log("+0x094 GdiSharedHandleTable                  : 0x%08x" % self.peb_struct.GdiSharedHandleTable, self.peb_struct.GdiSharedHandleTable)
            self.window.Log("+0x098 ProcessStarterHelper                  : 0x%08x" % self.peb_struct.ProcessStarterHelper, self.peb_struct.ProcessStarterHelper)
            self.window.Log("+0x09c GdiDCAttributeList                    : 0x%08x" % self.peb_struct.GdiDCAttributeList, self.peb_struct.GdiDCAttributeList)
            self.window.Log("+0x0a0 LoaderLock                            : 0x%08x" % self.peb_struct.LoaderLock, self.peb_struct.LoaderLock)
            self.window.Log("+0x0a4 osMajorVersion                        : 0x%08x" % self.peb_struct.OSMajorVersion, self.peb_struct.OSMajorVersion) 
            self.window.Log("+0x0a8 osMinorVersion                        : 0x%08x" % self.peb_struct.OSMinorVersion, self.peb_struct.OSMinorVersion) 
            self.window.Log("+0x0ac osBuildNumber                         : 0x%08x" % self.peb_struct.OSBuildNumber, self.peb_struct.OSBuildNumber) 
            self.window.Log("+0x0ae osCSDVersion                          : 0x%08x" % self.peb_struct.OSCSDVersion, self.peb_struct.OSCSDVersion) 
            self.window.Log("+0x0b0 osPlatformId                          : 0x%08x" % self.peb_struct.OSPlatformId, self.peb_struct.OSPlatformId) 
            self.window.Log("+0x0b4 ImageSubsystem                        : 0x%08x" % self.peb_struct.ImageSubsystem, self.peb_struct.ImageSubsystem) 
            self.window.Log("+0x0b8 ImageSubsystemMajorVersion            : 0x%08x" % self.peb_struct.ImageSubsystemMajorVersion, self.peb_struct.ImageSubsystemMajorVersion) 
            self.window.Log("+0x0bc ImageSubsystemMinorVersion            : 0x%08x" % self.peb_struct.ImageSubsystemMinorVersion, self.peb_struct.ImageSubsystemMinorVersion) 
            if self.os < 6.0:

                # ImageProcessAffinityMask == ActiveProcessAffinityMask 
                self.window.Log("+0x0c0 ImageProcessAffinityMask              : 0x%08x" % self.peb_struct.ImageProcessAffinityMask, self.peb_struct.ImageProcessAffinityMask) 
            elif self.os >= 6.0:
                self.window.Log("+0x0c0 ActiveProcessAffinityMask             : 0x%08x" % self.peb_struct.ImageProcessAffinityMask, self.peb_struct.ImageProcessAffinityMask) 
            for buff in self.peb_struct.GdiHandleBuffer:
                self.window.Log("    +0x0c4 GdiHandleBuffer                   : 0x%08x" % buff, buff) 
            self.window.Log("+0x14c PostProcessInitRoutine                : 0x%08x" % self.peb_struct.PostProcessInitRoutine, self.peb_struct.PostProcessInitRoutine) 
            self.window.Log("+0x150 TlsExpansionBitmap                    : 0x%08x" % self.peb_struct.TlsExpansionBitmap, self.peb_struct.TlsExpansionBitmap) 
            for bitmapbits in self.peb_struct.TlsExpansionBitmapBits:
                self.window.Log("    +0x154 TlsExpansionBitmapBits            : 0x%08x" % bitmapbits, bitmapbits) 
            self.window.Log("+0x1d4 SessionId                             : 0x%08x" % self.peb_struct.SessionId, self.peb_struct.SessionId) 
            self.window.Log("+0x1d8 AppCompatFlags                        : 0x%08x" % AppCompatFlags, AppCompatFlags) 
            self.window.Log("+0x1e0 AppCompatFlagsUser                    : 0x%08x" % AppCompatFlagsUser, AppCompatFlagsUser) 
            self.window.Log("+0x1e8 pShimData                             : 0x%08x" % pShimData, pShimData) 
            self.window.Log("+0x1ec AppCompatInfo                         : 0x%08x" % self.peb_struct.AppCompatInfo, self.peb_struct.AppCompatInfo) 
            self.window.Log("+0x1f0 CSDVersion                            : 0x%08x" % self.peb_struct.CSDVersion_Buffer, self.peb_struct.CSDVersion_Buffer) 
            self.window.Log("+0x1f8 ActivationContextData                 : 0x%08x" % ActivationContextData, ActivationContextData) 
            self.window.Log("+0x1fc ProcessAssemblyStorageMap             : 0x%08x" % ProcessAssemblyStorageMap, ProcessAssemblyStorageMap) 
            self.window.Log("+0x200 SystemDefaultActivationContextData    : 0x%08x" % SystemDefaultActivationContextData, SystemDefaultActivationContextData) 
            self.window.Log("+0x204 SystemAssemblyStorageMap              : 0x%08x" % SystemAssemblyStorageMap, SystemAssemblyStorageMap) 
            self.window.Log("+0x208 MinimumStackCommit                    : 0x%08x" % MinimumStackCommit, MinimumStackCommit) 
            if self.os >= 6.0:
                self.window.Log("+0x20c FlsCallback                       : 0x%08x" % FlsCallback,FlsCallback)
                self.window.Log("+0x210 FlsListHead                       : 0x%08x" % FlsListHead,FlsListHead)
                self.window.Log("+0x218 FlsBitmap                         : 0x%08x" % FlsBitmap,FlsBitmap)
                self.window.Log("+0x21c FlsBitmapBits                     : 0x%08x%08x" % (FlsBitmapBits,FlsBitmapBits2))
                self.window.Log("+0x22c FlsHighIndex                      : 0x%08x" % FlsHighIndex,FlsHighIndex)
                self.window.Log("+0x230 WerRegistrationData               : 0x%08x" % WerRegistrationData,WerRegistrationData)
                self.window.Log("+0x234 WerShipAssertPtr                  : 0x%08x" % WerShipAssertPtr,WerShipAssertPtr)
                self.window.Log("+0x238 pContextData                      : 0x%08x" % pContextData,pContextData)
                self.window.Log("+0x23c pImageHeaderHash                  : 0x%08x" % pImageHeaderHash,pImageHeaderHash)
            self.window.Log("---------------------------------------------------------")
            self.window.Log("")
            return "Dumped PEB successfully"
        else: 
            self.window.Log("(+) The PEB is located at 0x%08x" % self.peb,self.peb)
            peb_struct = self.imm.getPEB()

            # check at least to locations where the PEB might be patched..
            if peb_struct.BeingDebugged and peb_struct.NtGlobalFlag:
                self.window.Log("(!) Beaware! the PEB is not patched and heap operations may detect a debugger!")
            elif peb_struct.BeingDebugged == 0 and peb_struct.NtGlobalFlag == 0:
                self.window.Log("(+) Excellent, the PEB appears to be patched")
            return "(+) PEB is located at 0x%08x" % self.peb
    
    def print_teb(self):
        """
        dump Thread environment block - dumps the listed TEB's in the current process 
        (multi-threaded application)
        
        arguments:
        - obj imm
        - obj window
        
        return:
        - printed TEB addresses
        """
        currenttid = self.imm.getThreadId()
        threads = self.imm.getAllThreads()
        self.window.Log("")
        try:
            currentTEB = threads[currenttid].getTEB()
            self.window.Log("(+) The current TEB id is: %s and is located at: 0x%08x" % (currenttid,currentTEB),currentTEB)
        except:
            self.window.Log("(-) The current TEB id is: %s and is located at an unknown address" % (currenttid))
        tebArray = {}
        for key in threads:
            teb = key.getTEB()
            tid = key.getId()
            tebArray[teb] = tid
        valuelist = tebArray.keys()
        valuelist.sort()
        valuelist.reverse()
        if len(valuelist) == 1:
            self.window.Log("(!) There is only 1 thread running (the current TEB)")
        else:
            self.window.Log("(+) There are %d number of threads in this process" % len(valuelist))
            self.window.Log("(+) Other TEB's in this process:")
            for key in valuelist:
                self.window.Log("(+) ID: %s is located at: 0x%08x" % (tebArray[key],key), key)
        self.window.Log("-" * 40)
        return "(+) Dumped TEB successfully"

    def print_heap_struct(self):
        """
        allows you to dump the _heap structure

        arguments: 
        - int heap
        - obj imm
        - obj window

        return:
        - string showing the heap is dumped
        """
        if self.heap and ( self.heap in self.imm.getHeapsAddress() ):
            i = 0 
            v = 0
            self.window.Log("--------------------------------------------------")
            self.window.Log("Heap structure @ 0x%08x" % self.heap)
            self.window.Log("--------------------------------------------------")
            self.window.Log("+0x000 Entry                          : 0x%08x" % self.heap, self.heap)
            if self.os < 6.0:
                self.window.Log("+0x008 Signature                      : 0x%08x" % self.pheap.Signature, self.pheap.Signature)
                self.window.Log("+0x00c Flags                          : 0x%08x" % self.pheap.Flags, self.pheap.Flags)
                self.window.Log("+0x010 Forceflags                     : 0x%08x" % self.pheap.ForceFlags, self.pheap.ForceFlags)
                self.window.Log("+0x014 VirtualMemoryThreshold         : 0x%08x" % self.pheap.VirtualMemoryThreshold, self.pheap.VirtualMemoryThreshold) 
                self.window.Log("+0x018 SegmentReserve                 : 0x%08x" % self.pheap.SegmentReserve, self.pheap.SegmentReserve)
                self.window.Log("+0x01C SegmentCommit                  : 0x%08x" % self.pheap.SegmentCommit, self.pheap.SegmentCommit)
            elif self.os >= 6.0:
                self.window.Log("+0x008 SegmentSignature               : 0x%08x" % self.pheap.Signature, self.pheap.Signature)
                self.window.Log("+0x00c SegmentFlags                   : 0x%08x" % self.pheap.Flags, self.pheap.Flags)
                SegmentListEntry = self.imm.readMemory(self.heap+0x14, 4)
                SegmentListEntry = struct.unpack("L", SegmentListEntry)[0]
                self.window.Log("+0x010 SegmentListEntry               : 0x%08x" % SegmentListEntry, SegmentListEntry)
                self.window.Log("+0x018 Heap                           : 0x%08x" % self.pheap.SegmentReserve, self.pheap.SegmentReserve)
                self.window.Log("+0x01C BaseAddress                    : 0x%08x" % self.pheap.SegmentCommit, self.pheap.SegmentCommit)
            if self.os < 6.0:
                self.window.Log("+0x020 DeCommitFreeBlockThreshold     : 0x%08x" % self.pheap.DeCommitFreeBlockThreshold, self.pheap.DeCommitFreeBlockThreshold)
                self.window.Log("+0x024 DeCommitTotalBlockThreshold    : 0x%08x" % self.pheap.DeCommitTotalBlockThreshold, self.pheap.DeCommitTotalBlockThreshold)
                self.window.Log("+0x028 TotalFreeSize                  : 0x%08x" % self.pheap.TotalFreeSize, self.pheap.TotalFreeSize)
            elif self.os >= 6.0:
                self.window.Log("+0x020 NumberOfPages                  : 0x%08x" % self.pheap.NumberOfPages, self.pheap.NumberOfPages)
                self.window.Log("+0x024 FirstEntry                     : 0x%08x" % self.pheap.FirstEntry, self.pheap.FirstEntry)
                self.window.Log("+0x028 LastValidEntry                 : 0x%08x" % self.pheap.TotalFreeSize, self.pheap.TotalFreeSize)
            if self.os < 6.0:
                self.window.Log("+0x02c MaximumAllocationSize          : 0x%08x" % self.pheap.MaximumAllocationSize, self.pheap.MaximumAllocationSize)
            elif self.os >= 6.0:
                NumberOfUnCommittedPages = self.imm.readMemory(self.heap+0x2c, 4)
                NumberOfUnCommittedPages = struct.unpack("L", NumberOfUnCommittedPages)[0]
                self.window.Log("+0x02c NumberOfUnCommittedPages       : 0x%08x" % NumberOfUnCommittedPages, NumberOfUnCommittedPages)

            # libheap does not have some members, so we are on our own
            ProcessHeapsListIndex = self.imm.readMemory(self.heap+0x30, 2)
            ProcessHeapsListIndex = struct.unpack("H", ProcessHeapsListIndex)[0]
            if self.os < 6.0:            
                self.window.Log("+0x030 ProcessHeapsListIndex          : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)
            elif self.os >= 6.0:
                self.window.Log("+0x030 NumberOfUnCommittedRanges      : 0x%08x" % ProcessHeapsListIndex, ProcessHeapsListIndex)

                # libheap does not have some members, so we are on our own
                SegmentAllocatorBackTraceIndex = self.imm.readMemory(self.heap+0x34, 2)
                SegmentAllocatorBackTraceIndex = struct.unpack("H", SegmentAllocatorBackTraceIndex)[0]
                Reserved = self.imm.readMemory(self.heap+0x36, 2)
                Reserved = struct.unpack("H", Reserved)[0]
                UCRSegmentList = self.imm.readMemory(self.heap+0x38, 4)
                UCRSegmentList = struct.unpack("L", UCRSegmentList)[0]
                UCRSegmentList1 = self.imm.readMemory(self.heap+0x3c, 4)
                UCRSegmentList1 = struct.unpack("L", UCRSegmentList1)[0]
                self.window.Log("+0x034 SegmentAllocatorBackTraceIndex : 0x%08x" % SegmentAllocatorBackTraceIndex, SegmentAllocatorBackTraceIndex)
                self.window.Log("+0x036 Reserved                       : 0x%08x" % Reserved, Reserved)
                self.window.Log("+0x038 UCRSegmentList                 : 0x%08x%08x" % (UCRSegmentList,UCRSegmentList1))

            # uncommited range segments
            if self.os < 6.0:
                self.window.Log("+0x032 HeaderValidateLength           : 0x%08x" % self.pheap.HeaderValidateLength, self.pheap.HeaderValidateLength)
                self.window.Log("+0x034 HeaderValidateCopy             : 0x%08x" % self.pheap.HeaderValidateCopy, self.pheap.HeaderValidateCopy)
                self.window.Log("+0x038 NextAvailableTagIndex          : 0x%08x" % self.pheap.NextAvailableTagIndex, self.pheap.NextAvailableTagIndex)
                self.window.Log("+0x03a MaximumTagIndex                : 0x%08x" % self.pheap.MaximumTagIndex, self.pheap.MaximumTagIndex)
                self.window.Log("+0x03c TagEntries                     : 0x%08x" % self.pheap.TagEntries, self.pheap.TagEntries)
                self.window.Log("+0x040 UCRSegments                    : 0x%08x" % self.pheap.UCRSegments, self.pheap.UCRSegments)
                self.window.Log("+0x044 UnusedUncommittedRanges        : 0x%08x" % self.pheap.UnusedUnCommittedRanges, self.pheap.UnusedUnCommittedRanges)
                self.window.Log("+0x048 AlignRound                     : 0x%08x" % self.pheap.AlignRound, self.pheap.AlignRound)
                self.window.Log("+0x04c AlignMask                      : 0x%08x" % self.pheap.AlignMask, self.pheap.AlignMask)
            elif self.os >= 6.0:
                self.window.Log("+0x040 Flags                          : 0x%08x" % self.pheap.Flags, self.pheap.Flags)
                self.window.Log("+0x044 ForceFlags                     : 0x%08x" % self.pheap.ForceFlags, self.pheap.ForceFlags)
                self.window.Log("+0x048 CompatibilityFlags             : 0x%08x" % self.pheap.AlignRound, self.pheap.AlignRound)
                self.window.Log("+0x04c EncodeFlagMask                 : 0x%08x" % self.pheap.AlignMask, self.pheap.AlignMask)

            # lots of blocks..
            if self.os < 6.0:
                self.window.Log("+0x050 VirtualAllocedBlocks            ")
                for block in self.pheap.VirtualAllocedBlock:
                    v += 1
                    self.window.Log("       VirtualAllocedBlock %d          : 0x%08x" % (v,block), block)
                self.window.Log("+0x058 Segments")
                for segment in self.pheap.Segments:
                    i += 1
                    self.window.Log("       Segment %d                      : 0x%08x" % (i,segment.BaseAddress), segment.BaseAddress)                                      
                FreelistBitmap = self.imm.readMemory(self.heap+0x158, 4)
                FreelistBitmap = struct.unpack("L", FreelistBitmap)[0]
                self.window.Log("+0x158 FreelistBitmap                 : 0x%08x" % FreelistBitmap, FreelistBitmap)
                self.window.Log("+0x16a AllocatorBackTraceIndex        : 0x%08x" % self.pheap.AllocatorBackTraceIndex, self.pheap.AllocatorBackTraceIndex)
                NonDedicatedListLength = self.imm.readMemory(self.heap+0x16c, 4)
                NonDedicatedListLength = struct.unpack("L", NonDedicatedListLength)[0]
                self.window.Log("+0x16c NonDedicatedListLength         : 0x%08x" % NonDedicatedListLength, NonDedicatedListLength)
                if self.os < 6.0:
                    self.window.Log("+0x170 LargeBlocksIndex               : 0x%08x" % self.pheap.LargeBlocksIndex, self.pheap.LargeBlocksIndex)
                self.window.Log("+0x174 PseudoTagEntries               : 0x%08x" % self.pheap.PseudoTagEntries)
                self.window.Log("+0x178 Freelist[0]                    : 0x%08x" % (self.heap+0x178), (self.heap+0x178))
                self.window.Log("+0x578 LockVariable                   : 0x%08x" % self.pheap.LockVariable, self.pheap.LockVariable)
                self.window.Log("+0x57c CommitRoutine                  : 0x%08x" % self.pheap.CommitRoutine, self.pheap.CommitRoutine)
                FrontEndHeap = self.imm.readMemory(self.heap+0x580, 4)
                FrontEndHeap = struct.unpack("L", FrontEndHeap)[0]
                FrontHeapLockCount = self.imm.readMemory(self.heap+0x584, 2)
                FrontHeapLockCount = struct.unpack("H", FrontHeapLockCount)[0]
                FrontEndHeapType = self.imm.readMemory(self.heap+0x586, 1)
                FrontEndHeapType = struct.unpack("B", FrontEndHeapType)[0]
                LastSegmentIndex = self.imm.readMemory(self.heap+0x587, 1)
                LastSegmentIndex = struct.unpack("B", LastSegmentIndex)[0]
                self.window.Log("+0x580 FrontEndHeap                   : 0x%08x" % FrontEndHeap, FrontEndHeap)
                self.window.Log("+0x584 FrontHeapLockCount             : 0x%08x" % FrontHeapLockCount, FrontHeapLockCount)
                self.window.Log("+0x586 FrontEndHeapType               : 0x%08x" % FrontEndHeapType, FrontEndHeapType)
                self.window.Log("+0x587 LastSegmentIndex               : 0x%08x" % LastSegmentIndex, LastSegmentIndex)         
            elif self.os >= 6.0:
                Encoding = self.imm.readMemory(self.heap+0x50, 4)
                Encoding = struct.unpack("L", Encoding)[0]            
                self.window.Log("+0x050 Encoding                       : 0x%08x" % Encoding, Encoding)
                self.window.Log("+0x058 PointerKey                     : 0x%08x" % self.pheap.PointerKey, self.pheap.PointerKey)
                Interceptor = self.imm.readMemory(self.heap+0x5c, 4)
                Interceptor = struct.unpack("L", Interceptor)[0]            
                self.window.Log("+0x05c Interceptor                    : 0x%08x" % Interceptor, Interceptor)
                self.window.Log("+0x060 VirtualMemoryThreshold         : 0x%08x" % self.pheap.VirtualMemoryThreshold, self.pheap.VirtualMemoryThreshold)          
                self.window.Log("+0x064 Signature                      : 0x%08x" % self.pheap.Signature, self.pheap.Signature)
                self.window.Log("+0x068 SegmentReserve                 : 0x%08x" % self.pheap.SegmentReserve, self.pheap.SegmentReserve)
                self.window.Log("+0x06c SegmentCommit                  : 0x%08x" % self.pheap.SegmentCommit, self.pheap.SegmentCommit)
                DeCommitFreeBlockThreshold = self.imm.readMemory(self.heap+0x70, 4)
                DeCommitFreeBlockThreshold = struct.unpack("L", DeCommitFreeBlockThreshold)[0]  
                DeCommitTotalFreeThreshold = self.imm.readMemory(self.heap+0x74, 4)
                DeCommitTotalFreeThreshold = struct.unpack("L", DeCommitTotalFreeThreshold)[0]  
                self.window.Log("+0x070 DeCommitFreeBlockThreshold     : 0x%08x" % DeCommitFreeBlockThreshold, DeCommitFreeBlockThreshold)
                self.window.Log("+0x074 DeCommitTotalFreeThreshold     : 0x%08x" % DeCommitTotalFreeThreshold, DeCommitTotalFreeThreshold)
                self.window.Log("+0x078 TotalFreeSize                  : 0x%08x" % self.pheap.TotalFreeSize, self.pheap.TotalFreeSize)
                MaximumAllocationSize = self.imm.readMemory(self.heap+0x7c, 4)
                MaximumAllocationSize = struct.unpack("L", MaximumAllocationSize)[0]              
                self.window.Log("+0x07c MaximumAllocationSize          : 0x%08x" % MaximumAllocationSize, MaximumAllocationSize)
                self.window.Log("+0x080 ProcessHeapsListIndex          : 0x%08x" % self.pheap.ProcessHeapsListIndex, self.pheap.ProcessHeapsListIndex)
                self.window.Log("+0x082 HeaderValidateLength           : 0x%08x" % self.pheap.HeaderValidateLength, self.pheap.HeaderValidateLength)
                self.window.Log("+0x084 HeaderValidateCopy             : 0x%08x" % self.pheap.HeaderValidateCopy, self.pheap.HeaderValidateCopy)
                self.window.Log("+0x088 NextAvailableTagIndex          : 0x%08x" % self.pheap.NextAvailableTagIndex, self.pheap.NextAvailableTagIndex)
                self.window.Log("+0x08a MaximumTagIndex                : 0x%08x" % self.pheap.MaximumTagIndex, self.pheap.MaximumTagIndex)
                self.window.Log("+0x08c TagEntries                     : 0x%08x" % self.pheap.TagEntries, self.pheap.TagEntries)
                UCRList1 = self.imm.readMemory(self.heap+0x90, 4)
                UCRList1 = struct.unpack("L", UCRList1)[0]
                UCRList2 = self.imm.readMemory(self.heap+0x94, 4)
                UCRList2 = struct.unpack("L", UCRList2)[0]      
                self.window.Log("+0x090 UCRList                        : 0x%08x%08x" % (UCRList1, UCRList2))
                self.window.Log("+0x098 AlignRound                     : 0x%08x" % self.pheap.AlignRound, self.pheap.AlignRound)
                self.window.Log("+0x09c AlignMask                      : 0x%08x" % self.pheap.AlignMask, self.pheap.AlignMask)
                VirtualAllocdBlocks1 = self.imm.readMemory(self.heap+0x0a0, 4)
                VirtualAllocdBlocks1 = struct.unpack("L", VirtualAllocdBlocks1)[0]
                VirtualAllocdBlocks2 = self.imm.readMemory(self.heap+0x0a4, 4)
                VirtualAllocdBlocks2 = struct.unpack("L", VirtualAllocdBlocks2)[0]  
                self.window.Log("+0x0a0 VirtualAllocdBlocks            : 0x%08x%08x" % (VirtualAllocdBlocks1, VirtualAllocdBlocks2))
                SegmentList1 = self.imm.readMemory(self.heap+0x0a8, 4)
                SegmentList1 = struct.unpack("L", SegmentList1)[0]
                SegmentList2 = self.imm.readMemory(self.heap+0x0ac, 4)
                SegmentList2 = struct.unpack("L", SegmentList2)[0]
                self.window.Log("+0x0a8 SegmentList                    : 0x%08x%08x" % (SegmentList1, SegmentList2))            
                self.window.Log("+0x0b0 AllocatorBackTraceIndex        : 0x%08x" % self.pheap.AllocatorBackTraceIndex, self.pheap.AllocatorBackTraceIndex)
                NonDedicatedListLength = self.imm.readMemory(self.heap+0x0b4, 4)
                NonDedicatedListLength = struct.unpack("L", NonDedicatedListLength)[0]
                BlocksIndex = self.imm.readMemory(self.heap+0x0b8, 4)
                BlocksIndex = struct.unpack("L", BlocksIndex)[0]            
                UCRIndex = self.imm.readMemory(self.heap+0x0bc, 4)
                UCRIndex = struct.unpack("L", UCRIndex)[0] 
                FreeLists = self.imm.readMemory(self.heap+0x0c4, 4)
                FreeLists = struct.unpack("L", FreeLists)[0]
                self.window.Log("+0x0b4 NonDedicatedListLength         : 0x%08x" % NonDedicatedListLength, NonDedicatedListLength) 
                self.window.Log("+0x0b8 BlocksIndex                    : 0x%08x" % BlocksIndex, BlocksIndex)   
                self.window.Log("+0x0bc UCRIndex                       : 0x%08x" % UCRIndex, UCRIndex)      
                self.window.Log("+0x0c0 PseudoTagEntries               : 0x%08x" % self.pheap.PseudoTagEntries, self.pheap.PseudoTagEntries)
                self.window.Log("+0x0c4 FreeLists                      : 0x%08x" % FreeLists, FreeLists)      
                self.window.Log("+0x0cc LockVariable                   : 0x%08x" % self.pheap.LockVariable, self.pheap.LockVariable)
                self.window.Log("+0x0d0 CommitRoutine                  : 0x%08x" % self.pheap.CommitRoutine, self.pheap.CommitRoutine)
                FrontEndHeap = self.imm.readMemory(self.heap+0x0d4, 4)
                FrontEndHeap = struct.unpack("L", FrontEndHeap)[0]
                FrontHeapLockCount = self.imm.readMemory(self.heap+0x0d8, 2)
                FrontHeapLockCount = struct.unpack("H", FrontHeapLockCount)[0]
                FrontEndHeapType = self.imm.readMemory(self.heap+0x0da, 2)
                FrontEndHeapType = struct.unpack("H", FrontEndHeapType)[0]
                Counters = self.imm.readMemory(self.heap+0x0dc, 4)
                Counters = struct.unpack("L", Counters)[0]
                TuningParameters = self.imm.readMemory(self.heap+0x0d8, 4)
                TuningParameters = struct.unpack("L", TuningParameters)[0]
                self.window.Log("+0x0d4 FrontEndHeap                   : 0x%08x" % FrontEndHeap, FrontEndHeap) 
                self.window.Log("+0x0d8 FrontHeapLockCount             : 0x%04x" % FrontHeapLockCount, FrontHeapLockCount)   
                self.window.Log("+0x0da FrontEndHeapType               : 0x%04x" % FrontEndHeapType, FrontEndHeapType)              
                self.window.Log("+0x0dc Counters                       : 0x%08x" % Counters, Counters)  
                self.window.Log("+0x130 TuningParameters               : 0x%08x" % TuningParameters, TuningParameters)
        return "(+) Dumped the heap structure 0x%08x" % self.heap

    def print_segment_structure(self):
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
        for segment in self.pheap.Segments:
            self.window.Log("")
            self.window.Log("-" * 19)
            self.window.Log("Segment: 0x%08x" % segment.BaseAddress)
            self.window.Log("-" * 19)
            self.window.Log("")
            entry_0                     = self.imm.readMemory(segment.BaseAddress, 4)
            entry_0                     = struct.unpack("L", entry_0)[0]
            entry_1                     = self.imm.readMemory(segment.BaseAddress+0x4, 4)
            entry_1                     = struct.unpack("L", entry_1)[0]
            signature                   = self.imm.readMemory(segment.BaseAddress+0x8, 4)
            signature                   = struct.unpack("L", signature)[0]
            flags                       = self.imm.readMemory(segment.BaseAddress+0xc, 4)
            flags                       = struct.unpack("L", flags)[0]
            heap_                       = self.imm.readMemory(segment.BaseAddress+0x10, 4)
            heap_                       = struct.unpack("L", heap_)[0]
            LargestUncommitedRange      = self.imm.readMemory(segment.BaseAddress+0x14, 4)
            LargestUncommitedRange      = struct.unpack("L", LargestUncommitedRange)[0]
            BaseAddress                 = self.imm.readMemory(segment.BaseAddress+0x18, 4)
            BaseAddress                 = struct.unpack("L", BaseAddress)[0] 
            NumberOfPages               = self.imm.readMemory(segment.BaseAddress+0x1c, 4)
            NumberOfPages               = struct.unpack("L", NumberOfPages)[0]
            FirstEntry                  = self.imm.readMemory(segment.BaseAddress+0x20, 4)
            FirstEntry                  = struct.unpack("L", FirstEntry)[0]
            LastValidEntry              = self.imm.readMemory(segment.BaseAddress+0x24, 4)
            LastValidEntry              = struct.unpack("L", LastValidEntry)[0]
            NumberOfUncommitedPages     = self.imm.readMemory(segment.BaseAddress+0x28, 4)
            NumberOfUncommitedPages     = struct.unpack("L", NumberOfUncommitedPages)[0]
            NumberOfUncommitedRanges    = self.imm.readMemory(segment.BaseAddress+0x2c, 4)
            NumberOfUncommitedRanges    = struct.unpack("L", NumberOfUncommitedRanges)[0]
            UnCommitedRanges            = self.imm.readMemory(segment.BaseAddress+0x30, 4)
            UnCommitedRanges            = struct.unpack("L", UnCommitedRanges)[0]
            AllocatorBackTraceIndex     = self.imm.readMemory(segment.BaseAddress+0x34, 2)
            AllocatorBackTraceIndex     = struct.unpack("H", AllocatorBackTraceIndex)[0]
            Reserved                    = self.imm.readMemory(segment.BaseAddress+0x36, 2)
            Reserved                    = struct.unpack("H", Reserved)[0]
            LastEntryInSegment          = self.imm.readMemory(segment.BaseAddress+0x38, 4)
            LastEntryInSegment          = struct.unpack("L", LastEntryInSegment)[0]                                      
            self.window.Log("+0x000 Entry  (high)            : 0x%08x" % entry_0,entry_0)
            self.window.Log("+0x000 Entry  (low)             : 0x%08x" % entry_1,entry_1)
            self.window.Log("+0x008 Signature                : 0x%08x" % signature,signature)
            self.window.Log("+0x00c Flags                    : 0x%08x" % flags,flags)
            self.window.Log("+0x010 heap                     : 0x%08x" % heap_,heap_)
            self.window.Log("+0x014 LargestUncommitedRange   : 0x%08x" % LargestUncommitedRange,LargestUncommitedRange)
            self.window.Log("+0x018 BaseAddress              : 0x%08x" % BaseAddress,BaseAddress)
            self.window.Log("+0x01c NumberOfPages            : 0x%08x" % NumberOfPages,NumberOfPages)
            self.window.Log("+0x020 FirstEntry               : 0x%08x" % FirstEntry,FirstEntry)
            self.window.Log("+0x024 LastValidEntry           : 0x%08x" % LastValidEntry,LastValidEntry)
            self.window.Log("+0x028 NumberOfUncommitedPages  : 0x%08x" % NumberOfUncommitedPages,NumberOfUncommitedPages)
            self.window.Log("+0x02c NumberOfUncommitedRanges : 0x%08x" % NumberOfUncommitedRanges,NumberOfUncommitedRanges)
            self.window.Log("+0x030 UnCommitedRanges         : 0x%08x" % UnCommitedRanges,UnCommitedRanges)
            self.window.Log("+0x034 AllocatorBackTraceIndex  : 0x%08x" % AllocatorBackTraceIndex,AllocatorBackTraceIndex)
            self.window.Log("+0x036 Reserved                 : 0x%08x" % Reserved,Reserved)
            self.window.Log("+0x038 LastEntryInSegment       : 0x%08x" % LastEntryInSegment,LastEntryInSegment)
        return "(+) Dumped all Heap Segmements in heap 0x%08x" % self.heap

    # print all chunks, busy, free, frontend or backend
    def print_all_chunks(self, chunk_filter, show_detail=False):
        for chunk in self.pheap.chunks:
            trigger = False

            # chunks on the lookaside will "appear" busy
            if chunk_filter == "busy":
                if chunk.getflags(chunk.flags) == "B$":
                    trigger = True
                    self.window.Log("(+) Chunk on the Lookaside @ 0x%08x" % chunk.addr,chunk.addr)
                    self.window.Log("    -> Lookaside[0x%02x] entry" % chunk.size)
                    self.window.Log("        -> Flink: 0x%08x" % (chunk.addr+0x8))                    
                elif chunk.getflags(chunk.flags) == "B":
                    trigger = True
                    self.window.Log("(+) BUSY chunk @ 0x%08x" % chunk.addr,chunk.addr)
                elif chunk.getflags(chunk.flags) == "B|T" and chunk_filter == "busy":
                    trigger = True
                    self.window.Log("(+) Last BUSY chunk @ 0x%08x" % chunk.addr,chunk.addr)
            elif chunk_filter == "free":
                if chunk.getflags(chunk.flags) == "F$":
                    trigger = True
                    self.window.Log("(+) Chunk on the Lookaside @ 0x%08x" % chunk.addr,chunk.addr)
                elif chunk.getflags(chunk.flags) == "F":
                    trigger = True
                    self.window.Log("(+) Chunk on the Freelist @ 0x%08x+0x08 (0x%08x)" % (chunk.addr,(chunk.addr+0x08)), chunk.addr)
                    self.window.Log("    -> Freelist[0x%02x] entry" % chunk.size)
                    self.window.Log("        -> Flink: 0x%08x" % chunk.nextchunk) 
                    self.window.Log("        -> Blink: 0x%08x" % chunk.prevchunk)
            if trigger:
                self.window.Log("")
                self.window.Log("    -> size: 0x%08x  (8 * 0x%04x = 0x%04x, decimal: %d)" % (chunk.usize, chunk.size, chunk.usize, chunk.usize) )
                self.window.Log("    -> prevsize: 0x%08x (%04x)" % (chunk.upsize, chunk.psize))
                self.window.Log("    -> flags: 0x%04x (%s)" % (chunk.flags, chunk.getflags(chunk.flags)))
                if not show_detail:
                    self.window.Log("-" * 62)
            if show_detail:
                dump = immutils.hexdump(chunk.sample)
                for a in range(0, len(dump)):
                    if not a:
                        self.window.Log("    -> First 16 bytes of data:")
                        self.window.Log("        -> hex: \\x%s" % dump[a][0].rstrip().replace(" ", "\\x")) 
                        self.window.Log("        -> ascii: %s" % (dump[a][1]))
                        self.window.Log("-" * 80)

    def to_hexidecimal(self, n):
        return "%08x" % n

    def generate_githash(self, data):
        s = sha1()
        s.update("blob %u\0" % len(data))
        s.update(data)
        return s.hexdigest()


    def meets_access_level(self, page, accessLevel):
        """
        Checks if a given page meets a given access level
    
        Arguments:
        page - a page object
        accesslevel - a string containing one of the following access levels :
        R,W,X,RW,RX,WR,WX,RWX or *
    
        Return:
        a boolean
        """
        if "*" in accessLevel:
            return True
        
        pageAccess = page.getAccess(human=True)
        
        if "R" in accessLevel:
            if not "READ" in pageAccess:
                return False
        if "W" in accessLevel:
            if not "WRITE" in pageAccess:
                return False
        if "X" in accessLevel:
            if not "EXECUTE" in pageAccess:
                return False
                
        return True
    
    def find_hardcoded_pointers(self, usermodule=False):
        """
        This function finds all static function pointers
        either for a given module or all modules
        """
        text_addresses = {}
        if not usermodule:
            confirmation = self.imm.comboBox("Time is of essence, so are you sure?",["yes","no"])
            if confirmation == "yes":
                for name in self.imm.getAllModules().iterkeys():
                    module = name.lower()
                    module_page = self.imm.getMemoryPageByOwner(module)
                    usermod_obj = self.imm.findModuleByName(module)

                    # tries to filter the IAT, but if it fails, no big deal
                    iat_table = self.get_modules_iat(usermod_obj)
                    for u in module_page:
                        if u.section == ".text":
                            mod = self.imm.findModule(u.owner)
                            modname = mod[0]
                            usermod_obj = self.imm.getModule(modname)
                            if not text_addresses.has_key(u.baseaddress):
                                text_addresses[u.baseaddress] = [u.size, modname, usermod_obj.getVersion()]
                for addr, details in text_addresses.iteritems():
                    size = details[0]
                    self.window.Log("")
                    if details[2] != "":
                        self.window.Log("-" * (len(details[1])+58))
                        self.window.Log("(+) Module name: %s version: %s" % (details[1], details[2]))
                        self.window.Log("-" * (len(details[1])+58))
                    elif details[2] == "":
                        self.window.Log("-" * (len(details[1])+17))
                        self.window.Log("(+) Module name: %s" % (details[1]))
                        self.window.Log("-" * (len(details[1])+17))
                    self.window.Log("")
                    i = 0
                    while i < size:
                        try:
                            op = self.imm.disasmForward( addr )
                        except:
                            pass
                        if op.isCall() or op.isJmp():
                            if op.dump[0:4] == "FF15" or op.dump[0:4] == "FF25":
                                if op.getAddrConst() not in iat_table:
                                    mempage = self.imm.getMemoryPageByAddress(op.adrconst)
                                    if mempage:
                                        if self.meets_access_level(mempage, "W"):
                                            self.window.Log("0x%08x: %s" % (op.ip, op.result), op.ip)
                        addr = op.getAddress()
                        i += 1
            elif confirmation == "no":
                self.window.Log("")
                self.window.Log("(!) Maybe try with !heaper findptrs -m <module>")
                self.window.Log("")
                return "(!) Maybe try with !heaper findptrs -m <module>"
            else:
                self.window.Log("")
                self.window.Log("(!) Maybe try with !heaper findptrs -m <module>")
                self.window.Log("")
                return "(!) Invalid option %s" % confirmation

        # filter by module name        
        elif usermodule:
            try:
                module_page = self.imm.getMemoryPageByOwner(usermodule)
                usermod_obj = self.imm.findModuleByName(usermodule)
                iat_table = self.get_modules_iat(usermod_obj)
            except:
                self.window.Log("")
                self.window.Log("(-) Invalid module name!")
                self.window.Log("")
                return "(-) Invalid module name!"
            self.window.Log("")
            for u in module_page:
                if u.section == ".text":
                    mod = self.imm.findModule(u.owner)
                    modname = mod[0]
                    usermod_obj = self.imm.getModule(modname)
                    text_addresses[u.baseaddress] = [u.size, modname, usermod_obj.getVersion()]
            for addr, details in text_addresses.iteritems():
                size = details[0]               
                if details[2] != "":
                    self.window.Log("-" * (len(details[1])+58))
                    self.window.Log("(+) Module name: %s version: %s" % (details[1], details[2]))
                    self.window.Log("-" * (len(details[1])+58))
                elif details[2] == "":
                    self.window.Log("-" * (len(details[1])+17))
                    self.window.Log("(+) Module name: %s" % (details[1]))
                    self.window.Log("-" * (len(details[1])+17))
                self.window.Log("")
                i = 0
                while i < size:
                    try:
                        op = self.imm.disasmForward( addr )
                    except:
                        pass
                    if op.isCall() or op.isJmp():
                        if op.dump[0:4] == "FF15" or op.dump[0:4] == "FF25":
                            if op.getAddrConst() not in iat_table:
                                mempage = self.imm.getMemoryPageByAddress(op.adrconst)
                                if mempage:
                                    if self.meets_access_level(mempage, "W"):
                                        self.window.Log("0x%08x: %s" % (op.ip, op.result), op.ip)
                    addr = op.getAddress()
                    i += 1
    
    def analyse_function_pointers(self, args, patch=False, patch_val=False, restore=False, restore_val=False):
        fn_ptr = []
        exclude = []
        ndx = INDEXER

        # create the datatype object    
        dt = libdatatype.DataTypes(self.imm)

        # get the address and size
        if (patch_val == "all" or restore_val == "all") or (not patch_val and not restore_val):
            try:
                addr = int(args[args.index("-a")+1],16)
                size = int(args[args.index("-s")+1],16)
                mem = self.imm.readMemory( addr, size )
                if not mem:
                    return "(-) Error: Couldn't read any memory at address: 0x%08x" % addr
                ret = dt.Discover( mem, addr, what = 'pointers' )
            except:
                self.window.Log("")
                self.window.Log("(-) You need to specify the address and size using -a and -s")
                return "(-) You need to specify the address and size using -a and -s"

        # we are discovering..
        if not patch and not restore:
            fp=0
            for obj in ret:
                if obj.isFunctionPointer():
                    fp+=1
            self.window.Log("")
            self.window.Log( "(+) Found %d function pointers" % fp )
            self.window.Log("")
            for obj in ret:
                if obj.isFunctionPointer():
                    msg = "0x%08x -> 0x%08x in %s at the %s section" % (obj.address, obj.data, obj.mem.getOwner(), obj.mem.section)
                    self.window.Log( "%s" % ( msg ), address = obj.address)
            self.window.Log("-" * 60)
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
                self.window.Log("%s" % exclude)           
                if ret:
                    self.window.Log("")
                    for obj in ret:
                        if obj.isFunctionPointer() and obj.address not in exclude:

                            # remember what we are modifying
                            memory_dict[obj.address] = obj.data
                            self.window.Log( "(+) Modifying pointer: 0x%08x to 0x%08x" % (obj.address, ndx), obj.address)
                            self.imm.writeLong( obj.address, ndx )
                            ndx += 1
                            fn_ptr.append( obj )

                    # save the function pointers
                    self.imm.addKnowledge("fps_%s" % addr, memory_dict, force_add = 1)
                    hook = Function_triggered_hook( fn_ptr, self.window )
                    hook.add( "modptr_%08x" % addr )
                    self.window.Log("-" * 47)
                    return "(+) Hooking on %d Functions" % len( fn_ptr )
                else:
                    return "(-) No Function pointers found at address 0x%08x" % patch_val

            # we are patching a specific pointer
            elif patch_val != "all": 
                patch_val = int(patch_val,16)                      
                mem = self.imm.readMemory( patch_val, 4 )
                if not mem:
                    return "(-) Error: Couldn't read any memory at address: 0x%08x" % addr
                ret = dt.Discover( mem, patch_val, what = 'pointers' )
                if ret:
                    for obj in ret:
                        if obj.isFunctionPointer() and obj.address == patch_val:
                            memory_dict[obj.address] = obj.data
                            self.window.Log("")
                            self.window.Log( "(+) Modifying pointer: 0x%08x to 0x%08x" % (obj.address, ndx), obj.address)
                            self.imm.writeLong( obj.address, ndx )
                            ndx += 1
                            fn_ptr.append( obj )

                    # save the function pointer we are patching
                    self.imm.addKnowledge("fp_%x" % patch_val, memory_dict, force_add = 1)
                    hook = Function_triggered_hook( fn_ptr, self.window )
                    hook.add( "modptr_%08x" % patch_val )
                    self.window.Log("-" * 47)
                    return "Hooking on function pointer 0x%08x" % obj.address
                else:
                    self.window.Log("")
                    self.window.Log("(-) No Function pointer found at address 0x%08x" % patch_val)
                    self.window.Log("")
                    return "(-) No Function pointer found at address 0x%08x" % patch_val

        # we are restoring...
        elif restore and not patch:
            restore_dict = False
            for knowledge in self.heaper.imm.listKnowledge():
                if re.match("fp", knowledge):
                    restore_dict = self.heaper.imm.getKnowledge(knowledge)
                    self.heaper.imm.forgetKnowledge(knowledge)
            if restore_dict:
                for faddy, pointer in restore_dict.iteritems():
                    self.heaper.imm.writeLong( faddy, pointer )
                self.heaper.window.Log("")   
                self.heaper.window.Log("(+) Restored function pointer(s)...")
                self.heaper.window.Log("-" * 40)
                return "(+) Restored function pointer(s)..."
            else:
                self.heaper.window.Log("")
                self.heaper.window.Log("(!) Function pointer already restored...")
                self.heaper.window.Log("-" * 40)
                return "(!) Function pointer already restored..."
    
    def binary_to_decimal(self, binary):
        """Converts a binary list to decimal number"""
        dec = 0
        binary_list = []
        for b in binary:
            binary_list.append(int(b))
  
        # reverse list
        rev_bin = []
        for item in binary_list:
            rev_bin.insert(0,item)

        # calculate decimal
        for index in xrange(len(binary_list)):
            dec += rev_bin[index] * 2**index
        return dec
    
    def character_to_hexidecimal(self,n):
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

    def reverse(self, text):
        return ''.join([text[i] for i in range(len(text)-1,-1,-1)])

    def patch_peb(self):
        self.peb_struct
        if not self.peb_struct.BeingDebugged and not self.peb_struct.NtGlobalFlag:
            self.window.Log("(!) This process has already been patched!")
            self.window.Log("------------------------------------------")
            return False
        PEB = self.imm.getPEBAddress()

        # Just incase we cant get the peb
        if PEB == 0:
            self.window.Log("(-) No PEB to patch .. !?" )
            return
        self.window.Log("(+) Patching PEB.IsDebugged ..", address = PEB + 0x02 )
        self.imm.writeMemory(PEB + 0x02, self.imm.assemble( "db 0" ) )
        processheapflag = self.imm.readLong(PEB + 0x18)
        processheapflag += 0x10
        self.window.Log("(+) Patching PEB.ProcessHeap.Flag ..", address = processheapflag )
        self.imm.writeLong( processheapflag, 0 )
        self.window.Log("(+) Patching PEB.NtGlobalFlag ..", address = PEB + 0x68 )
        self.imm.writeLong(PEB + 0x68, 0)

        # Patch PEB_LDR_DATA 0xFEEEFEEE fill bytes ..  (about 3000 of them ..)
        ldr_data = self.imm.readLong(PEB + 0x0C)
        self.window.Log("(+) Patching PEB.LDR_DATA filling ..", address = ldr_data)
        while ldr_data != 0:
            ldr_data += 1
            try:
                b = self.imm.readLong(ldr_data)
                c = self.imm.readLong(ldr_data + 4)

                # Only patch the filling runs ..
                if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
                    self.imm.writeLong(ldr_data, 0)
                    self.imm.writeLong(ldr_data + 4, 0)
                    ldr_data += 7
            except:
                break
        self.window.Log("----------------------------------------")
        return True
    
# The Setcommand class
class Setcommand:
    """
    Class to call commands, show usage and parse arguments
    """
    def __init__(self, name, description, usage, parseProc, alias=""):
        self.name = name
        self.description = description
        self.usage = usage
        self.parseProc = parseProc
        self.alias = alias 

class Hook():
    def __init__(self, imm, heaper):
        self.imm                = imm
        self.heaper             = heaper
        self.ALLOCLABEL         = "RtlAllocateHeap Hook"
        self.FREELABEL          = "RtlFreeHeap Hook"
        self.rtlfree            = imm.getAddress("ntdll.RtlFreeHeap")
        self.rtlallocate        = imm.getAddress("ntdll.RtlAllocateHeap")
        self.log_return         = False  # hook flag that is constantly updated
        self.managed_chunks     = {}     # track all chunks
        self.double_free_chunks = []     # track double free chunks

    # We need to find this specific place
    def set_func_ret(self, max_opcodes = 300):
        addr = self.rtlallocate
        i = 0
        while i < max_opcodes:
            op = self.imm.disasmForward( addr )
            if op.isRet():
                if op.getImmConst() == 0xc:

                    # go back 3 opcodes and we will get EAX
                    op = self.imm.disasmBackward( addr, 3)     
                    self.rtlallocate = op.getAddress()
                    i += 1
            addr = op.getAddress()
        return self.rtlallocate

    def softhook_on_alloc(self, disable_hook=False):

        # check to see if the hooking should be disabled
        if not disable_hook:

            # have we set the return address for RtlAllocateHeap?
            if self.rtlallocate > 0:
                allocate_arguments = Function_hook( "RtlAllocateHeap", self.heaper.window, self.heaper.heap)
                allocate_arguments.add("RtlAllocateHeap_for_heap_%x" % self.heaper.heap, self.rtlallocate)
                self.heaper.window.Log("(+) Placed hook on RtlAllocateHeap epilog at 0x%08x" % self.rtlallocate, self.rtlallocate)

                # save the knowledge
                self.imm.addKnowledge("RtlAllocateHeap_for_heap_%x" % self.heaper.heap, allocate_arguments)
        elif disable_hook:
            rtlallocateheap = self.imm.getKnowledge("RtlAllocateHeap_for_heap_%x" % self.heaper.heap)
            if rtlallocateheap:
                rtlallocateheap.UnHook()
                self.imm.forgetKnowledge("RtlAllocateHeap_for_heap_%x" % self.heaper.heap)
                self.heaper.window.Log("")
                self.heaper.window.Log("(+) RtlAllocateHeap hook disabled!")
                self.heaper.window.Log("")
                return "(+) RtlAllocateHeap hook disabled!"
            else:
                self.heaper.window.Log("")
                self.heaper.window.Log("(-) RtlAllocateHeap hook hasn't been enabled yet!?")
                self.heaper.window.Log("")
                return "(-) RtlAllocateHeap hook hasn't been enabled yet!?!"
            
    def softhook_on_free(self, disable_hook=False):
        if not disable_hook:

            # have we set the return address for RtlAllocateHeap?
            if self.rtlfree > 0:
                free_arguments = Function_hook( "RtlFreeHeap", self.heaper.window, self.heaper.heap)      
                free_arguments.add("RtlFreeHeap_for_heap_%x" % self.heaper.heap, self.rtlfree)
                self.heaper.window.Log("(+) Placed hook on RtlFreeHeap epilog at 0x%08x" % self.rtlfree, self.rtlfree)

                # save the knowledge
                self.imm.addKnowledge("RtlFreeHeap_for_heap_%x" % self.heaper.heap, free_arguments)
        elif disable_hook:
            rtlfreeheap = self.imm.getKnowledge("RtlFreeHeap_for_heap_%x" % self.heaper.heap)
            if rtlfreeheap:
                rtlfreeheap.UnHook()
                self.imm.forgetKnowledge("RtlFreeHeap_for_heap_%x" % self.heaper.heap)
                self.heaper.window.Log("")
                self.heaper.window.Log("(+) RtlFreeHeap hook disabled!")
                self.heaper.window.Log("")
                return "(+) RtlAllocateHeap hook disabled!"
            else:
                self.heaper.window.Log("")
                self.heaper.window.Log("(-) RtlFreeHeap hook hasn't been enabled yet!?")
                self.heaper.window.Log("")
                return "(-) RtlFreeHeap hook hasn't been enabled yet!?!"                  

    def print_hooks(self):
        self.heaper.window.Log("(+) Hook RtlAllocateHeap:        0x%08x" % self.rtlallocate, self.rtlallocate)
        self.heaper.window.Log("(+) Hook RtlAllocateHeap return: 0x%08x" % self.rtlallocateret, self.rtlallocateret)
        self.heaper.window.Log("(+) Hook RtlFreeHeap:            0x%08x" % self.rtlfree, self.rtlfree)
        self.heaper.window.Log("(+) Hook RtlFreeHeap return:     0x%08x" % self.rtlfreeret, self.rtlfreeret)            

    def set_chunks(self, a, rtlallocate):
        if a[0] == rtlallocate:

            # lets log all the allocs
            if a[1][3] not in self.managed_chunks:
                self.managed_chunks[a[1][3]] = {}
                self.managed_chunks[a[1][3]]["alloc"] = 1
                self.managed_chunks[a[1][3]]["free"]  = 0
            else:
                self.managed_chunks[a[1][3]]["alloc"] += 1
        else:

            # lets log all the frees
            if a[1][2] not in self.managed_chunks:
                self.managed_chunks[a[1][2]] = {}
                self.managed_chunks[a[1][2]]["alloc"] = 0
                self.managed_chunks[a[1][2]]["free"]  = 1
            else:
                self.managed_chunks[a[1][2]]["free"] += 1

    def showresults(self, a, rtlallocate, extra = ""):
        if a[0] == rtlallocate:
            if a[1][3] in self.double_free_chunks:
                extra += "!! Potential double free on this chunk !!"
                self.heaper.window.Log("*" * 107)
                self.heaper.window.Log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x) <= 0x%08x %s" % ( a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3]  )
                self.heaper.window.Log("*" * 107)
            else:
                self.heaper.window.Log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x) <= 0x%08x %s" % ( a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3]  )
        else:
            if a[1][2] in self.double_free_chunks:
                extra += "!! Potential double free on this chunk !!"
                self.heaper.window.Log("*" * 89)
                self.heaper.window.Log("RtlFreeHeap(0x%08x, 0x%08x, 0x%08x) %s" % (a[1][0], a[1][1], a[1][2], extra), address = a[1][2])
                self.heaper.window.Log("*" * 89)
            else:
                self.heaper.window.Log("RtlFreeHeap(0x%08x, 0x%08x, 0x%08x) %s" % (a[1][0], a[1][1], a[1][2], extra), address = a[1][2])

# we add our own instance so we dont dirty the imm.log too much...
class STDCALLFastLogHook(FastLogHook):

    def __init__(self, imm):
        FastLogHook.__init__(self, imm)

    def logFunction(self, address, args = 0 ):
        if self.address:
            self.tbl.append( (self.address,  self.entry) )
            self.entry = []
    
        self.address = address
        for ndx in range(0, args):
            self.logBaseDisplacement( "ESP", ndx*4 + 4 )

    def addFastLogHook(self, alloc_size = 0x100000, memAddress = 0x0):
        CODE_HOOK_START = 8
        self.AllocSize = alloc_size
        table = self.get()

        # Allocate memory for the hook and the log
        if not memAddress: 
            memAddress = self.imm.remoteVirtualAlloc( alloc_size )
        self.memAddress = memAddress
        ptr = memAddress + CODE_HOOK_START
        fn_restore = []
        fn_ndx = 0
        while fn_ndx < len(table) :
            hookAddress = table[ fn_ndx ][0]
            entry       = table[ fn_ndx ][1]
            idx         = 0
            patch_code  = self.imm.assemble( "JMP 0x%08x" % ptr, address = hookAddress )
            while idx < len(patch_code): 
                op   = self.imm.disasm( hookAddress + idx )
                idx += op.getOpSize()
                if op.isCall() or op.isJmp():
                    op = None
                    break

            # Removing the BP from the table
            if not op:
                del table[ fn_ndx ]
                continue
            ex_prelude = self.imm.readMemory( hookAddress, idx ) 
            code = self.imm._createCodeforHook( memAddress, hookAddress + idx,\
                            fn_ndx + 1, entry, ex_prelude, alloc_size)
            self.imm.writeMemory( ptr , code )
            ptr += len(code)
            self.imm.writeMemory( hookAddress, patch_code )
            fn_restore.append( (ex_prelude, patch_code ) ) # Correspond in index with function address
            fn_ndx += 1
        self.setTable( table )
        if ptr % 4:
            ptr = 4 + ptr & ~(4-1)
        self.setMem( ptr )
        self.imm.writeLong( memAddress, ptr )
        self.setRestore( fn_restore )

# Hook class of LogBpHook
class Function_hook(LogBpHook):
    """
    Class to get the particular functions arguments for a debug instance
    Return 
    """

    def __init__(self, function_name, window, heap):
        LogBpHook.__init__(self)
        self.fname  = function_name
        self.window = window
        self.heap   = heap

    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        if self.fname == "RtlFreeHeap":
            res = imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("(-) RtlFreeHeap: the stack seems to broken, unable to get args")
                return 0x0
            (heap, flags, size) = struct.unpack("LLL", res)
            if heap == self.heap:
                self.window.Log("(+) RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, flags, size))
        elif self.fname == "RtlAllocateHeap":
            res = imm.readMemory( regs['ESP'] + 4, 0xc)
            if len(res) != 0xc:
                self.window.Log("RtlAllocateHeap: ESP seems to broken, unable to get args")
                return 0x0
            (heap, flags, size) = struct.unpack("LLL", res)
            if heap == self.heap:
                self.window.Log("(+) RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, flags, size))

    def is_heap_alloc_free_matching(self):
        return self.heap == self.rheap
    
# Access Violation Hook class
# thanks to the immunity team
class Function_triggered_hook(AccessViolationHook):
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
            
class Function_hook_return(LogBpHook):

    def __init__(self, function_name, window):
        LogBpHook.__init__(self)
        self.fname      = function_name
        self.window     = window
        self.log_return = False
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        chunk_address = regs['EAX']
        if self.log_return:
            self.window.Log("(+) %s() returned: 0x%08x" % (self.fname, chunk_address), chunk_address)
            border_len = len("(+) %s() returned: 0x%08x" % (self.fname, chunk_address))
            self.window.Log("=" * border_len)

###############################################
# Generic parent FrontEnd and BackEnd classes #
###############################################
    
# The FrontEnd heap class
class Front_end:

    def __init__(self, args, imm):
        self.imm = imm
        self.graphic_structure = False
        self.customfilename    = False
        self.block             = 0x8

# The BackEnd heap class
class Back_end:

    def __init__(self, imm):
        self.imm = imm
        self.graphic_structure = False
        self.customfilename    = False
        self.block             = 0x8

###############################
# Windows Vista/7/Server 2008 #
# NT 6.x                      #
###############################

# The Low Fragmentation Heap class (FrontEnd)
class Lfh(Front_end):
    
    def __init__(self, heaper):
        self.heaper = heaper
        self.lfh_userblocks_chunks = {}
        
    def run(self):
        self._LFH_HEAP = self.heaper.imm.readMemory(self.heaper.heap+0x580, 4)
        self._LFH_HEAP = struct.unpack("L", self._LFH_HEAP)
        self.filename  = "frontend_graph"

    # operational methods
    def perform_heuristics(self):
        vuln_chunks = 0
        for chunks in self.lfh_userblocks_chunks.itervalues():
            free_chunk_validation_list = []
            chunk_data      = chunks[1]
            userblocks_info = chunks[0]
            for chunk in chunk_data:
                if re.match("F",chunk[4]):
                    free_chunk_validation_list.append(chunk[4][2:5])
            free_chunk_validation_list.sort()
            for chunk in chunk_data:
                if chunk[7]:
                    vuln_chunks += 1
                    self.heaper.window.Log("")
                    self.heaper.window.Log("UserBlocks[0x%x]: 0x%08x" % (chunk[2],userblocks_info[4]))
                    self.heaper.window.Log("    => Chunk(0x%08x) -> NextOffset: 0x%04x NextVA -> UserBlocks + (NextOffset * 0x8): 0x%08x" % (chunk[1], chunk[5], (userblocks_info[4] + ( chunk[5] * 0x8))), chunk[1])
                    self.heaper.window.Log("    => %s!" % chunk[6])
                    self.heaper.window.Log("(!) 1. You will need %d allocations to overwrite the FreeEntryOffset" % len(free_chunk_validation_list))
                    self.heaper.window.Log("(!) 2. Using NextOffset: 0x%x, your next controlled allocation will be at 0x%08x" % (chunk[5],(userblocks_info[4] + ( chunk[5] * 0x8))))
        self.heaper.window.Log("")
        self.heaper.window.Log("(!) Found %d vulnerable chunks in heap 0x%08x" % (vuln_chunks, self.heaper.heap))
        self.heaper.window.Log("")

    def build_chunk_structure(self, subseg, index):
        chunk_validation_list       = []
        free_chunk_validation_list  = []
        for chunk in subseg.chunks:
            chunk_validation_list.append(chunk.addr)
            if chunk.freeorder != -1:
                free_chunk_validation_list.append(chunk.freeorder)
        free_chunk_validation_list.sort()

        # UserBlocks header
        self.lfh_userblocks_chunks[index] = []
        self.lfh_userblocks_chunks[index].append([])
        self.lfh_userblocks_chunks[index].append([])
        self.lfh_userblocks_chunks[index][0].append(self.heaper.pheap.LFH.address)           # _LFH_HEAP
        self.lfh_userblocks_chunks[index][0].append(self.heaper.pheap.LFH.LocalData.address) # _HEAP_LOCAL_DATA
        self.lfh_userblocks_chunks[index][0].append(subseg.BlockSize)                        # _HEAP_LOCAL_SEGMENT_INFO[n]

        try:
            self.lfh_userblocks_chunks[index][0].append(subseg.UserDataHeader.SubSegment)    # _HEAP_SUBSEGMENT
            self.lfh_userblocks_chunks[index][0].append(subseg.UserDataHeader.address)       # _HEAP_USERDATA_HEADER

        # In case we cant read the UserDataHeader data structure, 
        # its the best way I know how top handle it
        except:
            self.lfh_userblocks_chunks[index][0].append("?")                           # _HEAP_SUBSEGMENT(?)
            self.lfh_userblocks_chunks[index][0].append("?")                           # _HEAP_USERDATA_HEADER(?)
        self.lfh_userblocks_chunks[index][0].append(subseg.Offset)                           # FreeEntryOffset
        self.lfh_userblocks_chunks[index][0].append(subseg.Depth)                            # Depth
        i = 0
        for chk in subseg.chunks:
            chunk_data = []
            if chk.isLFH:
                i += 1
                s = "B"

                # yep, busy chunks dont have a EntryOffset, but still lets document the 2 bytes
                NextOffset = self.heaper.imm.readMemory(chk.addr+0x8,2)
                NextOffset = struct.unpack("H", NextOffset)[0]
            if chk.freeorder != -1:   
                s = "F(%02x)" % chk.freeorder                           
                chunk_data.append(i)           # chunk number in order
                chunk_data.append(chk.addr)    # chunk address
                chunk_data.append(chk.psize)   # chunk size
                chunk_data.append(chk.lfhflags)# lfh flags
                chunk_data.append(s)           # Free order
                chunk_data.append(NextOffset)  # NextOffset
                if (subseg.chunks.index(chk)+1) < len(subseg.chunks):
                    offset_next_chunk = subseg.UserBlocks+(NextOffset*0x8)
                    next_chunk = subseg.chunks[subseg.chunks.index(chk)+1].addr
                    if offset_next_chunk == next_chunk:
                        chunk_data.append("Chunk->NextOffset has been validated as the next chunk")    # validatation
                        chunk_data.append(False)                                                        # validated
                    elif offset_next_chunk in chunk_validation_list:
                        chunk_data.append("Chunk->NextOffset has been validated in the UserBlocks")    # validatation
                        chunk_data.append(False)                                                        # validated                                                     

                    # I can improve this, but no need right now..
                    elif chk.freeorder == free_chunk_validation_list[len(free_chunk_validation_list) -1]:
                        encoded_header = self.heaper.imm.readMemory(chk.addr-0x8,2)
                        encoded_header = struct.unpack("H", encoded_header)[0]

                        if NextOffset == 0xffff:
                            # shits gone funky y0! - bcoles :0)
                            # if its the last chunk and the nextoffset is 0xffff, then double check
                            # the rest of the header to ensure you havent overwritten it...
                            if encoded_header == NextOffset:
                                chunk_data.append("Chunk->NextOffset has been overwritten in the UserBlocks")  # validatation
                                chunk_data.append(True)                                                       # validatation                               
                            else:
                                chunk_data.append("Chunk->NextOffset has been validated as the last chunk in the UserBlocks")      # validatation
                                chunk_data.append(False)                                                                            # validated 
                        elif NextOffset != 0xffff:
                            chunk_data.append("Chunk->NextOffset has been overwritten in the UserBlocks")  # validatation
                            chunk_data.append(True)                                         
                    elif offset_next_chunk not in chunk_validation_list:
                        chunk_data.append("Chunk->NextOffset has been overwritten in the UserBlocks")  # validatation
                        chunk_data.append(False) 
                else:           
                    chunk_data.append("Chunk->NextOffset has been validated as the last chunk in the UserBlocks")  # validatation        
                    chunk_data.append(False)           
            elif chk.freeorder == -1:

                # no validation here as its a busy chunk..
                chunk_data.append(i)           # chunk number in order
                chunk_data.append(chk.addr)    # chunk address
                chunk_data.append(chk.psize)   # chunk size
                chunk_data.append(chk.lfhflags)# lfh flags
                chunk_data.append(s)           # Free order
                chunk_data.append(NextOffset)  # NextOffset                            
                chunk_data.append("Chunk->NextOffset cant be validated, this chunk is busy in the UserBlocks")      # validatation
                chunk_data.append(False)       # validated
            self.lfh_userblocks_chunks[index][1].append(chunk_data)
        return True 

    # print methods
    def print_chunks(self, size=False): 
        for chunks in self.lfh_userblocks_chunks.itervalues():
            userblocks_info = chunks[0]
            self.heaper.window.Log("")
            self.heaper.window.Log("(+) Dumping UserBlocks from =>")
            self.heaper.window.Log("        _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->_HEAP_LOCAL_DATA(0x%08x)" % (self.heaper.pheap.address, userblocks_info[0], userblocks_info[1]), userblocks_info[1])
            try:
                self.heaper.window.Log("            ->_HEAP_LOCAL_SEGMENT_INFO[0x%x]->_HEAP_SUBSEGMENT(0x%08x)->_HEAP_USERDATA_HEADER(0x%08x):" % (userblocks_info[2], userblocks_info[3], userblocks_info[4]), userblocks_info[4])
            except:
                self.heaper.window.Log("            ->_HEAP_LOCAL_SEGMENT_INFO[0x%x]->_HEAP_SUBSEGMENT(?)->_HEAP_USERDATA_HEADER(?):" % userblocks_info[2])
                
            self.heaper.window.Log("")
            try:
                self.heaper.window.Log("(+) UserBlocks(0x%08x) => Size: 0x%04x SubSegment: 0x%08x FreeEntryOffset: 0x%04x Depth: %d" % (userblocks_info[4], userblocks_info[2], userblocks_info[4], userblocks_info[5], userblocks_info[6]), address = userblocks_info[4])
                self.heaper.window.Log("(+) Header => SubSegment: 0x%08x SizeIndex: 0x%x" % (userblocks_info[3], userblocks_info[2]),userblocks_info[3])
                self.heaper.window.Log("(+) Current UserBlocks pointer => UserBlocks + FreeEntryOffset => 0x%08x + 0x%04x = 0x%08x" % (userblocks_info[4], userblocks_info[5], (userblocks_info[4]+userblocks_info[5])))
            except:
                self.heaper.window.Log("(+) UserBlocks(%s) => Size: 0x%04x SubSegment: %s FreeEntryOffset: 0x%04x Depth: %d" % (userblocks_info[4], userblocks_info[2], userblocks_info[4], userblocks_info[5], userblocks_info[6]))
                self.heaper.window.Log("(+) Header => SubSegment: ? SizeIndex: ? ")
                self.heaper.window.Log("(+) Current UserBlocks pointer => UserBlocks + FreeEntryOffset => %s + 0x%04x = 0x%08x" % (userblocks_info[4], userblocks_info[5], (0+userblocks_info[5])))
            self.heaper.window.Log("")
            chunk_data = chunks[1]
            for chunk in chunk_data:

                # chunk number in order    0
                # chunk address            1
                # chunk size               2
                # lfh flags                3
                # Free order               4
                # NextOffset               5     
                # Description              6
                # Validation               7
                self.heaper.window.Log("%04d: Chunk(0x%08x) -> Size: 0x%x LFHflag: 0x%x %s " % ( chunk[0], chunk[1], chunk[2],  chunk[3], chunk[4]), chunk[1])
                if re.match("F",chunk[4]):
                    self.heaper.window.Log("%04d: Chunk(0x%08x) -> NextOffset: 0x%04x NextVA -> UserBlocks + (NextOffset * 0x8): 0x%08x" % (chunk[0], chunk[1], chunk[5], (userblocks_info[4] + ( chunk[5] * 0x8))), chunk[1])
                    self.heaper.window.Log("-" * 99)
                if chunk[7]:
                    self.heaper.window.Log("    --> **********************************************************************************************")
                    self.heaper.window.Log("    --> ** %04d: Chunk(0x%08x) ** The EntryOffset (0x%04x) for this chunk has been overwritten! **" % (chunk[0], chunk[1], chunk[5]))
                    self.heaper.window.Log("    --> **********************************************************************************************")             

    # print the buckets in the LFH
    def print_buckets(self, size=False):
        self.heaper.window.Log("")
        self.heaper.window.Log("(+) Dumping buckets from _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->Buckets(+0x110):" % (self.heaper.pheap.address,self.heaper.pheap.LFH.address))
        self.heaper.window.Log("")
        if self.heaper.pheap.LFH.Buckets:    
            for bucket in self.heaper.pheap.LFH.Buckets:
                if size:
                    if bucket.SizeIndex == size:
                        self.heaper.window.Log("bucket[0x%03x] (0x%08x) -> BlockUnits: 0x%03x UseAffinity: %x DebugFlags: %x" % (bucket.SizeIndex, bucket.address, bucket.BlockUnits, bucket.UseAffinity, bucket.DebugFlags),bucket.address)
                else:
                    self.heaper.window.Log("bucket[0x%03x] (0x%08x) -> BlockUnits: 0x%03x UseAffinity: %x DebugFlags: %x" % (bucket.SizeIndex, bucket.address, bucket.BlockUnits, bucket.UseAffinity, bucket.DebugFlags),bucket.address)
        self.heaper.window.Log("-" * 83)

    # print the UserBlocks cache upon activation
    def print_block_cache(self):
        self.heaper.window.Log("")
        self.heaper.window.Log("(+) Dumping UserBlockCache from _HEAP(0x%08x)->_LFH_HEAP(0x%08x)->UserBlockCache(+0x50):" % (self.heaper.pheap.address,self.heaper.pheap.LFH.address))
        self.heaper.window.Log("")
        if self.heaper.pheap.LFH.UserBlockCache:
            for cache in self.heaper.pheap.LFH.UserBlockCache:           
                self.heaper.window.Log("Cache: 0x%08x Next: 0x%08x Depth: 0x%x Sequence: 0x%x AvailableBlocks: %d Reserved: 0x%x" % (cache.address, cache.Next, cache.Depth, cache.Sequence, cache.AvailableBlocks, cache.Reserved))
        self.heaper.window.Log("-" * 96)   

    def set_chunks(self, size=False):
        """
        sets up the lfh_userblocks_chunks datastructure
        lfh_userblocks_chunks = {X:[[][[]]]}
        
        bin ----|
        
        UserBlocks[n]
            - No. of chunks
            - Lookaside[n] address
            - Pointer to the first chunk
            - Maximum chunk depth
        chunks
            - Corruption? True/False
            - Chunk address
            - Read in size value
            - Read in cookie value
            
        1->+ many relationship

        """
        index = 0
        if self.heaper.pheap.LFH:
            if self.heaper.pheap.LFH.LocalData:
                for seginfo in self.heaper.pheap.LFH.LocalData.SegmentInfo:
                    subseg_management_list = seginfo.SubSegment
                    for subseg in subseg_management_list:
                        # filter on a size
                        index += 1
                        if size and size == subseg.BlockSize:
                            self.build_chunk_structure(subseg, index)
                        elif not size:
                            self.build_chunk_structure(subseg, index)
        return True

    def generate_userblocks_graph(self, size=False):
        for userblocks, chunks in self.lfh_userblocks_chunks.iteritems():

            # shouldnt get more than 1 overwrite in a UserBlocks..
            overwrite_flag = False
            userblocks_info = chunks[0]
            chunk_nodes = []
            chunk_info = chunks[1]
            for chunk in chunk_info:

                # chunk number in order    0
                # chunk address            1
                # chunk size               2
                # lfh flags                3
                # Free order               4
                # NextOffset               5     
                # Description              6
                # Validation               7
                chunk_data = "(%d) chunk 0x%08x" % (chunk[0], chunk[1])

                # free chunk
                if re.match("F",chunk[4]):
                    chunk_data += "\nFREE CHUNK\nNextVA: 0x%08x" % ((userblocks_info[4] + ( chunk[5] * 0x8)))                  
                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#33ccff"))

                # busy chunk
                elif re.match("B",chunk[4]):
                    chunk_data += "\nBUSY CHUNK"
                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#0055ee"))
                if chunk[7]:
                    overwrite_flag = True
                    chunk_data += "\nEntryOffset overwritten!"
                    chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="red"))

            # ok lets build the graph
            lfhgraph = pydot.Dot(graph_type='digraph')
            try:
                UserBlocks_data = "UserBlocks: 0x%08x\nSize: 0x%x" % (userblocks_info[4], userblocks_info[2])
            except:
                UserBlocks_data = "UserBlocks: 0x00000000\nSize: 0x%x" % (userblocks_info[2])

            # if we have at least one chunk, link the header to the first chunk            
            if len(chunk_nodes) >= 1:

                # turns out, you have to add the node twice for an edge
                lfhgraph.add_node(pydot.Node(UserBlocks_data, style="filled", shape="ellipse", label=UserBlocks_data, fillcolor="#00eeaa"))
                lfhgraph.add_edge(pydot.Edge(pydot.Node(UserBlocks_data, style="filled", shape="ellipse", label=UserBlocks_data, fillcolor="#00eeaa"), chunk_nodes[0]))

            # else we got no chunks for the UserBlocks
            else:
                lfhgraph.add_node(pydot.Node(UserBlocks_data, style="filled", shape="rectangle", label=UserBlocks_data+"\nNo chunks found", fillcolor="#00eeaa"))
            for node in chunk_nodes:
                lfhgraph.add_node(node)
                if (chunk_nodes.index(node)+1) < len(chunk_nodes):                        
                    next_chunk_label = chunk_nodes[chunk_nodes.index(node)+1].__get_attribute__("label")
                    if re.search("overwritten", next_chunk_label):
                        lfhgraph.add_edge(pydot.Edge(node, chunk_nodes[chunk_nodes.index(node)+1], label="  NextOffset overwritten!"))                        
                    elif not re.search("FREE CHUNK", next_chunk_label):                
                        lfhgraph.add_edge(pydot.Edge(node, chunk_nodes[chunk_nodes.index(node)+1]))
                    elif re.search("FREE CHUNK", next_chunk_label):
                        lfhgraph.add_edge(pydot.Edge(node, chunk_nodes[chunk_nodes.index(node)+1], label="  NextOffset"))                                                                   
            output_folder = self.heaper.imm.getKnowledge("config_workingdir")
            if output_folder[:-1] != "/" or output_folder[-1] != "\\":
                output_folder += "/"
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)
            if size:
                if userblocks_info[2] == size:
                    if overwrite_flag:
                        lfhgraph.write_png(output_folder + self.filename+"-bin-%02d-%02d_overwrite.png" % (userblocks_info[2],userblocks))
                    else:
                        lfhgraph.write_png(output_folder + self.filename+"-bin-%02d-%02d.png" % (userblocks_info[2],userblocks))
            else:
                if overwrite_flag:
                    lfhgraph.write_png(output_folder + self.filename+"-bin-%02d-%02d_overwrite.png" % (userblocks_info[2],userblocks))
                else:
                    lfhgraph.write_png(output_folder + self.filename+"-bin-%02d-%02d.png" % (userblocks_info[2],userblocks))

# The ListHint/FreeList Heap class (back_end)
class Listhintfreelist(Back_end):

    def __init__(self, heaper):
        self.heaper = heaper
        self.listhintfreelist_chunks = {}
        self.blocks_indexes = {}
        self.paths = {} 
        self.filename  = "backend_graph"

    def run(self):
        self.paths = {"dot":"C:\\Program Files\\Graphviz 2.28\\bin\\dot.exe",
         "twopi":"C:\\Program Files\\Graphviz 2.28\\bin\\twopi.exe",
         "neato":"C:\\Program Files\\Graphviz 2.28\\bin\\neato.exe",
         "circo":"C:\\Program Files\\Graphviz 2.28\\bin\\circo.exe",
         "fdp":"C:\\Program Files\\Graphviz 2.28\\bin\\fdp.exe"}

    def set_listhintfreeList_chunks(self):
        """
        set the listhint and freelist chunks datastructure
        """
        for i in range(0, len(self.heaper.pheap.blocks)):
            block = self.heaper.pheap.blocks[i]
            num_of_freelists = block.ArraySize - block.BaseIndex
            self.listhintfreelist_chunks = {}
            memory = self.heaper.imm.readMemory( block.ListHints, num_of_freelists * 8 )
            for a in range(block.BaseIndex, num_of_freelists):
                entry= block.FreeList[a]
                bin_entry = a + block.BaseIndex
                e=entry[0]
                (flink, heap_bucket) = struct.unpack("LL", memory[a * 0x8 : a * 0x8 + 0x8] )
                allocations = heap_bucket & 0x0000FFFF
                allocations = allocations / 2
                freelist_addr = block.ListHints + (bin_entry - block.BaseIndex) * 8
                if allocations > 0:
                    lfhthreshold = 0x11
                else:
                    lfhthreshold = 0x12
                amount_needed = lfhthreshold - allocations

                # if we have at least the 1 chunk
                self.listhintfreelist_chunks[bin_entry] = []
                self.listhintfreelist_chunks[bin_entry].append([])                    
                self.listhintfreelist_chunks[bin_entry].append([])
                self.listhintfreelist_chunks[bin_entry][0].append(bin_entry)        # bin size
                self.listhintfreelist_chunks[bin_entry][0].append(flink)            # flink (first chunk in the freelist)
                self.listhintfreelist_chunks[bin_entry][0].append(heap_bucket)      # heap_bucket (blink)
                self.listhintfreelist_chunks[bin_entry][0].append(allocations)      # allocations so far
                self.listhintfreelist_chunks[bin_entry][0].append(amount_needed)    # amount of chunks needed to trigger the LFH
                self.listhintfreelist_chunks[bin_entry][0].append(freelist_addr)    # freelist address
                chunk_list = []
                if e[0]:
                    chunk_list.append(e[0])                                         # bin chunk address
                    chunk_list.append(e[1])                                         # flink
                    chunk_list.append(e[2])                                         # blink
                    encoded_header = self.heaper.imm.readMemory(e[0]-0x8,0x4)
                    encoded_header = struct.unpack("L", encoded_header)[0] 
                    result = "%x" % (encoded_header ^ self.heaper.pheap.EncodingKey)

                    # The wtf 'if' statement, i was on hard drugs that night...
                    if (int(result[len(result)-4:len(result)],16) != a+block.BaseIndex 
                        and (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff):
                        if e[1] == e[2]:
                            chunk_list.append("size, flink and blink overwritten")  # size overwrite
                            chunk_list.append(True)                                 # we have an overwrite
                        else:
                            chunk_list.append("size overwritten")                   # size overwrite
                            chunk_list.append(True)                                 # we have an overwrite
                    elif (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff:
                        if e[1] == e[2]:
                            chunk_list.append("flink and blink overwritten")        # validation
                            chunk_list.append(True)                                 # chunk is not overwritten 
                        else:
                            chunk_list.append("validated")                          # validation
                            chunk_list.append(False)                                # chunk is not overwritten
                    else:
                        chunk_list.append("validated")                              # validation
                        chunk_list.append(False)                                    # chunk is not overwritten          
                    if (int(a+block.BaseIndex) != 0x7f and int(a+block.BaseIndex) != 0x7ff):
                        chunk_list.append(a+block.BaseIndex)                        # chunk size

                    # Listhint[7f] or Listhint[7ff] we dont know the chunk size
                    # so lets get it from the chunks header..
                    elif (int(a+block.BaseIndex) == 0x7f or int(a+block.BaseIndex) == 0x7ff):
                        decoded_size = int(result[len(result)-4:len(result)],16)
                        chunk_list.append(decoded_size)                             # chunk size
                    self.listhintfreelist_chunks[bin_entry][1].append(chunk_list)

                    # ok loop through the rest of the chunks
                    if len(entry[1:]) > 1:
                        for e in entry[1:]:
                            chunk_list = []
                            chunk_list.append(e[0])                                 # bin chunk address
                            chunk_list.append(e[1])                                 # flink
                            chunk_list.append(e[2])                                 # blink
                            encoded_header = self.heaper.imm.readMemory(e[0]-0x8,0x4)
                            encoded_header = struct.unpack("L", encoded_header)[0] 
                            result = "%x" % (encoded_header ^ self.heaper.pheap.EncodingKey)
                            if (int(result[len(result)-4:len(result)],16) != a+block.BaseIndex 
                                and (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff):
                                if e[1] == e[2]:
                                    chunk_list.append("size, flink and blink overwritten")      # validation
                                    chunk_list.append(True)                                     # chunk is not overwritten 
                                else:
                                    chunk_list.append("size overwritten")                       # size overwrite
                                    chunk_list.append(True)                                     # we have an overwrite        
                            elif (a+block.BaseIndex) != 0x7f and (a+block.BaseIndex) != 0x7ff:
                                if e[1] == e[2]:
                                    chunk_list.append("flink and blink overwritten")            # validation
                                    chunk_list.append(True)                                     # chunk is not overwritten 
                                else:
                                    chunk_list.append("validated")                              # validation
                                    chunk_list.append(False)                                    # chunk is not overwritten
                            else:
                                chunk_list.append("validated")                                  # validation
                                chunk_list.append(False)                                        # chunk is not overwritten
                            if (int(a+block.BaseIndex) != 0x7f and int(a+block.BaseIndex) != 0x7ff):
                                chunk_list.append(a+block.BaseIndex)                            # chunk size

                            # Listhint[7f] or Listhint[7ff] we dont know the chunk size
                            # so lets get it from the chunks header..
                            elif (int(a+block.BaseIndex) == 0x7f or int(a+block.BaseIndex) == 0x7ff):
                                decoded_size = int(result[len(result)-4:len(result)],16)
                                chunk_list.append(decoded_size)             # chunk size         
                            self.listhintfreelist_chunks[bin_entry][1].append(chunk_list)

            # build the blocksindex structure
            self.blocks_indexes[block.address] = self.listhintfreelist_chunks
        return True

    def print_listhintfreelist(self, args):
        """
        prints the listhint and freelist information
        """
        for i in range(0, len(self.heaper.pheap.blocks)):
            block = self.heaper.pheap.blocks[i]
            num_of_freelists = block.ArraySize - block.BaseIndex
            self.heaper.window.Log("")
            self.heaper.window.Log("HeapBase->BlocksIndex")
            self.heaper.window.Log("~~~~~~~~~~~~~~~~~~~~~")
            self.heaper.window.Log("(+) BlocksIndex information for 0x%08x->0x%08x" % (self.heaper.heap+0xb8,block.address),block.address)
            self.heaper.window.Log("(+) ExtendedLookup => 0x%08x" % block.ExtendedLookup)
            self.heaper.window.Log("(+) ArraySize [max permitted in blocks] => 0x%08x" % block.ArraySize)
            self.heaper.window.Log("(+) BaseIndex => 0x%08x" % block.BaseIndex)
            self.heaper.window.Log("(+) End Block information for 0x%08x" % block.address)
            self.heaper.window.Log("(+) Block has [0x%x] FreeLists starting at 0x%08x"  % (num_of_freelists, block.ListHints))
            self.heaper.window.Log("")
            if "-l" in args or "-f" in args:
                listhint_freelist_chunks = self.blocks_indexes[block.address]
                c = 0
                allocations_needed = {}
                for (block_address, chunks) in listhint_freelist_chunks.iteritems():
                    if "-l" in args:
                        list_data = chunks[0]
                        
                        # bin size
                        # flink (first chunk in the freelist)
                        # heap_bucket (blink)
                        # allocations so far
                        # amount of chunks needed to trigger the LFH
                        # freelist address
                        flink           = list_data[1]
                        heap_bucket     = list_data[2]
                        allocations     = list_data[3]
                        amount_needed   = list_data[4]
                        freelist_addr   = list_data[5]
                        if heap_bucket != 0:
                            if amount_needed in range (0x01,0x12):
                                allocations_needed[block_address] = amount_needed
                            else:
                                allocations_needed[block_address] = 0 
                            if heap_bucket & 1:
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: Enabled | Bucket => 0x%08x" % (block_address, flink, heap_bucket - 1), address = freelist_addr)
                            elif (heap_bucket & 0x0000FFFF) >= 0x22: #there appears to be a case where the LFH isn't activated when it should be...
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: ??????? | Bucket => 0x%08x" % (block_address, flink, heap_bucket), address = freelist_addr)
                            else:
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: Has had %d allocations | Needs %d more" % (block_address, flink, allocations, amount_needed), address = freelist_addr)
                        elif heap_bucket == 0:
                            if block_address != 0x1 and block_address != 0x0 and flink == 0:
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: Bin is Empty!" % (block_address, flink), address = freelist_addr)
                            elif block_address != 0x1 and block_address != 0x0 and block_address == (block.ArraySize-0x1) and flink != 0:
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: last entry contains large chunks!" % (block_address, flink), address = freelist_addr)
                            elif flink != 0 and block_address != 0x1 and block_address != 0x0:
                                self.heaper.window.Log("Bin[0x%04x] | Flink => 0x%08x :: Has had %d allocations | Needs %d more" % (block_address, flink, allocations, amount_needed), address = freelist_addr)
                                allocations_needed[block_address] = 0

                            # amount needed should always be between 0-18
                        if amount_needed in range (0x01,0x12):
                            allocations_needed[block_address] = amount_needed
                    if "-f" in args:
                        c = 0
                        list_chunks = chunks[1]
                        if len(list_chunks) > 0:
                            self.heaper.window.Log("ListHint[0x%03x]" % (block_address-block.BaseIndex))
                        for chunk in list_chunks:
                            c += 1
                            if chunk[4]:
                                self.heaper.window.Log("        ***************************************************************************************************************")
                                try:
                                    self.heaper.window.Log("        -> (%02d) Chunk: 0x%08x | Flink: 0x%08x | Blink: 0x%08x | Size: 0x%03x |=> %s" % (c,chunk[0],chunk[1],chunk[2],chunk[5],chunk[3]),chunk[1])
                                except:
                                    self.heaper.window.Log("        -> (%02d) Chunk: 0x%08x | Flink: 0x%08x | Blink: 0x%08x | Size: 0x%s |=> %s" % (c,chunk[0],chunk[1],chunk[2],chunk[5],chunk[3]),chunk[1])
                                self.heaper.window.Log("        ***************************************************************************************************************")
                            else:
                                try:
                                    self.heaper.window.Log("        (%02d) Chunk: 0x%08x | Flink: 0x%08x | Blink: 0x%08x | Size: 0x%03x |=> %s" % (c,chunk[0],chunk[1],chunk[2],chunk[5],chunk[3]),chunk[1])
                                except:
                                    self.heaper.window.Log("        (%02d) Chunk: 0x%08x | Flink: 0x%08x | Blink: 0x%08x | Size: 0x%s |=> %s" % (c,chunk[0],chunk[1],chunk[2],chunk[5],chunk[3]),chunk[1])

    def generate_freelist_graph(self):
        """
        This function generates the freelist graph
        """

        # configure the working directory
        output_folder = self.heaper.imm.getKnowledge("config_workingdir")
        if output_folder[:-1] != "/" or output_folder[-1] != "\\":
            output_folder += "\\"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)         

        # generate graph
        freelistgraph = pydot.Dot(graph_type='digraph')
        listhint_nodes = {}
        list_hint_dict = {}      
        num = 0         
        for i in range(0, len(self.heaper.pheap.blocks)):
            block = self.heaper.pheap.blocks[i]
            listhint_freelist_chunks = self.blocks_indexes[block.address]
            for chunks in listhint_freelist_chunks.itervalues():
                nodes = {}
                list_data   = chunks[0]
                list_chunks = chunks[1]
                bin_entry       = list_data[0]
                flink           = list_data[1]
                heap_bucket     = list_data[2]
                amount_needed   = list_data[4]
                a = bin_entry-block.BaseIndex
                if len(list_chunks) > 0:
                    for chunk in list_chunks:
                        try:
                            chunk_node_info = "Chunk => 0x%08x\nFlink => 0x%08x\nBlink => 0x%08x\nSize => 0x%x" % (chunk[0],chunk[1],chunk[2],chunk[5])

                        # overwrite
                        except:
                            chunk_node_info = "Chunk => 0x%08x\nFlink => 0x%08x\nBlink => 0x%08x\nSize => 0x%s" % (chunk[0],chunk[1],chunk[2],chunk[5])

                        # build the node structure
                        nodes[chunk[0]] = []
                        nodes[chunk[0]].append(chunk[1]) 

                        # if we have an overwrite....
                        if chunk[4]:
                            chunk_node_info += "\n=> %s overwrite!" % chunk[3]
                            nodes[chunk[0]].append(pydot.Node(chunk_node_info, style="filled", shape="rectangle", label=chunk_node_info, fillcolor="red"))
                        elif not chunk[4]:
                            nodes[chunk[0]].append(pydot.Node(chunk_node_info, style="filled", shape="rectangle", label=chunk_node_info, fillcolor="#33ccff"))

                if a not in list_hint_dict:
                    list_hint_dict[a] = nodes

                # no matter how many allocations, you will never trigger LFH
                if a == 0x7f or a == 0x7ff:
                    list_data = "ListHint[0x%x] flink => 0x%08x\nNo amount of allocs will\ntrigger LFH for this bin" % (a, flink) 
                elif heap_bucket & 1:
                    list_data = "ListHint[0x%x] flink => 0x%08x\nLFH Enabled!" % (a, flink)
                elif amount_needed < 0x12:
                    list_data = "ListHint[0x%x] flink => 0x%08x\nNo. of allocs to LFH = %d" % (a, flink, amount_needed)
                else:
                    list_data = "ListHint[0x%x] flink => 0x%08x\nNo. of allocs to LFH is unknown" % (a, flink)
                if len(list_chunks) > 0:
                    num += 1
                    if a not in listhint_nodes:
                        listhint_nodes[a] = []
                        listhint_nodes[a].append(flink)
                        listhint_nodes[a].append(nodes)
                        listhint_nodes[a].append(pydot.Node("ListHint[0x%x]" % a, style="filled", shape="ellipse", label=list_data, fillcolor="#66FF66"))

        # generate the graph
        listhint_nodes_copy = sorted(listhint_nodes.keys())
        for (listhints,nodes) in listhint_nodes.iteritems():
            list_hint_flink = nodes[0]
            list_hint_nodes_data = nodes[1]
            list_node = nodes[2]
            freelistgraph.add_node(list_node)
            for (chunk,node) in list_hint_nodes_data.iteritems():
                if chunk == list_hint_flink:
                    freelistgraph.add_node(node[1])
                    freelistgraph.add_edge(pydot.Edge(list_node,node[1]))
                else:
                    freelistgraph.add_node(node[1])
                if list_hint_nodes_data.get(node[0]):
                    freelistgraph.add_edge(pydot.Edge(node[1], list_hint_nodes_data.get(node[0])[1]))                
                elif not list_hint_nodes_data.get(node[0]):
                    if len(listhint_nodes_copy) > listhint_nodes_copy.index(listhints)+1:

                        # fml, that was tricky
                        n_nodes = listhint_nodes[listhint_nodes_copy[listhint_nodes_copy.index(listhints)+1]]
                        for i, (key,n_node) in enumerate(n_nodes[1].iteritems()):
                            if key == node[0]:
                                freelistgraph.add_edge(pydot.Edge(node[1], n_node[1]))

                            # else, there is prob an overwrite,
                            # save to assume that it links at this point?
                            elif re.search("overwrite", node[1].__get_attribute__("label")):

                                # just assume the first one in the list...
                                if i == 0:
                                    freelistgraph.add_edge(pydot.Edge(node[1], n_node[1]))
        freelistgraph.set_graphviz_executables(self.paths)
        freelistgraph.write_png(output_folder+self.filename+".png")

    def perform_heuristics(self):
        """
        This function performs heuristics against the FreeList
        """
        vuln_chunks = 0
        for i in range(0, len(self.heaper.pheap.blocks)):
            block = self.heaper.pheap.blocks[i]
            listhint_freelist_chunks = self.blocks_indexes[block.address]
            for chunks in listhint_freelist_chunks.itervalues():
                list_data   = chunks[0]
                list_chunks = chunks[1]
                bin_entry       = list_data[0]
                a = bin_entry-block.BaseIndex
                if len(list_chunks) > 0:
                    for chunk in list_chunks:
                        try:
                            chunk_node_info = "    Chunk => 0x%08x | Flink => 0x%08x | Blink => 0x%08x | Size => 0x%x" % (chunk[0],chunk[1],chunk[2],chunk[5])

                        # overwritten chunk
                        except:
                            chunk_node_info = "    Chunk => 0x%08x | Flink => 0x%08x | Blink => 0x%08x | Size => 0x%s" % (chunk[0],chunk[1],chunk[2],chunk[5])                        
                        if chunk[4]:
                            self.heaper.window.Log("")
                            vuln_chunks += 1
                            self.heaper.window.Log("ListHint[0x%x] =>" % a)
                            self.heaper.window.Log(chunk_node_info + " | => chunk %s" % chunk[3])
        self.heaper.window.Log("")
        self.heaper.window.Log("(!) Found %d vulnerable chunks in heap 0x%08x" % (vuln_chunks, self.heaper.heap))
        self.heaper.window.Log("")

###############################
# Windows 2000/XP/Server 2003 #
# NT 5.x                      #
###############################

class Lookaside(Front_end):

    def __init__(self, imm, heaper):
        self.lookaside_chunks   = {}
        self.heaper             = heaper
        self.imm                = imm
        self.block              = 0x8
        self.chunk_nodes        = []
        self.filename           = "lal_graph"
        self.FrontEndHeapType   = 0x0

    def run(self):
        self.Lookaside = self.imm.readMemory(self.heaper.heap+0x580, 4)
        self.Lookaside = struct.unpack("L", self.Lookaside)

        # the case when we are using the LFH under windows NT 5.X
        self.FrontEndHeapType = self.imm.readMemory(self.heaper.heap+0x586, 1)
        self.FrontEndHeapType = struct.unpack("b", self.FrontEndHeapType)[0]

    def perform_heuristics(self):
        """
        perform heuristics for a given Lookaside
        """
        vuln_chunks = 0
        for entry in range(0, len(self.heaper.pheap.Lookaside)):
            if self.lookaside_chunks.has_key(entry):
                entry_chunks = self.lookaside_chunks[entry]
                for a in entry_chunks[1]:
                    masked_size  = (a[4] & 0x0000ffff)
                    masked_flink = (a[3] & 0x0000ffff)
                    if a[2] and a[4] != entry and masked_size != masked_flink:
                        vuln_chunks += 1
                        self.heaper.window.Log("")
                        self.heaper.window.Log("Lookaside[0x%02x] - No. of chunks: %d, ListEntry: 0x%08x, Size: 0x%02x (%d+8=%d)" % (entry, entry_chunks[0][0], entry_chunks[0][1], (entry*self.block+self.block), (entry*self.block), (entry*self.block+self.block)) )
                        self.heaper.window.Log("")
                        self.heaper.window.Log("    Chunk:")
                        self.heaper.window.Log("    ~~~~~~~")
                        if (a[1]+self.block) == a[3]: 
                            self.heaper.window.Log("    "+"*" * 92)
                            self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x00000000, size: %d (0x%02x), cookie: 0x%x <= fake chunk created!" % (a[0],a[1],a[4],a[4],a[5]), address = a[1])
                            self.heaper.window.Log("    "+"*" * 92)                            
                        elif (a[1]+self.block) != a[3]:
                            self.heaper.window.Log("    "+"*" * 100)
                            self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= size/chunk corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                            self.heaper.window.Log("    "+"*" * 100)
         
                    # detect corruption, size overwrite only
                    elif a[2] and a[4] != entry and masked_size == masked_flink:
                        vuln_chunks += 1
                        self.heaper.window.Log("")
                        self.heaper.window.Log("Lookaside[0x%02x] - No. of chunks: %d, ListEntry: 0x%08x, Size: 0x%02x (%d+8=%d)" % (entry, entry_chunks[0][0], entry_chunks[0][1], (entry*self.block+self.block), (entry*self.block), (entry*self.block+self.block)) )
                        self.heaper.window.Log("")
                        self.heaper.window.Log("    Chunk:")
                        self.heaper.window.Log("    ~~~~~~~")
                        self.heaper.window.Log("    "+"*" * 106)
                        self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= flink corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                        self.heaper.window.Log("    "+"*" * 106)
        self.heaper.window.Log("")
        self.heaper.window.Log("(!) Found %d vulnerable chunk(s) in heap 0x%08x" % (vuln_chunks, self.heaper.heap))
        self.heaper.window.Log("")
                    
    def set_lookaside_chunks(self):
        """
        sets up the lookaside chunks datastructure into self.lookaside_chunks
        
        Entry:
            0. No. of chunks
            1. Lookaside[n] address
            2. Pointer to the first chunk
            3. Maximum chunk depth
            Chunks:
                0. Corruption? True/False
                1. Chunk address
                2. Read in size value
                3. Read in cookie value
        """
        no_chunks = 0
        if self.heaper.pheap.Lookaside:
            no_chunks = 0
            for ndx in range(0, len(self.heaper.pheap.Lookaside)):
                entry = self.heaper.pheap.Lookaside[ndx]
                self.lookaside_chunks[ndx] = []                             # bin, size
                self.lookaside_chunks[ndx].append([])                       # store info regarding Lookaside[n]
                self.lookaside_chunks[ndx].append([])                       # store the chunks
                if not entry.isEmpty():
                    self.lookaside_chunks[ndx][0].append(entry.Depth)       # Number of chunks 
                    self.lookaside_chunks[ndx][0].append(entry.addr)        # Lookaside[n] address
                    self.lookaside_chunks[ndx][0].append(entry.ListHead)    # Pointer to the first chunk
                    self.lookaside_chunks[ndx][0].append(entry.MaxDepth)    # Maximum chunk depth
                    b = 0
                    for chk in entry.getList():
                        chunk_data_values = []
                        b += 1

                        # get the chunks self size
                        chunk_read_self_size = ""
                        try:
                            chunk_read_self_size = self.heaper.imm.readMemory(chk, 0x2)
                            chunk_read_self_size = struct.unpack("H", chunk_read_self_size)[0]
                        except:
                            pass

                        # get the chunks cookie
                        chunk_cookie = ""
                        try:
                            chunk_cookie = self.heaper.imm.readMemory(chk+0x4, 0x1)
                            chunk_cookie = struct.unpack("B", chunk_cookie)[0]
                        except:
                            pass

                        # validate the flink!
                        chunk_overwrite = False
                        try:
                            flink = self.heaper.imm.readMemory(chk+0x8, 0x4)
                            flink = struct.unpack("L", flink)[0]
                        except:
                            chunk_overwrite = True
                        chunk_data_values.append(b)             # chunk number
                        chunk_data_values.append(chk)           # chunk address

                        # else the expected chunk size is not the same as the read in chunk..
                        if (chunk_read_self_size * self.block) != (ndx * self.block):
                            if chunk_read_self_size != "":

                                # if the size has been overwritten of the adjacent chunk
                                if not chunk_overwrite:
                                    chunk_data_values.append(True)                  # corruption (Boolean)
                                    chunk_data_values.append(flink)                 # chunk address
                                    chunk_data_values.append(chunk_read_self_size)  # size read from the chunk header
                                    chunk_data_values.append(chunk_cookie)          # cookie
                                elif chunk_overwrite:
                                    chunk_data_values.append(True)                  # corruption (Boolean)
                                    chunk_data_values.append(chk + 0x8)             # chunk address (cant read the value)
                                    chunk_data_values.append(0)                     # size read from the chunk header (cant read the value)
                                    chunk_data_values.append(0)                     # cookie (cant read the value)
                            elif chunk_read_self_size == "":
                                chunk_data_values.append(True)
                                chunk_data_values.append(chk + 0x8)
                                chunk_data_values.append(0)         
                                chunk_data_values.append(0)                                
                        elif (chunk_read_self_size * self.block) == (ndx * self.block):
                            if not chunk_overwrite:
                                chunk_data_values.append(False)                     # corruption (Boolean)
                                chunk_data_values.append(flink)                     # chunk address
                                chunk_data_values.append(chunk_read_self_size)      # size read from the chunk header
                                chunk_data_values.append(chunk_cookie)              # cookie                                 
                            elif chunk_overwrite:
                                chunk_data_values.append(True)                      # corruption (Boolean)
                                chunk_data_values.append(chk + 0x8)                 # chunk address (cant read the value)
                                chunk_data_values.append(0)                         # size read from the chunk header (cant read the value)
                                chunk_data_values.append(0)                         # cookie (cant read the value)
                        self.lookaside_chunks[ndx][1].append(chunk_data_values)
                elif entry.isEmpty():
                    no_chunks +=1             
        if no_chunks == 128:
            return False
        else:

            # may we land here please?
            return True

    def print_lookaside(self, verbose=False):
        """
        prints the Lookaside of the current heap
        """ 
        if not verbose:
            for bin_index, lists in self.lookaside_chunks.iteritems():
                if len(lists[0]) > 0:
                    bin_data = lists[0]                  
                    self.heaper.window.Log("Lookaside[0x%02x] - No. of chunks: %d, ListEntry: 0x%08x, Size: 0x%02x (%d+8=%d)" % (bin_index, bin_data[0], bin_data[1], (bin_index*self.block+self.block), (bin_index*self.block), (bin_index*self.block+self.block)) )
                    self.heaper.window.Log("")
                    if len(lists[1]) > 0:
                        for a in lists[1]:
                            masked_size  = (a[4] & 0x0000ffff)
                            masked_flink = (a[3] & 0x0000ffff)

                            # detect corruption, chunk header overwrite
                            if a[2] and a[4] != bin_index and masked_size != masked_flink:
                                if (a[1]+self.block) == a[3]: 
                                    self.heaper.window.Log("    "+"*" * 92)
                                    self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x00000000, size: %d (0x%02x), cookie: 0x%x <= fake chunk created!" % (a[0],a[1],a[4],a[4],a[5]), address = a[1])
                                    self.heaper.window.Log("    "+"*" * 92)                            
                                elif (a[1]+self.block) != a[3]:
                                    self.heaper.window.Log("    "+"*" * 100)
                                    self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= size/chunk corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                                    self.heaper.window.Log("    "+"*" * 100)
              
                            # detect corruption, size overwrite only
                            elif a[2] and a[4] != bin_index and masked_size == masked_flink:
                                self.heaper.window.Log("    "+"*" * 106)
                                self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= flink corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                                self.heaper.window.Log("    "+"*" * 106)

                            # corruption not detected
                            elif not a[2] and a[4] > 0:
                                self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                        self.heaper.window.Log("")
                        self.heaper.window.Log("-" * 80)
                        self.heaper.window.Log("")
        elif verbose:
            lookaside_entry = self.heaper.heap+0x688
            for bin_index, lists in self.lookaside_chunks.iteritems():
                if len(lists[0]) == 0:
                    ListEntry = lookaside_entry + (0x30 * bin_index)
                    self.heaper.window.Log("Lookaside[0x%02x] - No. of chunks: 0, ListEntry: 0x%08x, Size: 0x%02x (%d+8=%d)" % (bin_index, ListEntry, (bin_index*self.block+self.block), (bin_index*self.block), (bin_index*self.block+self.block)) )
                elif len(lists[0]) > 0:
                    bin_data = lists[0]                  
                    self.heaper.window.Log("Lookaside[0x%02x] - No. of chunks: %d, ListEntry: 0x%08x, Size: 0x%02x (%d+8=%d)" % (bin_index, bin_data[0], bin_data[1], (bin_index*self.block+self.block), (bin_index*self.block), (bin_index*self.block+self.block)) )
                    self.heaper.window.Log("")
                    if len(lists[1]) > 0:
                        for a in lists[1]:
                            masked_size  = (a[4] & 0x0000ffff)
                            masked_flink = (a[3] & 0x0000ffff)

                            # detect corruption, chunk header overwrite
                            if a[2] and a[4] != bin_index and masked_size != masked_flink:
                                if (a[1]+self.block) == a[3]: 
                                    self.heaper.window.Log("    "+"*" * 92)
                                    self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x00000000, size: %d (0x%02x), cookie: 0x%x <= fake chunk created!" % (a[0],a[1],a[4],a[4],a[5]), address = a[1])
                                    self.heaper.window.Log("    "+"*" * 92)                            
                                elif (a[1]+self.block) != a[3]:
                                    self.heaper.window.Log("    "+"*" * 100)
                                    self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= size/chunk corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                                    self.heaper.window.Log("    "+"*" * 100)
             
                            # detect corruption, size overwrite only
                            elif a[2] and a[4] != bin_index and masked_size == masked_flink:
                                self.heaper.window.Log("    "+"*" * 106)
                                self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x <= flink corruption detected!" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                                self.heaper.window.Log("    "+"*" * 106)

                            # corruption not detected
                            elif not a[2] and a[4] > 0:
                                self.heaper.window.Log("    chunk (%d): 0x%08x, flink: 0x%08x, size: %d (0x%02x), cookie: 0x%x" % (a[0],a[1],a[3],a[4],a[4],a[5]), address = a[1])
                        self.heaper.window.Log("")
                        self.heaper.window.Log("-" * 80)
                        self.heaper.window.Log("")
        
    def generate_lookaside_graph(self, verbose=False):
        """
        Generates the Lookaside graph using pydot. It analyses the self.lookaside_chunks
        datastructure and generates the graph according to which chunks exist and their integrity

        @return: the file name/path of the created graph
        """
        lalgraph = pydot.Dot(graph_type='digraph')
        chunk_dict          = {}
        chunk_nodes         = []
        for ndx in range(0, len(self.heaper.pheap.Lookaside)):
            chunk_nodes         = []
            lookasidelist_node  = pydot.Node("Lookaside[0x%02x]" % ndx, style="filled", shape="rectangle", fillcolor="#66FF66")
            if self.lookaside_chunks.has_key(ndx):
                entry_chunks = self.lookaside_chunks[ndx]
                for a in entry_chunks[1]:
                    masked_size  = (a[4] & 0x0000ffff)
                    masked_flink = (a[3] & 0x0000ffff)
                    chunk_data = ("chunk (%d) 0x%08x \nFlink 0x%08x" % (a[0], a[1], a[3]))
                    if a[2] and a[4] != ndx and masked_size != masked_flink:
                        if (a[1]+self.block) == a[3]:
                            chunk_data = ("chunk (%d) 0x%08x \nFlink 0x00000000" % (a[0], a[1]))
                            chunk_nodes.append(pydot.Node(chunk_data+"\nfake chunk", style="filled", shape="rectangle", label=chunk_data+"\nfake chunk", fillcolor="red"))
                        elif (a[1]+self.block) != a[3]:
                            chunk_nodes.append(pydot.Node(chunk_data+"\nsize/chunk corruption", style="filled", shape="rectangle", label=chunk_data+"\nsize/chunk corruption", fillcolor="red"))            

                    # detect corruption, size overwrite only
                    elif a[2] and a[4] != ndx and masked_size == masked_flink:
                        chunk_nodes.append(pydot.Node(chunk_data+"\nflink corruption", style="filled", shape="rectangle", label=chunk_data+"\nflink corruption", fillcolor="red"))  

                    # corruption not detected
                    elif not a[2] and a[4] > 0:
                        chunk_nodes.append(pydot.Node(chunk_data, style="filled", shape="rectangle", label=chunk_data, fillcolor="#3366ff" ))     

            # build the datastructure
            chunk_dict[ndx] = [lookasidelist_node, chunk_nodes]
        for lookasidelist in chunk_dict:
            node_list = chunk_dict[lookasidelist]

            # if using verbose mode, add all the node entries and add edges...
            if verbose:
                lalgraph.add_node(node_list[0])
                try:
                    lalgraph.add_edge(pydot.Edge(chunk_dict[lookasidelist][0], chunk_dict[lookasidelist+1][0]) )
                except:
                    pass
            if len(chunk_dict[lookasidelist][1]) > 0:

                # if not using verbose mode, just add the node entry that has chunks...
                if not verbose:
                    lalgraph.add_node(node_list[0])

                # loop through the chunk nodes
                node_list = chunk_dict[lookasidelist][1]
                for node in node_list:
                    lalgraph.add_node(node)

                    # if its the first chunk, link it to the Lookaside list entry
                    if node_list.index(node) == 0:
                        lalgraph.add_edge(pydot.Edge(chunk_dict[lookasidelist][0],node))
                    if node_list.index(node) < (len(node_list)-1):
                        index = node_list.index(node)+1

                        # possible exploitation..
                        if re.search("flink corruption", node.get_name().strip('"')):
                            lalgraph.add_edge(pydot.Edge( node, node_list[index], label=" chunk on the lookaside\noverwrite!" ))
                        else:
                            lalgraph.add_edge(pydot.Edge( node, node_list[index] ))
        output_folder = self.heaper.imm.getKnowledge("config_workingdir")
        if output_folder[:-1] != "/" or output_folder[-1] != "\\":
            output_folder += "\\"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        # save the output
        lalgraph.write_png(output_folder+self.filename + ".png")
        
        # return the filename
        return output_folder+self.filename + ".png"

class Freelist(Back_end):

    def __init__(self, heaper):
        self.heaper = heaper
        self.freelist_chunks = {}

    def run(self):
        self.filename        = "freelist_graph"

    # operational methods
    def perform_heuristics(self):
        """
        perform heuristics for FreeList[n] and FreeList[0]
        """
        vuln_chunks = 0
        self.heaper.window.Log("")
        for data in self.freelist_chunks.itervalues():
            i = 0
            for chunk in data:

                # must be chunks for the list entry
                # we must check for error based chunks here
                if i > 0:
                    for chunk_data in chunk:
                        if chunk_data[8]:
                            vuln_chunks += 1
                            list_entry = data[0]
                            if list_entry[0] == 0x00:
                                self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: > 1016]" % 
                                                       (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4)), list_entry[1])                        
                            elif list_entry[0] > 0x00:
                                self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: 0x%02x * 0x8 = 0x%04x]" % 
                                                       (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4), list_entry[0], (list_entry[0] * 0x8)), list_entry[1]) 
                            self.heaper.window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x].flink : 0x%08x]" % 
                                                   (list_entry[0], list_entry[2], list_entry[0], list_entry[3]), list_entry[1])
                            self.heaper.window.Log("")
                            self.heaper.window.Log("        "+"*" * 86)
                            self.heaper.window.Log("        * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x] <= %s overwrite!" % 
                            (chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3], chunk_data[7]), chunk_data[1])
                            self.heaper.window.Log("        "+"*" * 86)
                            self.heaper.window.Log("                [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x <= %s overwrite!" % 
                            (chunk_data[0], chunk_data[4], (chunk_data[4] * 0x8), (chunk_data[4] * 0x8), chunk_data[5], chunk_data[7]), chunk_data[1])
                            self.heaper.window.Log("        "+"*" * 86)             
                            self.heaper.window.Log("")
                i += 1
        self.heaper.window.Log("(!) Found %d vulnerable chunk(s) in heap 0x%08x" % (vuln_chunks, self.heaper.heap))
        self.heaper.window.Log("")

    # set methods
    def set_heapcache_bitmap(self, get_chunk_dict=False):
        bit_list = {}
        chunk_dict = {}
        for a in range(0, len(self.heaper.pheap.HeapCache.Buckets)):
            if self.heaper.pheap.HeapCache.Buckets[a]:
                bit_list[a+0x80] = 1
                if get_chunk_dict:
                    chunk_dict[self.heaper.pheap.HeapCache.Buckets[a]] = a + 0x80 # not sure why I did this, need to double check...
            else:
                bit_list[a+0x80] = 0
        if get_chunk_dict:
            return bit_list, chunk_dict
        else:
            return bit_list

    # here we can patch FreeListInUse depending on what
    # values the user sets
    def set_freelistinuse_bitmap(self, value):
        fliu_0 = list(self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[0]))
        fliu_1 = list(self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[1]))
        fliu_2 = list(self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[2]))
        fliu_3 = list(self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[3]))

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
        fliu_0 = self.heaper.binary_to_decimal(fliu_0[::-1])
        fliu_1 = self.heaper.binary_to_decimal(fliu_1[::-1])
        fliu_2 = self.heaper.binary_to_decimal(fliu_2[::-1])
        fliu_3 = self.heaper.binary_to_decimal(fliu_3[::-1])

        # patch memory
        self.heaper.imm.writeLong( self.heaper.heap+0x158+0x00, fliu_0 )
        self.heaper.imm.writeLong( self.heaper.heap+0x158+0x04, fliu_1 )
        self.heaper.imm.writeLong( self.heaper.heap+0x158+0x08, fliu_2 )
        self.heaper.imm.writeLong( self.heaper.heap+0x158+0x0c, fliu_3 )

    def set_freelist_chunks(self):
        """                    
        sets the following datastruture into self.feelist_chunks:
        
            Entry:
                0. bin size
                1. freelist[n] address
                2. blink
                3. flink
                
                Chunks:
                    0. chunk number (in order)
                    1. chunk address
                    2. chunks blink address
                    3. chunks flink address
                    4. chunks bin size
                    5. chunk size (user size)
                    6. chunk cookie
                    7. description upon validation
                    8. boolean on passing validation (True/False)
        """
        for a in range(0, 128):
            entry = self.heaper.pheap.FreeList[a]
            e = entry[0]
            if e[0]:
                if len(entry[1:]) >= 1:
                    chunk_num = 0

                    # freelist entry structure
                    self.freelist_chunks[a] = []
                    self.freelist_chunks[a].append([])
                    self.freelist_chunks[a].append([])
                    self.freelist_chunks[a][0].append(a)        # bin
                    self.freelist_chunks[a][0].append(e[0])     # freelist[n] address
                    self.freelist_chunks[a][0].append(e[1])     # blink
                    self.freelist_chunks[a][0].append(e[2])     # flink
                    for fc in entry[1:]:
                        if len(entry[1:]) == 1:
                            prevchunk_address = e[0]
                        else:
                            prevchunk_address = entry[1:][entry[1:].index(fc)-1][0]
                        try:
                            nextchunk_address = entry[1:][entry[1:].index(fc)+1][0]
                        except:
                            nextchunk_address = 1
                        chunk_address   = fc[0]
                        chunk_blink     = fc[1]
                        chunk_flink     = fc[2]
                        try:
                            sz = self.heaper.pheap.get_chunk( chunk_address - self.heaper.block ).size

                            # avoid freelist[0] as it can be anything > 1016
                            if a != 0:
                                calc_sz = (sz * self.heaper.block) - self.heaper.block
                            else:
                                calc_sz = 0
                        except:
                            calc_sz = 0
                            sz = 0
                        chunk_cookie = self.heaper.imm.readMemory(chunk_address-0x4, 1) # chunk_address includes header
                        chunk_cookie = struct.unpack("B", chunk_cookie)[0]
                        chunk_num += 1

                        # chunk structure
                        chunk_data = []
                        chunk_data.append(chunk_num)                        # chunk number (in order)
                        chunk_data.append(chunk_address)                    # chunk address
                        chunk_data.append(chunk_blink)                      # chunk blink address
                        chunk_data.append(chunk_flink)                      # chunk flink address
                        chunk_data.append(sz)                               # chunk size (bin)
                        chunk_data.append(calc_sz)                          # chunk size (user size)
                        chunk_data.append(chunk_cookie)                     # chunk cookie     

                        if a != 0:

                            # now lets validate the integrity of the linked list using safe unlinking checks
                            # Not the last chunk in the entry..
                            if sz != a and nextchunk_address != 1:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_data.append("Size, Flink and Blink")          # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed
                                else:
                                    chunk_data.append("Size")                           # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed                           

                            # now lets validate the integrity of the linked list using safe unlinking checks and size validation
                            # Last chunk in the entry..
                            elif sz != a and nextchunk_address == 1:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_data.append("Size, Flink and Blink")          # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed
                                else:
                                    chunk_data.append("Size")                           # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed 
                            else:
                                chunk_data.append("validated")                          # chunk validation passed
                                chunk_data.append(False)                                # chunk validation passed
                        elif a == 0:

                            # check if this chunk is not the last chunk in the entry
                            if nextchunk_address != 1:
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_data.append("Size, Flink and Blink")          # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed 
                                else:
                                    chunk_data.append("validated")                      # chunk validation passed
                                    chunk_data.append(False)                            # chunk validation passed                       

                            # last chunk
                            elif nextchunk_address == 1:            
                                if prevchunk_address != chunk_blink and chunk_flink != nextchunk_address:
                                    chunk_data.append("Size, Flink and Blink")          # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed                        
                                else:
                                    chunk_data.append("validated")                      # chunk validation passed
                                    chunk_data.append(False)                            # chunk validation passed 

                            # else just check blink
                            # code probably never lands here... will check and remove soon
                            else:
                                if prevchunk_address != chunk_blink:
                                    chunk_data.append("Flink and Blink")                # chunk validation failed
                                    chunk_data.append(True)                             # chunk validation failed
                                else:
                                    chunk_data.append("validated")                      # chunk validation passed
                                    chunk_data.append(False)                            # chunk validation passed 
                        self.freelist_chunks[a][1].append(chunk_data)

    # get the bits for each freelist[n] entry
    def get_freelistinuse(self):
        # ensure we are dealing with 32 bit integers only, lose the LSB
        bitblocks = "%s%s%s%s" % (self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[0])[0:32],
                                  self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[1])[0:32],
                                  self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[2])[0:32],
                                  self.heaper.pheap.decimal2binary(self.heaper.pheap.FreeListInUseLong[3])[0:32])
        bits = []
        for bit in bitblocks:
            bits.append(int(bit))
        return bits

    def print_freelistinuse_bitmap(self):
        bits = self.get_freelistinuse()
        i = 0
        self.heaper.window.Log("")
        self.heaper.window.Log("FreeListInUse:")
        self.heaper.window.Log("--------------")
        for b in bits:
            if i == 0:
                self.heaper.window.Log("FreeList[0x%x] = NA" % (i))
            else:
                self.heaper.window.Log("FreeList[0x%x] = %d" % (i,b))
            i+= 1

    # print methods
    def print_heapcache_bitmap(self):
        bit_list = self.set_heapcache_bitmap()
        
        for k,v in bit_list.items():
            self.heaper.window.Log("bucket[0x%03x] = %d" % (k,v))   

    def print_heapcache_struc(self):
        self.heaper.window.Log("-" * 45)
        self.heaper.window.Log("HeapCache structure @ 0x%08x (unofficial)" % (self.heaper.pheap.HeapCache.addr),self.heaper.pheap.HeapCache.addr)
        self.heaper.window.Log("-" * 45)
        self.heaper.window.Log("")
        self.heaper.window.Log("+0x000 NumBuckets            : 0x%08x" % self.heaper.pheap.HeapCache.NumBuckets, self.heaper.pheap.HeapCache.NumBuckets)                       
        self.heaper.window.Log("+0x004 CommittedSize         : 0x%08x" % self.heaper.pheap.HeapCache.CommittedSize, self.heaper.pheap.HeapCache.CommittedSize)
        self.heaper.window.Log("+0x008 CounterFrequency      : 0x%08x" % self.heaper.pheap.HeapCache.CounterFrequency, self.heaper.pheap.HeapCache.CounterFrequency)
        self.heaper.window.Log("+0x010 AverageAllocTime      : 0x%08x" % self.heaper.pheap.HeapCache.AverageAllocTime, self.heaper.pheap.HeapCache.AverageAllocTime)
        self.heaper.window.Log("+0x018 AverageFreeTime       : 0x%08x" % self.heaper.pheap.HeapCache.AverageFreeTime, self.heaper.pheap.HeapCache.AverageFreeTime)
        self.heaper.window.Log("+0x020 SampleCounter         : 0x%08x" % self.heaper.pheap.HeapCache.SampleCounter, self.heaper.pheap.HeapCache.SampleCounter)
        self.heaper.window.Log("+0x024 field_24              : 0x%08x" % self.heaper.pheap.HeapCache.field_24, self.heaper.pheap.HeapCache.field_24)
        self.heaper.window.Log("+0x028 AllocTimeRunningTotal : 0x%08x" % self.heaper.pheap.HeapCache.AllocTimeRunningTotal, self.heaper.pheap.HeapCache.AllocTimeRunningTotal)
        self.heaper.window.Log("+0x030 FreeTimeRunningTotal  : 0x%08x" % self.heaper.pheap.HeapCache.FreeTimeRunningTotal, self.heaper.pheap.HeapCache.FreeTimeRunningTotal)
        self.heaper.window.Log("+0x038 AllocTimeCount        : 0x%08x" % self.heaper.pheap.HeapCache.AllocTimeCount, self.heaper.pheap.HeapCache.AllocTimeCount)
        self.heaper.window.Log("+0x03c FreeTimeCount         : 0x%08x" % self.heaper.pheap.HeapCache.FreeTimeCount, self.heaper.pheap.HeapCache.FreeTimeCount)
        self.heaper.window.Log("+0x040 Depth                 : 0x%08x" % self.heaper.pheap.HeapCache.Depth, self.heaper.pheap.HeapCache.Depth)
        self.heaper.window.Log("+0x044 HighDepth             : 0x%08x" % self.heaper.pheap.HeapCache.HighDepth, self.heaper.pheap.HeapCache.HighDepth)
        self.heaper.window.Log("+0x048 LowDepth              : 0x%08x" % self.heaper.pheap.HeapCache.LowDepth, self.heaper.pheap.HeapCache.LowDepth)
        self.heaper.window.Log("+0x04c Sequence              : 0x%08x" % self.heaper.pheap.HeapCache.Sequence, self.heaper.pheap.HeapCache.Sequence)
        self.heaper.window.Log("+0x050 ExtendCount           : 0x%08x" % self.heaper.pheap.HeapCache.ExtendCount, self.heaper.pheap.HeapCache.ExtendCount)
        self.heaper.window.Log("+0x054 CreateUCRCount        : 0x%08x" % self.heaper.pheap.HeapCache.CreateUCRCount, self.heaper.pheap.HeapCache.CreateUCRCount)
        self.heaper.window.Log("+0x058 LargestHighDepth      : 0x%08x" % self.heaper.pheap.HeapCache.LargestHighDepth, self.heaper.pheap.HeapCache.LargestHighDepth)
        self.heaper.window.Log("+0x05c HighLowDifference     : 0x%08x" % self.heaper.pheap.HeapCache.HighLowDifference, self.heaper.pheap.HeapCache.HighLowDifference)
        self.heaper.window.Log("+0x060 pBitmap               : 0x00%14x" % self.heaper.pheap.HeapCache.pBitmap, self.heaper.pheap.HeapCache.pBitmap)

    # print the heap cache
    def print_heapcache(self):
        for a in range(0, self.heaper.pheap.HeapCache.NumBuckets):
            if self.heaper.pheap.HeapCache.Buckets[a]:

                # assumed size
                size = (a+0x80-0x1) * self.heaper.block
                try:
                    flink = self.heaper.imm.readMemory(self.heaper.pheap.HeapCache.Buckets[a]+0x8,0x4)
                    (flink) = struct.unpack("L", flink)
                except:
                    flink = None
                try:
                    blink = self.heaper.imm.readMemory(self.heaper.pheap.HeapCache.Buckets[a]+0xc,0x4)
                    (blink) = struct.unpack("L", blink)
                except:
                    blink = None
                if flink != None and blink != None:
                    self.heaper.window.Log("HEAP_CACHE[0x%03x] = 0x%08x (flink: 0x%08x, blink: 0x%08x, size: 0x%x - %d)" % 
                    (a+0x80, self.heaper.pheap.HeapCache.Buckets[a], flink[0], blink[0], size, size), address = self.heaper.pheap.HeapCache.Buckets[a])
                else:

                    # tell the user something is funky with flink/blink
                    self.heaper.window.Log("HEAP_CACHE[0x%03x] = 0x%08x (size: 0x%x - %d)" % 
                    (a+0x80, self.heaper.pheap.HeapCache.Buckets[a], size, size), address = self.heaper.pheap.HeapCache.Buckets[a])                    

    def print_freelist(self, verbose=False):
        """
        sets the following datastruture into self.feelist_chunks:
        
            Entry:
                0. bin size
                1. freelist[n] address
                2. blink
                3. flink
                
                Chunks:
                    0. chunk number (in order)
                    1. chunk address
                    2. chunks blink address
                    3. chunks flink address
                    4. chunks bin size
                    5. chunk size (user size)
                    6. chunk cookie
                    7. description upon validation
                    8. boolean on passing validation (True/False)
        """
        if not verbose:
            for data in self.freelist_chunks.itervalues():
                i = 0
                for chunk in data:

                    # must be the list entry
                    if i == 0:
                        list_entry = chunk
                        if list_entry[0] == 0x00:
                            self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: > 1016]" % 
                                                   (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4)), list_entry[1])                        
                        elif list_entry[0] > 0x00:
                            self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: 0x%02x * 0x8 = 0x%04x]" % 
                                                   (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4), list_entry[0], (list_entry[0] * 0x8)), list_entry[1]) 
                        self.heaper.window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x].flink : 0x%08x]" % 
                                               (list_entry[0], list_entry[2], list_entry[0], list_entry[3]), list_entry[1]) 

                    # must be chunks for the list entry
                    # we must check for error based chunks here
                    elif i > 0:
                        for chunk_data in chunk:
                            if chunk_data[8]:
                                self.heaper.window.Log("")
                                self.heaper.window.Log("        "+"*" * 86)
                                self.heaper.window.Log("        * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x] <= %s overwrite!" % 
                                (chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3], chunk_data[7]), chunk_data[1])
                                self.heaper.window.Log("        "+"*" * 86)
                                self.heaper.window.Log("                [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x <= %s overwrite!" % 
                                (chunk_data[0], chunk_data[4], (chunk_data[4] * 0x8), (chunk_data[4] * 0x8), chunk_data[5], chunk_data[7]), chunk_data[1])
                                self.heaper.window.Log("        "+"*" * 86)             
                                self.heaper.window.Log("")
                            elif not chunk_data[8]:
                                self.heaper.window.Log("        * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x]" % 
                                (chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]), chunk_data[1])
                                self.heaper.window.Log("                [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x" % 
                                (chunk_data[0], chunk_data[4], (chunk_data[4] * 0x8), (chunk_data[4] * 0x8), chunk_data[5]), chunk_data[1])
                    i += 1
        elif verbose:
            for chunk in range(0, 0x80):
                if self.freelist_chunks.has_key(chunk):
                    data = self.freelist_chunks[chunk]
                    i = 0
                    for chunk in data:

                        # must be the list entry
                        if i == 0:
                            list_entry = chunk
                            if list_entry[0] == 0x00:
                                self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: > 1016]" % 
                                                           (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4)), list_entry[1])                        
                            elif list_entry[0] > 0x00:
                                self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: 0x%02x * 0x8 = 0x%04x]" % 
                                                           (list_entry[0], list_entry[1], (list_entry[1]+0x4), (list_entry[1]-0x4), list_entry[0], (list_entry[0] * 0x8)), list_entry[1]) 
                            self.heaper.window.Log("        [FreeList[0x%02x].blink : 0x%08x | FreeLists[0x%02x].flink : 0x%08x]" % 
                                                    (list_entry[0], list_entry[2], list_entry[0], list_entry[3]), list_entry[1]) 

                        # must be chunks for the list entry
                        elif i > 0:
                            for chunk_data in chunk:
                                self.heaper.window.Log("        * Chunk [%d]: 0x%08x  [blink : 0x%08x  | flink : 0x%08x]" % 
                                                        (chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]), chunk_data[1])
                                self.heaper.window.Log("                [%d]: size: 0x%04x | calculated size: %d (0x%04x) - cookie: 0x%02x" % 
                                                        (chunk_data[0], chunk_data[4], (chunk_data[4] * 0x8), (chunk_data[4] * 0x8), chunk_data[5]), chunk_data[1])
                        i += 1 
                elif not self.freelist_chunks.has_key(chunk):
                    freelist_offset = self.heaper.heap + 0x178
                    entry_offset    = chunk * 0x8
                    freelist_entry = freelist_offset + entry_offset
                    if chunk == 0:
                        self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: > 1016]" % 
                        (chunk, freelist_entry, (freelist_entry+0x4), (freelist_entry-0x4)))
                    elif chunk > 0:
                        self.heaper.window.Log("FreeList[0x%02x] - 0x%08x| +0x4 = 0x%08x | -0x4 = 0x%08x [expected size: 0x%02x * 0x8 = 0x%04x]" % 
                        (chunk, freelist_entry, (freelist_entry+0x4), (freelist_entry-0x4), chunk, (chunk*0x8)))

    def generate_freelist_graph(self, verbose=False):
        """
        Generates the Freelist graph using pydot. It analyses the self.freelist_chunks
        datastructure and generates the graph according to which chunks exist and their integrity

        @return: the file name/path of the created graph
        """
        freelistgraph = pydot.Dot(graph_type='digraph')
        chunk_dict          = {}
        chunk_nodes         = []
        output_folder = self.heaper.imm.getKnowledge("config_workingdir")
        if output_folder[:-1] != "/" or output_folder[-1] != "\\":
            output_folder += "\\"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        self.heaper.window.Log("")
        if verbose:
            self.heaper.window.Log("(+) Generating a verbose Freelist graph...")
        elif not verbose:
            self.heaper.window.Log("(+) Generating a Freelist graph...")
        self.heaper.window.Log("(+) Output location will be: %s" % (output_folder+self.filename + ".png"))
        for bin_index in range(0, 0x80):
            chunk_nodes         = []
            freelist_node  = pydot.Node("Freelist[0x%02x]" % bin_index, style="filled", shape="rectangle", fillcolor="#66FF66")
            if self.freelist_chunks.has_key(bin_index):
                data = self.freelist_chunks[bin_index]
                i = 0
                for chunk in data:

                    # must be chunks for the list entry
                    # we check for error based chunks here
                    if i > 0:
                        for chunk_data in chunk:
                            chunk_label = ("chunk (%d) 0x%08x\nBlink 0x%08x\nFlink 0x%08x" % 
                            (chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]))
                            if chunk_data[8]:
                                chunk_nodes.append(pydot.Node(chunk_label+"\n%s overwrite" % chunk_data[7], style="filled", shape="rectangle", label=chunk_label+"\n%s overwrite" % chunk_data[7], fillcolor="red"))
                            elif not chunk_data[8]:
                                chunk_nodes.append(pydot.Node(chunk_label, style="filled", shape="rectangle", label=chunk_label, fillcolor="#3366ff" ))
                    i += 1

            # build the datastructure
            chunk_dict[bin_index] = [freelist_node, chunk_nodes]

        # write the graph      
        for listentry_node, chunk_node in chunk_dict.iteritems():

            # if verbose mode, link all the bins
            if verbose:
                freelistgraph.add_node(chunk_node[0])
                try:
                    freelistgraph.add_edge(pydot.Edge(chunk_dict[listentry_node][0], chunk_dict[listentry_node+1][0]) )

                # i know this is bad code, but deal with it.
                except:
                    pass
            if len(chunk_node[1]) > 0:

                # we dont care about linking the bin entries here
                if not verbose:
                    freelistgraph.add_node(chunk_node[0])

                # loop through the chunk nodes
                node_list = chunk_node[1]
                for node in node_list:
                    freelistgraph.add_node(node)

                    # if its the first chunk, link it to the Lookaside list entry
                    if node_list.index(node) == 0:
                        freelistgraph.add_edge(pydot.Edge(chunk_node[0],node))                    
                    if node_list.index(node) < (len(node_list)-1):
                        index = node_list.index(node)+1

                        # possible exploitation..
                        if re.search("flink corruption", node.get_name().strip('"')):
                            freelistgraph.add_edge(pydot.Edge( node, node_list[index], label=" chunk on the lookaside\noverwrite!" ))
                        else:
                            freelistgraph.add_edge(pydot.Edge( node, node_list[index] ))

        # save the output
        freelistgraph.write_png(output_folder+self.filename + ".png")

        # return the filename
        return output_folder+self.filename + ".png"

# The main entry       
def main(args):
    imm = immlib.Debugger()

    # custom window
    if not opennewwindow:            
        window = imm.getKnowledge(windowtag)
        if window and not window.isValidHandle():
            imm.forgetKnowledge(windowtag)
            del window
            window = None
        if not window:
            window = imm.createTable("Heaper - by mr_me", ["Address", "Information"])
            imm.addKnowledge(windowtag, window, force_add = 1)
    heaper = Heaper(imm, window)    
    heaper.run()
    if not args:
        heaper.banner()
        return heaper.usage()
    heaper.banner()
    if len(args) > 1:
        heaper.set_usage()

        # show the user how to do things
        # ==============================
        if args[0].lower().strip() == "help":
            if args[1].lower().strip() in heaper.available_commands:
                usage_text = heaper.cmds[args[1].lower().strip()].usage.split("\n")
                for line in usage_text:
                    heaper.window.Log(line)
                return "(+) Good luck!"
            elif args[1].lower().strip() not in heaper.available_commands:
                heaper.usage()
                return "(-) Invalid command specified!"

    # commands that only require one argument
    # =======================================
    if len(args) == 1:
        if args[0].lower().strip() in heaper.available_commands:
            if args[0].lower().strip() == "dumpheaps" or args[0].lower().strip() == "dh":
                return heaper.print_heaps()
            elif args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
                    return heaper.print_peb_struct()
            elif args[0].lower().strip() == "dumpteb" or args[0].lower().strip() == "dt":
                return heaper.print_teb()
            elif args[0].lower().strip() == "help" or args[0].lower().strip() == "-h":
                return heaper.usage()

            # update
            # ======
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
                if heaper.generate_githash("".join(latest_build2)) != heaper.generate_githash("".join(current_build2)):
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
                heaper.window.Log("")
                heaper.window.Log("(-) Invalid number of arguments!")
                heaper.window.Log("(!) Try '!heaper help %s'" % args[0].lower().strip())
                heaper.window.Log("-" * 32)
                return "(-) Invalid number of arguments"
        else:
            heaper.usage()
            return "(-) Invalid command specified!"

    # the main entry into the arguments
    # =================================
    elif len(args) >= 2:

        # dump the process environment block
        # ==================================
        if args[0].lower().strip() == "dumppeb" or args[0].lower().strip() == "dp":
            if args[1] == "-m":
                heaper.print_peb_struct(True)
            return "(!) PEB dumped!"
        elif args[0].lower().strip() == "patch" or args[0].lower().strip() == "p":
            if args[1].lower().strip() == "peb":
                heaper.window.Log("")
                if heaper.patch_peb():
                    return "(+) Patching complete!"
                else:
                    return "(-) This processes PEB has already been patched!"

        # find writable pointers to target
        # ================================
        elif args[0].lower().strip() == "findwritablepointers" or args[0].lower().strip() == "findwptrs":
            heaper.window.Log("")
            if "-m" in args and (args.index("-m") < (len(args)-1)):

                # this will take alot of time to execute...
                if args[args.index("-m")+1].lower() == "all":
                    heaper.window.Log("(+) Dumping all calls/jmps that use")
                    heaper.window.Log("    writable and static pointers from all modules")
                    heaper.find_hardcoded_pointers()
                else:
                    heaper.window.Log("(+) Dumping all calls/jmps that use")
                    heaper.window.Log("    writable and static pointers from %s" % args[args.index("-m")+1].lower())
                    heaper.find_hardcoded_pointers(args[args.index("-m")+1].lower())
                heaper.window.Log("=" * 40)
            elif "-m" not in args:
                usage_text = heaper.cmds["findwptrs"].usage.split("\n")
                for line in usage_text:
                    heaper.window.Log(line)
                return "(!) Please include the -m <module> flag"
            return "(+) Dumped all pointers!"

        # view and set the configuration
        # ==============================
        elif args[0].lower().strip() == "config" or args[0].lower().strip() == "cnf":
            heaper.window.Log("")
            heaper.config_settings.append("")
            if "-d" in args:
                i = 0
                for setting in heaper.get_config():
                    i += 1
                    heaper.window.Log("%d. %s = \"%s\"" % (i, setting[7:], heaper.imm.getKnowledge(setting)))
                heaper.window.Log("")
                return "(+) Displaying config"
            elif "-s" in args:
                try:
                    setting = args[args.index("-s")+1]
                except:
                    heaper.window.Log("(!) No value to set!")
                    heaper.window.Log("")
                    return "(!) No value to set!"
                if setting not in heaper.config_settings:
                    heaper.window.Log("(!) setting not avaliable!")
                    heaper.window.Log("")
                    return "(!) Setting not avaliable!"
                elif setting in heaper.config_settings:
                    try:
                        setting_value   = args[args.index("-s")+2] 
                    except:
                        heaper.window.Log("(!) No value to set!")
                        heaper.window.Log("")
                        return "(!) No value to set!"
                    setting = "config_" + setting
                    heaper.imm.forgetKnowledge(setting)
                    heaper.imm.addKnowledge(setting, setting_value)
                    i = 0
                    for setting in heaper.get_config():
                        i += 1
                        heaper.window.Log("%d. %s = \"%s\"" % (i, setting[7:], heaper.imm.getKnowledge(setting)))
                    heaper.window.Log("")
                return "(+) Finsihed setting the config"

        # exploit heuristics for a given heap
        # ===================================
        elif args[0].lower().strip() == "exploit" or args[0].lower().strip() == "exp":
            all_heaps = args[1].lower().strip().lower()
            if all_heaps == "all":
                heaper.window.Log("")
                if heaper.os >= 6.0:
                    if "-b" in args and "-f" not in args:

                        # for each heap, we update the object instance
                        for heap_handle in imm.getHeapsAddress():
                            heaper.heap     = heap_handle
                            heaper.pheap    = imm.getHeap( heaper.heap )
                            backend         = Listhintfreelist(heaper)
                            backend.run() 
                            backend.set_listhintfreeList_chunks() 
                            backend.perform_heuristics()
                    elif "-f" in args and "-b" not in args:
                        for heap_handle in imm.getHeapsAddress():
                            heaper.heap     = heap_handle
                            heaper.pheap    = imm.getHeap( heaper.heap )
                            frontend        = Lfh(heaper)
                            frontend.run()
                            frontend.set_chunks()                    
                            frontend.perform_heuristics()
                return "(!) Scanned all %d heap(s)" % len(imm.getHeapsAddress())
            elif not int(all_heaps, 16):
                heaper.window.Log("")
                heaper.window.Log("(!) invalid option '%s': try !heaper help exploit" % all_heaps)
                heaper.window.Log("")
                return "(!) invalid option: try !heaper help exploit"

        # dump function pointers
        # ======================
        elif args[0].lower().strip() == "dumpfunctionpointers" or args[0].lower().strip() == "dfp":

            # some checks
            patch = False
            restore = False
            if "-p" in args and "-r" not in args:
                patch = True
                try:
                    patch_val = args[args.index("-p")+1].lower().strip()
                except:
                    return "(-) You must provide a argument to -p <address/all>"
                return heaper.analyse_function_pointers(args, window, imm, True, patch_val, False, False)
            elif "-r" in args and "-p" not in args:
                restore = True
                try:
                    restore_val = args[args.index("-r")+1].lower().strip()
                except:
                    return "(-) You must provide a argument to -r <address/all>"
                return heaper.analyse_function_pointers(args, False, False, True, restore_val)
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
                return heaper.analyse_function_pointers(args, False, False, False, False)

        # commands that require use of a heap
        # ===================================
        if (args[0].lower().strip() in heaper.available_commands and args[0].lower().rstrip() not in ["help","-h"]):
            try:
                heap = args[1].lower().strip()
                heaper.heap = int( heap,16 )
                heaper.pheap = imm.getHeap( heaper.heap )
            except:
                for heap_handle in imm.getHeapsAddress():
                    try:
                        int(args[1].lower().strip(),16)
                    except:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Incorrect value for the heap address")
                        heaper.window.Log("")
                        return "(-) Incorrect value for the heap address"
                    if heap_handle == int(args[1].lower().strip(),16):
                        heaper.window.Log("") 
                        heaper.window.Log("(!) The heap address supplied is valid, but the heap has a chunk overwrite", address = heap_handle, focus = 1)
                        return "(!) Cannot analyse the heap if there is a chunk overwrite"  
                heaper.window.Log("")
                heaper.window.Log("(-) Invalid heap address or cannot read address!")
                return "(-) Invalid heap address or cannot read address!"
            if heaper.pheap.address:
                if heaper.os < 6.0:
                    frontend   = Lookaside(imm, heaper)
                    backend    = Freelist(heaper)
                elif heaper.os >= 6.0:
                    frontend    = Lfh(heaper)
                    backend     = Listhintfreelist(heaper)
            else:
                heaper.window.Log("")
                heaper.window.Log("(-) Incorrect value for the heap address")
                heaper.window.Log("")
                return "(-) Incorrect value for the heap address"
            frontend.run()
            backend.run()

            # check if we are graphing, if so, do we have a custom filename?
            if "-g" in args:
                if not pydot:
                    heaper.window.Log("(-) Please ensure pydot, pyparser and graphviz are installed")
                    heaper.window.Log("    when using the graphing functionaility.")
                    return "(-) Please ensure pydot, pyparser and graphviz are installed!"
                frontend.graphic_structure  = True
                backend.graphic_structure   = True
                if "-o" in args:
                    try:
                        frontend.customfilename = True
                        backend.customfilename  = True
                        frontend.filename = args[args.index("-o")+1]
                        backend.filename = args[args.index("-o")+1]
                    except:
                        return "(-) no filename specified"
            else:
                frontend.graphic_structure  = False
                backend.graphic_structure   = False              

            # analyse a heap structure
            # ========================
            if args[0].lower().strip() == "analyseheap" or args[0].lower().strip() == "ah":
                heaper.print_heap_struct()
                heaper.window.Log("-" * 50)

            # analyse the frontend
            # ====================
            elif args[0].lower().strip() == "analysefrontend" or args[0].lower().strip() == "af":
                if heaper.os < 6.0:
                    if "-l" in args:
                        if frontend.set_lookaside_chunks():
                            heaper.window.Log("-" * 57)
                            heaper.window.Log("Lookaside List structure @ 0x%08x" % frontend.Lookaside)
                            heaper.window.Log("-" * 57)
                        else:
                            heaper.window.Log("(-) Lookaside List not activeated for heap 0x%08x" % heaper.heap)
                            return "(-) Lookaside List not activeated for heap 0x%08x" % heaper.heap
                        if frontend.FrontEndHeapType < 0x2:
                            if "-v" in args:
                                frontend.print_lookaside(True)
                                if frontend.graphic_structure:
                                    heaper.window.Log("")
                                    heaper.window.Log("(+) Generated graph: %s" % frontend.generate_lookaside_graph(True))
                                    heaper.window.Log("")
                            elif "-v" not in args:
                                frontend.print_lookaside()
                                if frontend.graphic_structure:
                                    heaper.window.Log("")
                                    heaper.window.Log("(+) Generated graph: %s" % frontend.generate_lookaside_graph())
                                    heaper.window.Log("")
                            return "(+) Lookaside analysis complete"
                        else:
                            imm.getDebuggedName()
                            heaper.window.Log("(!) The %s process is running under NT 5.X and using the LFH" % imm.getDebuggedName())
                            heaper.window.Log("(!) If you reach this, email mr_me to fix the issue (he can be lazy)")
                            heaper.window.Log("=" * 40)
                            return "(!) The %s process is running under NT 5.X and using the LFH" % imm.getDebuggedName()
                    elif "-l" not in args:
                        usageText = heaper.cmds["analysefrontend"].usage.split("\n")
                        for line in usageText:
                            window.Log(line)
                        window.Log("=" * 40)
                        return "(!) Please specify -l"
                elif heaper.os >= 6.0:
                    if heaper.pheap.FrontEndHeapType == 0x2:
                        switch = {}
                        switch["bucket_flag"] = False
                        switch["UserBlockCache_flag"] = False
                        switch["UserBlocks_flag"] = False
                        switch["Bin_size"] = False
                        if "-s" in args:
                            try:
                                switch["Bin_size"] = int(args[args.index("-s")+1],16)
                            except:
                                heaper.window.Log("")
                                heaper.window.Log("(-) This is not a size value!")
                                window.Log("")
                                return "(-) This is not a size value!"
                            if switch["Bin_size"] < 0x0 and switch["Bin_size"] > 0x7ff:
                                heaper.window.Log("")
                                heaper.window.Log("(-) This size is not within the UserBlocks range!")
                                window.Log("")
                                return "(-) This size is not within the UserBlocks range!"
                            else:
                                frontend.set_chunks(switch["Bin_size"])
                        else:
                            frontend.set_chunks()           
                        if "-b" in args:
                            switch["bucket_flag"] = True
                        if "-c" in args:
                            switch["UserBlockCache_flag"] = True
                        if "-u" in args:
                            switch["UserBlocks_flag"] = True
                        if "-b" not in args and "-c" not in args and "-u" not in args:
                            usageText = heaper.cmds["analysefrontend"].usage.split("\n")
                            for line in usageText:
                                window.Log(line)
                            window.Log("=" * 40)
                            return "(!) Please specify a correct option"
                        window.Log("")
                        window.Log("-" * 28)
                        window.Log("LFH information @ 0x%08x" % (heaper.pheap.LFH.address),heaper.pheap.LFH.address)
                        window.Log("-" * 28)
                        if frontend.graphic_structure:
                            if "-o" in args:
                                try:
                                    frontend.filename = args[args.index("-o")+1]
                                except:
                                    heaper.window.Log("")
                                    heaper.window.Log("(!) No filename provided!")
                                    heaper.window.Log("")
                                    return "(!) No filename provided!"
                        if switch["UserBlocks_flag"] and "-s" not in args:
                            frontend.print_chunks()
                            if frontend.graphic_structure:
                                frontend.generate_userblocks_graph()
                        elif switch["UserBlocks_flag"] and "-s" in args:
                            frontend.print_chunks(switch["Bin_size"])
                            if frontend.graphic_structure:
                                frontend.generate_userblocks_graph(switch["Bin_size"])
                        elif switch["bucket_flag"] and "-s" not in args:
                            frontend.print_buckets()
                        elif switch["bucket_flag"] and "-s" in args:
                            frontend.print_buckets(switch["Bin_size"])
                        elif switch["UserBlockCache_flag"]:
                            frontend.print_block_cache()
                    elif heaper.pheap.FrontEndHeapType == 0x1:
                        window.Log("")
                        window.Log("(!) You are running windows NT 6.x yet the Lookaside List is being used?")
                        window.Log("(!) Submit this test case to @net__ninja for him to fix it...")
                        window.Log("")
                        return "(!) You are running windows 7 / Server 2008 yet the Lookaside list is being used?"

            # analyse the backend
            # ===================
            elif args[0].lower().strip() == "analysebackend" or args[0].lower().strip() == "ab":
                if heaper.os < 6.0:
                    if heaper.pheap.HeapCache:
                        heaper.window.Log("-" * 62)
                        heaper.window.Log("FreeList structure @ 0x%08x (HeapCache active)" % (heaper.heap+0x178))
                        heaper.window.Log("- use '!heaper ahc 0x%08x' to dump the HeapCache separately" % (heaper.heap+0x178))
                        heaper.window.Log("-" * 62)
                    else:
                        window.Log("-" * 52)
                        window.Log("FreeList structure @ 0x%08x (HeapCache inactive)" % (heaper.heap+0x178))
                        window.Log("-" * 52)
                    backend.set_freelist_chunks()
                    if "-f" in args and "-h" not in args:
                        if "-v" in args:
                            backend.print_freelist(True)
                            if "-g" in args:
                                backend.generate_freelist_graph(True)
                        else:
                            backend.print_freelist()
                            if "-g" in args:
                                backend.generate_freelist_graph()
                        heaper.window.Log("")
                        heaper.window.Log("(+) Dumped Freelist[n] for heap 0x%08x" % heaper.heap)
                        return ("(+) Dumped Freelist[n] for heap 0x%08x" % heaper.heap)
                    elif "-h" in args and "-f" not in args:
                        if heaper.pheap.HeapCache:
                            if "-v" in args:
                                backend.print_heapcache()
                                backend.print_heapcache_struc()
                            else:
                                backend.print_heapcache()
                            heaper.window.Log("")
                            heaper.window.Log("(+) Dumped the HeapCache (Freelist[0]) for heap 0x%08x" % heaper.heap)
                            return ("(+) Dumped the HeapCache (Freelist[0]) for heap 0x%08x" % heaper.heap)
                        elif not heaper.pheap.HeapCache:
                            heaper.window.Log("(!) HeapCache is not active for this heap!")
                            return "(!) HeapCache is not active for this heap!"
                    else:
                        usage_text = heaper.cmds["ab"].usage.split("\n")
                        for line in usage_text:
                            heaper.window.Log(line)
                        window.Log("=" * 40)
                        return "(!) Please specify either -f or -h"
                elif heaper.os >= 6.0:
                    if backend.set_listhintfreeList_chunks():
                        backend.print_listhintfreelist(args)
                        if backend.graphic_structure:
                            backend.generate_freelist_graph()

            # perform hueristics
            # ==================
            elif args[0].lower().strip() == "exploit" or args[0].lower().strip() == "exp":
                if heaper.os >= 6.0:    
                    backend.set_listhintfreeList_chunks()
                    frontend.set_chunks()
                elif heaper.os < 6.0:
                    backend.set_freelist_chunks()    
                    frontend.set_lookaside_chunks()        
                if "-f" in args:
                    frontend.perform_heuristics()
                elif "-b" in args:
                    backend.perform_heuristics()
                else:
                    usage_text = heaper.cmds["exp"].usage.split("\n")
                    for line in usage_text:
                        heaper.window.Log(line)
                    window.Log("=" * 40)          
                    return "(-) Please specify either -f (frontend) or -b (backend)"
                return "(!) vulnerability analysis complete"

            # analyse segments
            # ================
            elif args[0].lower().strip() == "analysesegments" or args[0].lower().strip() == "as":
                heaper.print_segment_structure()

            # analyse segment chunks
            # ======================
            elif args[0].lower().strip() == "analysechunks" or args[0].lower().strip() == "ac":
                show_detail = False
                if "-v" in args:
                    show_detail = True
                if "-f" in args and (args.index("-f") < (len(args)-1)):
                    if args[args.index("-f")+1] in ["free", "busy"]:
                        heaper.window.Log("-" * 62)
                        heaper.window.Log("Dumping chunks @ heap address: 0x%08x" % (heaper.heap))
                        heaper.window.Log("Analyzing %d segments" % len(heaper.pheap.Segments))
                        for segment in heaper.pheap.Segments:
                                window.Log("- 0x%08x" % segment.BaseAddress)
                        heaper.window.Log("-" * 62)
                        heaper.window.Log("Note: chunks on the lookaside will appear BUSY")
                        heaper.window.Log("~" * 46)
                        heaper.print_all_chunks(args[args.index("-f")+1], show_detail)
                    else:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Invalid chunk filter option! use free/busy only")
                        return "(-) Invalid chunk filter option! use free/busy only"
                elif "-f" not in args:
                    usage_text = heaper.cmds["ac"].usage.split("\n")
                    for line in usage_text:
                        heaper.window.Log(line)
                    window.Log("=" * 40)
                    return "(!) Missing the -f switch"
                else:
                    usage_text = heaper.cmds["ac"].usage.split("\n")
                    for line in usage_text:
                        heaper.window.Log(line)
                    window.Log("=" * 40)
                    return "(!) Missing argument for the -f switch"

            # analyse heap cache if it exists
            # ===============================
            elif args[0].lower().strip() == "analyseheapcache" or args[0].lower().strip() == "ahc":
                if heaper.os < 6.0:
                    if heaper.pheap.HeapCache:
                        backend.print_heapcache_struc()
                        window.Log("")
                        window.Log("HeapCache:")
                        window.Log("----------")
                        backend.print_heapcache()
                        window.Log("")
                        window.Log("HeapCache Bitmap:")
                        window.Log("-----------------")
                        backend.print_heapcache_bitmap()
                    else:
                        window.Log("")
                        window.Log("(!) The HeapCache is inactive for this heap!")
                        window.Log("(+) You can activate it by:")
                        window.Log("    1. Freeing 32 blocks into FreeList[0] simultaneously")
                        window.Log("    2. De-commiting 256 blocks")
                        return "(-) The HeapCache is inactive for this heap!"
                elif heaper.os >= 6.0:
                    heaper.window.Log("")
                    heaper.window.Log("(-) Freelist HeapCache not supported under Windows 7 / Server 2008")
                    heaper.window.Log("")
                    return "(-) HeapCache not supported under Windows 7 / Server 2008"

            # analyse FreelistInUse
            # =====================
            elif args[0].lower().strip() == "freelistinuse" or args[0].lower().strip() == "fliu":
                heaper.window.Log("")
                if heaper.os < 6.0:
                    if len(args) > 2:
                        if args[2] == "-p":
                            window.Log("")
                            if args[3] and int(args[3],16) in range(0x00,0x80):
                                backend.set_freelistinuse_bitmap(int(args[3],16))
                                window.Log("(+) Patched FreeList[%x]'s FreeListInUse entry!" % int(args[3],16))
                                window.Log("(+) Now run: '!heaper fliu 0x%08x' to see the changes" % heaper.heap)
                            else:
                                window.Log("(-) Failed to patch FreeListInUse for heap 0x%08x" % heaper.heap)
                    else:
                        window.Log("(+) Dumping the FreeListInUse for heap 0x%08x" % heaper.heap)
                        backend.print_freelistinuse_bitmap()
                elif heaper.os >= 6.0:
                    heaper.window.Log("")
                    heaper.window.Log("(!) The FreeListInUse bitmap does not exist in Windows 7 / Server 2008")
                    heaper.window.Log("")
                    return "(!) The FreeListInUse bitmap does not exist in Windows 7 / Server 2008"

            # hard hook heap
            # ==============
            elif args[0].lower().strip() == "hardhook" or args[0].lower().strip() == "hh":
                chunkaddress    = None
                disable_hook    = False
                clear_hook      = False
                enable_hook     = False
                show_hook       = False
                pause_hook      = False
                continue_hook   = False
                window.Log("")
                if "-h" in args and "-u" not in args and "-s" not in args:
                    enable_hook     = True
                elif "-s" in args and "-u" not in args and "-h" not in args:
                    show_hook       = True
                elif "-u" in args and "-h" not in args and "-s" not in args:
                    disable_hook    = True

                # optional arguments
                if "-p" in args and "-c" not in args and "-d" not in args and "-C" not in args:
                    pause_hook      = True
                elif "-c" in args and "-p" not in args and "-d" not in args and "-C" not in args:
                    continue_hook   = True
                elif "-C" in args and "-c" not in args and "-d" not in args and "-p" not in args:
                    clear_hook = True
                elif "-d" in args and "-C" not in args and "-p" not in args and "-c" not in args:
                    clear_hook = True
                if "-a" in args and "-s" in args:
                    try:
                        chunkaddress = int(args[args.index("-a")+1], 16)
                    except:
                        return "(-) Invalid chunk address porvided"
                imm.pause()
                hook = Hook(imm, heaper)
                hook.rtlallocate = hook.set_func_ret(1000)
                name = "hardhookall"

                # We need to hook on the the ret point of RtlAllocateHeap so we can
                # get the result of the allocation.
                mod = imm.getModule("ntdll.dll")
                if not mod.isAnalysed():
                    imm.analyseCode( mod.getCodebase() )

                # hard hook here  
                if enable_hook:

                    # use our own for less logging
                    fast = STDCALLFastLogHook(imm)
                    heaper.window.Log("(+) Hard hooking RtlAllocateHeap 0x%08x" % hook.rtlallocate, hook.rtlallocate)
                    heaper.window.Log("(+) Hard hooking RtlFreeHeap 0x%08x" % hook.rtlfree, hook.rtlfree)
                    heaper.window.Log("=" * 43)
                    heaper.window.Log("")
                    fast.logFunction( hook.rtlfree, 3 )
                    fast.logFunction( hook.rtlallocate, 0)
                    fast.logBaseDisplacement( "EBP",    8)
                    fast.logBaseDisplacement( "EBP",  0xC)
                    fast.logBaseDisplacement( "EBP", 0x10)
                    fast.logRegister( "EAX" )
                    fast.Hook()
                    imm.addKnowledge(name, fast, force_add = 1)
                    imm.addKnowledge("FuncNames",  ( hook.rtlallocate, hook.rtlfree ) )
                elif show_hook:
                    fast = imm.getKnowledge(name)
                    double_free = False
                    rtlallocate, rtlfree = imm.getKnowledge("FuncNames")
                    ret = fast.getAllLog()
                    NDX = {rtlallocate: 3, rtlfree: 2}
                    if not fast:
                        heaper.window.Log("")
                        heaper.window.Log("(-) heap alloc/free is not hard hooked yet!")
                        heaper.window.Log("")
                        return "(-) heap alloc/free is not hard hooked yet!"

                    # first we set the chunks to find double frees..
                    # we want to known when they were allocated and freed
                    for a in ret:
                        extra = ""                           
                        if heaper.heap:
                            if heaper.heap == a[1][0]:
                                hook.set_chunks(a, rtlallocate)                           
                        else:
                            hook.set_chunks(a, rtlallocate)
                    for chunk in hook.managed_chunks:

                        # if the number of frees for a given chunk exceed the number of allocations
                        # we possibly have a double free
                        if hook.managed_chunks[chunk]["free"] > hook.managed_chunks[chunk]["alloc"]:
                            hook.double_free_chunks.append(chunk)

                    # now we print them
                    for a in ret:
                        extra = ""                           
                        if heaper.heap:
                            if heaper.heap == a[1][0]:
                                if chunkaddress:
                                    if a[1][ NDX[ a[0] ] ] == chunkaddress:
                                        extra = "<---- * FOUND *"
                                hook.showresults(a, rtlallocate, extra)        
                        else:
                            if chunkaddress:
                                if a[1][ NDX[ a[0] ] ] == chunkaddress:
                                    extra = "<---- * FOUND *"
                            hook.showresults(a, rtlallocate, extra)
                    for chunk in hook.managed_chunks:

                        # if the number of frees for a given chunk exceed the number of allocations
                        # we possibly have a double free
                        if hook.managed_chunks[chunk]["free"] > hook.managed_chunks[chunk]["alloc"]:
                            double_free = True
                            heaper.window.Log("*" * 74)
                            heaper.window.Log("(!) Warning - There is a potential double free with this chunk: 0x%08x" % chunk, chunk)
                            heaper.window.Log("*" * 74)
                    if double_free:
                        heaper.window.Log("")
                        if heaper.os < 6.0:
                            heaper.window.Log("(1) Double frees can be exploited by having 1 chunk in the Lookaside or FreeList")
                            heaper.window.Log("    and using the other chunk to overwrite its own flink/blink. From there, attacks")
                            heaper.window.Log("    such as FreeList[0] insert/relink/search is possible as with Lookaside chunk overwrites")
                        elif heaper.os >= 6.0:
                            heaper.window.Log("(1) An undocumented condition exists whereby if a chunk is freed and still used by the application thus,")
                            heaper.window.Log("    hopefully allowing an attacker to control its contents, then the attacker can overwrite the EntryOffset")
                            heaper.window.Log("    and perform an offset match attack or FreeEntryOffset attack against the adjacent chunk")
                            heaper.window.Log("")
                            heaper.window.Log("(2) Alternatively, if you can find a write primitive to modify a bit/byte at a arbitray location")
                            heaper.window.Log("    then you could sucessfully trigger the double free and perform an offset match attack by targeting")                           
                            heaper.window.Log("    the bit/byte control at _heap_entry + 0x7")                    
                    heaper.window.Log("=" * 0x2f)
                    heaper.window.Log("")     
                    heaper.window.Log("(+) Traced %d functions" % len(ret))     
                    heaper.window.Log("")                 
                    return "(+) Traced %d functions" % len(ret)
                elif disable_hook:
                    fast = imm.getKnowledge( name )
                    if not fast:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Hook not set")
                        heaper.window.Log("")
                        return "(-) Hook not set" 
                    fast.unHook()
                    imm.forgetKnowledge( name )     
                    heaper.window.Log("")     
                    heaper.window.Log("(+) Hook has been removed")     
                    heaper.window.Log("")                      
                    return "(+) Hook has been removed"
                elif clear_hook:
                    fast = imm.getKnowledge(name)
                    if not fast:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Hook not set")
                        heaper.window.Log("")
                        return "(-) Hook not set" 
                    fast.Clear()
                    heaper.window.Log("")     
                    heaper.window.Log("(+) Hook has been cleared")     
                    heaper.window.Log("")                      
                    return "(+) Hook has been cleared"              
                elif pause_hook:
                    fast = imm.getKnowledge(name)
                    if not fast:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Hook not set")
                        heaper.window.Log("")
                        return "(-) Hook not set" 
                    if not fast.Pause():
                        heaper.window.Log("")
                        heaper.window.Log("(-) Error: not been able to pause the hook")
                        heaper.window.Log("")
                        return "(-) Error: not been able to pause the hook"
                    imm.addKnowledge(name, fast, force_add = 1)
                    heaper.window.Log("")
                    heaper.window.Log("(+) Hook paused")
                    heaper.window.Log("")
                    return "(+) Hook paused"
                elif continue_hook:
                    fast = imm.getKnowledge(name)
                    if not fast:
                        heaper.window.Log("")
                        heaper.window.Log("(-) Hook not set")
                        heaper.window.Log("")
                        return "(-) Hook not set" 
                    if not fast.Continue():
                        heaper.window.Log("")
                        heaper.window.Log("(-) Error: not been able to continue the hook")
                        heaper.window.Log("")                        
                        return "(-) Error: not been able to continue the hook"
                    imm.addKnowledge(name, fast, force_add = 1)
                    heaper.window.Log("")
                    heaper.window.Log("(+) Continuing hook")
                    heaper.window.Log("")                    
                    return "(+) Continuing hook"                              

            # soft hook heap
            # ==============
            elif args[0].lower().strip() == "softhook" or args[0].lower().strip() == "sh":
                valid_functions = ["alloc", "free"]
                disable_hook    = False
                AllocFlag       = False
                FreeFlag        = False    
                window.Log("")
                for arg in args:
                    if arg == "-f" or arg == "-u":
                        if arg == "-u":
                            disable_hook = True
                        if args[args.index(arg)+1].lower().strip() in valid_functions:
                            if args[args.index(arg)+1].lower().strip() == "alloc":
                                AllocFlag = True
                            elif args[args.index(arg)+1].lower().strip() == "free":
                                FreeFlag = True
                hook = Hook(imm, heaper)
                mod = imm.getModule("ntdll.dll")
                if not mod.isAnalysed():
                    imm.analyseCode( mod.getCodebase() )

                # hard hook here  
                if AllocFlag:
                    hook.softhook_on_alloc(disable_hook)
                elif FreeFlag:
                    hook.softhook_on_free(disable_hook)