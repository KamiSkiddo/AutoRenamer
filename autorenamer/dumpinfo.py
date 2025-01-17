from __future__ import print_function

import json
import sys

import ida_funcs
import ida_ida
import ida_nalt
import ida_name
from idc import *
import idaapi

class DumpInfo():
    def __init__(self):
        pass
    
    def try_get_comment(self, ea):
        cmt = GetCommentEx(ea, 0)
        if cmt is not None:
            return cmt
        return GetCommentEx(ea, 1)

    def dump_info(self, filepath):
        imgBase = ida_nalt.get_imagebase()

        output = {}
        
        # Vtables
        for i in range(0, ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            if ida_funcs.get_func(ea) is not None:
                continue
            n = ida_name.get_nlist_name(i)
            maxi = 2**32
            if n.startswith("vtable_"):
                output[n] = hex(ea - imgBase)
        
        segment = idaapi.get_segm_by_name(".data")
        if segment is not None:
            start = segment.start_ea
            end = segment.end_ea
            currentAddress = start
            while end >= currentAddress:
                comment = self.try_get_comment(currentAddress)
                blacklist = ["reference to RTTI's vftable", "type descriptor name", "internal runtime reference"]
                if (comment is not None) and (comment not in blacklist):
                    output["@" + hex(currentAddress - imgBase)] = comment 
                currentAddress += 8
        else:
            print(".data segments is null")
                       
        # Functions            
        start = ida_ida.cvar.inf.min_ea
        end   = ida_ida.cvar.inf.max_ea
        chunk = ida_funcs.get_fchunk(start)
        if not chunk:
            chunk = ida_funcs.get_next_fchunk(start)
        while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
            chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
        func = chunk
        while func and func.start_ea < end:
            start_ea = func.start_ea
            func_name = ida_funcs.get_func_name(start_ea)
            if not (("sub_" in func_name) or ("loc_" in func_name) or ("unknown_libname" in func_name)
                    or ("?" in func_name) or ("@" in func_name)):
                output[func_name] = hex(start_ea - imgBase)
            
            func = ida_funcs.get_next_func(start_ea)
                

        with open(filepath, "w") as f:
            json.dump(output, f, indent=4)