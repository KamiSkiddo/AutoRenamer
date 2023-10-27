import json

import ida_name
import ida_nalt
import idc

class OffsetsImporter:
    def __init__(self):
        pass

    def process_json(self, filepath):
        self.base = ida_nalt.get_imagebase()
        offsets = None
        with open(filepath, 'r') as f:
            offsets = json.load(f)
            for key, value in offsets.items():
                self.__import_name(key, value)

    def __import_name(self, name, addr):
        if name.startswith("@"):
            comment_addr = int(name.replace("@", ""), 16)
            idc.set_cmt(comment_addr, str(addr), False)
        elif name.startswith("#"):
            ref_addr = int(addr, 16)
            try:
                func_addr = int(idc.print_operand(ref_addr, 0).split("offset ")[-1][4:], 16)
                ida_name.set_name(func_addr + self.base, str(name).replace("#", ""))
            except ValueError:
                # idc.set_cmt(ref_addr, str(addr), False)
                pass
        else:
            name_addr = int(addr, 16)
            name = name.replace('<','(').replace('>',')')
            ida_name.set_name(name_addr + self.base, str(name))
