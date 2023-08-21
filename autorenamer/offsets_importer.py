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
        name_addr = int(addr, 16)
        if name.startswith("@"):
            idc.set_cmt(name_addr, str(name.replace("@", "")), False)
        else:
            name = name.replace('<','(').replace('>',')')
            ida_name.set_name(name_addr + self.base, str(name))
