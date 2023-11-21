__version__ = '0.4'

import ida_idaapi

import autorenamer.command_dumpinfo
import autorenamer.command_importoffsets

class AutoRenamerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE

    comment = "Auto Renamer"
    wanted_name = 'Renamer'
    wanted_hotkey = ''
    help = 'https://github.com/mixaill/FakePDB'

    def init(self):
        autorenamer.command_dumpinfo.register_actions()
        autorenamer.command_importoffsets.register_actions()

        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return AutoRenamerPlugin()
