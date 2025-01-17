import os
import ida_kernwin
from .offsets_importer import OffsetsImporter

class __autorenamer_offsetsimport_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):

        importer = OffsetsImporter()

        print('FakePDB/import offsets:')
        
        f = ida_kernwin.ask_file(False, "*.json", "Select the file to load")
        if f and os.path.exists(f):
            importer.process_json(f)
            print('    * finished')
        else:
            print('    * canceled')
                
        print('')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'renamer_offsets_import',                # The action name. This acts like an ID and must be unique
        'Import offsets from .json',             # The action text.
        __autorenamer_offsetsimport_actionhandler(), # The action handler.
        'Ctrl+Shift+3',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/AutoRenamer/', 'renamer_offsets_import', ida_kernwin.SETMENU_APP)
