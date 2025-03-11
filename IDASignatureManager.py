import ida_diskio
import ida_idaapi
import ida_kernwin
import ida_loader

from IDASignatureManager.manager import IdaSignatureManager
    

        
        

class IdaSignatureManagerPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Plugin for import signatures from sig files"
    help = ""
    wanted_name = "IdaSignatureManager"
    wanted_hotkey = ""
    
    def __init__(self):
        self.ida_signature_manager = None
    
    def init(self):
        self.ida_signature_manager = IdaSignatureManager()
        return ida_idaapi.PLUGIN_KEEP
    
    def run(self, *args):
        sig_file = ida_kernwin.ask_file(False, ida_loader.get_path(ida_loader.PATH_TYPE_IDB), None)
        if sig_file:
            self.ida_signature_manager.process_sig_file(sig_file)
    
    
    def term(self):
        pass