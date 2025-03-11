import ida_kernwin
import ida_loader
import os

from IDASignatureManager.manager import IdaSignatureManager

import pydevd_pycharm
pydevd_pycharm.settrace('localhost', port=1337, stdoutToServer=True, stderrToServer=True, suspend=False)


ida_signature_manager = IdaSignatureManager()

sig_file = ida_kernwin.ask_file(False, "*.sig", "Please choose sig file")
if sig_file:
    ida_signature_manager.process_sig_file(sig_file)