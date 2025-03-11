import os

import ida_auto
import ida_funcs
import ida_idp
import ida_undo

from IDASignatureManager.FunctionElement import FunctionElement


def disable_history():
    try:
        if "IDA_NO_HISTORY" in os.environ:
            value = os.environ["IDA_NO_HISTORY"]
            os.environ["IDA_NO_HISTORY"] = "1"
            return value
        else:
            os.environ["IDA_NO_HISTORY"] = "1"
            return None
    except:
        pass

def revert_history(value):
    try:
        if value is not None:
            if "IDA_NO_HISTORY" in os.environ:
                os.environ["IDA_NO_HISTORY"] = value
        else:
            os.environ.pop("IDA_NO_HISTORY")
    except:
        pass


def create_undo(label: str = "Initial state, auto analysis"):
    if ida_undo.create_undo_point("ida_feeds:", label):
        print(f"Successfully created an undo point...")
    else:
        print(f"Failed to created an undo point...")


def perform_undo():
    if ida_undo.perform_undo():
        print(f"Successfully reverted database changes...")
    else:
        print(f"Failed to revert database changes...")


def get_sig_index(sig_file_name: str):
    for index in range(0, ida_funcs.get_idasgn_qty()):
        fname, _, _ = ida_funcs.get_idasgn_desc_with_matches(index)
        if fname == sig_file_name:
            return index
    return -1

    
class SigHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.matched_funcs = dict()

    def idasgn_matched_ea(self, ea, name, lib_name):
        self.matched_funcs[ea] = {"imported_name": name, "exist_type": None}
        print(f"idasgn_matched_ea: 0x{ea:X}, {name}, {lib_name}".format(ea=ea, name=name, lib_name=lib_name))
        
def apply_sig_file(sig_file_name: str):
    if not os.path.isfile(sig_file_name):
        print(f"The specified value {sig_file_name} is not a valid file name")
        return

    root, extension = os.path.splitext(sig_file_name)
    if extension != ".sig":
        print(f"The specified value {sig_file_name} is not a valid sig file")
        return

    # Install hook on IDB to collect func_matches
    sig_hook = SigHooks()
    sig_hook.hook()

    # Start apply process and wait for it
    ida_funcs.plan_to_apply_idasgn(sig_file_name)
    idx = get_sig_index(sig_file_name)
    if idx < 0:
        return None

    iterations = 0
    while True:
        iterations += 1
        state = ida_funcs.calc_idasgn_state(idx)
        if state == ida_funcs.IDASGN_BADARG:
            break
        if state == ida_funcs.IDASGN_APPLIED:
            break
        if not ida_auto.auto_wait():
            break
        if iterations > 128:
            break

    matches = sig_hook.matched_funcs
    sig_hook.unhook()

    return matches

def get_matches(sig_file_name: str):
    try:
        hist = disable_history()
        create_undo()
        matches = apply_sig_file(sig_file_name)
        imported_matches = []
        for addr in matches:
            elem = FunctionElement.collect_info(addr)
            elem.name = matches[addr]["imported_name"]
            imported_matches.append(elem)
        perform_undo()
        revert_history(hist)
    except Exception as e:
        print(f"Failed to get matches for sig file: {sig_file_name}: {e}")
        return None
    sorted(imported_matches, key=lambda x: x.key)
    return imported_matches

    
    