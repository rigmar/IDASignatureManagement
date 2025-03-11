import collections
import pickle
import sys

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_typeinf
import idc

# from ida_database_merger.Importer import DatabaseImporter
from IDASignatureManager.IDB_elements import IDB_element, ProcessedItem
# from IDASignatureManager.FunctionLocalVarsElement import FunctionLocalVarsElement
from IDASignatureManager.UI_base import BaseChooser, UI_BaseChooser
from IDASignatureManager.logger import logger_instance
from IDASignatureManager.utils import ParseTypeString, GetTypeString, get_typeinf, get_typestring_depends, serialize_tinfo


def check_guess_type(existed_elem, imported_elem):
    if (existed_elem.typeinf is None or existed_elem.typeinf[0] is None) and imported_elem.typeinf[0] is not None:
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tif, existed_elem.addr):
            existed_elem_guess_type = tif.dstr()
            if existed_elem_guess_type == imported_elem.typeinf[2]:
                existed_elem.typeinf = serialize_tinfo(tif)
        del tif

class FunctionElement(IDB_element):
    
    # local_vars: FunctionLocalVarsElement
    table_name = "FunctionElements"
    columns_info = [
        ["addr", "text"],
        ["name", "text"],
        ["typeinf", "text"],
        ["local_vars", "text"]
    ]
    
    def __init__(self, addr=None, name=None, typeinf=None, local_vars = None):
        super().__init__()
        self.addr = addr
        self.name = name
        self.typeinf = typeinf
        self.local_vars = local_vars

    @property
    def key(self):
        return self.addr
    
    @staticmethod
    def collect_info(addr,collect_locals = False):
        name = ida_funcs.get_func_name(addr)
        # type = ida_typeinf.idc_get_type_raw(addr)
        # print("Functions: Collect info for 0x%08X"%addr)
        # typeinf = (ParseTypeString(type[0]) if type else [], type[1] if type else None)
        # local_vars = None
        # if collect_locals:
        #     local_vars = FunctionLocalVarsElement.collect_info(addr)
        
        tif = ida_typeinf.tinfo_t()
        ida_hexrays.get_type(addr, tif, ida_hexrays.GUESSED_NONE)
        if tif.empty():
            typeinf = (None, None, "")
        else:
            type_string, fields, fldcmts = tif.serialize()
            typeinf = (type_string, fldcmts ,tif.dstr())
        return FunctionElement(addr,name,typeinf,None)
    
    def apply_info(self, apply_locals = False, apply_type = False):
        ida_name.set_name(self.addr, self.name, 0)
        #todo aply for types not ready. Need to rewrite
        if apply_type:
            ida_typeinf.apply_type(
                None,
                self.typeinf[0],
                self.typeinf[1],
                self.addr,
                ida_typeinf.TINFO_DEFINITE,
            )
        
        if apply_locals and self.local_vars:
            self.local_vars.apply_info()
            
    def to_dict(self):
        ser_dic = collections.OrderedDict()
        ser_dic["addr"] = self.addr
        ser_dic["name"] = self.name
        ser_dic["typeinf"] = pickle.dumps(self.typeinf)
        ser_dic["local_vars"] = pickle.dumps(self.local_vars)
        return ser_dic
    
    def from_dict(self,ser_dict):
        self.name = ser_dict["name"]
        self.addr = int(ser_dict["addr"])
        self.typeinf = pickle.loads(ser_dict["typeinf"])
        self.local_vars = pickle.loads(ser_dict["local_vars"])
        return self
    
    def is_empty(self):
        return (self.name is None or len(self.name)==0) and (self.typeinf is None or self.typeinf[0] is None)
    
    def name_is_empty(self):
        return self.name is None or len(self.name)==0 or self.name.startswith("sub_")
    
    def isEqual(self,obj):
        """

        :type obj: FunctionElement
        """
        if self.name == obj.name and self.addr == obj.addr and self.typeinf[2] == obj.typeinf[2]:
            return True
        return False

    @staticmethod
    def get_processed_item(existed_elem, imported_elem):
        """

        :type existed_elem: FunctionElement
        :type imported_elem: FunctionElement
        """
        check_guess_type(existed_elem, imported_elem)
        
        if not existed_elem.is_empty():
            if existed_elem.isEqual(imported_elem):
                ui_merged_type =  'same'
            elif existed_elem.typeinf[2] == imported_elem.typeinf[2] and existed_elem.name_is_empty():
                ui_merged_type = 'new'
            else:
                ui_merged_type = 'conflict'
        else:
            ui_merged_type = 'new'
        return ProcessedItem(existed_elem, imported_elem,imported_elem.get_dict_for_merge(imported_elem,existed_elem,ui_merged_type),ui_merged_type)
    
    @staticmethod
    def get_dict_for_merge(imported_obj, exist_obj, ui_merged_type):
        """

        :type ui_merged_type: str
        :type exist_obj: FunctionElement
        :type imported_obj: FunctionElement
        """
        merge_dict = collections.OrderedDict()
        merge_dict["Address"] = imported_obj.addr
        if exist_obj:
            merge_dict["Exist name"] = exist_obj.name
            merge_dict["Exist type"] = exist_obj.typeinf[2]
        else:
            merge_dict["Exist name"] = ""
            merge_dict["Exist type"] = ""
        merge_dict["Imported name"] = imported_obj.name
        merge_dict["Imported type"] = imported_obj.typeinf[2]
        merge_dict["Merge type"] = ui_merged_type
        return merge_dict

    @staticmethod
    def get_resolver(database_importer, processed_elements):
        return Resolver(database_importer, processed_elements)


class UI_ChooserFunctions(UI_BaseChooser):
    cols = [["Line", 1], ["Address", 3 | ida_kernwin.CHCOL_EA], ["Exist name", 20], ["Exist type", 20], ["Imported name", 20],
            ["Imported type", 20], ["Merge type", 1]]
    
    def __init__(self, resolver):
        self.view_details_cmd_id = None
        self.use_new_cmd_id = None
        self.use_exist_cmd_id = None
        super(UI_ChooserFunctions, self).__init__("Merge for Functions", UI_ChooserFunctions.cols, resolver)
    
    def add_item(self, item):
        self.items.append(["%05lu" % self.n, "0x%08X" % item[0], *item[1:]])
        self.n += 1

    def get_item_key(self, n):
        return int(self.items[n][1], 16)

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        self.add_commands()
        return True

    def do_select_line(self, n):
        item = self.items[n]
        try:
            jump_ea = int(item[1], 16)
            # Only jump for valid addresses
            if idc.is_mapped(jump_ea):
                ida_kernwin.jumpto(jump_ea)
        except:
            print("do_select_line", sys.exc_info()[1])

    def do_view_detail(self, n):
        f = Details_UI(self.items[n])
        r = f.Go()
        if r == 1:
            self.UseImportingElem(n)
        elif r == 0:
            self.HoldExistingElem(n)

    # def ApplyImportedInformationHandler(self,n):
    #     for num in self.selected_items:
    #         addr = int(self.items[num][1],16)
    #         # print(num, "0x%08X"%addr)
    #         self.resolver.processed_elements[addr].imported_elem.apply_info()
    #         self.resolver.processed_elements[addr].merged_type = "resolved"
    #         self.items[n][-1] = "resolved"
    #         self.Refresh()


class Resolver(object):
    # database_importer: DatabaseImporter
    
    def __init__(self, database_importer, processed_elements):
        self.database_importer = database_importer
        self.processed_elements = processed_elements
        self.ui_chooser = UI_ChooserFunctions(self)
    
    def start(self):
        lines = list(map(lambda x: list(self.processed_elements[x].merge_dict.values()), self.processed_elements))
        self.ui_chooser.add_items(lines)
        self.ui_chooser.show()
    
    def resolve_dependencies_and_apply(self, addr, resolve_types = False):
        if resolve_types:
            if self.processed_elements[addr].imported_elem.typeinf[0]:
                dependencies = get_typestring_depends(self.processed_elements[addr].imported_elem.typeinf[0])
                if len(dependencies) > 0:
                    if not self.database_importer.resolve_types_dependencies(dependencies):
                        logger_instance.error("Can't resolve type dependencies for element at 0x%08X. Some error or closed window for dependencies resolve" % addr)
                        ida_kernwin.warning("Can't resolve type dependencies for element at 0x%08X. Some error or closed window for dependencies resolve" % addr)
                        return False
        self.processed_elements[addr].imported_elem.apply_info()
        return True


class Details_UI(ida_kernwin.Form):
    
    def __init__(self, items_list):
        self.item_list = items_list
        
        self.cNameChooser = SpecPartDesc("Name", [["Exist name", 20], ["Imported name", 20], ["Merge type", 1]],
                                         [[items_list[2], items_list[4], Details_UI.get_merged_type(items_list[2], items_list[4])]])

        self.cTypeChooser = SpecPartDesc("Assigned type", [["Exist type", 20], ["Imported type", 20], ["Merge type", 1]],
                                         [[items_list[3], items_list[5], Details_UI.get_merged_type(items_list[3], items_list[5])]])
        
        super(Details_UI, self).__init__(r"""BUTTON YES Apply imported
BUTTON CANCEL Dismiss
BUTTON NO Hold existed
        Function merge details
        Element address: {cAddr}

        <Name:{cNameChooserControl}>
        <Assigned type:{cTypeChooserControl}>
        """, {
            'cAddr': ida_kernwin.Form.NumericLabel(int(items_list[1], 16), ida_kernwin.Form.FT_ADDR),
            'cNameChooserControl': ida_kernwin.Form.EmbeddedChooserControl(self.cNameChooser),
            'cTypeChooserControl': ida_kernwin.Form.EmbeddedChooserControl(self.cTypeChooser)
        })
    
    @staticmethod
    def get_merged_type(item1, item2):
        if item1 == item2:
            return "same"
        elif item1 == "":
            return "new"
        else:
            return "conflict"
    
    def Go(self):
        self.Compile()
        ok = self.Execute()
        return ok


class SpecPartDesc(ida_kernwin.Choose):
    
    def __init__(self, title, col_list, items_list, width=0, height=0, flags=0):
        super(SpecPartDesc, self).__init__(title, col_list, embedded=True, width=width, height=height, flags=flags)
        self.n = 0
        self.items = items_list
    
    def OnClsoe(self):
        pass
    
    def OnGetLine(self, n):
        return self.items[n]
    
    def OnGetSize(self):
        n = len(self.items)
        return n
    
    def OnGetLineAttr(self, n):
        item = self.items[n]
        merged_type = item[-1]
        color = 0xFFFFFF
        if merged_type == "same":
            color = 0x9AFF9A
        elif merged_type == "resolved":
            color = 0x20B030
        elif merged_type == "conflict":
            color = 0x5A5AFF
        elif merged_type == "new":
            color = 0x5AFFFF
        return [color, 0]