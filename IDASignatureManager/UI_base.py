import os
import sys
from datetime import datetime

import PyQt5
import ida_kernwin
import ida_nalt
import idc
import pydevd_pycharm
from ida_kernwin import Choose


class command_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, obj, cmd_id, num_args=2, enabled = True):
        self.obj = obj
        self.cmd_id = cmd_id
        self.num_args = num_args
        self.enabled = enabled
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        if self.num_args == 1:
            return self.obj.OnCommand(self.cmd_id)
        if len(self.obj.selected_items) == 0:
            sel = 0
        else:
            sel = self.obj.selected_items[0]
        return self.obj.OnCommand(sel, self.cmd_id)
    
    def update(self, ctx):
        if self.enabled:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

class PopUp_Populating_UIHook(ida_kernwin.UI_Hooks):
    
    def __init__(self, target):
        
        self.target = target
        super(PopUp_Populating_UIHook, self).__init__()
        
    def finish_populating_widget_popup(self, *args):
        # pydevd_pycharm.settrace('localhost', port=1337, stdoutToServer=True, stderrToServer=True, suspend=True)
        # print('enter finish_populating_widget_popup')
        widget, popup_handle = args
        pyqt_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget)
        widget_title = pyqt_widget.windowTitle().strip().rsplit(":")[0]
        if widget_title == self.target.parent_form.title:
            childs = pyqt_widget.findChildren(PyQt5.QtWidgets.QTableView)
            # print('finish_populating_widget_popup: len(childs) = ',len(childs))
            if len(childs) == 1:
                tv = childs[0]
                target_cols = list(map(lambda x: x[0], self.target.cols))
                for i in range(tv.model().columnCount()):
                    if tv.model().headerData(i, 1) != target_cols[i]:
                        return
                self.target.OnPopup(widget, popup_handle)
        

class Chooser(Choose):
    def __init__(self, title, cols, flags=0, embedded = False, width = None, height = None):
        Choose.__init__(self, title, cols, flags, embedded= embedded, width = width, height = height)
        # self.title = title
        self.actions = []
    
    def AddCommand(self, menu_name, shortcut=None):
        if menu_name is not None:
            action_name = "IdaDatabaseMerger:%s" % menu_name.replace(" ", "")
        else:
            action_name = None
        self.actions.append([len(self.actions), action_name, menu_name, shortcut])
        return len(self.actions) - 1
    
    def CheckCommandCondition(self, cmd_id):
        raise NotImplementedError
        
    
    def OnPopup(self, form, popup_handle):
        pydevd_pycharm.settrace('localhost', port=1337, stdoutToServer=True, stderrToServer=True, suspend=False)
        for num, action_name, menu_name, shortcut in self.actions:
            if menu_name is None:
                ida_kernwin.attach_action_to_popup(form, popup_handle, None)
            else:
                if self.CheckCommandCondition(num):
                    handler = command_handler_t(self, num, 2)
                    desc = ida_kernwin.action_desc_t(action_name, menu_name, handler, shortcut)
                    ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)


class BaseChooser(Chooser):
    

    def __init__(self, title, cols, resolver, embedded = False, width = None, height = None):
        self.items = []
        self.n = 0
        self.selected_items = []
        self.resolver = resolver
        self.use_new_cmd_id = None
        self.use_exist_cmd_id = None
        self.view_details_cmd_id = None
        Chooser.__init__(self, title, cols, Choose.CH_MULTI, embedded=embedded, width = width, height = height)

    def add_item(self, item):
        self.items.append(["%05lu" % self.n, *item])
        self.n += 1

    def add_items(self, items):
        for item in items:
            self.add_item(item)

    def get_item_key(self, n):
        raise NotImplementedError

    def ViewDetailsHandler(self, n):
        self.do_view_detail(n)

    def do_view_detail(self, n):
        raise NotImplementedError
    
    def OnGetLine(self, n):
        try:
            return self.items[n]
        except:
            print("OnGetLine", sys.exc_info()[1])
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list

    def OnSelectLine(self, n):
        # try:
        self.do_select_line(n[0])
        # except:
        #     print("OnSelectLine", sys.exc_info()[1])

    def do_select_line(self, n):
        raise NotImplementedError

    def OnGetLineAttr(self, n):
        item = self.items[n]
        merged_type = item[-1]
        color = 0xFFFFFF
        if merged_type == "same":
            color = 0x9AFF9A
        elif merged_type in ("imported", "holded"):
            color = 0x20B030
        elif merged_type == "conflict":
            color = 0x5A5AFF
        elif merged_type == "new":
            color = 0x5AFFFF
        return [color, 0]

    def UseImportingElem(self, n):
        raise NotImplementedError

    def HoldExistingElem(self, n):
        raise NotImplementedError

    def add_commands(self):
        self.view_details_cmd_id = self.AddCommand("View element details")
        self.use_new_cmd_id = self.AddCommand("Use importing element")
        self.use_exist_cmd_id = self.AddCommand("Hold exist element")
        return True

    def CheckCommandCondition(self, cmd_id):
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=1337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if cmd_id == self.view_details_cmd_id:
            if len(self.selected_items) > 1:
                return False
        elif cmd_id == self.use_exist_cmd_id:
            for sel in self.selected_items:
                elem_key = self.get_item_key(sel)
                if self.resolver.processed_elements[elem_key].ui_merged_type != 'conflict':
                    return False
        elif cmd_id == self.use_new_cmd_id:
            for sel in self.selected_items:
                elem_key = self.get_item_key(sel)
                if self.resolver.processed_elements[elem_key].ui_merged_type not in ('conflict', 'new'):
                    return False
    
        return True

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.view_details_cmd_id:
            self.ViewDetailsHandler(n)
        elif cmd_id == self.use_new_cmd_id:
            self.UseImportingElem(n)
        elif cmd_id == self.use_exist_cmd_id:
            self.HoldExistingElem(n)
    
        return True

class UI_BaseChooser(BaseChooser):
    
    def do_select_line(self, n):
        raise NotImplementedError

    def do_view_detail(self, n):
        raise NotImplementedError

    def get_item_key(self, n):
        raise NotImplementedError

    def refresh_merge_type(self):
        for n in range(len(self.items)):
            elem_key = self.get_item_key(n)
            self.items[n][-1] = self.resolver.processed_elements[elem_key].ui_merged_type
    
    def OnRefresh(self, n):
        # self.refresh_merge_type()
        pass
    
    def UseImportingElem(self, n):
        for n in self.selected_items:
            elem_key = self.get_item_key(n)
            if self.do_import(elem_key):
            # self.resolver.processed_elements[type_name].merged_type = "resolved"
                self.items[n][-1] = "imported"
                self.items[n][2] = self.items[n][4]
        self.Refresh()
    
    def do_import(self, elem_key):
        if self.resolver.processed_elements[elem_key].ui_merged_type != 'resolved' and self.resolver.resolve_dependencies_and_apply(elem_key):
            self.resolver.processed_elements[elem_key].exist_elem = self.resolver.processed_elements[elem_key].imported_elem
            self.resolver.processed_elements[elem_key].ui_merged_type = 'resolved'
            return True
        elif self.resolver.processed_elements[elem_key].ui_merged_type == 'resolved':
            return True
        return False
    
    def HoldExistingElem(self, n):
        for n in self.selected_items:
            elem_key = self.get_item_key(n)
            if self.do_hold(elem_key):
            # self.resolver.processed_elements[type_name].merged_type = 'resolved'
                self.items[n][-1] = "holded"
        self.Refresh()
    
    def do_hold(self, elem_key):
        self.resolver.processed_elements[elem_key].ui_merged_type = 'resolved'
        return True

    

class EmbeddedChooser(BaseChooser):
    
    def __init__(self, title, cols, resolver, embedded = True, width = None, height = None):
        
        # self.popup_hook = PopUp_Populating_UIHook(self)
        super().__init__(title, cols, resolver, embedded = embedded, width = width, height = height)
        
    def OnInit(self):
        # self.popup_hook.hook()
        pass
    
    def OnClose(self):
        # self.popup_hook.unhook()
        pass
    
    def get_item_key(self, n):
        raise NotImplementedError

    def do_view_detail(self, n):
        raise NotImplementedError

    def do_select_line(self, n):
        raise NotImplementedError

    def UseImportingElem(self, n):
        raise NotImplementedError

    def HoldExistingElem(self, n):
        raise NotImplementedError
    



class UI_EmbeddedChooser(EmbeddedChooser):
    
    def __init__(self, title, cols, resolver, parent_form, control_name, width = None, height = None):
        
        self.parent_form = parent_form
        self.control_name = control_name
        super(UI_EmbeddedChooser, self).__init__(title, cols, resolver, embedded=True, width = width, height = height)
    
    def get_item_key(self, n):
        raise NotImplementedError

    def do_view_detail(self, n):
        raise NotImplementedError

    def do_select_line(self, n):
        raise NotImplementedError
    
    def UseImportingElem(self, n):
        for n in self.selected_items:
            elem_key = self.get_item_key(n)
            if self.do_import(elem_key):
            # self.resolver.processed_elements[type_name].merged_type = "resolved"
                self.items[n][-1] = "resolved"
        self.parent_form.RefreshField(self.parent_form[self.control_name])
    
    def do_import(self, elem_key):
        raise NotImplementedError
    
    def HoldExistingElem(self, n):
        for n in self.selected_items:
            elem_key = self.get_item_key(n)
            if self.do_hold(elem_key):
            # self.resolver.processed_elements[type_name].merged_type = 'resolved'
                self.items[n][-1] = "resolved"
        self.parent_form.RefreshField(self.parent_form[self.control_name])
    
    def do_hold(self, elem_key):
        raise NotImplementedError


class UI_PluginForm(ida_kernwin.Form):
    form_template = """BUTTON YES NONE
BUTTON CANCEL NONE
BUTTON NO NONE
IdaDatabaseMerger
<Import database:{cButtonImport}>|<Export database:{cButtonExport}>
"""
    
    def __init__(self, ida_database_meger):
        self.ida_database_meger = ida_database_meger
        self.db_path = None
        self.clear_exist = True
        self.result = 0
        super(UI_PluginForm, self).__init__(self.form_template, {
            'cButtonImport': ida_kernwin.Form.ButtonInput(self.OnImport),
            'cButtonExport': ida_kernwin.Form.ButtonInput(self.OnExport),
            
            # 'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange)
        })
    
    def OnImport(self, code=0):
        ui = UI_PluginFormImport(self.ida_database_meger)
        db_path = ui.Go()
        if db_path is not None:
            self.result = 2
            self.db_path = db_path
        self.Close(True)
    
    def OnExport(self, code=0):
        ui = UI_PluginFormExport(self.ida_database_meger)
        db_path, clear_exist = ui.Go()
        if db_path is not None:
            self.result = 1
            self.db_path = db_path
            self.clear_exist = clear_exist
        self.Close(True)
    
    def Go(self):
        self.Compile()
        return self.Execute()


class UI_BaseChooserForm(ida_kernwin.Form):
    
    form_template = """BUTTON YES NONE
    BUTTON CANCEL NONE
    BUTTON NO NONE
%s
Filters:
<New:{rNew}>|<Conflict:{rConfict}>|<Same:{rSame}>|<Merged:{rMerged}>>
<Elements:{cElementsChooser}>
"""
    
    def __init__(self, title, cols, resolver, embedded = False, width = None, height = None):
        super().__init__(self.form_template, {})
        pass
    


class UI_PluginFormExport(ida_kernwin.Form):
    form_template = """BUTTON NO NONE
IdaDatabaseMerger Export

<Select database to export:{iFileSave}>|<Clear exist database:{rClear}>{cGroup}>
"""
    
    def __init__(self, ida_database_meger):
        self.ida_database_meger = ida_database_meger
        current_file = os.path.splitext(ida_nalt.get_root_filename())[0]
        db_file_name = current_file + datetime.today().strftime('_%Y%m%d%H%M%S')
        super(UI_PluginFormExport, self).__init__(self.form_template, {
            'iFileSave': ida_kernwin.Form.FileInput(save=True, value=db_file_name + ".db"),
            'cGroup': ida_kernwin.Form.ChkGroupControl(["rClear"]),
            # 'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange)
        })
    
    def Go(self):
        self.Compile()
        self.rClear.checked = True
        r = self.Execute()
        if r == 1:
            return self.iFileSave.value, self.rClear.checked
        return None, None


class UI_PluginFormImport(ida_kernwin.Form):
    form_template = """BUTTON NO NONE
IdaDatabaseMerger Import

<Select database to import:{iFileSave}>
"""
    
    def __init__(self, ida_database_meger):
        self.ida_database_meger = ida_database_meger
        super(UI_PluginFormImport, self).__init__(self.form_template, {
            'iFileSave': ida_kernwin.Form.FileInput(open=True, value="*.db"),
            # 'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange)
        })
    
    def Go(self):
        self.Compile()
        r = self.Execute()
        if r == 1:
            return self.iFileSave.value
        return None