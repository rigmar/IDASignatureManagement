
class ProcessedItem(object):
    
    def __init__(self, exist_elem, imported_elem, merge_dict, ui_merged_type):
        self.exist_elem = exist_elem
        self.imported_elem = imported_elem
        self.merge_dict = merge_dict
        self.ui_merged_type = ui_merged_type

class IDB_element(object):
    
    def __init__(self):
        self.name = None
        self.addr = None
        
    @property
    def key(self):
        return None
    
    def apply_info(self):
        pass
    
    @staticmethod
    def collect_info(*args):
        pass
    
    def to_dict(self):
        pass
    
    def from_dict(self,*args):
        pass
    
    def is_empty(self):
        return self.name is None
    
    def isEqual(self,obj):
        pass


