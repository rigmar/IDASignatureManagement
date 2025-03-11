
from IDASignatureManager.FLIRT_engine import get_matches
from IDASignatureManager.FunctionElement import FunctionElement

from IDASignatureManager.logger import logger_instance


class IdaSignatureManager(object):
    # elements_tables = {"LocalTypes": LocalType, "GlobalVariables": GlobalVariable, "FunctionElements": FunctionElement,
    #                    "FunctionLocalVarsElements": FunctionLocalVarsElement}
    elements_tables = {"FunctionElements": FunctionElement}
    
    def __init__(self):
        self.resolver = None
        self.sig_file = None
        self.imported_elements = {}
        self.processed_elements = {}
        
        for elems_name in self.elements_tables:
            self.imported_elements[elems_name] = []
            self.processed_elements[elems_name] = {}
    
    def clear(self):
        self.sig_file = None
        self.imported_elements = {}
        self.processed_elements = {}
        
        for elems_name in self.elements_tables:
            self.imported_elements[elems_name] = []
            self.processed_elements[elems_name] = {}
    
    def process_elements_list(self, element_name):
        if element_name in self.imported_elements:
            imported_elements = self.imported_elements[element_name]
            self.processed_elements[element_name] = {}
            
            for imported_element in imported_elements:
                logger_instance.trace("Process imported element for %s element list: name =  %s, addr = %s" % (
                    element_name, imported_element.name, "0x%08X" % imported_element.addr if imported_element.addr is not None else "None"))
                exist_element = type(imported_element).collect_info(imported_element.key)
                self.processed_elements[element_name][imported_element.key] = imported_element.get_processed_item(exist_element, imported_element)
            return self.processed_elements[element_name]
        logger_instance.error("Elements name '%s' not in imported elements dictionary!" % element_name)
        return None
    
    def process(self):
        for elements_list_name in self.elements_tables:
            if self.process_elements_list(elements_list_name) is None:
                logger_instance.error("Proccessing '%s' elements was failed!" % elements_list_name)
        return self.processed_elements
    
    def process_sig_file(self, sig_file):
        self.sig_file = sig_file
        self.imported_elements["FunctionElements"] = get_matches(self.sig_file)
        self.process()
        self.resolver = self.elements_tables["FunctionElements"].get_resolver(self, self.processed_elements["FunctionElements"])
        self.resolver.start()