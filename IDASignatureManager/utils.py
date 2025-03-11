import os

import ida_diskio
import ida_hexrays
import ida_typeinf
import struct



def  get_guess_type(addr):
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.guess_tinfo(tif, addr):
        dstr = tif.dstr()
        del tif
        return dstr
    return ""

def user_resource(directory, filename):
    """
    Return the absolute path to a resource located in the user directory.
    It should be:
    * %APPDATA%\\Roaming\\Hex-Rays\\IDA Pro\\plugin\\idarling under Windows
    * $HOME/.idapro/plugins/idarling under Linux and MacOS.
    """
    user_dir = ida_diskio.get_user_idadir()
    plug_dir = os.path.join(user_dir, "plugins")
    local_dir = os.path.join(plug_dir, "ida_database_merger")
    res_dir = os.path.join(local_dir, directory)
    if not os.path.exists(res_dir):
        os.makedirs(res_dir, 493)  # 0755
    return os.path.join(res_dir, filename)

wrapperTypeString = b'\x0d\x01\x01'
my_ti = None
def get_my_ti():
    global my_ti
    if my_ti is None:
        my_ti = ida_typeinf.get_idati()
    return my_ti

class TinfoReader(object):
    def __init__(self, tp):
        self.pos = 0
        self.tp = tp

    def read_byte(self):
        (result,) = struct.unpack("<B", self.tp[self.pos:self.pos+1])
        self.pos += 1
        return result

    def read_string(self,cb):
        ret = self.tp[self.pos:self.pos+cb]
        self.pos += cb
        return ret

    def keep_going(self):
        return self.pos < len(self.tp)

    def remain_len(self):
        return len(self.tp) - self.pos
    
    def set_pos(self, new_pos):
        self.pos = new_pos
        
    def get_pos(self):
        return self.pos

def encode_ordinal_to_string(ordinal):
    enc = []
    #print "encode_ordinal_to_string: ordinal %d"%ordinal
    enc.append(ordinal&0x7f|0x40)
    if ordinal > 0x3f:
        bt = ordinal
        bt = bt // 0x40
        enc.append(bt&0x7f|0x80)
        while bt > 0x7f:
            bt = bt // 0x80
            enc.append(bt&0x7f|0x80)
    # stemp = struct.pack("B",len(enc)+2) + "#"
    stemp = []
    stemp.append(len(enc)+2)
    stemp.append(ord("#"))
    # for i in range(0,len(enc)):
    #     stemp = stemp + struct.pack("B",enc.pop(-1))
    #print stemp
    #print enc
    enc.reverse()
    #print enc
    stemp = stemp + enc
    return stemp

def decode_ordinal_string(enc):
    if enc[1] == ord("#"):
        ord_num = 0
        i = 0
        fEnd = 0
        str_len = struct.unpack("B",enc[0:1])[0] - 2
        #print len
        for ch in enc[2:]:
            if ch == 0:
                return 0
            ord_num = ord_num * 0x40
            if ch&0x80 != 0:
                ord_num = ord_num * 2
                ch = ch & 0x7f
            else:
                ch = ch & 0x3f
                fEnd = 1
            ord_num = ord_num | ch
            i = i + 1
            if fEnd > 0 or i >= str_len:
                break
        return ord_num
    return 0

def decode_ordinal(enc):
    ord_num = 0
    i = 0
    fEnd = 0
    (ord_len,) = struct.unpack("B",enc[0])
    ord_len -= 2
    for ch in enc[2:]:
        ch = ord(ch)
        if ch == 0:
            return 0
        ord_num = ord_num * 0x40
        if ch&0x80 != 0:
            ord_num = ord_num * 2
            ch = ch & 0x7f
        else:
            ch = ch & 0x3f
            fEnd = 1
        ord_num = ord_num | ch
        if fEnd > 0 or i >= ord_len:
            break
    return ord_num

def encode_ordinal(ordinal):
    enc = []
    enc.append(ordinal&0x3f|0x40)
    if ordinal > 0x3f:
        bt = ordinal
        bt = bt // 0x40 # >> 6
        enc.append(bt&0x7f|0x80)
        while bt > 0x7f:
            bt = bt // 0x80 # >> 7
            enc.append(bt&0x7f|0x80)
    stemp = b""
    for i in range(0,len(enc)):
        stemp = stemp + struct.pack("B",enc.pop(-1))
    return stemp

def get_typestring_depends(parsedList):
    dependencies = []
    for thing in parsedList:
        if type(thing) == dict and len(thing) == 1 and list(thing.keys())[0] == 'local_type':
            dependency = list(thing.values())[0]
            if dependency not in dependencies:
                dependencies.append(dependency)
    return dependencies

def GetTypeString(parsedList, name=""):
    ti = ida_typeinf.get_idati()
    # print "GetTypeString: name %s"%self.name
    the_bytes = []
    for thing in parsedList:
        if type(thing) == int:  # if it's a byte, just put it back in
            the_bytes.append(thing)
        elif len(thing) == 1:
            # if list(thing.keys())[0] == "local_type":
            #     the_bytes.append(ord("="))  # a type starts with =
            # print type(thing["local_type"]),thing["local_type"]
            ordinal = ida_typeinf.get_type_ordinal(ti, list(thing.values())[0])  # get the ordinal of the Local Type based on its name
            if ordinal > 0:
                the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
            else:
                raise NameError("Depends local type not in IDB")
        else:
            raise NameError("Wrong depend record for type: %s!" % name)
    packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
    return packed

def check_rare_type_condition(bytes_to_check):
    if len(bytes_to_check)>1 and type(bytes_to_check[-1]) == int:
        if (len(bytes_to_check) >= 4 and bytes_to_check[-4:-1] == [0x0A, 0x0D, 0x01]) or (len(bytes_to_check) >= 3 and bytes_to_check[-3:-1] == [0x0D, 0x01]):
            return True
    return False

def get_typeinf(addr):
    tif = ida_typeinf.tinfo_t()
    ida_hexrays.get_type(addr, tif, ida_hexrays.GUESSED_NONE)
    if tif.empty():
        typeinf = (None, None, "")
    else:
        type_string, fields, fldcmts = tif.serialize()
        typeinf = (ParseTypeString(type_string), fields, tif.dstr())
    return typeinf

def serialize_tinfo(tif):
    if tif.empty():
        typeinf = (None, None, "")
    else:
        type_string, fields, fldcmts = tif.serialize()
        typeinf = (ParseTypeString(type_string), fields, tif.dstr())
    return typeinf

def get_de_encoded_len(de_bytes):
    i = 0
    for b in de_bytes:
        if b & 0x80 == 0:
            if b & 0x40:
                i += 1
                return i
            else:
                return 0
        else:
            i += 1
                

def ParseTypeString(type_string):
    tp = TinfoReader(type_string)
    ti = ida_typeinf.get_idati()
    # print idc_print_type(type_, fields, "fun_name", 0)
    # print type_.encode("string_escape")
    output = []
    """
    Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
    Pass all other bytes through as-is.
    """
    while tp.keep_going():
        a_byte = tp.read_byte()
        unwritten_bytes = [a_byte]
        if a_byte == ord("=") and tp.pos < len(tp.tp):  # a type begins
            ordinal_length = tp.read_byte()
            if tp.pos < len(tp.tp) and len(tp.tp) - (tp.pos + ordinal_length - 1) >= 0:
                number_marker = tp.read_byte()
                if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
                    ordinal = decode_ordinal_string(struct.pack("B", ordinal_length) + b"#" + tp.read_string(ordinal_length - 2))
                    t = ida_typeinf.get_numbered_type_name(ti,ordinal)
                    output.append(a_byte)
                    output.append({"local_type": t})
                    # if t not in self.depends:
                    #     self.depends.append(t)
                    #     self.depends_ordinals.append(ordinal)
                    continue
                else:
                    unwritten_bytes.append(ordinal_length)
                    unwritten_bytes.append(number_marker)
            else:
                unwritten_bytes.append(ordinal_length)
        elif a_byte == ord("#") and check_rare_type_condition(output):
            ordinal_length = output[-1]
            if tp.remain_len() >= (ordinal_length -2):
                output.pop(-1)
                ordinal = decode_ordinal_string(struct.pack("B", ordinal_length) + b"#" + tp.read_string(ordinal_length - 2))
                t = ida_typeinf.get_numbered_type_name(ti,ordinal)
                output.append({"local_type": t})
                # if t not in self.depends:
                #     self.depends.append(t)
                #     self.depends_ordinals.append(ordinal)
            continue
        
        output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is
    
    return output