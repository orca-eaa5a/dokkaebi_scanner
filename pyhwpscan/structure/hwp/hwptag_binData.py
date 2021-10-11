from ctypes import *
import struct
from io import BytesIO
class Properties:
    def __init__(self, properties) -> None:
        self.lnk = False
        self.embedding = False
        self.storage = False
        self.default_mode = False
        self.compressed_no_except = False
        self.compressed_except = False
        self.set_properties(properties)
        pass

    def set_properties(self, properties):
        type_prop = properties & 0xF
        if type_prop == 0:
            self.lnk = True
        if type_prop & 0x1:
            self.embedding = True
        if type_prop & 0x2:
            self.storage = True
        compress_prop = (properties >> 4)  
        if compress_prop == 0:
            self.default_mode = True
        if compress_prop & 0x1:
            self.compressed_no_except = True
        if compress_prop & 0x2:
            self.compressed_except = True

class HWPTAG_binData:
    def __init__(self, bytez):
        stream = BytesIO(bytez)
        self.properties =  Properties(struct.unpack("<H", stream.read(2))[0])
        if self.properties.lnk:
            self.abs_path_len = struct.unpack("<H", stream.read(2))[0]
            self.abs_lnk_path = stream.read(self.abs_path_len)
            self.rel_path_len = struct.unpack("<H", stream.read(2))[0]
            self.rel_lnk_path = stream.read(self.rel_lnk_path)
            raise Exception("Please input original .hwp file")
        
        self.bin_id = struct.unpack("<H", stream.read(2))[0]
        self.bin_name_len = struct.unpack("<H", stream.read(2))[0]
        self.extension = stream.read(self.bin_name_len*2).decode("utf16").replace("\x00","")
    