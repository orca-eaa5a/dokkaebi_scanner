from ctypes import *
from distutils.log import error
import imp
import zlib
from structure.c_style_structure import CStyleStructure
import struct
from io import BytesIO
from common.errors import *

class HWP_JScriptVersion(CStyleStructure):
    def __init__(self, ptr_size=0, pack=0):
        super().__init__(ptr_size=ptr_size, pack=pack)
        self.version_high = c_uint32
        self.version_low = c_uint32
    
    def get_version(self):
        return str(self.version_high)+"."+str(self.version_low)

class DefaultJScript:
    SCRIPT_END_FLAG = -1
    def __init__(self) -> None:
        self.header_len = 0
        self.header = ""
        self.script_len = 0
        self.script = ""
        self.pre_script_len = 0
        self.pre_script = ""
        self.post_script_len = 0
        self.post_script = ""
        self.end_flag = 0
        self.stream_name = ""
        pass
    
    def parse(self, stream):
        self.header_len = struct.unpack("<I", stream.read(4))[0]
        self.header = stream.read(self.header_len*2).decode("utf-16")
        self.script_len = struct.unpack("<I", stream.read(4))[0]
        self.script = stream.read(self.script_len*2).decode("utf-16")
        self.pre_script_len = struct.unpack("<I", stream.read(4))[0]
        self.pre_script = stream.read(self.pre_script_len*2).decode("utf-16")
        self.post_script_len = struct.unpack("<I", stream.read(4))[0]
        self.post_script = stream.read(self.post_script_len*2).decode("utf-16")
        self.end_flag = struct.unpack("<i", stream.read(4))[0]
        if self.end_flag != DefaultJScript.SCRIPT_END_FLAG:
            raise Exception("DefaultJScript parsed error")

    def name(self):
        return self.stream_name

    def get_script_str(self):
        return self.header + "\r\n" + self.pre_script + "\r\n" + self.script + "\r\n" + self.post_script 

class HWPJScript:
    def __init__(self, ole_container) -> None:
        self.ole_container = ole_container
        self.script_version = HWP_JScriptVersion()
        self.script_storage = self.ole_container.get_dir_entry_by_name('Scripts')
        if not self.script_storage:
            raise StreamNotFoundError
        self.script_streams = []
        pass

    def get_scripts_streams(self, child_id):
        child = self.ole_container.get_dir_entry(child_id)
        try:
            if child.name() == "JScriptVersion":
                dec_stream = child.get_decompressed_stream()
                self.script_version.cast(dec_stream)
            else:
                new_default_script = DefaultJScript()
                new_default_script.stream_name = child.name()
                dec_stream = child.get_decompressed_stream()
                new_default_script.parse(BytesIO(dec_stream))
                self.script_streams.append(new_default_script)
        except Exception as unk_err:
            print(unk_err)
            pass
            
            
        if child.LeftSiblingID != 0xFFFFFFFF:
            self.get_scripts_streams(child.LeftSiblingID)
        if child.RightSiblingID != 0xFFFFFFFF:
            self.get_scripts_streams(child.RightSiblingID)
        return

    def parse(self):
        self.get_scripts_streams(self.script_storage.ChildID)
            

