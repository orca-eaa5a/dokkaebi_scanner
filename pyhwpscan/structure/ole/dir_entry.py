'''
http://www.reversenote.info/ole-parser-python/
'''

from concurrent.futures import thread
from ctypes import *
from io import BytesIO
import zlib
from c_style_structure import CStyleStructure
class DirectoryEntry(CStyleStructure):
    def __init__(self, ptr_size=4, pack=0):
        super().__init__(ptr_size=ptr_size, pack=1)
        self.DirectoryEntryName = c_ubyte * 0x40
        self.DirectoryEntryNameLength = c_short
        self.ObjectType = c_ubyte
        self.ColorFlag = c_ubyte
        self.LeftSiblingID = c_uint32
        self.RightSiblingID = c_uint32
        self.ChildID = c_uint32
        self.CLSID = c_ubyte * 0x10
        self.StateFlags = c_uint32
        self.CreationTime = c_uint64
        self.ModificationTime = c_uint64
        self.StartingSectorLocation = c_uint32
        self.StreamSize = c_uint64
        self.stream = None
        self.zobj = zlib.decompressobj(-zlib.MAX_WBITS)
        self.dec_stream = None

    def size(self):
        return self.sizeof()
    def stream_size(self):
        return self.StreamSize
    def name(self):
        return bytes(self.DirectoryEntryName).decode('utf16').replace('\x00', '')
    def name_raw(self):
        return bytes(self.DirectoryEntryName)
    def get_stream(self):
        return self.stream[:self.StreamSize]
    def raw(self):
        return self.get_bytes()
        
    def get_decompressed_stream(self):
        if not self.dec_stream:
            try:
                self.dec_stream = self.zobj.decompress(self.get_stream())
            except zlib.error as z_err:
                import structure.ole.hwp_distdoc as distdoc_decryptor
                self.dec_stream = zlib.decompress(
                    distdoc_decryptor.decrypt_distdoc(
                        BytesIO(self.get_stream())
                    ),
                    -15
                )

        return self.dec_stream
        
    