'''
http://www.reversenote.info/ole-parser-python/
'''
from ctypes import *
from c_style_structure import CStyleStructure
import structure.ole.ole_const as ole_const

class CompoundFileBinaryHeader(CStyleStructure):
    def __init__(self, ptr_size=0, pack=0):
        super().__init__(ptr_size=ptr_size, pack=pack)
        self.HeaderSignature = c_ubyte * 8
        self.HeaderCLSID = c_ubyte * 16
        self.MinorVersion = c_ushort
        self.MajorVersion = c_ushort
        self.ByteOrder = c_ushort
        self.SectorShift = c_ushort
        self.MiniSectorShift = c_ushort
        self.Reserved = c_ubyte * 6
        self.NumberOfDirectorySectors = c_uint32
        self.NumberOfFATSectors = c_uint32
        self.FirstDirectorySectorLocation = c_uint32
        self.TransactionSignatureNumber = c_uint32
        self.MiniStreamCutoffSize = c_uint32
        self.FirstMiniFATSectorLocation = c_uint32
        self.NumberOfMiniFATSectors = c_uint32
        self.FirstDIFATSectorLocation = c_uint32
        self.NumberOfDIFATSectors = c_uint32
        self.DIFAT = c_uint32 * ole_const.MAXFATENTRY