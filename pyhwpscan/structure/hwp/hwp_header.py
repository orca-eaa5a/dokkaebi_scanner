from ctypes import *
from structure.c_style_structure import CStyleStructure
import structure.ole.ole_const as ole_const
from structure.hwp.hwp_version import HWPVersion

class Properties:
    # 4byte properties
    def __init__(self, properties) -> None:
        self.compressed = False
        self.encrypted = False
        self.distribution = False
        self.script = False
        self.drm = False
        self.hasXmlTemplateStorage = False
        self.vcs = False
        self.hasElectronicSignature = False
        self.isPKEncrypted = False
        self.prepareSignature = False
        self.certificateDRM = False
        self.ccl = False
        self.mobile = False
        self.isPriviacySecurityDocs = False
        self.kogl = False
        self.hasVideoCtrl = False
        self.hasOrderFiledControl = False
        self.set_properties(properties)
        pass

    def set_properties(self, properties) -> None:
        if ((1 << 0) & properties) == 1:
            self.compressed = True
        if ((1 << 1) & properties) == 1:
            self.encrypted = True
        if ((1 << 2) & properties) == 1:
            self.distribution = True
        if ((1 << 3) & properties) == 1:
            self.script = True
        if ((1 << 4) & properties) == 1:
            self.drm = True
        if ((1 << 5) & properties) == 1:
            self.hasXmlTemplateStorage = True
        if ((1 << 6) & properties) == 1:
            self.vcs = True
        if ((1 << 7) & properties) == 1:
            self.hasElectronicSignature = True
        if ((1 << 8) & properties) == 1:
            self.isPKEncrypted = True
        if ((1 << 9) & properties) == 1:
            self.prepareSignature = True
        if ((1 << 10) & properties) == 1:
            self.certificateDRM = True
        if ((1 << 11) & properties) == 1:
            self.ccl = True
        if ((1 << 12) & properties) == 1:
            self.mobile = True
        if ((1 << 13) & properties) == 1:
            self.isPriviacySecurityDocs = True
        if ((1 << 14) & properties) == 1:
            self.kogl = True
        if ((1 << 15) & properties) == 1:
            self.hasVideoCtrl = True
        if ((1 << 16) & properties) == 1:
            self.hasOrderFiledControl = True

class HWPHeader(CStyleStructure):
    def __init__(self, ptr_size=0, pack=0):
        super().__init__(ptr_size=ptr_size, pack=pack)
        self.signature = c_ubyte*0x20
        self.version = c_uint32
        self.__properties = c_uint32
        self.reserved_properties = c_uint32
        self.encrypt_version = c_uint32
        self.license = c_ubyte
        self.reserved = c_ubyte*207
        self.properties = None

    def parse(self, bytez):
        super().cast(bytez)
        self.set_properties()

    def get_signature(self):
        return bytes(self.signature).decode('ascii').replace("\x00","")
    def set_properties(self):
        self.properties = Properties(self.__properties)
    def get_properties(self):
        return self.properties
