from common.errors import StreamNotFoundError
from pyparser.oleparser import OleParser
from structure.hwp.hwp_header import HWPHeader
from structure.hwp.hwp_bindata import HWPBinData
from structure.hwp.hwp_docinfo import HWPDocInfo
from structure.hwp.hwp_script import HWPJScript
from structure.hwp.hwp_bodytext import HWPBodyText

class HwpParser:
    def __init__(self, ole_container:OleParser) -> None:
        self.ole_container = ole_container
        self.hwp_header = None
        self.hwp_bindata = None
        self.hwp_docinfo = None
        self.hwp_jscript = None
        self.hwp_bodytext = None
        pass
    
    def get_bindata(self):
        return self.hwp_bindata

    def parse_file_header(self):
        if not self.hwp_header:
            file_header_entry = self.ole_container.get_dir_entry_by_name('FileHeader')
            if not file_header_entry:
                raise StreamNotFoundError
            bytez = file_header_entry.get_stream()
            self.hwp_header = HWPHeader()
            self.hwp_header.parse(bytez)
        
        return True
    
    def parse_bindata(self, ole_container):
        self.hwp_bindata = HWPBinData(ole_container)
        self.hwp_bindata.parse()

    def parse_jscript(self, ole_container):
        self.hwp_jscript = HWPJScript(ole_container)
        self.hwp_jscript.parse()

    def parse_docinfo(self, ole_container):
        self.hwp_docinfo = HWPDocInfo(ole_container)
        self.hwp_docinfo.parse()

    def parse_bodytext(self, ole_container):
        self.hwp_bodytext = HWPBodyText(ole_container)
        self.hwp_bodytext.parse()

    def parse(self):
        self.parse_file_header()
        self.parse_bindata(self.ole_container)
        self.parse_docinfo(self.ole_container)
        self.parse_bodytext(self.ole_container)
        self.parse_jscript(self.ole_container)
        
        