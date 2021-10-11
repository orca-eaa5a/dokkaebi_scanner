from ctypes import *
from structure.hwp.hwp_record import HWPRecord
from io import BytesIO

class HWPChar:
    NEWLINE = 0
    CHAR = 1
    INLINE = 2
    EXTEND = 3
    def __init__(self, _type_, wchar_c) -> None:
        self._type_ = _type_
        self.wchar = wchar_c
        pass

class HWPSection:
    HWPTAG_BEGIN = 0x10
    PARAHEADER_TAG_ID = HWPTAG_BEGIN + 50
    PARATEXT_TAG_ID = HWPTAG_BEGIN + 51
    def __init__(self, bytez) -> None:
        self.section_raw = BytesIO(bytez)
        self.para_headers = []
        self.para_text_records = []
        #self.para_header = HWPTAG_ParaHeader()
        self.para_text_wchar_set = []
        self.para_text_content = ""
        self.para_text_raw = b''
        pass
    
    def parse(self):
        '''
        HWP Section is the set of HWP_Records
        Parsing method of HWP Section is same with HWP Docinfo
        '''
        stream = self.section_raw
        while True:
            new_hwp_record = HWPRecord()
            res = new_hwp_record.parse(stream)
            '''
            We just want to parse PARA_TEXT
            '''
            if new_hwp_record.header.tag_id == HWPSection.PARAHEADER_TAG_ID:
                self.para_text_records.append(new_hwp_record)
            if not res:
                break
        self.parse_paratext()
    
    def parse_paratext(self):
        for record in self.para_text_records:
            payload = record.payload
            self.para_text_raw += payload
            payload_sz = len(payload)
            readbytes = 0
            stream = BytesIO(payload)
            while (readbytes < payload_sz):
                uncode_bytz = stream.read(2)
                wchar_c = int.from_bytes(uncode_bytz, "little")
                if wchar_c in [0, 10, 13]:
                    hwp_char = HWPChar(HWPChar.NEWLINE, wchar_c)
                    readbytes += 2
                elif wchar_c in [4, 5, 6, 7, 8, 9 ,19 ,20]:
                    hwp_char = HWPChar(HWPChar.INLINE, wchar_c)
                    readbytes+=16
                    stream.read(14)
                elif wchar_c in [1, 2, 3, 11, 12, 14, 15, 16, 17, 18, 21, 22, 23]:
                    hwp_char = HWPChar(HWPChar.EXTEND, wchar_c)
                    readbytes+=16
                    stream.read(14)
                else:
                    hwp_char = HWPChar(HWPChar.CHAR, uncode_bytz.decode("utf-16"))
                    readbytes+=2
                self.para_text_wchar_set.append(hwp_char)

    def get_paratext(self):
        if not self.para_text_content:
            for para_text in self.para_text_wchar_set:
                if para_text._type_ == HWPChar.CHAR:
                    self.para_text_content += para_text.wchar
                elif para_text._type_ == HWPChar.NEWLINE:
                    self.para_text_content += "\n"
        return self.para_text_content
                



