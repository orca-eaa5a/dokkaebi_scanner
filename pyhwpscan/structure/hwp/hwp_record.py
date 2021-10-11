import struct
from io import BytesIO

class HWPRecordHeader:
    def __init__(self) -> None:
        self.tag_id = 0
        self.level = 0
        self.size = 0
        pass

    def set_filed(self, stream:BytesIO):
        hwp_header_value_raw = stream.read(4)
        if not hwp_header_value_raw:
            return False
        hwp_header_value = struct.unpack('<I', hwp_header_value_raw)[0]
        self.tag_id = hwp_header_value & 0x3FF
        self.level = (hwp_header_value >> 10) & 0x3FF
        self.size = (hwp_header_value >> 20) & 0xFFF
        if self.size == 0xFFF:
            hwp_header_value_raw = stream.read(4)
            hwp_header_value = struct.unpack('<I', hwp_header_value_raw)[0]
            self.size = struct.unpack('<I', hwp_header_value)
        return True
    
class HWPRecord:
    def __init__(self) -> None:
        self.header = HWPRecordHeader()
        self.payload = None
        pass

    def parse(self, stream:BytesIO):
        res = self.header.set_filed(stream)
        if not res:
            return False
        self.payload = stream.read(self.header.size)
        if not self.payload:
            return False
        return True