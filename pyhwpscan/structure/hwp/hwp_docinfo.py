from structure.hwp.hwp_record import HWPRecord
from structure.hwp.hwptag_binData import HWPTAG_binData
from io import BytesIO
from common.errors import *
class HWPDocInfo:
    HWPTAG_BEGIN = 0x10
    HWPTAG_ID_BINDATA = HWPTAG_BEGIN + 2
    HWPTAG_DISTRIBUTE_DOC_DATA = HWPTAG_BEGIN + 12

    def __init__(self, ole_container) -> None:
        self.ole_container = ole_container
        self.docinfo_stream = self.ole_container.get_dir_entry_by_name('DocInfo')
        if not self.docinfo_stream:
            StreamNotFoundError
        self.hwptag_bindatas = []
        self.records = {}
        pass

    def parse(self):
        stream = BytesIO(self.docinfo_stream.get_decompressed_stream())
        while True:
            new_hwp_record = HWPRecord()
            res = new_hwp_record.parse(stream)
            if new_hwp_record.header.tag_id not in self.records:
                self.records[new_hwp_record.header.tag_id] = [new_hwp_record]
            else:
                self.records[new_hwp_record.header.tag_id].append(new_hwp_record)
            if not res:
                break
        self.parse_hwptag_bindata()

    def parse_hwptag_bindata(self):
        hwptag_bindatas = self.records[HWPDocInfo.HWPTAG_ID_BINDATA]
        for hwptag_bindata in hwptag_bindatas:
            hwptag_bindata_binary = HWPTAG_binData(hwptag_bindata.payload)
            self.hwptag_bindatas.append(hwptag_bindata_binary)

