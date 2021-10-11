from common.errors import *
class HWPBinData:
    def __init__(self, ole_container) -> None:
        self.ole_container = ole_container
        self.bindata_storage = self.ole_container.get_dir_entry_by_name('BinData')
        if not self.bindata_storage:
            raise StorageNotFoundError
        self.bindata = []
        pass

    def get_bindata_streams(self, child_id):
        child = self.ole_container.get_dir_entry(child_id)
        if not child:
            raise StreamNotFoundError
        self.bindata.append(child)
        if child.LeftSiblingID != 0xFFFFFFFF:
            self.get_bindata_streams(child.LeftSiblingID)
        if child.RightSiblingID != 0xFFFFFFFF:
            self.get_bindata_streams(child.RightSiblingID)
        return

    def parse(self):
        self.get_bindata_streams(self.bindata_storage.ChildID)
        pass