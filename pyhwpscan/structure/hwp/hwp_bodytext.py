from structure.hwp.hwp_section import HWPSection
from common.errors import *
class HWPBodyText:
    def __init__(self, ole_container) -> None:
        self.ole_container = ole_container
        self.bodytext_stoarge = self.ole_container.get_dir_entry_by_name('BodyText')
        if not self.bodytext_stoarge:
            raise StorageNotFoundError
        self.sections = []
        pass

    def get_sections(self, child_id):
        child = self.ole_container.get_dir_entry(child_id)
        if not child:
            StorageNotFoundError
        new_section = HWPSection(child.get_decompressed_stream())
        new_section.parse()
        self.sections.append(
            new_section
        )
        if child.LeftSiblingID != 0xFFFFFFFF:
            self.get_sections(child.LeftSiblingID)
        if child.RightSiblingID != 0xFFFFFFFF:
            self.get_sections(child.RightSiblingID)
        return

    def parse(self):
        self.get_sections(self.bodytext_stoarge.ChildID)