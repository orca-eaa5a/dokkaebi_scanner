from ctypes import c_uint32
import ctypes
from math import log
import struct
import logging
from structure.ole.cfb_header import CompoundFileBinaryHeader
from structure.ole.dir_entry import DirectoryEntry
from structure.ole.ole_const import ENDOFCHAIN, FREESECT, MAGIC_ID, MAXFATENTRY, NOSTREAM, STORAGE, ROOT, SECTORSIZE, MAXREGSID, MINISECTORSIZE, DIRECTORYENTRYSIZE
from common.errors import *
MINISTREAMCUTOFFSIZE = int()

class OleParser:
    def __init__(self) -> None:
        self.ole_bin = None
        self.file_sz = -1
        self.cfb_header = CompoundFileBinaryHeader()
        self.root_entry = None
        self.FAT_array = []
        self.FAT_stream = None
        self.mini_FAT_array = []
        self.mini_FAT_stream = []
        self.dir_entry_array = []
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.console_logger = logging.StreamHandler()
        self.formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        self.console_logger.setFormatter(self.formatter)
        self.logger.addHandler(self.console_logger)

        pass
    
    def read_ole_binary(self, file_name) -> None:
        fp = open(file_name, 'rb')
        self.ole_bin = fp.read()
        fp.close()
        self.file_sz = len(self.ole_bin)
        pass

    def parse_cfb_header(self) -> None:
        self.cfb_header.cast(self.ole_bin)
        global MINISTREAMCUTOFFSIZE
        MINISTREAMCUTOFFSIZE = self.cfb_header.MiniStreamCutoffSize
        pass

    def parse_sectors(self) -> None:
        FAT_sectors = []
        for i in range(0, MAXFATENTRY):
            if self.cfb_header.DIFAT[i] == FREESECT or \
                self.cfb_header.NumberOfFATSectors < i:
                break
            FAT_sectors.append(self.cfb_header.DIFAT[i])
        
        DIFATsector = self.cfb_header.FirstDIFATSectorLocation
        for i in range(0, self.cfb_header.NumberOfDIFATSectors):
            buf = self.get_sector(DIFATsector)
            DIFAT = self.make_integer_list(buf, ctypes.sizeof(c_uint32))
            DIFATsector = DIFAT[-1]
            FAT_sectors += DIFAT[:-1]
        
        buf = b''
        for FAT in FAT_sectors:
            buf += self.get_sector(FAT)
        self.FAT_array = self.make_integer_list(buf, ctypes.sizeof(c_uint32))

        buf = b''
        start_sector = self.cfb_header.FirstMiniFATSectorLocation
        if self.cfb_header.NumberOfMiniFATSectors > 1:
            buf = self.read_stream_from_FAT_array(start_sector)
        else:
            buf = self.get_sector(start_sector)
        self.mini_FAT_array = self.make_integer_list(buf, ctypes.sizeof(c_uint32))
        pass
    
    def parse_root_entry(self)->None:
        buf = self.read_stream_from_FAT_array(self.cfb_header.FirstDirectorySectorLocation)
        dir_entry = DirectoryEntry()
        dir_entry.cast(buf[0:0+DIRECTORYENTRYSIZE])
        self.root_entry = dir_entry

    def parse_directory_entry(self) -> None:
        buf = self.read_stream_from_FAT_array(self.cfb_header.FirstDirectorySectorLocation)
        for i in range(0, len(buf), DIRECTORYENTRYSIZE):
            dir_entry = DirectoryEntry()
            dir_entry.cast(buf[i:i+DIRECTORYENTRYSIZE])
            dir_entry.stream = self.get_dir_entry_stream(dir_entry)
            self.dir_entry_array.append(dir_entry)
        pass
    
    def parse_mini_FAT_stream(self) -> None:
        self.mini_FAT_stream = self.read_stream_from_FAT_array(self.root_entry.StartingSectorLocation)
        pass
    
    def parse(self):
        self.parse_cfb_header()
        if bytes(self.cfb_header.HeaderSignature) != MAGIC_ID:
            self.logger.error("File is not OLE Binary")
            raise FilsIsNotOLEBinaryError
        self.parse_sectors()
        self.parse_root_entry()
        self.parse_mini_FAT_stream()
        self.parse_directory_entry()
        return True

    def read_stream_from_FAT_array(self, start_sector):
        sector_index = start_sector
        buf = b''
        while sector_index not in (ENDOFCHAIN, FREESECT):
            buf = buf + self.get_sector(sector_index)
            sector_index = self.FAT_array[sector_index]
        return buf

    def read_stream_from_mini_FAT_array(self, start_sector):
        buf = b''
        sector_index = start_sector
        while sector_index not in (ENDOFCHAIN, NOSTREAM) and sector_index < MAXREGSID:
            buf = buf + self.get_mini_sector(sector_index)
            sector_index = self.mini_FAT_array[sector_index]
        return buf

    def get_mini_sector(self, sector_index):
        offset = sector_index * MINISECTORSIZE
        buf = self.mini_FAT_stream[offset:offset+MINISECTORSIZE]
        return buf

    def get_sector(self, sector_index):
        offset = (sector_index + 1) * SECTORSIZE

        return self.ole_bin[offset:offset + SECTORSIZE]

    def make_integer_list(self, buf, size_of_type) -> list:
        if len(buf) % size_of_type != 0:
            return None
        l = []
        fmt = 'c'
        if size_of_type == (1 << 0):
            fmt = 'B'
        elif size_of_type == (1 << 1):
            fmt = 'H'
        elif size_of_type == (1 << 2):
            fmt = 'I'
        elif size_of_type == (1 << 3):
            fmt = 'Q'
        for i in range(0, len(buf), size_of_type):
            l.append(
                struct.unpack('<'+fmt, buf[i:i+size_of_type])[0]
            )
        return l

    def print_dir_entry_all(self, entry_id=0, depth=0):
        dir_entry:DirectoryEntry = self.dir_entry_array[entry_id]
        tab = '    ' * depth
        print('[%02d]' % entry_id + tab + bytes(dir_entry.DirectoryEntryName).decode('utf16'))
        if dir_entry.ChildID != NOSTREAM:
            depth += 1
            self.print_dir_entry_all(dir_entry.ChildID, depth)
        if dir_entry.LeftSiblingID != NOSTREAM:
            self.print_dir_entry_all(dir_entry.LeftSiblingID, depth)
        if dir_entry.RightSiblingID != NOSTREAM:
            self.print_dir_entry_all(dir_entry.RightSiblingID, depth)

    def get_dir_entry_all(self, strt_dict={}, entry_id=0, depth=0):
        dir_entry:DirectoryEntry = self.dir_entry_array[entry_id]
        nm = bytes(dir_entry.DirectoryEntryName).decode('utf16').replace("\x00", "")
        strt_dict[nm] = {}
        if dir_entry.ChildID != NOSTREAM:
            depth += 1            
            self.get_dir_entry_all(entry_id=dir_entry.ChildID, strt_dict=strt_dict[nm], depth=depth)      
        if dir_entry.ChildID == NOSTREAM:
            strt_dict[nm] = dir_entry.StreamSize
        if dir_entry.LeftSiblingID != NOSTREAM:
            self.get_dir_entry_all(entry_id=dir_entry.LeftSiblingID, strt_dict=strt_dict, depth=depth)
        if dir_entry.RightSiblingID != NOSTREAM:
            self.get_dir_entry_all(entry_id=dir_entry.RightSiblingID, strt_dict=strt_dict, depth=depth)

        pass

    def get_dir_entry(self, entry_id):
        try:
            return self.dir_entry_array[entry_id]
        except IndexError:
            return -1

    def get_dir_entry_id_by_name(self, name, sub_str_match=False, regex=False):
        for entry_id in range(0, len(self.dir_entry_array)):
            cur_dir_entry = self.dir_entry_array[entry_id]
            dir_entry_name = bytes(cur_dir_entry.DirectoryEntryName).decode('utf16').replace('\x00', '')
            if sub_str_match:
                if name in dir_entry_name:
                    return cur_dir_entry
            elif regex:
                import re
                q = re.compile(name)
                m = q.search(dir_entry_name)
                if m:
                    return cur_dir_entry
            else:
                if name == dir_entry_name:
                    return entry_id
        return -1

    def get_dir_entry_by_name(self, name, sub_str_match=False, regex=False):
        entry_id = self.get_dir_entry_id_by_name(name, sub_str_match, regex)
        if entry_id:
            return self.dir_entry_array[entry_id]
        return None

    def get_dir_entry_stream(self, entry):
        if type(entry) == int:
            dir_entry = self.dir_entry_array[entry]
        elif type(entry) == DirectoryEntry:
            dir_entry = entry
        else:
            raise Exception("Invalid Argument")
        buf = b''

        if dir_entry.ObjectType == STORAGE:
            return b''

        stream_sz = dir_entry.StreamSize
        start_sector = dir_entry.StartingSectorLocation

        if stream_sz < MINISTREAMCUTOFFSIZE and dir_entry.ObjectType != ROOT:
            buf = self.read_stream_from_mini_FAT_array(start_sector)
        else:
            buf = self.read_stream_from_FAT_array(start_sector)

        return buf
    

if __name__ == '__main__':
    ole_parser = OleParser()
    ole_parser.read_ole_binary('./sample/sample.hwp')
    r = ole_parser.parse()
    ole_parser.print_dir_entry_all()
    bin_data_id = ole_parser.get_dir_entry_id_by_name('FileHeader')
    file_header = ole_parser.get_dir_entry_by_name('FileHeader')
    print(file_header.size())
    print(file_header.name())
    print(file_header.name_raw())
    #buf = ole_parser.get_dir_entry_stream(bin_data_id)