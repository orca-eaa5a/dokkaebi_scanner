from threading import current_thread

from jsbeautifier.javascript.beautifier import remove_redundant_indentation
from pyparser.oleparser import OleParser
from pyparser.hwp_parser import HwpParser
from scan.init_scan import init_hwp5_scan
from scan.bindata_scanner import BinData_Scanner
from scan.jscript_scanner import JS_Scanner
from scan.paratext_scanner import ParaText_Scanner
import zipfile
import os
import sys
import platform
from common.errors import *
from utils.dumphex import print_hexdump

js_scanner = None
bindata_scanner = None
paratext_scanner = None
_platform = None
binary_info = {
    "type": "",
    "p": None
}

def cmd_handler(cmdline):
    global binary_info
    global js_scanner
    global bindata_scanner
    global paratext_scanner
    global _platform

    ty = binary_info["type"]
    parser = binary_info["p"]
    
    s_cmd = cmdline.split(" ")
    cmd = s_cmd[0]
    arg = s_cmd[1:]

    if "windows" in _platform:
        os.system('cls')
    else:
        os.system('clear')

    print(">> "+cmdline)
    if cmd == "help":
        
        print("> tree")
        print("  Print the structure of target Binary")

        print("> dump [binary_name] [directory]")
        print("  Dump OLE or Zipped Binary at specific direcotry (default is current direcotry)")
        
        print("> show-hex [binary_name]")
        print("  Print hexcidecimal view of specific OLE or Zipped Binary")
        
        print("> scan")
        print("  re-scanning the target file")

        print("> exit")
        print("  quit command liner")
        return 1

    elif cmd == "clear":
        if "windows" in _platform:
            os.system('cls')
        else:
            os.system('clear')
        return 0

    elif cmd == "tree":
        if ty == "hwp":
            parser.ole_container.print_dir_entry_all()
        else:
            for file in parser.filelist:
                print(file.filename)
        return 0

    elif cmd == "dump":
        if len(arg) > 1:
            binary_name, target_dir = arg[0], arg[1]
        else:
            binary_name, target_dir = arg[0], None
        
        if not target_dir:
            target_dir = os.getcwd()
        
        if ty == "hwp":
            stream = parser.ole_container.get_dir_entry_by_name(binary_name).get_decompressed_stream()
        else:
            targ = ""
            for file in parser.filelist:
                fname = file.filename.split("/")[-1]
                if fname == binary_name:
                    targ = file.filename
                    break
            if not targ:
                print("no file exist")
                return 0
            stream = parser.read(targ)
        with open(target_dir+"/"+binary_name, "wb") as f:
            f.write(stream)

        print("dump succeed..")
        return 1

    elif cmd == "show-hex":
        binary_name = arg[0]
        if ty == "hwp":
            stream = parser.ole_container.get_dir_entry_by_name(binary_name).get_decompressed_stream()
        else:
            stream = parser.read(binary_name)
        print_hexdump(stream)
        return 1

    elif cmd == "scan":
        if ty == "hwp":
            bindata_scanner.scan()
            js_scanner.scan()
        else:
            paratext_scanner.scan()
        return 1
    
    elif cmd == "exit":
        return -1
    else:
        print("unknown command..")
        return 0
    print()

class HWPScanner:
    def __init__(self) -> None:
        self.__platform__ = platform.platform()
        self.hwpx_flag = False
        self.ole_parser = OleParser()
        self.hwp_parser = None
        pass

    def parse_hwpdoc(self, file_name):
        self.file_name = file_name
        self.ole_parser.read_ole_binary(file_name)
        try:
            self.ole_parser.parse()
            self.hwp_parser = HwpParser(self.ole_parser)
            self.hwp_parser.parse()
            if not init_hwp5_scan(self.hwp_parser.hwp_header):
                exit(-1)
        except:
            self.hwpx_docs = zipfile.ZipFile(self.file_name, "r")
            self.hwpx_flag = True 
        pass
    '''
    def parse_hwpdoc(self):
        try:
            self.hwp_parser = HwpParser(self.ole_parser)
            self.hwp_parser.parse()
            if not init_hwp5_scan(self.hwp_parser.hwp_header):
                exit(-1)
            
        except:
            self.hwpx_docs = zipfile.ZipFile(self.file_name, "r")
            self.hwpx_flag = True            
        pass
    '''
    def setup_scanner(self):
        if not self.hwpx_flag:
            self.js_scanner = JS_Scanner(self.hwp_parser)
            self.bindata_scanner = BinData_Scanner(self.hwp_parser)
        else:
            self.paratext_scanner = ParaText_Scanner(self.hwpx_docs)

    def get_file_structure(self):
        strt = {}
        if not self.hwpx_flag:
            self.ole_parser.get_dir_entry_all(strt, entry_id=0, depth=0)
        else:

            for _file in self.hwpx_docs.filelist:
                _path = os.path.split( _file.filename)
                if _path[0] not in strt:
                    # root
                    if _path[0]:
                        strt[_path[0]] = {}
                    else:
                        strt[_path[1]] = _file.file_size
                        continue
                cur_strt = strt[_path[0]]
                for path in _path:
                    if path not in strt:
                        if path == _path[-1]:
                            cur_strt[path] = _file.file_size
                        else:
                            cur_strt[path] = {}
                            cur_strt = cur_strt[path]
                    else:
                        cur_strt = strt[path]
                    
        return strt

    def scan(self):
        scan_result = ""
        if not self.hwpx_flag:
            scan_result += self.js_scanner.scan()
            scan_result += self.bindata_scanner.scan()
        else:
            scan_result += self.paratext_scanner.scan()
        return scan_result