from pyparser.oleparser import OleParser
from pyparser.hwp_parser import HwpParser
from scan.init_scan import init_scan
from scan.binData_scanner import scan_BinData
from scan.jscript_scanner import scan_JScript

import os

from common.errors import *

class NotOLEBinaryError(Exception):
    def __str__(self):
        return "Parsed file is not a OLE binary"

if __name__ == '__main__':
    file = "javascript_abuse.hwp.bin"
    ole_parser = OleParser()
    ole_parser.read_ole_binary('./sample/'+file)
    print(">> [%s] scanning..." % file)
    r = ole_parser.parse()
    if not r:
        print("[%s] is not a OLE File.." % file)
        print("Please check..")
        raise NotOLEBinaryError
    
    hwp_parser = HwpParser(ole_parser)
    hwp_parser.parse()
    if not init_scan(hwp_parser.hwp_header):
        exit(-1)

    scan_res = scan_JScript(hwp_parser)
    