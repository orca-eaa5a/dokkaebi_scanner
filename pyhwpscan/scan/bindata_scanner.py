
from posixpath import join
from utils.dumphex import dump_as_physical_file, print_hexdump
import logging
import yara
import os
import re
import sys
global cve_2017_8921_rule

class BinData_Scanner:
    _path_ = os.path.split(os.path.abspath(__file__))[0]
    cve_2017_8921_rule = yara.compile(os.path.join(_path_, "yara", "eps", "cve-2017-8921.yar"))
    cve_2015_2545_rule = yara.compile(os.path.join(_path_, "yara", "eps", "cve-2015-2545.yar"))
    cve_2013_0808_rule = yara.compile(os.path.join(_path_, "yara", "eps", "cve-2013-0808.yar"))
    
    raw_hex_regex = re.compile(b'[a-fA-F0-9]*')
    def __init__(self, hwp_parser, is_debug=False) -> None:
        self.hwp_parser = hwp_parser
        self.is_debug = is_debug
        if self.is_debug:
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            self.console_logger = logging.StreamHandler()
            self.formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            self.console_logger.setFormatter(self.formatter)
            self.logger.addHandler(self.console_logger)
        self.hwp_parser = hwp_parser

    @staticmethod
    def ps_cve_scan(yar_rule, buf):
        match = yar_rule.match(data=buf)
        res = []
        if match:
            for matched in match["main"]:
                res.append(matched["meta"]["tag"])
        return res

    @staticmethod
    def scan_raw_hexstring(buf):
        hex_string_length_threshold = 0x20
        match = BinData_Scanner.raw_hex_regex.findall(buf)
        for m in match:
            if len(m)%2 != 0:
                continue
            if len(m) > hex_string_length_threshold:
                return "EPS.Heur.SuspiciousBin"
        return ""

    def get_suspicious_ole(self):
        suspicious_record = []
        BinData = self.hwp_parser.hwp_bindata.bindata
        for record in BinData:
            if record.name().split(".")[-1] not in ["jpg", "bmp", "gif", "png"]:
                suspicious_record.append(record)
        return suspicious_record

    def scan(self):
        res = ""
        suspicious_records = self.get_suspicious_ole()
        for record in suspicious_records:
            record_stream = record.get_decompressed_stream()
            cve201308080_yar_scan = BinData_Scanner.ps_cve_scan(BinData_Scanner.cve_2013_0808_rule,record_stream)
            if cve201308080_yar_scan:
                for res in cve201308080_yar_scan:
                    print("[%s] >>> %s"%(record.name(), res))
                    res += "[%s] >>> %s"%(record.name(), res)+"\n"
            
            cve20152545_yar_scan = BinData_Scanner.ps_cve_scan(BinData_Scanner.cve_2015_2545_rule,record_stream)
            if cve20152545_yar_scan:
                for res in cve20152545_yar_scan:
                    print("[%s] >>> %s"%(record.name(), res))
                    res += "[%s] >>> %s"%(record.name(), res)+"\n"
            
            cve20178921_yar_scan = BinData_Scanner.ps_cve_scan(BinData_Scanner.cve_2017_8921_rule,record_stream)
            if cve20178921_yar_scan:
                for res in cve20178921_yar_scan:
                    print("[%s] >>> %s"%(record.name(), res))
                    res += "[%s] >>> %s"%(record.name(), res)+"\n"
            
            hex_scan = BinData_Scanner.scan_raw_hexstring(record_stream)
            if hex_scan:
                print("[%s] >>> %s"%(record.name(), hex_scan))
                res += "[%s] >>> %s"%(record.name(), hex_scan)+"\n"

        return res
        pass