import logging
import yara
import os

class ParaText_Scanner:
    _path_ = os.path.split(os.path.abspath(__file__))[0]
    cve_2015_6585_rule = yara.compile(os.path.join(_path_, "yara", "para_text", "cve-2015-6585.yar"))
    
    @staticmethod
    def ps_cve_scan(yar_rule, buf):
        match = yar_rule.match(data=buf)
        res = []
        if match:
            for matched in match["main"]:
                res.append(matched["meta"]["tag"])
        return res

    def __init__(self, hwpx, is_debug=False) -> None:
        self.is_debug = is_debug
        if self.is_debug:
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            self.console_logger = logging.StreamHandler()
            self.formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            self.console_logger.setFormatter(self.formatter)
            self.logger.addHandler(self.console_logger)
        self.hwpx = hwpx
        pass

    def scan(self):
        res = ""
        for file in self.hwpx.filelist:
            if "section" not in file.filename.lower():
                continue
            section = self.hwpx.read(file.filename)
            match = ParaText_Scanner.ps_cve_scan(ParaText_Scanner.cve_2015_6585_rule, section)
            for m in match:
                print("[%s] >>> %s"%(file.filename, m))
                res += "[%s] >>> %s"%(file.filename, m)+"\n"
        return res