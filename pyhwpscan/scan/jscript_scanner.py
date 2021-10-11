from utils.beautify_js import beautify_js
import logging
import math
import yara
import os
import re


class JS_Scanner:
    _path_ = os.path.split(os.path.abspath(__file__))[0]
    jscript_scan_rule = yara.compile(os.path.join(_path_, "yara", "jscript", "suspicious_js.yar"))
    entropy_threshold = 5.44203995
    obfu_threshold = 13.6808922
    @staticmethod
    def obfuscation_scan(jscript_str):
        def get_everage_string_length(jscript_str):
            strs = re.split("[=;(){}]", jscript_str)
            len_sum = 0
            for _str in strs:
                len_sum += len(_str)
            return len_sum / len(strs)

        score = get_everage_string_length(jscript_str)

        if score > JS_Scanner.obfu_threshold:
            return (score, "JS.Heur.Ob#1")
        return (0, "")

    @staticmethod
    def entropy_scan(jscript_str):
        def get_shannon_entropy(jscript_str):
            prob = [ float(jscript_str.count(c)) / len(jscript_str) for c in dict.fromkeys(list(jscript_str)) ]
            entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

            return entropy

        entropy = get_shannon_entropy(jscript_str)
        if JS_Scanner.entropy_threshold < entropy:
            return (entropy, "JS.Heur.Ob#2")
        return (0, "")

    @staticmethod
    def js_yara_scan(jscript_str):
        match = JS_Scanner.jscript_scan_rule.match(data=jscript_str)
        res = []
        if match:
            for matched in match["main"]:
                res.append(matched["meta"]["tag"])
        return res

    def __init__(self, hwp_parser, is_debug=False) -> None:
        self.is_debug = is_debug
        if self.is_debug:
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            self.console_logger = logging.StreamHandler()
            self.formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            self.console_logger.setFormatter(self.formatter)
            self.logger.addHandler(self.console_logger)
        self.hwp_parser = hwp_parser
        pass

    def scan(self):
        result = ""
        for jscript_stream in self.hwp_parser.hwp_jscript.script_streams:
            b_js = beautify_js(jscript_stream.get_script_str())
            if not b_js:
                if self.is_debug:
                    self.logger.error("target javascript is not invalid")
                pass
            else:
                obf_scan = JS_Scanner.obfuscation_scan(b_js)
                entropy_scan = JS_Scanner.entropy_scan(b_js)
                yar_scan = JS_Scanner.js_yara_scan(b_js)
                if obf_scan[0] != 0:
                    if self.is_debug:
                        self.logger.info("ObfuscationScan#1")
                        self.logger.info("   Average string length of generic javascipts is %f" % JS_Scanner.obfu_threshold)
                        self.logger.info("   Current average string length of javascript is %f" % obf_scan[0])
                    print("[%s] >>> %s"%(jscript_stream.name(), obf_scan[1]))
                    result += "[%s] >>> %s"%(jscript_stream.name(), obf_scan[1])+"\n"
                if entropy_scan[0] != 0:
                    if self.is_debug:
                        self.logger.info("ObfuscationScan#2")
                        self.logger.info("   Average entropy of generic javascipts is %f" % JS_Scanner.obfu_threshold)
                        self.logger.info("   Current entropy of javascript is %f" % entropy_scan[0])
                    print("[%s] >>> %s"%(jscript_stream.name(), entropy_scan[1]))
                    result += "[%s] >>> %s"%(jscript_stream.name(), obf_scan[1])+"\n"
                if yar_scan:
                    for res in yar_scan:
                        print("[%s] >>> %s"%(jscript_stream.name(), res))
                        result += "[%s] >>> %s"%(jscript_stream.name(), obf_scan[1])+"\n"
        return result