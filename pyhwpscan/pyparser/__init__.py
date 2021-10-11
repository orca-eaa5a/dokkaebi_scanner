import os
import sys
import inspect

sys.path.insert(0, 
    os.path.dirname(
         os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    )
) 
from structure import ole
from structure.ole import cfb_header
from structure.ole.dir_entry import DirectoryEntry
from structure.ole.ole_const import ENDOFCHAIN, FREESECT, MAGIC_ID, MAXFATENTRY, NOSTREAM, STORAGE, ROOT, SECTORSIZE, MAXREGSID, MINISECTORSIZE, DIRECTORYENTRYSIZE

from structure.hwp.hwp_header import HWPHeader
from structure.hwp.hwp_bindata import HWPBinData
from structure.hwp.hwp_docinfo import HWPDocInfo
from structure.hwp.hwp_script import HWPJScript
from structure.hwp.hwp_bodytext import HWPBodyText

__author__ = ["orca.eaa5a dlfguswn@naver.com"]
__version__ = "1.0.0"