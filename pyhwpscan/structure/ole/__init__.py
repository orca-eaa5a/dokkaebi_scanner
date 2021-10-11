import os
import sys
import inspect

sys.path.insert(0, 
    os.path.dirname(
         os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    )
)
  
import c_style_structure
from c_style_structure import CStyleStructure