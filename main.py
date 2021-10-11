import os
import sys

from frame.ui_main import load_mainwindow
from frame.ui_main import HwpScanMainWindow
from PySide2.QtCore import QFile, QIODevice
from PySide2.QtWidgets import QApplication
import pyhwpscan
if __name__ == '__main__':
    frame_path = "frame"
    app = QApplication(sys.argv)
    ui_file = os.path.join(os.getcwd(), frame_path,"main.ui")
    main_window = load_mainwindow(ui_file, frame_path)
    window = HwpScanMainWindow(main_window)
    window.launch()
    sys.exit(app.exec_())