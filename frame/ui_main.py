from io import BytesIO
import io
import os
import sys
import threading
from zlib import decompress
import PySide2
import hexdump
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QMessageBox, QMainWindow
from PySide2.QtCore import QFile, QIODevice, QTimer, Signal, QEvent, QObject, QThread
from PySide2.QtGui import QIcon, QStandardItemModel, QFont, QTextDocument, QTextOption
from PySide2.QtWidgets import *
from xml.sax.saxutils import escape as escape

from pyhwpscan.hwp_scan import HWPScanner

#from pyhwpscan.hwp_scan import HWPScanner

WINDOW_STATE = 0
global _path
global current_tree_widget_name

def show_error_dialog(title, text):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Warning)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()

def load_mainwindow(ui_file, frame_path):
    global _path

    _path = os.path.join(os.getcwd(), frame_path)
    q_file = QFile(ui_file)
    if not q_file.open(QIODevice.ReadOnly):
        show_error_dialog("error", "unable to open {} file".format(ui_file))
        sys.exit(-1)
    q_loader = QUiLoader()
    main_window = q_loader.load(q_file)
    q_file.close()
    if not main_window:
        show_error_dialog("error", "unable to load {} file".format(ui_file))
        sys.exit(-1)

    return main_window

def clickable(widget, type, function):
    class Filter(QObject):
        clicked = Signal()	#pyside2 사용자는 pyqtSignal() -> Signal()로 변경
        def eventFilter(self, obj, event):
            if obj == widget:
                if event.type() == type:
                    function(event)
                    self.clicked.emit()
                    return True
            return False
    filter = Filter(widget)
    widget.installEventFilter(filter)
    return filter.clicked
            
class HexDump:
    def __init__(self, QMainWindow, off_window, hex_window, ascii_window) -> None:
        self.lines = None
        self.total_length = 0
        self.current_line = 0
        self.QMainWindow = QMainWindow
        self.off_window = off_window
        self.hex_window = hex_window
        self.ascii_window = ascii_window
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_hexdump)
        self.timer.setInterval(500)
        pass

    def set_target(self, buf) -> None:
        dump = hexdump.hexdump(buf, 'return')
        sstream = io.StringIO(dump)
        self.lines = sstream.readlines()
        self.total_length = len(self.lines)
    
    def get_chunks(self, start_line, end_line=None) -> int:
        chunk = None
        if not end_line:
            end_line = 1000
        if start_line + end_line > self.total_length:
            self.current_line = self.total_length
            chunk = self.lines[start_line:]
        else:
            chunk = self.lines[start_line:start_line+end_line]
            self.current_line = start_line+end_line

        off = ""
        _hex = ""
        _ascii = ""
        for line in chunk: # parse hexdump lib output
            off += line[1:8]+"\n"
            _hex += line[10:58]+"\n"
            _ascii += line[60:]
        
        off = off[:-1]
        _hex = _hex[:-1]
        _ascii = _ascii[:-1]

        return off, _hex, _ascii

    def load(self):
        self.timer.start()

    def check_loading(self):
        return self.timer.isActive()

    def quit_loading(self):
        self.timer.stop()

    def load_hexdump(self):
        off, _hex, _ascii = self.get_chunks(self.current_line)
        sb1_v = self.QMainWindow.scroll_bar1.value()
        sb2_v = self.QMainWindow.scroll_bar2.value()
        sb3_v = self.QMainWindow.scroll_bar3.value()
        self.hex_window.append(_hex)
        self.ascii_window.append(_ascii)
        self.off_window.append(off)
        if self.current_line == self.total_length:
            self.timer.stop()
        self.QMainWindow.scroll_bar1.setValue(sb1_v)
        self.QMainWindow.scroll_bar2.setValue(sb2_v)
        self.QMainWindow.scroll_bar3.setValue(sb3_v)

class HwpScanMainWindow(QMainWindow):
    def __init__(self, main_window) -> None:
        global current_tree_widget_name
        current_tree_widget_name = ""
        self.main_window = main_window
        self.set_mainwindow_property()
        self.load_resources()
        self.setup_ui_event_listener()
        self.full_path = ""
        self.hwp_scanner = None
        self.raw_hexdump = HexDump(self, self.main_window.offsetview, self.main_window.hexview, self.main_window.asciiview)
        
        pass

    def set_mainwindow_property(self):
        global WINDOW_STATE
        self.main_window.setWindowFlag(PySide2.QtCore.Qt.FramelessWindowHint)
        self.main_window.setAttribute(PySide2.QtCore.Qt.WA_TranslucentBackground)
        self.main_window.asciiview.setWordWrapMode(PySide2.QtGui.QTextOption.WrapMode.WrapAnywhere);
        self.main_window.hexview.setFont(QFont('Courier New', 15))
        self.main_window.asciiview.setFont(QFont('Courier New', 15))
        self.main_window.offsetview.setFont(QFont('Courier New', 15))
        
        self.scroll_bar1 = self.main_window.offsetview.verticalScrollBar()
        self.scroll_bar2 = self.main_window.hexview.verticalScrollBar()
        self.scroll_bar3 = self.main_window.asciiview.verticalScrollBar()
        #self.scroll_bar1_prev_value = self.scroll_bar1.value()
        #self.scroll_bar2_prev_value = self.scroll_bar2.value()
        #self.scroll_bar3_prev_value = self.scroll_bar3.value()
        
        self.main_window.showMaximized()

        WINDOW_STATE = 1

    def ui_event_sycnscroll(self, scroll_bar, targ1, targ2):
        sliderValue = scroll_bar.value()
        targ1.setValue(sliderValue)
        targ2.setValue(sliderValue)

    def ui_event_fullscreen(self):
        global WINDOW_STATE
        status = WINDOW_STATE

        if status == 0:
            self.main_window.showMaximized()

            WINDOW_STATE = 1
            self.main_window.base_layout_widget.setContentsMargins(0, 0, 0, 0)
            self.main_window.frame_titlebar.setStyleSheet("background-color: rgba(51, 51, 51, 255);")
            self.main_window.frame_statusbar.setStyleSheet("background-color: rgba(223, 225, 229, 255);")
            self.main_window.maximize_btn.setToolTip("Restore")
        else:
            WINDOW_STATE = 0
            self.main_window.showNormal()
            self.main_window.resize(self.main_window.width()+1, self.main_window.height()+1)
            self.main_window.base_layout_widget.setContentsMargins(10, 10, 10, 10)
            self.main_window.frame_titlebar.setStyleSheet("background-color: rgba(51, 51, 51, 255); border-top-right-radius: 7px; border-top-left-radius: 7px;")
            self.main_window.frame_statusbar.setStyleSheet("background-color: rgba(223, 225, 229, 255); border-bottom-right-radius: 7px; border-bottom-left-radius: 7px;")
            self.main_window.maximize_btn.setToolTip("Maximize")

    def ui_event_minimize(self):
        self.main_window.showMinimized()

    def ui_event_close_window(self):
        self.main_window.close()

    def ui_event_window_clicked(self, event):
        self.main_window.dragPos = event.globalPos()

    def ui_event_move_window(self, event):
        global WINDOW_STATE
        if WINDOW_STATE == 1: # full screen
            self.ui_event_fullscreen()
        if event.buttons() == PySide2.QtCore.Qt.LeftButton:
            self.main_window.move(self.main_window.pos() + event.globalPos() - self.main_window.dragPos)
            self.main_window.dragPos = event.globalPos()
            event.accept()

    #@PySide2.QtCore.Signal(PySide2.QtWidgets.QTreeWidgetItem, int)
    def ui_event_tab_widget_clicked(self, it, col):
        global current_tree_widget_name
        widget_name = it.text(col)
        current_tree_widget_name = widget_name
        try:
            if not self.hwp_scanner.hwpx_flag:
                dir_entry = self.hwp_scanner.ole_parser.get_dir_entry_by_name(widget_name)
                self.main_window.tabWidget.setCurrentIndex(1)
                decompressed_stream = dir_entry.get_decompressed_stream()
                if decompressed_stream:
                    self.setup_hexview_widget(decompressed_stream)
                else:
                    self.setup_hexview_widget(dir_entry.get_stream())
                
            else:
                target_file = ""
                for f in self.hwp_scanner.hwpx_docs.filelist:
                    if current_tree_widget_name in f.filename:
                        target_file = f.filename
                if not target_file:
                    QMessageBox.information(self.main_window, 'Error', "Selected File is not Exist")
                else:   
                    _bin = self.hwp_scanner.hwpx_docs.read(target_file)
                    self.main_window.tabWidget.setCurrentIndex(1)
                    self.setup_hexview_widget(_bin)
                
        except Exception as e:
            print(e)
        pass

    def ui_event_fileopen_button_clicked(self):
        fname = QFileDialog.getOpenFileName(self.main_window, 'Open file', './')
        if fname[0]:
            self.full_path = fname[0]
            self.file_name = os.path.split(self.full_path)[-1]
            with open(fname[0], 'rb') as f:
                self.buf = f.read()
            self.widget_clear()
            del self.hwp_scanner
            self.hwp_scanner = HWPScanner()
            self.hwp_scanner.parse_hwpdoc(self.full_path)
            self._file_strt_ = self.hwp_scanner.get_file_structure()
            self.setup_tree_view_widget(self._file_strt_)
            
        pass

    def ui_event_scan_button_clicked(self):
        self.main_window.tabWidget.setCurrentIndex(0)
        self.hwp_scanner.setup_scanner()
        scan_result = self.hwp_scanner.scan()
        if scan_result:
            self.main_window.scan_result.setText(scan_result)
            QMessageBox.information(self.main_window, 'Info', "Threat Detected!")
        else:
            self.main_window.scan_result.setText("No Threat Detected!")
        pass
    
    def ui_event_export_button_clicked(self):
        global current_tree_widget_name

        if not current_tree_widget_name:
            reply = QMessageBox.information(self.main_window, 'Error', 'Please select export target')
            pass
        else:
            dirname = QFileDialog.getExistingDirectory(self.main_window, 'Open file', './')
            if dirname:
                export_path = os.path.join(dirname, current_tree_widget_name+".dmp")
                try:
                    with open(export_path, 'wb') as fp:
                        buf = b''
                        if not self.hwp_scanner.hwpx_flag:
                            dir_entry = self.hwp_scanner.ole_parser.get_dir_entry_by_name(current_tree_widget_name)
                            try:
                                buf = dir_entry.get_decompressed_stream()
                            except Exception as e:
                                print(e)
                                buf = dir_entry.get_stream()
                        else:
                            target_file = ""
                            for f in self.hwp_scanner.hwpx_docs.filelist:
                                if current_tree_widget_name in f.filename:
                                    target_file = f.filename
                                    break
                            if not target_file:
                                QMessageBox.information(self.main_window, "Error", "Can not export target file")
                            else:
                                buf = self.hwp_scanner.hwpx_docs.read(target_file)
                        fp.write(buf)
                        QMessageBox.information(self.main_window, 'Info', 'Export file Success!\n%s' % export_path)
                except Exception as e:
                    QMessageBox.information(self.main_window, 'Error', 'Export file faild..')    
        
        pass


    def load_resources(self):
        global _path
        resource_dir = "rsrc"
        self.docs_icon = QIcon(os.path.join(_path, resource_dir, "docs.png"))
        self.doc_folder_icon = QIcon(os.path.join(_path, resource_dir, "doc_folder.png"))
        self.main_window.fileopen_btn.setStyleSheet("""
            QPushButton#fileopen_btn{
                border-image: url("./frame/rsrc/folder.png");
            }
            QPushButton#fileopen_btn:hover {
                background-color: rgba(10, 149, 255, 0.3);
                border-radius: 6px;
            }
            QPushButton#fileopen_btn:pressed {
                background-color: rgba(10, 149, 255, 0.8);
                border-radius: 6px;
            }
            """
        )
        self.main_window.fileopen_btn.setToolTip("파일 열기")
        
        self.main_window.scan_btn.setStyleSheet("""
            QPushButton#scan_btn{
                border-image: url("./frame/rsrc/file_scan.png");
            }
            QPushButton#scan_btn:hover {
                background-color: rgba(10, 149, 255, 0.3);
                border-radius: 6px;
            }
            QPushButton#scan_btn:pressed {
                background-color: rgba(10, 149, 255, 0.8);
                border-radius: 6px;
            }
        """
        )
        self.main_window.scan_btn.setToolTip("스캔")

        self.main_window.export_btn.setStyleSheet("""
            QPushButton#export_btn{
                border-image: url("./frame/rsrc/export.png");
            }
            QPushButton#export_btn:hover {
                background-color: rgba(10, 149, 255, 0.3);
                border-radius: 6px;
            }
            QPushButton#export_btn:pressed {
                background-color: rgba(10, 149, 255, 0.8);
                border-radius: 6px;
            }
        """
        )
        self.main_window.export_btn.setToolTip("추출")

    def widget_clear(self):
        from PySide2.QtWidgets import QTreeWidgetItemIterator
        #self.main_window.ole_tree.itemClicked.disconnect()
        current_tree_widget_name = None
        iterator = QTreeWidgetItemIterator(self.main_window.ole_tree, QTreeWidgetItemIterator.All)
        if iterator.value():
            self.main_window.ole_tree.itemClicked.disconnect()
        while iterator.value():
            iterator.value().takeChildren()
            iterator += 1
        i = self.main_window.ole_tree.topLevelItemCount()
        while i > -1:
            self.main_window.ole_tree.takeTopLevelItem(i)
            i -= 1
        self.main_window.scan_result.setText("")
        self.main_window.hexview.setText("")
        self.main_window.asciiview.setText("")
        self.main_window.offsetview.setText("")

    def setup_ui_event_listener(self):
        self.main_window.maximize_btn.clicked.connect(self.ui_event_fullscreen)
        self.main_window.minimize_btn.clicked.connect(self.ui_event_minimize)
        self.main_window.close_btn.clicked.connect(self.ui_event_close_window)
        self.main_window.fileopen_btn.clicked.connect(self.ui_event_fileopen_button_clicked)
        self.main_window.scan_btn.clicked.connect(self.ui_event_scan_button_clicked)
        self.main_window.export_btn.clicked.connect(self.ui_event_export_button_clicked)
        clickable(self.main_window.frame_titlebar, QEvent.MouseButtonPress, self.ui_event_window_clicked).connect(lambda:None)
        clickable(self.main_window.frame_titlebar, QEvent.MouseMove, self.ui_event_move_window).connect(lambda:None)
        self.scroll_bar1.valueChanged.connect(lambda: self.ui_event_sycnscroll(self.scroll_bar1, self.scroll_bar2, self.scroll_bar3))
        
    def setup_tree_view_widget(self, file_strt):
        def make_with_depth(cur_widget, cur_pos):
            for keys in cur_pos:
                if type(cur_pos[keys]) == int:
                    widget = QTreeWidgetItem(cur_widget)
                    widget.setIcon(0, self.docs_icon)
                    widget.setText(0, keys)
                    
                else:
                    widget = QTreeWidgetItem(cur_widget)
                    widget.setIcon(0, self.doc_folder_icon)
                    widget.setText(0, keys)
                    make_with_depth(widget, cur_pos[keys])
                    #self.main_window.ole_tree.resizeColumnToContents(1)                    
            return

        #global mock_entry
        entry = file_strt
        self.main_window.ole_tree.setColumnCount(2)
        self.main_window.ole_tree.setHeaderLabels(["Name", "Size"])
        self.main_window.ole_tree.header().setSectionResizeMode(PySide2.QtWidgets.QHeaderView.ResizeToContents)
        #self.main_window.ole_tree.itemChanged.connect(self.ui_event_tree_widget_clicked)
        self.main_window.ole_tree.itemClicked.connect(self.ui_event_tab_widget_clicked)
        widget = QTreeWidgetItem(self.main_window.ole_tree)
        first_key = list(entry.keys())[0]
        widget.setText(0, self.file_name)
        widget.setIcon(0, self.doc_folder_icon)
        make_with_depth(widget, entry)
        del entry
        del first_key

    
    def setup_hexview_widget(self, buf):
        #self.renew_hexview_widget(None)
        if self.raw_hexdump.check_loading():
            self.raw_hexdump.quit_loading()

        self.raw_hexdump.set_target(buf)
        off, _hex, _ascii = self.raw_hexdump.get_chunks(0, 100) # load first 100 line
        self.main_window.hexview.setText(_hex)
        self.main_window.asciiview.setText(_ascii)
        self.main_window.offsetview.setText(off)
        self.raw_hexdump.load()

    def launch(self):
        self.main_window.show()