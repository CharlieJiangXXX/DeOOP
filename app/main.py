from typing import List

from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QFileSystemModel
from PyQt6.QtWidgets import QApplication, QMainWindow

from app.widgets import DeOOPTreeView
from main_window import DeOOPWindow
from config import *
import sys
from data_manager import DataManager

class TestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._treeView = DeOOPTreeView()
        model = QFileSystemModel()
        model.setRootPath("C:/Users/")
        self._treeView.setModel(model)
        self.setCentralWidget(self._treeView)

class DeOOPApplication(QApplication):
    def __init__(self, argv: List[str]):
        super().__init__(argv)
        self._window = DeOOPWindow()
        self._window.show()
        self.setOrganizationName(COMPANY_NAME)
        self.setOrganizationDomain(DOMAIN_NAME)
        self.setApplicationName(PRETTY_NAME)


sys.exit(DeOOPApplication(sys.argv).exec())
