from typing import List

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QStandardItemModel, QStandardItem
from PyQt6.QtWidgets import QWidget, QScrollArea, QVBoxLayout, QPushButton, QFrame, QHBoxLayout, QLabel, QListWidget, \
    QListView

from app.data_manager import DataManager
from widgets import IconButton, get_local_icon


class Sidebar(QWidget):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.setFixedWidth(64)

        self._topBar = QListView()
        self._bottomBar = QListView()
        self._separator = QFrame()
        self._separator.setFrameShape(QFrame.Shape.HLine)
        self._separator.setLineWidth(3)

        # should be read from registry!

        self._topBarModel = QStandardItemModel()
        self._topBarModel.appendRow(QStandardItem("Headers"))
        self._topBarModel.appendRow(QStandardItem("Functions"))
        self._topBar.setModel(self._topBarModel)
        self._topBar.setIconSize(QSize(32, 32))

        self._bottomBarModel = QStandardItemModel()
        self._bottomBarModel.appendRow(QStandardItem("Types"))
        self._bottomBarModel.appendRow(QStandardItem("Enums"))
        self._bottomBar.setModel(self._bottomBarModel)
        self._bottomBar.setIconSize(QSize(32, 32))

        self._buttonOrder = [0, 1, 2, 3]

        self._layout = QVBoxLayout()
        self._layout.addWidget(self._topBar)
        self._layout.addWidget(self._separator)
        self._layout.addWidget(self._bottomBar)
        self.setLayout(self._layout)

class SidePanel(QWidget):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._title = ""
        self._layout = QVBoxLayout()
        self._topLayout = QHBoxLayout()
        self._topLayout.addWidget(QLabel(self.title))

    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, title: str) -> None:
        self._title = title


class FunctionsPanel(SidePanel):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._funcList = QListWidget()
        self._topLayout.addWidget(self._funcList)
    

    @property
    def title(self) -> str:
        return "Functions"

