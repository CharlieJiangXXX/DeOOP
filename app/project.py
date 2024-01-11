from dataclasses import dataclass
from typing import Callable, List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QFont, QAction, QStandardItemModel
from PyQt6.QtWidgets import QMainWindow, QPushButton, QSplashScreen, QApplication, QVBoxLayout, QHBoxLayout, \
    QWidget, QLabel, QStackedWidget, QListView

from app.data_manager import DataManager
from app.sidebar import Sidebar
from widgets import TabWidget



class EmptyScreen(QWidget):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._layout = QVBoxLayout()
        self._layout.addWidget(QLabel("Open a header or function to proceed!"))
        self.setLayout(self._layout)

class ProjectWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self._sidebar = Sidebar()
        self._mainView = QStackedWidget()
        self._emptyScreen = EmptyScreen()
        self._tabs = TabWidget()
        self._tabs.setTabsClosable(True)
        self._mainView.addWidget(self._emptyScreen)
        self._mainView.addWidget(self._tabs)

        self._mainLayout = QHBoxLayout()
        self._mainLayout.addWidget(self._sidebar)
        self._mainLayout.addWidget(self._mainView)
        self._statusBar = QPushButton("status")

        self._layout = QVBoxLayout()
        self._layout.addLayout(self._mainLayout)
        self._layout.addWidget(self._statusBar)

        self._container = QWidget()
        self._container.setLayout(self._layout)
        self.setCentralWidget(self._container)

        self._menubar = self.menuBar()
        self._fileMenu = self._menubar.addMenu('File')
        self._exitAction = QAction('Exit', self)
        self._exitAction.setShortcut('Ctrl+Q')
        self._exitAction.triggered.connect(QApplication.quit)
        self._fileMenu.addAction(self._exitAction)

        # Create an Edit menu and add actions
        self._editMenu = self._menubar.addMenu('Edit')
        # ... Add edit actions here

        # Create a Help menu and add actions
        self._helpMenu = self._menubar.addMenu('Help')


@dataclass
class Order:
    name: str
    sort: Callable[[List[str]], List[str]]


class FunctionList(QWidget):
    def __init__(self, functions: List[str], orders: List[Order], parent: QWidget = None):
        super().__init__(parent)
        self._functions = {}
        for order in orders:
            self._functions[order.name] = order.sort(functions)
        self._functionView = QListView()
        self._functionModel = QStandardItemModel()
        for function in functions:
            self._functionModel.appendRow(function)
        self._functionView.setModel(self._functionModel)
        self._functionModel.sortRole()
        # orders: alphabetical, start address, segment, length, class, topological