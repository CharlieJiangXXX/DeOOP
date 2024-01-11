from typing import List, Callable

from PyQt6 import QtGui
from PyQt6.QtCore import QEvent, Qt, QStringListModel, QRectF, QPoint, QSize, QModelIndex
from PyQt6.QtGui import QPixmap, QEnterEvent, QFont, QStandardItemModel, QFocusEvent, QColor, QPen, QAction, QRegion, \
    QPainter, QIcon
from PyQt6.QtWidgets import QMainWindow, QSplashScreen, QApplication, QWidget, QHBoxLayout, QVBoxLayout, QListView, \
    QFrame, QStyle, QLabel, QPushButton, QStyledItemDelegate, QTabWidget, QLineEdit, QFileDialog, QMenu, QTreeView, \
    QStyleOptionViewItem
from networkx import DiGraph, is_tree

from app.data_manager import DataManager


class IconButton(QPushButton):
    def __init__(self, name: str = "", parent: QWidget = None):
        super().__init__(parent)
        pic = QPixmap(DataManager.get_file(name, 0))
        painter = QPainter()
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        painter.fillRect(pic.rect(), QColor("black"))
        painter.end()
        self.setIcon(QIcon(pic))
        self.setIconSize(QSize(32, 32))

def get_local_icon(name: str) -> QIcon:
    pic = QPixmap(DataManager.get_file(name, 0))
    painter = QPainter()
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(pic.rect(), QColor("black"))
    painter.end()
    return QIcon(pic)


class DeOOPListDelegate(QStyledItemDelegate):
    def __init__(self, editable: bool = False, parent=None):
        super(DeOOPListDelegate, self).__init__(parent)
        self._editable = editable

    def createEditor(self, parent, option, index):
        if not self._editable:
            return None
        return super().createEditor(parent, option, index)

    def paint(self, painter, option, index):
        #return super().paint(painter, option, index)
        # Extract item data
        text = index.data(Qt.ItemDataRole.DisplayRole)
        color = index.data(Qt.ItemDataRole.UserRole) or "white"

        # Start painting
        painter.save()

        def get_color():
            if option.state & QStyle.StateFlag.State_HasFocus:
                return QColor("skyblue")
            if option.state & QStyle.StateFlag.State_MouseOver:
                return QColor("lightskyblue")
            if option.state & QStyle.StateFlag.State_Selected:
                return QColor("silver")
            return QColor(color)

        # Set the background color
        painter.setBrush(get_color())
        painter.setPen(Qt.PenStyle.NoPen)  # No border

        # Draw the rounded rectangle background
        rect = QRectF(option.rect)
        border_radius = 15
        painter.drawRoundedRect(rect, border_radius, border_radius)

        # Set the pen for the text
        painter.setPen(QPen(Qt.GlobalColor.black))

        # Draw the text
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

        painter.restore()

class DeOOPListView(QListView):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.setItemDelegate(DeOOPListDelegate(self))
        self.setStyleSheet("""
                    QListView {
                        border: none; 
                        background: transparent;  /* Remove background */
                    }
                """)


class DeOOPTreeDelegate(QStyledItemDelegate):
    def __init__(self, editable: bool = False, parent=None):
        super(DeOOPTreeDelegate, self).__init__(parent)
        self._editable = editable

    def createEditor(self, parent, option, index):
        if not self._editable:
            return None
        return super().createEditor(parent, option, index)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):
        assert index.isValid()

        self.initStyleOption(option, index)

        # Extract item data
        decorations = index.data(Qt.ItemDataRole.DecorationRole)
        text = index.data(Qt.ItemDataRole.DisplayRole)
        color = index.data(Qt.ItemDataRole.UserRole) or "white"

        # Start painting
        painter.save()

        def get_color():
            if option.state & QStyle.StateFlag.State_HasFocus:
                return QColor("skyblue")
            if option.state & QStyle.StateFlag.State_MouseOver:
                return QColor("lightskyblue")
            if option.state & QStyle.StateFlag.State_Selected:
                return QColor("silver")
            return QColor(color)

        # Set the background color
        painter.setBrush(get_color())
        painter.setPen(Qt.PenStyle.NoPen)  # No border

        # Draw the rounded rectangle background
        rect = QRectF(option.rect)
        border_radius = 15
        painter.drawRoundedRect(rect, border_radius, border_radius)

        # Set the pen for the text
        painter.setPen(QPen(Qt.GlobalColor.black))

        # Draw the text
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

        painter.restore()

class DeOOPTreeView(QTreeView):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.setItemDelegate(DeOOPListDelegate(True, self))

class LabeledEdit(QWidget):
    def __init__(self, label: str, tool_tip: str = "",
                 text_changed: Callable[[str], None] = None, parent: QWidget = None):
        super().__init__(parent)
        self._label = QLabel(label)
        tool_tip and self._label.setToolTip(tool_tip)
        self.edit = QLineEdit()
        text_changed and self.edit.textChanged.connect(text_changed)
        self._layout = QHBoxLayout()
        self._layout.addWidget(self._label)
        self._layout.addWidget(self.edit)
        self.setLayout(self._layout)

class DirectoryBrowserWidget(LabeledEdit):
    def __init__(self, label: str, tool_tip: str = "", text_changed: Callable[[str], None] = None,
                 dialog_title: str = "", parent: QWidget = None):
        super().__init__(label, tool_tip, text_changed, parent)
        self._dialogTitle = dialog_title
        self._button = QPushButton('Browse')
        self._button.clicked.connect(self.on_browse)
        self.layout().addWidget(self._button)

    def on_browse(self):
        directory = QFileDialog.getExistingDirectory(self, self._dialogTitle or "Select File")
        if directory:
            self.edit.setText(directory)

class FileBrowserWidget(DirectoryBrowserWidget):
    def __init__(self, label: str, file_types: str = "", tool_tip: str = "",
                 text_changed: Callable[[str], None] = None, dialog_title: str = "", parent: QWidget = None):
        super().__init__(label, tool_tip, text_changed, dialog_title, parent)
        self._fileTypes = file_types

    def on_browse(self):
        file_name, _ = QFileDialog.getOpenFileName(self, self._dialogTitle or "Select File", "",
                                                   f"{self._fileTypes};;All Files (*)")
        if file_name:
            self.edit.setText(file_name)

class TabWidget(QTabWidget):
    def __init__(self, parent=None, new=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.tabBar().setMouseTracking(True)
        self.setMovable(True)
        self.setDocumentMode(True)
        if new:
            TabWidget.setup(self)

    def __setstate__(self, data):
        self.__init__(new=False)
        self.setParent(data["parent"])
        for widget, tab_name in data["tabs"]:
            self.addTab(widget, tab_name)
        TabWidget.setup(self)

    def __getstate__(self):
        data = {
            "parent": self.parent(),
            "tabs": [],
        }
        tab_list = data["tabs"]
        for k in range(self.count()):
            tab_name = self.tabText(k)
            widget = self.widget(k)
            tab_list.append((widget, tab_name))
        return data

    def setup(self):
        pass

    def mouseMoveEvent(self, e):
        tab_bar = self.tabBar()
        index = tab_bar.tabAt(e.pos())
        tab_rect = tab_bar.tabRect(index)

        pixmap = QPixmap(tab_rect.size())
        tab_bar.render(pixmap, QPoint(), QRegion(tab_rect))

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        close_all_tabs = QAction("Close All Tabs", self)
        close_all_tabs.triggered.connect(self.close_all_tabs)
        menu.addAction(close_all_tabs)
        menu.exec(event.globalPos())

    def close_all_tabs(self):
        self.clear()