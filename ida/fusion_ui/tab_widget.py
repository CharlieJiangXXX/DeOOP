from PyQt5.QtCore import QMimeData, QPoint, Qt
from PyQt5.QtGui import QCursor, QDrag, QPixmap, QRegion
from PyQt5.QtWidgets import QTabWidget, QMenu, QAction


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
