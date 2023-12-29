import ida_kernwin
import networkx as nx
from PyQt5.QtWidgets import QTabWidget, QSpacerItem, QSizePolicy, QGridLayout, QTableView, QHeaderView
from idaapi import PluginForm

from fusion_ui.editor import *
from ida.function_retriever import FunctionRetriever
from menu import *
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtWidgets import QPushButton, QWidget, QVBoxLayout, QLabel


class ShowFusion(ActionHandler):
    NAME = "show_fusion"
    TEXT = "Fusion View"
    HOTKEY = "F7"
    TOOLTIP = ''
    ICON = -1

    def __init__(self):
        super().__init__()

    def update(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_DUMP, idaapi.BWN_PSEUDOCODE]:
            return idaapi.AST_ENABLE
        return idaapi.AST_DISABLE

    def _activate(self, ctx: ida_kernwin.action_ctx_base_t):
        func = idaapi.get_func(ctx.cur_ea)
        if not func:
            return

        # make naming more optimal
        name = idaapi.get_ea_name(func.start_ea)
        tform = idaapi.find_widget(name)
        if tform:
            idaapi.activate_widget(tform, True)
        else:
            FusionViewer(FunctionRetriever.fetch_function_tree(func.start_ea)).Show()


class QtViewer(PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)


class FusionViewer(QtViewer):
    def __init__(self, scc_tree: nx.DiGraph):
        super().__init__()
        self._tree = scc_tree

    def OnCreate(self, form):
        super().OnCreate(form)
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('hei')

        btn_finalize = QPushButton("&Finalize")
        btn_disable = QPushButton("&Disable")
        btn_enable = QPushButton("&Enable")
        btn_origin = QPushButton("&Origin")
        btn_array = QPushButton("&Array")
        btn_pack = QPushButton("&Pack")
        btn_unpack = QPushButton("&Unpack")
        btn_remove = QPushButton("&Remove")
        btn_resolve = QPushButton("Resolve")
        btn_clear = QPushButton("Clear")  # Clear button doesn't have shortcut because it can fuck up all work
        btn_recognize = QPushButton("Recognize Shape")
        btn_recognize.setStyleSheet("QPushButton {width: 100px; height: 20px;}")

        btn_finalize.setShortcut("f")
        btn_disable.setShortcut("d")
        btn_enable.setShortcut("e")
        btn_origin.setShortcut("o")
        btn_array.setShortcut("a")
        btn_pack.setShortcut("p")
        btn_unpack.setShortcut("u")
        btn_remove.setShortcut("r")

        self._tabWidget = QTabWidget(parent=None)
        self._tabWidget.addTab(FusionEditor("cpp"), "Func 1")
        self._tabWidget.setTabsClosable(True)
        self._tabWidget.setStyleSheet("QTabWidget {border: none;}")

        grid_box = QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_finalize, 0, 0)
        grid_box.addWidget(btn_enable, 0, 1)
        grid_box.addWidget(btn_disable, 0, 2)
        grid_box.addWidget(btn_origin, 0, 3)
        grid_box.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Expanding), 0, 5)
        grid_box.addWidget(btn_array, 1, 0)
        grid_box.addWidget(btn_pack, 1, 1)
        grid_box.addWidget(btn_unpack, 1, 2)
        grid_box.addWidget(btn_remove, 1, 3)
        grid_box.addWidget(btn_resolve, 0, 4)
        grid_box.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Expanding), 1, 5)
        grid_box.addWidget(btn_recognize, 0, 6)
        grid_box.addWidget(btn_clear, 1, 6)

        vertical_box = QVBoxLayout()
        vertical_box.addWidget(self._tabWidget)
        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

        self._editors = []
