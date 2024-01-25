import ida_kernwin
import networkx as nx
#from PyQt5.QtWidgets import QTabWidget, QSpacerItem, QSizePolicy, QGridLayout, QTableView, QHeaderView
from idaapi import PluginForm

#from fusion_ui.editor import *
from api.function_retriever import FunctionRetriever
from menu import *
#from PyQt5.QtCore import Qt
#from PyQt5.QtGui import QFont, QPixmap
#from PyQt5.QtWidgets import QPushButton, QWidget, QVBoxLayout, QLabel


class ShowFusion(ActionHandler):
    NAME = "show_fusion"
    TEXT = "Fusion View"
    HOTKEY = "F7"
    TOOLTIP = ''
    ICON = -1

    def __init__(self):
        super().__init__()

    def update(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.widget_type in [ida_api.BWN_DISASM, ida_api.BWN_DUMP, ida_api.BWN_PSEUDOCODE]:
            return ida_api.AST_ENABLE
        return ida_api.AST_DISABLE

    def _activate(self, ctx: ida_kernwin.action_ctx_base_t):
        func = ida_api.get_func(ctx.cur_ea)
        if not func:
            return

        # make naming more optimal
        name = ida_api.get_ea_name(func.start_ea)
        tform = ida_api.find_widget(name)
        if tform:
            ida_api.activate_widget(tform, True)
        else:
            FusionViewer(FunctionRetriever.fetch_function_tree(func.start_ea)).Show()


class QtViewer(PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None

    def OnCreate(self, form):
        self.parent = ida_api.PluginForm.FormToPyQtWidget(form)

    def Show(self, caption=None, options=0):
        return ida_api.PluginForm.Show(self, caption, options=options)


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

        # explorer has two modes:
        # all funcs in topo order (or other orders)
        # Headers + Tree of descendants

        self._editors = []