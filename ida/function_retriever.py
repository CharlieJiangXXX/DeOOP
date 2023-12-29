import dataclasses

import ida_kernwin
import sark
import networkx as nx
from typing import List, Generator, Dict, Tuple
import os
import pickle
import ida_hexrays
import idautils
from menu import *


def _bin2name(bin_name: str) -> str:
    return os.path.join(idautils.GetIdbDir(), f'{bin_name.replace(".", "_")}.pickle')


def loadall(filename: str) -> Generator:
    with open(filename, "rb") as f:
        while True:
            try:
                yield pickle.load(f)
            except EOFError:
                break


@dataclasses.dataclass
class FunctionInfo:
    func: sark.code.function.Function
    control_flow_graph: nx.DiGraph
    pseudocode: str

    def __init__(self, ea: int):
        print(ea)
        self.func = sark.Function(ea)
        self.control_flow_graph = sark.get_nx_graph(ea)
        self.pseudocode = ida_hexrays.decompile(ea)


SCCInfo = List[FunctionInfo]


class FunctionRetriever:
    def __init__(self, bin_name: str):
        self._fileName: str = _bin2name(bin_name)
        if not self.read():
            # Condense call graph into SCCs; no need to sort separately since
            # the condensation is already in lexicographical topological order
            self._callGraph: nx.DiGraph = nx.condensation(self.get_func_graph())

            # Functions stored in topological order
            self._orderedSCCs: List[SCCInfo] = [[]] * len(self._callGraph.nodes)
            self._remainingSCCs: int = len(self._callGraph.nodes)

            # how may this be efficiently cached?

    def __del__(self):
        self.save()

    @property
    def all_fetched(self) -> bool:
        return not self._remainingSCCs

    @staticmethod
    def get_func_graph():
        graph = sark.graph.get_idb_graph()
        out = graph.copy()
        for node in graph:
            if not sark.is_function(node):
                out.remove_node(node)
        return out

    def read(self) -> bool:
        if os.path.isfile(self._fileName):
            objs = list(loadall(self._fileName))
            if len(objs) == 2:
                self._callGraph = objs[0]
                self._orderedSCCs = objs[1]
                return True
        return False

    def save(self) -> None:
        # create file
        with open(self._fileName, "wb") as f:
            pickle.dump(self._callGraph, f)
            pickle.dump(self._orderedSCCs, f)

    def process_scc(self, index: int, scc: Dict) -> SCCInfo:
        orig_nodes: List[int] = list(scc["members"])
        if not orig_nodes:
            raise Exception("SCC empty!")

        if not self._orderedSCCs[index]:
            for ea in orig_nodes:
                out = FunctionInfo(ea)
                self._orderedSCCs[index].append(out)
            self._remainingSCCs += 1
        return self._orderedSCCs[index]

    def fetch_all(self) -> None:
        for scc in self._callGraph.nodes.data():
            self.process_scc(scc[0], scc[1])

    def fetch_function_tree(self, ea: int) -> nx.DiGraph:
        def get_scc():
            for s in self._callGraph.nodes.data():
                if ea in s[1]["members"]:
                    return s
            return None

        scc = get_scc()
        if not scc:
            raise Exception("No SCC matching ea!")

        bfs_tree = nx.bfs_tree(self._callGraph, scc[0])
        for node in bfs_tree.nodes:
            bfs_tree.nodes[node]["members"] = self._callGraph.nodes[node]["members"]
        return bfs_tree

    @property
    def num_remaining_functions(self) -> int:
        return len(self._callGraph.nodes) - len(self._orderedSCCs)

    @property
    def topo_ordered_sccs(self) -> List[SCCInfo]:
        return self._orderedSCCs

    @staticmethod
    def plot() -> None:
        viewer = sark.ui.NXGraph(FunctionRetriever.get_func_graph(), handler=sark.ui.AddressNodeHandler())
        viewer.Show()


class RetrieveAllHandler(ActionHandler):
    NAME = "retrieve_all"
    TEXT = 'Retrieve All Functions'
    HOTKEY = ""
    TOOLTIP = 'Load address, assembly, and pseudocode of all functions to DeOOP in topological order.'
    ICON = -1

    def _activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if config.function_retriever and not config.function_retriever.all_fetched:
            config.function_retriever.fetch_all()


class RetrieveFunctionHandler(ActionHandler):
    NAME = "retrieve_func"
    TEXT = 'Retrieve This Functions'
    HOTKEY = ""
    TOOLTIP = 'Load address, assembly, and pseudocode of this function and all its descendants to DeOOP.'
    ICON = -1

    def _activate(self, ctx):
        pass

