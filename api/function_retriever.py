import dataclasses

import ida_kernwin
import ida_nalt
import sark
import networkx as nx
import pickle
import ida_hexrays
import idautils
from trash.menu import *


SCCInfo = List[FunctionInfo]

class FunctionRetriever:

    @classmethod
    def init(cls):
        cls.filename: str = os.path.join(idautils.GetIdbDir(),
                                         f'{ida_nalt.get_root_filename().replace(".", "_")}.pickle')
        if not cls.read():
            # Condense call graph into SCCs; no need to sort separately since
            # the condensation is already in lexicographical topological order
            cls.call_graph: nx.DiGraph = nx.condensation(cls._get_func_graph())

            # Functions stored in topological order
            cls.ordered_sccs: List[SCCInfo] = [[]] * len(cls.call_graph.nodes)
            cls.sccs_remaining: int = len(cls.call_graph.nodes)
            # how may this be efficiently cached?
        cls.initialized = True

    @classmethod
    @property
    @post_init
    def all_fetched(cls) -> bool:
        return cls.initialized and not cls.sccs_remaining

    @staticmethod
    def _get_func_graph():


    @post_init
    def process_scc(cls, index: int, scc: Dict) -> SCCInfo:
        orig_nodes: List[int] = list(scc["members"])
        if not orig_nodes:
            raise Exception("SCC empty!")

        if not cls.ordered_sccs[index]:
            for ea in orig_nodes:
                out = FunctionInfo(ea)
                cls.ordered_sccs[index].append(out)
            cls.sccs_remaining += 1
        return cls.ordered_sccs[index]

    @classmethod
    @post_init
    def fetch_all(cls) -> None:
        for scc in cls.call_graph.nodes.data():
            cls.process_scc(scc[0], scc[1])

    @classmethod
    @post_init
    def fetch_function_tree(cls, ea: int) -> nx.DiGraph:
        def get_scc():
            for s in cls.call_graph.nodes.data():
                if ea in s[1]["members"]:
                    return s
            return None

        scc = get_scc()
        if not scc:
            raise Exception("No SCC matching ea!")

        bfs_tree = nx.bfs_tree(cls.call_graph, scc[0])
        for node in bfs_tree.nodes:
            bfs_tree.nodes[node]["members"] = cls.call_graph.nodes[node]["members"]
        return bfs_tree

    @property
    @post_init
    def num_remaining_functions(cls) -> int:
        return len(cls.call_graph.nodes) - len(cls.ordered_sccs)