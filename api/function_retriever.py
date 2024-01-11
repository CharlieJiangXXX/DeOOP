import dataclasses

import ida_kernwin
import ida_nalt
import sark
import networkx as nx
import pickle
import ida_hexrays
import idautils
from trash.menu import *





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
    filename = ""
    call_graph: nx.DiGraph = None
    ordered_sccs: List[SCCInfo] = []
    sccs_remaining: int = 0
    initialized = False

    @classmethod
    def post_init(cls, func):
        if cls.initialized:
            return func
        raise Exception("Cannot retrieve functions before initialization.")

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
        graph = sark.graph.get_idb_graph()
        out = graph.copy()
        for node in graph:
            if not sark.is_function(node):
                out.remove_node(node)
        return out

    @classmethod
    def read(cls) -> bool:
        if os.path.isfile(cls.filename):
            objs = list(loadall(cls.filename))
            if len(objs) == 3:
                cls.call_graph = objs[0]
                cls.ordered_sccs = objs[1]
                cls.sccs_remaining = objs[2]
                return True
        return False

    @classmethod
    def save(cls) -> None:
        # create file
        with open(cls.filename, "wb") as f:
            for obj in [cls.call_graph, cls.ordered_sccs, cls.sccs_remaining]:
                pickle.dump(obj, f)

    @classmethod
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

    @classmethod
    @property
    @post_init
    def num_remaining_functions(cls) -> int:
        return len(cls.call_graph.nodes) - len(cls.ordered_sccs)

    @staticmethod
    @post_init
    def plot() -> None:
        viewer = sark.ui.NXGraph(FunctionRetriever._get_func_graph(), handler=sark.ui.AddressNodeHandler())
        viewer.Show()


class RetrieveAllHandler(ActionHandler):
    NAME = "retrieve_all"
    TEXT = 'Retrieve All Functions'
    HOTKEY = ""
    TOOLTIP = 'Load address, assembly, and pseudocode of all functions to DeOOP in topological order.'
    ICON = -1

    def _activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if not FunctionRetriever.all_fetched:
            FunctionRetriever.fetch_all()


class RetrieveFunctionHandler(ActionHandler):
    NAME = "retrieve_func"
    TEXT = 'Retrieve This Functions'
    HOTKEY = ""
    TOOLTIP = 'Load address, assembly, and pseudocode of this function and all its descendants to DeOOP.'
    ICON = -1

    def _activate(self, ctx):
        pass

