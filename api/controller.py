import shutil
from typing import List

from .interface import DecompilerInterface
from .ida.interface import IDAInterface


class Decompiler:
    def __init__(self, handle: int, interfaces: List[str]):
        self._handle = handle
        self.interfaces = list(map(self. interface_from_desc, interfaces))
        # in the event of multiple different interfaces, merge or keep both based on user's settings
        # Condense call graph into SCCs; no need to sort separately since
        # the condensation is already in lexicographical topological order
        #self.call_graph: nx.DiGraph = nx.condensation(cls._get_func_graph())

        # Functions stored in topological order
        #self.ordered_sccs: List[SCCInfo] = [[]] * len(cls.call_graph.nodes)
        #self.sccs_remaining: int = len(cls.call_graph.nodes)

        # check if each decompiler is present, and create DecompilerInterface instances from them;
        # this would include function retriever, and resolving conflicts between possible function differences
        #

        # collect global variables
        # error correction
        # type propagation
        #

    def interface_from_desc(self, desc: str):
        match desc:
            case "ida":
                return IDAInterface(self._handle)
        raise NotImplementedError

    def load_from_file(self, file_path: str):
        pass

    def save_to_file(self, file_path: str):
        pass

    def test(self):
        print(hex(self.interfaces[0].binary_base_addr))
        print(self.interfaces[0].decompiler_available)

    def apply_patches(self, output_path: str = None):
        target = self.interface.binary_path
        if output_path:
            target = shutil.copy(target, output_path)

        with open(target, "rb+") as output:
            for patch in self.interface.patches.values():
                output.seek(patch.addr.offset_in_bin)
                output.write(bytes([patch.bytes]))