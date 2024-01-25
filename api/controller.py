import shutil
from typing import List

from .interface import DecompilerInterface
from .ida.interface import IDAInterface


class Decompiler:
    def __init__(self, handle: int, interfaces: List[str]):
        self._handle = handle
        interface_lambdas = {
            'ida': lambda: IDAInterface(self._handle)
        }
        self.interfaces = {key: interface_lambdas[key]() for key in interfaces if key in interface_lambdas}
        # in the event of multiple different interfaces, merge or keep both based on user's settings

        # Functions stored in topological order
        #self.ordered_sccs: List[SCCInfo] = [[]] * len(cls.call_graph.nodes)
        #self.sccs_remaining: int = len(cls.call_graph.nodes)

        # this would include function retriever, and resolving conflicts between possible function differences
        #

        # collect global variables
        # error correction
        # type propagation
        #

    def load_from_file(self, file_path: str):
        pass

    def save_to_file(self, file_path: str):
        pass

    def apply_patches(self, interface: str, output_path: str = None):
        target = self.interfaces[interface].binary_path
        if output_path:
            target = shutil.copy(target, output_path)

        with open(target, "rb+") as output:
            for patch in self.interfaces[interface].patches.values():
                output.seek(patch.addr.offset_in_bin)
                output.write(bytes([patch.bytes]))
