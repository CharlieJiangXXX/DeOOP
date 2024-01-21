from typing import Optional, Dict, List

import networkx as nx
from .artifacts.address import Address, AddressRange, Patch


class DecompilerInterface:
    def __init__(self, handle: int):
        self._handle = handle

    @property
    def binary_base_addr(self) -> int:
        """
        Returns the base address of the binary in the decompiler. This is useful for calculating offsets
        in the binary. Also mandatory for using the lifting and lowering API.
        """
        raise NotImplementedError

    @property
    def binary_hash(self) -> str:
        """
        Returns a hex string of the currently loaded binary in the decompiler. For most cases,
        this will simply be a md5 hash of the binary.

        @rtype: hex string
        """
        raise NotImplementedError

    @property
    def binary_path(self) -> Optional[str]:
        """
        Returns a string that is the path of the currently loaded binary. If there is no binary loaded
        then None should be returned.

        @rtype: path-like string (/path/to/binary)
        """
        raise NotImplementedError

    @property
    def decompiler_available(self) -> bool:
        return False

    def lines_in(self, span: AddressRange):
        """Iterate lines in range.

        Args:
            span: Address range, start to end if `None`.
            reverse: Set to true to iterate in reverse order.
            selection: If set to True, replaces start and end with current selection.

        Returns:
            iterator of `Line` objects.
        """
        pass

    @property
    def lines(self):
        """
        Dangerous! Output may be particularly large
        :return:
        """
        raise NotImplementedError

    def functions_in(self, span: AddressRange):
        """Get all functions in range.

        Returns:
            This is a generator that iterates over all the functions in the IDB.
        """
        pass

    @property
    def functions(self):
        raise NotImplementedError

    def call_graph(self, address: Address) -> nx.DiGraph:
        """Export IDB to a NetworkX graph.

        Use xrefs to and from functions to build a DiGraph containing all
        the functions in the IDB and all the links between them.
        The graph can later be used to perform analysis on the IDB.

        :return: nx.DiGraph()
        """
        pass

    def get_function(self, address: Address):
        pass

    def add_function(self, span: AddressRange) -> bool:
        pass

    def get_flow_chart(self) -> nx.DiGraph:
        pass

    def get_bytes(self, address: Address) -> str:
        pass

    def set_patch(self, patch: Patch) -> bool:
        pass

    def get_patch(self, address: Address) -> Optional[Patch]:
        pass

    @property
    def patches(self) -> Dict[int, Patch]:
        raise NotImplementedError



# queries tbd later