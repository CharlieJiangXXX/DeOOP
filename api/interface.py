import itertools
from typing import Optional, Dict, List

import networkx as nx
from .artifacts.line import Line
from .artifacts.address import Patch, Address
from .artifacts.function import Function
from .exceptions import NoFunction
from .utils import AddressRange, Xref


class DecompilerInterface:
    def __init__(self, handle: int):
        self._handle = handle

    @property
    def binary_base_addr(self) -> int:
        """
        Returns the base address of the binary in the decompiler. This is useful for calculating offsets
        in the binary. Also, mandatory for using the lifting and lowering API.
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

    def demangle(self, name: str, *args, **kwargs) -> str:
        raise NotImplementedError

    # Address

    @property
    def min_addr(self) -> Address:
        raise NotImplementedError

    @property
    def max_addr(self) -> Address:
        raise NotImplementedError

    def addr(self, addr: Optional[int] = None) -> Optional[Address]:
        raise NotImplementedError

    def addr_range(self, start: Optional[int] = None, end: Optional[int] = None) -> AddressRange:
        raise NotImplementedError

    # TO-DO: make this more robust (error handling, different types of names)
    def set_name(self, addr: Address, name: str) -> bool:
        raise NotImplementedError

    def xrefs_to(self, addr: Address) -> List[Xref]:
        return []

    def xrefs_from(self, addr: Address) -> List[Xref]:
        return []

    # Lines are immutable in the sense that one cannot be added on the fly, but each can be modified to one's
    # likings

    # TO-DO: find way to optimally store artifacts, such as lines. if we save lines both independently and
    # in functions, we are bloating the size by 2

    def line(self, addr: int) -> Line:
        raise NotImplementedError

    def lines_in(self, span: AddressRange) -> List[Line]:
        """Iterate lines in range.

        Args:
            span: Address range, start to end if `None`.

        Returns:
            iterator of `Line` objects.
        """
        lines = []
        item = self.line(span.start.value)
        while item.start_addr < span.end.value:
            lines.append(item)
            item = item.next
        return lines

    @property
    def lines(self) -> List[Line]:
        """
        Dangerous! Output may be particularly large
        :return:
        """
        return self.lines_in(self.addr_range())

    def function(self, addr: Address) -> Function:
        pass

    def call_graph(self) -> nx.DiGraph:
        """Export IDB to a NetworkX graph.

        Use xrefs to and from functions to build a DiGraph containing all
        the functions in the IDB and all the links between them.
        The graph can later be used to perform analysis on the IDB.

        :return: nx.DiGraph()
        """
        digraph = nx.DiGraph()

        for function in self.functions:
            for xref in itertools.chain(function.xrefs_from, function.xrefs_to):
                try:
                    frm = self.function(xref.frm).start_addr
                    to = self.function(xref.to).start_addr
                    digraph.add_edge(frm, to)
                except NoFunction:
                    continue

        return digraph

    def condensed_graph(self) -> nx.DiGraph:
        # Condense call graph into SCCs; no need to sort separately since
        # the condensation is already in lexicographical topological order
        return nx.condensation(self.call_graph())

    def functions_in(self, span: AddressRange):
        """Get all functions in range.

        Returns:
            This is a generator that iterates over all the functions in the IDB.
        """
        raise NotImplementedError

    @property
    def functions(self):
        return self.functions_in(self.addr_range())

    def decompile(self, function: Function) -> str:
        raise NotImplementedError

    def add_function(self, span: AddressRange) -> bool:
        pass

    def cfg(self, function) -> nx.DiGraph:
        pass

    # general function object should support lifted operations,
    # such as stack variable names, etc.

    def set_global_variable(self, gvar) -> bool:
        return False

    def get_global_var(self, addr: Address):
        return None

    @property
    def global_var(self) -> Dict:
        """
        Returns a dict of libbs.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # structs
    # enums

    # other objects like words and stuff

    def get_bytes(self, address: Address) -> str:
        pass

    def set_patch(self, patch: Patch) -> bool:
        pass

    def get_patch(self, address: Address) -> Optional[Patch]:
        pass

    @property
    def patches(self) -> Dict[int, Patch]:
        return {}

    # demangle



# queries tbd later