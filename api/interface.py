import itertools
import os
from functools import cached_property, lru_cache, wraps
from typing import Optional, Dict, List, Generator, Callable, Any

import networkx as nx
from .artifacts.line import Line
from .artifacts.address import Patch, Address
from .artifacts.function import Function
from .exceptions import NoFunction
from .launcher import Launcher
from .nested_asyncio import NestedAsyncIO
from .utils import AddressRange, Xref, ExceptionWrapperProtocol

SCC = List[Function]


class DecompilerInterface:
    def __init__(self, handle: int):
        self._handle = handle
        self._functionSCCMapping = {}
        self._tasks = {}
        self._pid = os.getpid()

    def is_local(self):
        return os.getpid() == self._pid

    @staticmethod
    def execute(wait: bool = True, handler: Callable[[Any], None] = None,
                mode: int = Launcher.TaskMode.SAFE, priority: int = 2):
        def decorator(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                if not self.is_local():
                    return func(self, *args, **kwargs)

                launcher = Launcher.instance()
                task = launcher.enqueue_task(self._handle, lambda: func(self, *args, **kwargs),
                                             handler, mode, priority)

                def check_exception(res):
                    out, exception = res
                    if isinstance(exception, ExceptionWrapperProtocol):
                        class AggregatedException(type(exception.e)):
                            def __init__(self, *a):
                                super().__init__(*a)
                                self.remote_traceback = exception.traceback

                            def __str__(self):
                                original_message = super().__str__()
                                return (f"{original_message}\n\n"
                                        f"Remote Traceback (most recent call last):\n"
                                        f"{self.remote_traceback}")

                        raise AggregatedException(*exception.e.args)
                    return out

                if wait:
                    loop = task.get_loop()
                    if loop.is_running():
                        with NestedAsyncIO(loop):
                            result = loop.run_until_complete(task)
                            return check_exception(result)
                    return check_exception(task.get_loop().run_until_complete(task))
                task.add_done_callback(lambda future: check_exception(future.result()))
                return task

            return wrapper

        return decorator

    @staticmethod
    def local(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.is_local():
                raise Exception("This function must be called within the local process")
            return func(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def remote(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.is_local():
                raise Exception("This function must be called remotely")
            return func(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def shared(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            pass

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

    # artifact_retriever decorator that marks all functions that should be run inside
    # of the local process. these would all have sync and async counterparts that need
    # to be overriden. we also need to write something that could be safely called remotely

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

    @cached_property
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

    @cached_property
    def condensed_graph(self) -> nx.DiGraph:
        # No need to sort separately since the condensation is
        # already in lexicographical topological order
        graph = nx.condensation(self.call_graph)
        self._functionSCCMapping = {
            member: scc_id
            for scc_id, data in graph.nodes.data()
            for member in data["members"]
        }
        return graph

    @property
    def sccs(self) -> Generator[SCC, None, None]:
        for i, scc in self.condensed_graph.nodes.data():
            yield [self.function(self.addr(func)) for func in scc["members"]]

    def scc_of(self, function: Function) -> SCC:
        if scc_idx := self._functionSCCMapping.get(function.start_addr, None):
            return [self.function(self.addr(addr)) for addr in self.condensed_graph[scc_idx]["members"]]
        return []

    def function_tree(self, function: Function) -> nx.DiGraph:
        def get_scc():
            for s in self.condensed_graph.nodes.data():
                if ea in s[1]["members"]:
                    return s
            return None

        scc = get_scc()
        if not scc:
            raise Exception("No SCC matching ea!")

        bfs_tree = nx.bfs_tree(self.condensed_graph, scc[0])
        for node in bfs_tree.nodes:
            bfs_tree.nodes[node]["members"] = self.condensed_graph.nodes[node]["members"]
        return bfs_tree

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