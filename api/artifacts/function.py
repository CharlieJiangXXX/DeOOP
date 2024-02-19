from .artifact import Artifact
from .address import Address, HasAddr
from typing import Any, List, Union, Callable
from .line import Line


class Function(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "_end_addr",
        "comments",
        "xrefs",
        "lvars",
        "lines",
        "frame_size",
        "flags",
        "signature",
        "tinfo",
        "comparator",
        "pseudocode",
        "external",
        "init",
        "fini",
        "plt"
    )

    def __init__(self, addr: Address, last_change: Any = None):
        super().__init__(last_change)

        self.addr = addr
        self._end_addr = None
        self.comments = {}
        self.xrefs = {"from": [], "to": []}
        self.lvars: List[str] = []
        self.lines: List[Line] = []
        self.frame_size = 0
        self.flags = 0
        self.signature = ""
        self.tinfo = None
        self.comparator: Callable[[int, int], bool] = None
        self.external = False
        self.init = False
        self.fini = False
        self.plt = False

        self.pseudocode = ""

    def __eq__(self, other: 'Function'):
        try:
            return self.start_addr == other.start_addr
        except AttributeError:
            return False

    def __hash__(self):
        return self.start_addr

    @property
    def xrefs_from(self):
        """Xrefs from this line.

        :return: Xrefs as `sark.code.xref.Xref` objects.
        """
        return self.xrefs["from"]

    @property
    def xrefs_to(self):
        """Xrefs to this line.

        Returns:
            Xrefs as `sark.code.xref.Xref` objects.
        """
        return self.xrefs["to"]

    @property
    def start_addr(self) -> int:
        """Start Address"""
        return self.addr.value

    @property
    def end_addr(self):
        """End Address

        Note that taking all the lines between `start_ea` and `end_ea` does not guarantee
        that you get all the lines in the function. To get all the lines, use `.lines`.
        """
        return self._end_addr.value

    def __repr__(self):
        return 'Function(name="{}", addr=0x{:08X})'.format(self.name, self.start_addr)

    def __contains__(self, item: Union[Address, HasAddr]):
        """Is an item contained (its EA is in) the function. Item must either have an attributed called addr
        of type Address or itself be one."""
        ea = getattr(item, "addr", item)

        return self.comparator(ea.value, self.start_addr)

    @property
    def name(self):
        return self.lines[0].addr.name
