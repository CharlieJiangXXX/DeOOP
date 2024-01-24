from .address import Address
from .artifact import Artifact


class Line(Artifact):
    """
    An arbitrary line in the binary, either code or data.
    """

    __slots__ = Artifact.__slots__ + (
        "_addr",
        "_comments"
    )

    def __init__(self, addr: Address, last_change=None):
        super().__init__(last_change=last_change)

        self.addr = addr
        self.comments = {}
        self.xrefs = {"from": [], "to": []}
        self.size = 0
        self.asm = ""
        self.bytes = ""

        self.type_flags = 0
        self.type_info = ""
        self.factory = None

    @property
    def start_addr(self) -> int:
        """End address of line (first byte after the line)"""
        return self.addr.value

    @property
    def end_addr(self) -> int:
        """End address of line (first byte after the line)"""
        return self.start_addr + self.size

    def __repr__(self):
        return "[{:08X}] {}".format(int(self.addr), self.asm)

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
    def next(self) -> 'Line':
        """The next line."""
        return self.factory(self.end_addr)

    @property
    def prev(self) -> 'Line':
        """The previous line."""
        return self.factory(self.start_addr - 1)

    def __eq__(self, other):
        if not isinstance(other, Line):
            return False

        return self.start_addr == other.start_addr

    def __ne__(self, other):
        return not self.__eq__(other)
