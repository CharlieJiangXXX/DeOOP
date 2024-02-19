from .address import Address
from .artifact import Artifact


class Segment(Artifact):
    """
    An arbitrary line in the binary, either code or data.
    """

    __slots__ = Artifact.__slots__ + (
        "addr",
        "comments",
        "xrefs",
        "size",
        "asm",
        "bytes",
        "type_flags",
        "type_info",
        "factory"
    )

    def __init__(self, addr: Address, last_change=None):
        super().__init__(last_change=last_change)

        self.addr = addr
        self._end_addr = None
        self.comments = {}
        self.asm = ""
        self.bytes = ""
        self.execute = False
        self.write = False
        self.read = False
        self.type = None
        self.name = None
        self.bitness = 0


    @property
    def start_addr(self) -> int:
        return self.addr.value

    @property
    def end_addr(self) -> int:
        return self._end_addr.value

    @property
    def size(self):
        return self.start_addr - self.end_addr

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
