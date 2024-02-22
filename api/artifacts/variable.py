from .artifact import Artifact


class Variable(Artifact):
    """
    Describes a stack variable for a given function.
    """

    __slots__ = Artifact.__slots__ + (
        "offset",
        "name",
        "type",
        "size",
        "xrefs"
    )

    def __init__(self, offset: int = 0, name: str = "", size: int = 0, type_: str = "", last_change=None):
        super().__init__(last_change)
        self.offset = offset
        self.name = name
        self.type = type_
        self.size = size
        self.xrefs = []

    def __eq__(self, other: 'Variable'):
        return isinstance(other, Variable) \
               and other.offset == self.offset \
               and other.name == self.name \
               and other.type == self.type \
               and other.size == self.size

    def __str__(self):
        return f"<StackVar: {self.type} {self.name}; {hex(self.offset)}>"

    def __repr__(self):
        return self.__str__()
