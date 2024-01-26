import codecs
from typing import Optional, Any, Protocol

from .artifact import Artifact


class Address(Artifact):
    __slots__ = Artifact.__slots__ + (
        "value",
        "offset_in_bin",
        "_name",
    )

    def __init__(self, addr: Optional[int] = None):
        super().__init__()
        self.value = addr
        self.offset_in_bin = -1
        self._name = ""

    def __int__(self):
        return self.value

    def __hash__(self):
        return hash(self.value)

    @property
    def name(self) -> str:
        return self._name or "0x{:08X}".format(self.value)


class HasAddr(Protocol):
    @property
    def addr(self) -> Address:
        ...


class Patch(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "bytes"
    )

    def __init__(self, addr: Optional[int] = None, data: Any = None, name: Optional[str] = None, last_change=None):
        super().__init__(last_change)
        self.addr = Address(addr)
        self.name = name
        self.bytes = data

    def __str__(self):
        return f"<Patch: {self.name}@{hex(int(self.addr))} len={len(self.bytes)}>"

    def __repr__(self):
        return self.__str__()

    def __getstate__(self):
        return {
            "name": self.name,
            "addr": hex(int(self.addr)),
            "bytes": codecs.encode(self.bytes, "hex"),
            "last_change": self.last_change
        }

    @classmethod
    def dump_many(cls, patches):
        patches_ = {}
        for v in patches.values():
            patches_[hex(int(v.addr))] = v.__getstate__()
        return patches_

    def copy(self):
        return Patch(
            int(self.addr),
            self.bytes,
            self.name,
            self.last_change
        )
