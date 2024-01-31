import os
import pickle

from typing import Optional, Protocol, runtime_checkable, Generator
from .artifacts.address import Address


def concat(*args):
    assert args
    return os.path.join(*args).replace("\\", "/")


def loadall(filename: str) -> Generator:
    with open(filename, "rb") as f:
        while True:
            try:
                yield pickle.load(f)
            except EOFError:
                break


def is_signed(number, size: int):
    return number & (1 << ((8 * size) - 1))


class AddressRange:
    def __init__(self, start: Optional[Address], end: Optional[Address]) -> None:
        self.start = start
        self.end = end

    @property
    def start_addr(self) -> int:
        return self.start.value

    @property
    def end_addr(self) -> int:
        return self.end.value

    def __str__(self):
        return f"<AddressRange: {hex(self.start_addr)}-{hex(self.end_addr)}>"

    def __repr__(self):
        return self.__str__()

    # expand based on ida range_t


class XrefType:
    def __init__(self, type_):
        self._type = type_

    @property
    def type(self) -> int:
        raise NotImplementedError

    @property
    def flags(self) -> int:
        raise NotImplementedError

    @property
    def name(self) -> str:
        raise NotImplementedError

    def __repr__(self):
        return self.name


class Xref:
    def __init__(self, frm: Address, to: Address, iscode: bool, user: bool, type_: XrefType):
        self.frm = frm
        self.to = to
        self.iscode = iscode
        self.user = user
        self.type = type_


@runtime_checkable
class ExceptionWrapperProtocol(Protocol):
    e: Exception
    traceback: str

    def __init__(self, e: Exception, trace: str) -> None:
        ...
