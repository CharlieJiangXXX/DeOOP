from enum import IntEnum, IntFlag
from typing import List

from ..artifacts.function import Function
from ..utils import AddressRange


class FcBlockType(IntEnum):
    Normal = 0  # normal block
    IndJump = 1  # block ends with indirect jump
    Ret = 2  # return block
    CndRet = 3  # conditional return block
    NoRet = 4  # noreturn block
    ENoRet = 5  # external noreturn block (does not belong to the function)
    Extern = 6  # external normal block
    Error = 7  # block passes execution past the function end


class FlowChartFlags(IntFlag):
    Print = 0x0001  # Print names (used only by display_flow_chart())
    NoExtern = 0x0002  # Do not compute external blocks. Use this to prevent jumps leaving the
    # function from appearing in the flow chart. Unless specified, the
    # targets of those outgoing jumps will be present in the flow
    # chart under the form of one-instruction blocks
    Reserved = 0x0004  # Former FC_PREDS
    MultiRange = 0x0008  # Multirange flowchart (set by append_to_flowchart)
    CheckBreak = 0x0010  # build_qflow_chart() may be aborted by user
    CallEnds = 0x0020  # Call instructions terminate basic blocks
    NoPreds = 0x0040  # Do not compute predecessor lists


class BasicBlock:
    def __init__(self, index: int, range_: AddressRange, type_: FcBlockType):
        self.index = index
        self.range = range_
        self.type = type_
        self.preds: List[BasicBlock] = []
        self.succs: List[BasicBlock] = []

    @property
    def is_noret(self) -> bool:
        return self.type in (FcBlockType.NoRet, FcBlockType.ENoRet)

    @property
    def is_ret(self) -> bool:
        return self.type in (FcBlockType.Ret, FcBlockType.CndRet)


class FlowChart:
    def __init__(self, function: Function):
        self.func = function
        self.size = 0
        self.flags = -1
        self.num_proper = 0
        self.blocks: List[BasicBlock] = []

    def __iter__(self):
        return (self.__getitem__(index) for index in range(self.size))

    def __getitem__(self, index):
        if index >= self.size:
            raise KeyError
        else:
            return self.blocks[index]
