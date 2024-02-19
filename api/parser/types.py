from pydantic import Field
from typing import Optional, List
from pydantic import BaseModel


class RegexedSourceRef(BaseModel):
    file_index: int = 0
    line_index: int = 0
    column: int = 0


class AsmFileDef(BaseModel):
    file_index: int
    file_name: str


class AsmRange(BaseModel):
    start_col: int = 0
    end_col: int = 0


class AsmLabel(BaseModel):
    name: str = ""
    range = Field(default_factory=AsmRange)


class AsmLabelPair(BaseModel):
    first: str
    second: int


class AsmStabN(BaseModel):
    type: int
    line: int = 0


class AsmSourceInfo(BaseModel):
    file: str = ""
    file_idx: int = 0
    line: int = 0
    column: int = 0
    is_end: bool = False
    is_usercode: bool = False
    inside_proc: bool = False


class AsmLine(BaseModel):
    text: str = ""
    section: str = ""
    labels: List[AsmLabel] = Field(default_factory=list)
    opcodes: List[str] = Field(default_factory=list)
    closest_parent_label: str = ""
    is_label: bool = False
    is_internal_label: bool = False
    label: str = ""
    source: AsmSourceInfo = Field(default_factory=AsmSourceInfo)
    address: Optional[int] = None
    is_used: bool = False
    is_used_through_alias: bool = False
    is_used_data_through_alias: bool = False
    is_data: bool = False
    is_inline_asm: bool = False
    has_opcode: bool = False
    is_directive: bool = False
    is_assignment: bool = False
