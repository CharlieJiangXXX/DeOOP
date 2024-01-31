from typing import Optional, List, Dict, Union
from pydantic import BaseModel


class AsmResultSource(BaseModel):
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    mainsource: Optional[bool] = None


class AsmResultLink(BaseModel):
    offset: int
    length: int
    to: int


class AsmResultLabelRange(BaseModel):
    startCol: int
    endCol: int


class AsmResultLabel(BaseModel):
    name: str
    range: AsmResultLabelRange


class ParsedAsmResultLine(BaseModel):
    text: str
    opcodes: Optional[List[str]] = None
    address: Optional[int] = None
    disassembly: Optional[str] = None
    source: Optional[AsmResultSource] = None
    links: Optional[List[AsmResultLink]] = None
    labels: Optional[List[AsmResultLabel]] = None


class ParsedAsmResult(BaseModel):
    asm: List[ParsedAsmResultLine]
    labelDefinitions: Optional[Dict[str, int]] = None
    parsingTime: Optional[str] = None
    filteredCount: Optional[int] = None
    externalParserUsed: Optional[bool] = None
    objdumpTime: Optional[Union[int, str]] = None
    execTime: Optional[str] = None
    languageId: Optional[str] = None


class IRResultLine(ParsedAsmResultLine):
    scope: Optional[str] = None
