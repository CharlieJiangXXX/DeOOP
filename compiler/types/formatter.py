from typing import List, Optional, Literal
from pydantic import BaseModel


class FormatterInfo(BaseModel):
    name: str
    exe: str
    styles: List[str]
    type: str
    version: str
    explicitVersion: Optional[str] = None
    versionArgument: Optional[str] = None
    versionReExp: Optional[str] = None


class FormatOptions(BaseModel):
    useSpaces: bool
    tabWidth: int
    baseStyle: str


FormatBase = Literal['Google', 'LLVM', 'Mozilla', 'Chromium', 'WebKit', 'Microsoft', 'GNU']


class FormattingRequest(BaseModel):
    source: str
    formatterId: str
    base: FormatBase | Literal['__DefaultStyle']
    tabWidth: int
    useSpaces: bool


class FormattingResponse(BaseModel):
    answer: Optional[str] = None
    exit: int
    throw: Optional[Literal[True]] = None