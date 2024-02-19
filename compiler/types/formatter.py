from typing import List, Optional, Literal
from pydantic import BaseModel, field_validator


class FormatterInfo(BaseModel):
    name: str
    exe: str
    styles: List[str]
    type: str
    version: str
    explicitVersion: Optional[str] = None
    versionArgument: Optional[str] = None
    versionReExp: Optional[str] = None

    @field_validator("name")
    @classmethod
    def patch_clang(cls, v):
        if v == "clang-format":
            return "clangformat"
        return v


FormatBase = Literal['Google', 'LLVM', 'Mozilla', 'Chromium', 'WebKit', 'Microsoft', 'GNU']


class FormattingRequest(BaseModel):
    source: str
    formatterId: str
    base: FormatBase | Literal['__DefaultStyle']
    tabWidth: int = 4
    useSpaces: bool = True

    @field_validator("formatterId", mode="before")
    @classmethod
    def patch_clang(cls, v):
        if v == "clang-format":
            return "clangformat"
        return v


class FormattingResponse(BaseModel):
    answer: Optional[str] = None
    exit: int
    throw: Optional[Literal[True]] = None
