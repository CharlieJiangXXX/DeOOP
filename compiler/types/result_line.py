from typing import Optional, List
from pydantic import BaseModel


class Link(BaseModel):
    text: str
    url: str


class MessageWithLocation(BaseModel):
    line: Optional[int] = None
    column: Optional[int] = None
    file: Optional[str] = None
    text: str
    endline: Optional[int] = None
    endcolumn: Optional[int] = None


class Fix(BaseModel):
    title: str
    edits: List[MessageWithLocation]


class ResultLineTag(MessageWithLocation):
    severity: int
    link: Optional[Link] = None
    flow: Optional[List[MessageWithLocation]] = None
    fixes: Optional[List[Fix]] = None


class ResultLineSource(BaseModel):
    file: Optional[str] = None
    line: int
    mainsource: Optional[bool] = None


class ResultLine(BaseModel):
    text: str
    tag: Optional[ResultLineTag] = None
    source: Optional[ResultLineSource] = None
    line: Optional[int] = None
