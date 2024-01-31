from typing import List, Optional, Literal
from pydantic import BaseModel

from .languages import LanguageKey
from .result_line import ResultLine

ToolTypeKey = Literal['independent', 'postcompilation']


class ToolInfo(BaseModel):
    id: str
    name: Optional[str] = None
    type: Optional[ToolTypeKey] = None
    exe: str
    exclude: List[str]
    includeKey: Optional[str] = None
    options: List[str]
    args: Optional[str] = None
    languageId: Optional[LanguageKey] = None
    stdinHint: Optional[str] = None
    monacoStdin: Optional[bool] = None
    icon: Optional[str] = None
    darkIcon: Optional[str] = None
    compilerLanguage: LanguageKey


class Tool(BaseModel):
    tool: ToolInfo
    id: Optional[str] = None
    type: Optional[str] = None


ArtifactType = Literal[
        'application/octet-stream',
        'nesrom',
        'bbcdiskimage',
        'zxtape',
        'smsrom',
        'timetracejson',
        'c64prg',
        'heaptracktxt']


class Artifact(BaseModel):
    content: str
    type: ArtifactType
    name: str
    title: str


class ToolResult(BaseModel):
    id: str
    name: Optional[str] = None
    code: int
    languageId: Optional[LanguageKey | Literal['stderr']] = None  # Assuming LanguageKey is a string
    stderr: List[ResultLine]
    stdout: List[ResultLine]
    artifact: Optional[Artifact] = None
    sourcechanged: Optional[bool] = None
    newsource: Optional[str] = None
