from typing import Callable, List, Dict, Optional, Literal
from pydantic import BaseModel

from .result_line import ResultLine


FilenameTransformFunc = Dict #Callable[[str], str]


class UnprocessedExecResult(BaseModel):
    code: int
    okToCache: bool
    filenameTransform: FilenameTransformFunc  # This will be just a placeholder in Pydantic
    stdout: str
    stderr: str
    execTime: str
    timedOut: bool
    languageId: Optional[str] = None
    truncated: bool


class BasicExecutionResult(BaseModel):
    code: int
    okToCache: bool
    filenameTransform: FilenameTransformFunc  # Placeholder
    stdout: List[ResultLine]
    stderr: List[ResultLine]
    execTime: str
    processExecutionResultTime: Optional[int] = None
    timedOut: bool
    languageId: Optional[str] = None
    truncated: Optional[bool] = None


RuntimeToolType = Literal["env", "heaptrack"]


class RuntimeToolOption(BaseModel):
    name: str
    value: str


class PossibleRuntimeToolOption(BaseModel):
    name: str
    possibleValues: List[str]


class PossibleRuntimeTool(BaseModel):
    name: RuntimeToolType
    description: str
    possibleOptions: List[PossibleRuntimeToolOption]


PossibleRuntimeTools = List[PossibleRuntimeTool]

RuntimeToolOptions = List[RuntimeToolOption]


class ConfiguredRuntimeTool(BaseModel):
    name: RuntimeToolType
    options: RuntimeToolOptions


ConfiguredRuntimeTools = List[ConfiguredRuntimeTool]


class ExecutableExecutionOptions(BaseModel):
    args: List[str]
    stdin: str
    ldPath: List[str]
    env: Dict[str, str]
    runtimeTools: Optional[ConfiguredRuntimeTools] = None
