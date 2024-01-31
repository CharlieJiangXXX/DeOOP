from typing import Optional, List, Callable, Dict
from pydantic import BaseModel

PreProcessLinesFunc = Dict # Callable[[List[str]], List[str]]


class CompilerOutputOptions(BaseModel):
    binary: Optional[bool] = None
    binaryObject: Optional[bool] = None
    execute: Optional[bool] = None
    demangle: Optional[bool] = None
    intel: Optional[bool] = None


class ParseFiltersAndOutputOptions(CompilerOutputOptions):
    labels: Optional[bool] = None
    libraryCode: Optional[bool] = None
    directives: Optional[bool] = None
    commentOnly: Optional[bool] = None
    trim: Optional[bool] = None
    debugCalls: Optional[bool] = None
    dontMaskFilenames: Optional[bool] = None
    optOutput: Optional[bool] = None
    preProcessLines: Optional[PreProcessLinesFunc] = None
    preProcessBinaryAsmLines: Optional[PreProcessLinesFunc] = None
