from typing import Optional, List, Dict
from pydantic import BaseModel

from ..result_line import ResultLine


class Pass(BaseModel):
    name: str
    machine: bool
    after: List[ResultLine]
    before: List[ResultLine]
    irChanged: bool


OptPipelineResults = Dict[str, List[Pass]]


class OptPipelineOutput(BaseModel):
    error: Optional[str] = None
    results: OptPipelineResults
    compileTime: Optional[int | str] = None
    parseTime: Optional[int] = None


class OptPipelineBackendOptions(BaseModel):
    filterDebugInfo: bool
    filterIRMetadata: bool
    fullModule: bool
    noDiscardValueNames: bool
    demangle: bool
    libraryFunctions: bool
