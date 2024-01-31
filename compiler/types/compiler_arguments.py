from typing import Dict, Optional, List

from pydantic import BaseModel


class Specifically(BaseModel):
    arg: str
    timesused: int


class Argument(BaseModel): 
    description: str
    timesused: int
    specifically: Optional[List[Specifically]] = None


PossibleArguments = Dict[str, Argument]
