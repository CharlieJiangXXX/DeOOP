from typing import Optional, List, Dict
from pydantic import BaseModel


class LibraryVersion(BaseModel):
    name: Optional[str] = None
    staticliblink: List[str]
    alias: Optional[List[str]] = None
    version: Optional[str] = None
    dependencies: List[str]
    liblink: List[str]
    libpath: List[str]
    path: List[str]
    options: List[str]
    hidden: Optional[bool] = None
    packagedheaders: Optional[bool] = None


class Library(BaseModel):
    id: str
    url: Optional[str] = None
    name: Optional[str] = None
    versions: List[LibraryVersion]


class SelectedLibraryVersion(BaseModel):
    id: str
    version: str
