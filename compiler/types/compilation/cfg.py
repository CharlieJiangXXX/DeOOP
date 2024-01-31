from typing import Generic, TypeVar, List, Dict
from pydantic import BaseModel


class EdgeDescriptor(BaseModel):
    from_: str
    to: str
    arrows: str
    color: str


class NodeDescriptor(BaseModel):
    id: str  # typically label for the bb
    label: str  # really the source


class AnnotatedNodeDescriptor(NodeDescriptor):
    width: int  # in pixels
    height: int  # in pixels


ND = TypeVar('ND', NodeDescriptor, AnnotatedNodeDescriptor)


class CfgDescriptor_(BaseModel, Generic[ND]):
    edges: List[EdgeDescriptor]
    nodes: List[ND]


CfgDescriptor = CfgDescriptor_[NodeDescriptor]
AnnotatedCfgDescriptor = CfgDescriptor_[AnnotatedNodeDescriptor]

CFGResult = Dict[str, CfgDescriptor]
AnnotatedCFGResult = Dict[str, AnnotatedCfgDescriptor]
