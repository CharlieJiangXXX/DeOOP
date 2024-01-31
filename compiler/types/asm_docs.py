from pydantic import BaseModel, Field, AliasChoices

from .compiler_info import InstructionSet


class AssemblyDocumentationRequest(BaseModel):
    instructionSet: InstructionSet
    opcode: str


class AssemblyDocumentationResponse(BaseModel):
    value: str = Field(validation_alias=AliasChoices('tooltip', 'html', 'url'))


class AssemblyDocumentationError(BaseModel):
    error: str
