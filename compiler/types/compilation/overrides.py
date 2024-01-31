from typing import Literal, Set, Optional, List
from pydantic import BaseModel, field_validator

CompilerOverrideType = Literal['stdlib', 'gcclib', 'toolchain', 'arch', 'env', 'edition', 'stdver', 'action']

CompilerOverrideTypes = Set[CompilerOverrideType]


class CompilerOverrideOption(BaseModel):
    name: str
    value: str


class CompilerOverrideNameAndOptions(BaseModel):
    name: CompilerOverrideType
    display_title: str
    description: str
    flags: List[str]
    values: List[CompilerOverrideOption]
    default: Optional[str] = None


AllCompilerOverrideOptions = List[CompilerOverrideNameAndOptions]


class EnvVarOverride(BaseModel):
    name: str
    value: str


EnvVarOverrides = List[EnvVarOverride]


class ConfiguredOverrideGeneral(BaseModel):
    name: CompilerOverrideType
    value: str

    @field_validator('name')
    @classmethod
    def name_cannot_be_env(cls, v):
        if v == 'env':
            raise ValueError("ConfiguredOverrideGeneral validation: 'env' not allowed, please use ConfiguredOverrideEnv")
        return v


class ConfiguredOverrideEnv(BaseModel):
    name: Literal['env']
    values: EnvVarOverrides


ConfiguredOverride = ConfiguredOverrideGeneral | ConfiguredOverrideEnv
ConfiguredOverrides = List[ConfiguredOverride]
