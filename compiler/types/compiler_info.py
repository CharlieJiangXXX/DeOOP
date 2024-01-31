from typing import Optional, List, Dict, Tuple, Literal, Any, Annotated
from pydantic import BaseModel, Field, field_validator

from .execution import PossibleRuntimeTools
from .languages import LanguageKey
from .tools import Tool
from .compilation.overrides import AllCompilerOverrideOptions

InstructionSet = Literal[
    '6502',
    'aarch64',
    'amd64',
    'arm32',
    'avr',
    'beam',
    'c6x',
    'ebpf',
    'evm',
    'hook',
    'core',
    'java',
    'kvx',
    'llvm',
    'loongarch',
    'm68k',
    'mips',
    'mos6502',
    'mrisc32',
    'msp430',
    'powerpc',
    'ptx',
    'python',
    'riscv32',
    'riscv64',
    's390x',
    'sass',
    'sh',
    'sparc',
    'spirv',
    'vax',
    'wasm32',
    'wasm64',
    'xtensa',
    'z80',
]


class LicenseInfo(BaseModel):
    link: Optional[str] = None
    name: Optional[str] = None
    preamble: Optional[str] = None


class RemoteInfo(BaseModel):
    target: str
    path: str
    cmakePath: str


class BuildEnvSetup(BaseModel):
    id: str
    props: Optional[Dict[str, str]] = None  # Assuming the function (name: string, def: string) => string is represented as a dictionary


class BuildEnvDownloadInfo(BaseModel):
    step: str
    packageUrl: str
    time: str


class OptPipeline(BaseModel):
    groupName: Optional[str] = None
    supportedOptions: Optional[List[str]] = None
    supportedFilters: Optional[List[str]] = None
    arg: Optional[List[str]] = None
    moduleScopeArg: Optional[List[str]] = None
    noDiscardValueNamesArg: Optional[List[str]] = None
    monacoLanguage: Optional[str] = None


class CompilerInfo(BaseModel):
    id: str
    exe: str
    name: str
    version: str
    fullVersion: str
    baseName: Optional[str] = None
    alias: List[str]
    options: str
    versionFlag: Optional[List[str]] = None
    versionRe: Optional[str] = None
    explicitVersion: Optional[str] = None
    compilerType: str
    compilerCategories: Optional[List[str]] = None
    debugPatched: Optional[bool] = None
    demangler: str
    demanglerType: str
    demanglerArgs: Optional[List[str]] = None
    objdumper: str
    objdumperType: str
    objdumperArgs: Optional[List[str]] = None
    intelAsm: str
    supportsAsmDocs: bool
    instructionSet: Optional[InstructionSet] = None
    needsMulti: bool
    adarts: str
    supportsDeviceAsmView: Optional[bool] = None
    supportsDemangle: Optional[bool] = None
    supportsBinary: Optional[bool] = None
    supportsBinaryObject: Optional[bool] = None
    supportsIntel: Optional[bool] = None
    interpreted: Optional[bool] = None
    supportsExecute: Optional[bool] = None
    supportsGccDump: Optional[bool] = None
    supportsFiltersInBinary: Optional[bool] = None
    supportsOptOutput: Optional[bool] = None
    supportsStackUsageOutput: Optional[bool] = None
    supportsPpView: Optional[bool] = None
    supportsAstView: Optional[bool] = None
    supportsIrView: Optional[bool] = None
    supportsRustMirView: Optional[bool] = None
    supportsRustMacroExpView: Optional[bool] = None
    supportsRustHirView: Optional[bool] = None
    supportsHaskellCoreView: Optional[bool] = None
    supportsHaskellStgView: Optional[bool] = None
    supportsHaskellCmmView: Optional[bool] = None
    supportsCfg: Optional[bool] = None
    supportsGnatDebugViews: Optional[bool] = None
    supportsLibraryCodeFilter: Optional[bool] = None
    supportsMarch: Optional[bool] = None
    supportsTarget: Optional[bool] = None
    supportsTargetIs: Optional[bool] = None
    executionWrapper: str
    executionWrapperArgs: Optional[List[str]] = None
    postProcess: List[str]
    lang: LanguageKey
    group: str
    groupName: str
    includeFlag: str
    includePath: str
    linkFlag: str
    rpathFlag: str
    libpathFlag: str
    libPath: List[str]
    ldPath: List[str]
    extraPath: Optional[List[str]] = None
    envVars: List[Tuple[str, str]]
    notification: str
    isSemVer: bool
    semver: str
    isNightly: Optional[bool] = None
    libsArr: List[str]
    tools: Dict[str, Tool]
    unwiseOptions: List[str]
    hidden: bool
    buildenvsetup: Optional[BuildEnvSetup] = None
    license: Optional[LicenseInfo] = None
    remote: Optional[RemoteInfo] = None
    possibleOverrides: Optional[AllCompilerOverrideOptions] = None
    possibleRuntimeTools: Optional[PossibleRuntimeTools] = None
    disabledFilters: List[str]
    optArg: Optional[str] = None
    stackUsageArg: Optional[str] = None
    externalparser: Optional[Any] = None
    removeEmptyGccDump: Optional[bool] = None
    irArg: Optional[List[str]] = None
    minIrArgs: Optional[List[str]] = None
    optPipeline: Optional[OptPipeline] = None
    cachedPossibleArguments: Optional[Any] = None
    nvdisasm: Optional[str] = None
    mtime: Optional[Any] = None
    order: Optional[Annotated[int, Field(alias='$order')]] = None

    @field_validator('versionFlag', mode="before")
    @classmethod
    def str2list(cls, v):
        if isinstance(v, str):
            return [v]
