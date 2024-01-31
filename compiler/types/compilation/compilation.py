from enum import Enum
from typing import List, Optional, Annotated, Literal, Dict, Callable, Any
from pydantic import BaseModel, Field

from .cfg import CFGResult
from .ir import LLVMIrBackendOptions
from .opt_pipeline_output import OptPipelineBackendOptions, OptPipelineOutput
from .overrides import ConfiguredOverrides
from ..asm_results import ParsedAsmResultLine
from ..compiler_info import BuildEnvDownloadInfo
from ..execution import ConfiguredRuntimeTools, BasicExecutionResult
from ..filters import ParseFiltersAndOutputOptions
from ..languages import LanguageKey
from ..result_line import ResultLine
from ..tools import ToolResult, Artifact


class ActiveTools(BaseModel):
    id: int
    args: List[str]
    stdin: str


class ExecutionParams(BaseModel):
    args: Optional[List[str] | str] = None
    stdin: Optional[str] = None
    runtimeTools: Optional[ConfiguredRuntimeTools] = None


class CompileChildLibraries(BaseModel):
    id: str
    version: str


class GccDumpFlags(BaseModel):
    gimpleFe: bool
    address: bool
    slim: bool
    raw: bool
    details: bool
    stats: bool
    blocks: bool
    vops: bool
    lineno: bool
    uid: bool
    all: bool


class GccDumpViewSelectedPass(BaseModel):
    filename_suffix: Optional[str] = None
    name: Optional[str] = None
    command_prefix: Optional[str] = None
    selectedPass: Optional[str] = None


class ProduceGccDumpOptions(BaseModel):
    opened: bool
    _pass: Optional[Annotated[GccDumpViewSelectedPass, Field(alias="pass")]] = None
    treeDump: Optional[bool] = None
    rtlDump: Optional[bool] = None
    ipaDump: Optional[bool] = None
    dumpFlags: Optional[GccDumpFlags] = None


class ProduceCfgOptions(BaseModel):
    asm: bool
    ir: bool


class PPOptions(BaseModel):
    filter_headers: bool
    clang_format: bool


class CompilerOptions(BaseModel):
    executorRequest: Optional[bool] = None
    skipAsm: Optional[bool] = None
    producePp: Optional[PPOptions] = None
    produceAst: Optional[bool] = None
    produceGccDump: Optional[ProduceGccDumpOptions] = None
    produceStackUsageInfo: Optional[bool] = None
    produceOptInfo: Optional[bool] = None
    produceCfg: Optional[ProduceCfgOptions | Literal[False]] = None
    produceGnatDebugTree: Optional[bool] = None
    produceGnatDebug: Optional[bool] = None
    produceIr: Optional[LLVMIrBackendOptions] = None
    produceOptPipeline: Optional[OptPipelineBackendOptions] = None
    produceDevice: Optional[bool] = None
    produceRustMir: Optional[bool] = None
    produceRustMacroExp: Optional[bool] = None
    produceRustHir: Optional[bool] = None
    produceHaskellCore: Optional[bool] = None
    produceHaskellStg: Optional[bool] = None
    produceHaskellCmm: Optional[bool] = None
    cmakeArgs: Optional[str] = None
    customOutputFilename: Optional[str] = None
    overrides: Optional[ConfiguredOverrides] = None


class CompilationRequestOptions(BaseModel):
    userArguments: str
    compilerOptions: CompilerOptions = CompilerOptions()
    executeParameters: ExecutionParams = ExecutionParams()
    filters: ParseFiltersAndOutputOptions = ParseFiltersAndOutputOptions()
    tools: List[ActiveTools] = []
    libraries: List[CompileChildLibraries] = []


class BypassCache(Enum):
    NoBypass = 0
    Compilation = 1
    Execution = 2


class FiledataPair(BaseModel):
    filename: str
    contents: str


class CompilationRequest(BaseModel):
    source: str
    compiler: str
    options: CompilationRequestOptions
    lang: Optional[LanguageKey] = None
    files: List[FiledataPair] = []
    bypassCache: Optional[BypassCache] = None


class ExecutionResultData(BaseModel):
    code: int
    didExecute: bool
    stdout: Optional[List[ResultLine]] = None
    stderr: Optional[List[ResultLine]] = None
    buildResult: Optional['BuildResult'] = None
    execTime: Optional[int] = None


class IrOutput(BaseModel):
    asm: List[ParsedAsmResultLine]
    cfg: Optional[CFGResult] = None


class BuildStep(BasicExecutionResult):
    compilationOptions: List[str]
    step: str


class SourceLocation(BaseModel):
    File: str
    Line: int
    Column: int


class suCodeEntry(BaseModel):
    DebugLoc: SourceLocation
    Function: str
    Qualifier: Literal['static', 'dynamic', 'dynamic,bounded']
    BytesUsed: int
    displayString: str


class CompilationResult(BaseModel):
    code: int
    timedOut: bool
    okToCache: Optional[bool] = None
    buildResult: Optional['BuildResult'] = None
    buildsteps: Optional[List[BuildStep]] = None
    inputFilename: Optional[str] = None
    asm: Optional[List[ResultLine]] = None
    devices: Optional[Dict[str, 'CompilationResult']] = None
    stdout: List[ResultLine]
    stderr: List[ResultLine]
    truncated: Optional[bool] = None
    didExecute: Optional[bool] = None
    execResult: Optional[ExecutionResultData] = None

    hasGnatDebugOutput: Optional[bool] = None
    gnatDebugOutput: Optional[List[ResultLine]] = None
    hasGnatDebugTreeOutput: Optional[bool] = None
    gnatDebugTreeOutput: Optional[List[ResultLine]] = None
    tools: Optional[List[ToolResult]] = None
    dirPath: Optional[str] = None
    compilationOptions: Optional[List[str]] = None
    downloads: Optional[List[BuildEnvDownloadInfo]] = None
    gccDumpOutput: Optional[Any] = None
    languageId: Optional[str] = None
    result: Optional['CompilationResult'] = None

    hasPpOutput: Optional[bool] = None
    ppOutput: Optional[Any] = None

    hasOptOutput: Optional[bool] = None
    optOutput: Optional[Any] = None
    optPath: Optional[str] = None

    hasStackUsageOutput: Optional[bool] = None
    stackUsageOutput: Optional[List[suCodeEntry]] = None
    stackUsagePath: Optional[str] = None

    hasAstOutput: Optional[bool] = None
    astOutput: Optional[Any] = None

    hasIrOutput: Optional[bool] = None
    irOutput: Optional[IrOutput] = None

    hasOptPipelineOutput: Optional[bool] = None
    optPipelineOutput: Optional[OptPipelineOutput] = None

    cfg: Optional[CFGResult] = None

    hasRustMirOutput: Optional[bool] = None
    rustMirOutput: Optional[Any] = None

    hasRustMacroExpOutput: Optional[bool] = None
    rustMacroExpOutput: Optional[Any] = None

    hasRustHirOutput: Optional[bool] = None
    rustHirOutput: Optional[Any] = None

    hasHaskellCoreOutput: Optional[bool] = None
    haskellCoreOutput: Optional[Any] = None

    hasHaskellStgOutput: Optional[bool] = None
    haskellStgOutput: Optional[Any] = None

    hasHaskellCmmOutput: Optional[bool] = None
    haskellCmmOutput: Optional[Any] = None

    forceBinaryView: Optional[bool] = None

    artifacts: Optional[List[Artifact]] = None

    hints: Optional[List[bool]] = None

    retreivedFromCache: Optional[bool] = None
    retreivedFromCacheTime: Optional[int] = None
    packageDownloadAndUnzipTime: Optional[int] = None
    execTime: Optional[int | str] = None
    processExecutionResultTime: Optional[float] = None
    objdumpTime: Optional[int] = None
    parsingTime: Optional[int] = None

    source: Optional[bool] = None


class ExecutionOptions(BaseModel):
    timeoutMs: Optional[int] = None
    maxErrorOutput: Optional[int] = None
    env: Optional[Dict[str, str]] = None
    wrapper: Optional[Any] = None
    maxOutput: Optional[int] = None
    ldPath: Optional[List[bool]] = None
    appHome: Optional[bool] = None
    customCwd: Optional[bool] = None
    createAndUseTempDir: Optional[bool] = None
    input: Optional[Any] = None
    killChild: Optional[Dict]  # Callable[[], None]] = None


class BuildResult(CompilationResult):
    downloads: List[BuildEnvDownloadInfo]
    executableFilename: str
    compilationOptions: List[str]
    stdout: List[ResultLine]
    stderr: List[ResultLine]
    code: int
