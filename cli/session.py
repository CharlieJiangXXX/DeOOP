import asyncio
import re
from typing import List, Optional

from config import config
from api.artifacts.function import Function
from api.controller import Decompiler
from api.launcher import Launcher
from api.model import QueryCompleteCallback
from api.models.base_model import Query, LLM
from compiler.client import AsyncCompilerClient
from api.ida.interface import IDAInterface
from compiler.types.compilation.compilation import CompilationRequest, CompilationRequestOptions

from compiler.types.languages import LanguageKey


class Session:
    def __init__(self, binary: str, support_decompilers: List[str], models: List[LLM], proj_dir: Optional[str] = None):
        self._handle = None
        self._binary = binary
        self._projDir = proj_dir or ""
        self._supported = support_decompilers or []
        self._controller = None
        self._binaryLanguage = LanguageKey.cpp
        self._compilerSettings = "g95"
        self._compiler = AsyncCompilerClient({self._binaryLanguage})
        self._models = {model.name: model for model in models or [] if isinstance(model, LLM)}
        self._activeModel = 0
        self._modelCollab = False
        assert len(self._models)

    @staticmethod
    def jaccard_similarity(l1: List, l2: List):
        """Define Jaccard Similarity function for two sets"""
        intersection = len(list(set(l1).intersection(l2)))
        union = (len(l2) + len(l2)) - intersection
        return float(intersection) / union

    async def start(self):
        launcher = Launcher.instance()
        self._handle = launcher.launch(self._binary, decompilers=self._supported)
        launcher.stream_ida_logs(self._handle)
        launcher.execute_cmd(self._handle, "import sys")
        path = config.root_dir.replace("\\", "\\\\")
        launcher.execute_cmd(self._handle, f'sys.path.append("{path}")')
        await self._compiler.start()

        self._controller = Decompiler(self._handle, self._supported)
        self._projDir and self._controller.load_from_file(self._projDir)
        self.preprocess()

    async def stop(self):
        await self._compiler.stop()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    def preprocess(self) -> bool:
        ida_interface: IDAInterface = self._controller.interfaces["ida"]
        if not ida_interface.condensed_graph:
            return False

        # gather global variables
        # return when all the xref things are done
        # filter out externs
        return True

    async def analyze_all(self):
        ida_interface: IDAInterface = self._controller.interfaces["ida"]
        for scc in ida_interface.sccs:
            # do some scc processing shit
            for function in scc:
                await self._analyze_func(function)

    async def _analyze_func(self, function: Function) -> bool:
        code, result = await self.compile(function)
        match code:
            case 1:
                print(await self.resolve_errors(function, result))
            case _:
                pass
        return True

    def query(self, query: Query, handler: QueryCompleteCallback = None, model: str = "") -> asyncio.Future:
        model = self._models.get(model, next(iter(self._models.values())))
        future = model.enqueue_query(query)
        handler and future.add_done_callback(lambda fut: handler(fut.result()))
        return future

    async def compile(self, function: Function):
        if function.pseudocode:
            options = CompilationRequestOptions(userArguments="-O3")
            request = CompilationRequest(source=function.pseudocode, compiler=self._compilerSettings,
                                         lang=self._binaryLanguage,
                                         options=options)
            result = await self._compiler.compile(request)

            if result:
                if result.code:
                    ansi_escape = re.compile(r'\x1b\[([0-9]+;)*([0-9]+)?[mK]')
                    escaped_errors = ""
                    for line in result.stderr:
                        escaped_errors += ansi_escape.sub('', line.text) + "\n"
                    return 1, escaped_errors
        return None, None

    async def resolve_errors(self, function: Function, errs: str):
        """
        Compilability
        3. Fix missing headers (ask if there are missing decs, proceed to define, repeat)
        5. Please fix the following compilation errors in the source code: {compiler_error} {pseudocode} (iterative)
        """
        query = Query(system=["You are an expert reverse engineering capable of converting pseudocode into compilable "
                              "C code. When you augment pseudocode based on error messages, you only fix the relevant "
                              "components since you like to be efficient."],
                      prompt="Please modify the source code so that these compilation errors would be resolved.",
                      data=f"Source code:{function.pseudocode}\n"
                           f"Errors: {errs}"
                      )
        return await self.query(query)
