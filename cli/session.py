import asyncio
import os
import re
import tempfile
from functools import cached_property

from clang import cindex

from typing import List, Optional
from api.artifacts.provenance import CompilerProvenance
from compiler.types.formatter import FormattingRequest
from config import config
from api.artifacts.function import Function
from api.controller import Decompiler
from api.launcher import Launcher
from api.model import QueryCompleteCallback
from api.models.base_model import Query, LLM
from compiler.client import AsyncCompilerClient
from api.ida.interface import IDAInterface
from compiler.types.compilation.compilation import CompilationRequest, CompilationRequestOptions


class Session:
    def __init__(self, source: Optional[str], binary: str, support_decompilers: List[str], models: List[LLM],
                 proj_dir: Optional[str] = None):
        self._sourceAsm = None
        self._handle = None
        self._source = source
        self._binary = binary
        self._projDir = proj_dir or ""
        self._supported = support_decompilers or []
        self._controller = None
        self._compilerProvenance = CompilerProvenance(binary)
        self._compiler = AsyncCompilerClient({self._compilerProvenance.language})
        self._models = {model.name: model for model in models or [] if isinstance(model, LLM)}
        self._activeModel = 0
        self._modelCollab = False
        self._defs = ""
        assert len(self._models)

    async def compile_src(self):
        with open(self._source, 'r') as file:
            source = (await self._compiler.format(FormattingRequest(source=file.read(),
                                                                    formatterId="clang-format",
                                                                    base="Google"))).answer
            # find functions from source
            options = CompilationRequestOptions(userArguments=' '.join(self._compilerProvenance.arguments),
                                                **self._compilerProvenance.options)
            request = CompilationRequest(source=source, compiler=self._compilerProvenance.family,
                                         lang=self._compilerProvenance.language,
                                         options=options)
            return await self._compiler.compile(request)

    @staticmethod
    def jaccard_similarity(l1: List, l2: List):
        """Define Jaccard Similarity function for two sets"""
        intersection = len(list(set(l1).intersection(l2)))
        union = (len(l2) + len(l2)) - intersection
        return float(intersection) / union

    @staticmethod
    def diff_asm_funcs(a1: str, a2: str):
        pass

    async def start(self):
        launcher = Launcher.instance()
        self._handle = launcher.launch(self._binary, decompilers=self._supported)
        launcher.stream_ida_logs(self._handle)
        launcher.execute_cmd(self._handle, "import sys")
        path = config.root_dir.replace("\\", "\\\\")
        launcher.execute_cmd(self._handle, f'sys.path.append("{path}")')
        await self._compiler.start()

        if self._source:
            self._sourceAsm = await self.compile_src()
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

        # set function asm to that generated from src if src exists
        # gather global variables
        # return when all the xref things are done
        # filter out externs
        return True

    @staticmethod
    def is_user_defined(file: str, cursor: cindex.Cursor):
        if cursor.location.file:
            return os.path.samefile(cursor.location.file.name, file)
        return False

    @cached_property
    def functions_in_src(self):
        functions = []

        def find_functions(node):
            if node.kind == cindex.CursorKind.FUNCTION_DECL \
                    and self.is_user_defined(self._source, node):
                functions.append(node.spelling)
            # Recurse for children of this node
            for child in node.get_children():
                find_functions(child)

        index = cindex.Index.create()
        tu = index.parse(self._source, args=self._compilerProvenance.arguments)
        find_functions(tu.cursor)
        return functions

    async def analyze_all(self):
        ida_interface: IDAInterface = self._controller.interfaces["ida"]
        for scc in ida_interface.sccs:
            # do some scc processing shit
            for function in scc:
                await self._analyze_func(function)

    async def _analyze_func(self, function: Function) -> bool:
        if function.external:
            self._defs += self.func_declaration(function.name, function.signature)
            return True
        if function.init or function.fini or function.plt \
                or self._compilerProvenance.function_filter(function) \
                or self._source and function.name not in self.functions_in_src:
            return True

        print("lvars")
        print(function.lvars)
        while True:
            code, result = await self.compile(function)
            match code:
                case 0:
                    print("perfecting")
                    print(function.pseudocode)
                    await self.perfect("", function)
                    return True
                case 1:
                    print(f"error: {result}")
                    function.pseudocode = await self.resolve_errors(function, result)
                case _:
                    pass

    @staticmethod
    def func_declaration(name: str, signature: str):
        return ""

    def query(self, query: Query, handler: QueryCompleteCallback = None, model: str = "") -> asyncio.Future:
        model = self._models.get(model, next(iter(self._models.values())))
        future = model.enqueue_query(query)
        handler and future.add_done_callback(lambda fut: handler(fut.result()))
        return future

    async def compile(self, function: Function):
        if function.pseudocode:
            options = CompilationRequestOptions(userArguments=' '.join(self._compilerProvenance.arguments),
                                                **self._compilerProvenance.options)
            request = CompilationRequest(source=function.pseudocode, compiler=self._compilerProvenance.family,
                                         lang=self._compilerProvenance.language,
                                         options=options)
            result = await self._compiler.compile(request)
            print(result)

            if result:
                if result.code:
                    ansi_escape = re.compile(r'\x1b\[([0-9]+;)*([0-9]+)?[mK]')
                    escaped_errors = ""
                    for line in result.stderr:
                        escaped_errors += ansi_escape.sub('', line.text) + "\n"
                    return 1, escaped_errors
                return 0, result.asm
        return None, None

    async def resolve_errors(self, function: Function, errs: str):
        """
        Compilability
        3. Fix missing headers (ask if there are missing decs, proceed to define, repeat)
        5. Please fix the following compilation errors in the source code: {compiler_error} {pseudocode} (iterative)
        """

        # note: std headers may be included without resorting to "external libs", so we're good for now!
        query = Query(system=["You are an expert reverse engineering capable of converting pseudocode into compilable "
                              "C code. When you augment pseudocode based on error messages, you only fix the relevant "
                              "components since you like to be efficient."],
                      prompt="Please modify the source code so that these compilation errors would be resolved. If the "
                             "errors are caused by missing headers, please explicitly out the name of the library in "
                             "the first line of your response. Afterwards output the modified function directly - NO "
                             "EXPLANATION IS NEEDED!!!",
                      data=f"Source code:{function.pseudocode}\n"
                           f"Errors: {errs}"
                      )
        return (await self.query(query))[0]

    @staticmethod
    def get_source(file, start_offset, end_offset):
        file.seek(start_offset)
        return file.read(end_offset - start_offset)

    async def perfect(self, asm: str, function: Function) -> bool:
        def find_nodes(file, node, depth=0):
            if self.is_user_defined(file.name, node):
                source_text = self.get_source(file, node.extent.start.offset,
                                              node.extent.end.offset)
                print('  ' * depth + f'{node.kind.name}: {node.spelling} | C code: {source_text}')
            for child in node.get_children():
                find_nodes(file, child, depth + 1)

        # info available: disasm (would need parsing) / original asm (for testing), compilable pseudo, pseudo asm
        # find diffs in asm
        # data flow analysis

        # diff -> pseudo
        # original asm-c mapping
        # correlate back to pseudo, and aggregate actions for all places that haven't been matched if there does not exist


        # a strict correlation (80%)
        # find the deepest corresponding node (leaf) in the ast
        # generate action schema
        # prompt the model to act

        # RL (50%)

        # LLM Input:
        # 1. asm diff
        # 2. relevant c code (differing c + context c)
        # finding relevant subset of pseudocode for modification
        # 3. edit action set (optional, generated from AST)

        # LLM Output:
        # edited c / action from c

        """
        Note: compiler provenance recovery is left for future work


        Equivalence
        6. (algorithmic) Compile & disassemble, diff against original binary assembly -> intraprocedual analysis to
        specify exact places to be changed. "Highlight" by asking first more important changes (structural changes),
        based on how Decomperson categorized them in their UI.
        Types to be considered:
            Control Flow: Constructs that redirect the execution of a program, such as conditionals, loops, and exceptions.
            Declarations: Definitions of new variables, typically locals. We classify these separately from other statements
            because they change the layout of a function’s stack frame.
            Functions: Changes that alter the signature of a function, such as changes to the return type, name, or arguments.
            Statements: Typical imperative programming statements, like assignments, increments, and function calls.
            Types: Constructs that define custom data types, or edits to member variables. (note that we gotta look
            deeper into this, because big types should not be modified, whereas "temp" types should be created)
        7. Iteratively send each difference (pair of code & assembly) to model, also provide Jaccard similarity
        coefficient of bin diffing to give the model a sense of progress.
        Consider using function API of OpenAI (bound model to certain actions, prevents hallucination)

        Remarks:
        - replace absolute memory references with symbols / generic identifiers to avoid diff complaints
        - give the model some rewards (e.g. adjust weight of layer?) when it comes up with regional perfect decompilation
        - clarify on what exact types of operations are allowed, and make sure edits happen one (or those of one type) at
        a time
        - provide function symbol (for exported ones) if possible!
        - maybe prompt for human input if model cannot make correct changes after a while
        - decompilation on binaries with O-level > 0 is a 1-to-n mapping; that is, even after semantic equivalence,
        changes can still be made to further streamline/simplify the code, as all those would be abstracted away upon
        compilation. This part needs further exploration (e.g. switch case optims, arithmetic optims), maybe view as
        separate phase, with correct decompilation as input, stripped source code as criterion, all while making sure the code
        still matches assembly

        Feature was developed based upon:
        1. https://arxiv.org/pdf/2310.06530.pdf
        2. https://www.usenix.org/system/files/sec22-burk.pdf
        Utilize methods from Decomperson and "Refining Decompiled C Code with Large Language Models" to augment
        preprocessed pseudocode to ensure it is a perfect decompilation. The model has a conversation with a compiler
        oracle until a configurable correctness is
        reached.
        :return: bool
        """
        #if asm == "\n".join(line.asm for line in function.lines):
        #    return True

        with tempfile.TemporaryFile(suffix='.c', delete=False, mode='w+t') as tmp_file:
            tmp_file.write(function.pseudocode)
        index = cindex.Index.create()
        with open(tmp_file.name) as f:
            tu = index.parse(f.name, args=self._compilerProvenance.arguments)
            find_nodes(f, tu.cursor)
        return True


# By supposition, we have the original compilable asm and all compiler settings.
# Say we have now corrected all compilation errors in the target pseudocode, which
# we compile according to the same settings, producing ASM that is mapped to surjectively
# from the C code (though technically this is not a mapping as some lines may not have
# matches) and an AST.
# Our goal is to resolve all conflicts between the ASMs by inflicting patches on the
# pseudocode C code such that each step is legal and atomic. To effectively propagate
# information to the LLM, however, is challenging, again due to failure of mapping formed
# possibly by inlining, etc. Hence, instead of directly comparing the ASMs verbatim, we use
# an ASM parser to spot differences more generally. Then we attempt to locate the corresponding
# cursor in the AST by first mapping the places where the ASM differ to C and then C to AST.
# We also mark all nodes visited (that was mapped successfully) in the AST, so that the lingering
# parts could be sorted by process of elimination. Further, we use the AST to determine actions
# that could be undertaken by the model at any given time, since there are only a finite
# set of actions applicable at each cursor.
