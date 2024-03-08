import asyncio
import base64
import os
import re
import tempfile
from functools import cached_property
import numpy as np

import archinfo
import docker
import pyvex
import networkx as nx
from clang import cindex

from typing import List, Optional, Tuple, Set
from collections import Counter
from api.artifacts.provenance import CompilerProvenance
from compiler.types.compilation.cfg import CfgDescriptor
from compiler.types.formatter import FormattingRequest
from config import config
from api.artifacts.function import Function
from api.controller import Decompiler
from api.launcher import Launcher
from api.model import QueryCompleteCallback
from api.models.base_model import Query, LLM
from compiler.client import AsyncCompilerClient
from api.ida.interface import IDAInterface
from api.isomorphism import mcisi
from compiler.types.compilation.compilation import CompilationRequest, CompilationRequestOptions, CompilationResult

arch_to_pyvex_arch_map = {
    'x86': archinfo.ArchX86(),
    'x86-32': archinfo.ArchX86(),
    'x64': archinfo.ArchAMD64(),
    'x86-64': archinfo.ArchAMD64(),
    'arm32': archinfo.ArchARM(),
    'arm-32': archinfo.ArchARM(),
    'arm64': archinfo.ArchAArch64(),
    'arm-64': archinfo.ArchAArch64(),
    'mips32': archinfo.ArchMIPS32(),
    'mips-32': archinfo.ArchMIPS32(),
    'mips64': archinfo.ArchMIPS64(),
    'mips-64': archinfo.ArchMIPS64(),
}

arch_to_pwntools_arch_map = {
    'x86': 'i386',
    'x86-32': 'i386',
    'x64': 'amd64',
    'x86-64': 'amd64',
    'arm32': 'arm',
    'arm-32': 'arm',
    'arm64': 'aarch64',
    'arm-64': 'aarch64',
    'mips32': 'mips',
    'mips-32': 'mips',
    'mips64': 'mips64',
    'mips-64': 'mips64',
}


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
        self._dockerClient = None
        self._dockerTag = "verbatim:latest"
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
    def jaccard_similarity(l1: Set, l2: Set):
        """Define Jaccard Similarity function for two sets"""
        intersection = len(list(l1.intersection(l2)))
        union = (len(l1) + len(l2)) - intersection
        return float(intersection) / union

    @staticmethod
    def cosine_similarity(vector1, vector2):
        dot_product = np.dot(vector1, vector2)
        magnitude1 = np.linalg.norm(vector1)
        magnitude2 = np.linalg.norm(vector2)
        similarity = dot_product / (magnitude1 * magnitude2)
        return similarity

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
            self._sourceAsm = (await self.compile_src()).asm
        self._controller = Decompiler(self._handle, self._supported)
        self._dockerClient = docker.from_env()
        if not self._dockerClient.images.list(name=self._dockerTag):
            self._dockerClient.images.build(path=os.path.dirname(__file__), tag=self._dockerTag)
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

    def similar(self):
        pass

    async def _analyze_func(self, function: Function) -> bool:
        if function.external:
            self._defs += self.func_declaration(function.name, function.signature)
            return True
        if function.init or function.fini or function.plt \
                or self._compilerProvenance.function_filter(function) \
                or self._source and function.name not in self.functions_in_src:
            return True

        target_cfg = self.extract_vex(self._controller.interfaces["ida"].cfg(function), function)
        while True:
            code, result = await self.compile(function)
            match code:
                case 0:
                    # We keep the CFG structure from -S while adopting BB asm
                    # from -c so that they could actually be assembled with pwntools
                    current_cfg = self.cfg_desc_to_nx(next(iter(result.cfg.values())))
                    self._compilerProvenance.compile_to_object = True
                    _, result = await self.compile(function)
                    self._compilerProvenance.compile_to_object = False
                    result.asm = list(filter(lambda obj: obj.source, result.asm))
                    nodes = next(iter(result.cfg.values())).nodes

                    i, j = 0, 0
                    for node, data in current_cfg.nodes(data=True):
                        # we need error handling here
                        # the target block would always be larger than the original
                        src_lines = data["src"].split("\n")
                        target_lines = nodes[i].label.split("\n")

                        # strip label
                        label = src_lines[0]
                        src_lines = src_lines[1:]
                        target_lines = target_lines[1:]

                        if len(target_lines) - len(src_lines) > 0:
                            nodes[i].label = "\n".join([label] + target_lines[len(src_lines):])
                            target_lines = target_lines[:len(src_lines)]
                        else:
                            i += 1

                        def _strip(s):
                            return re.sub(r'\s+', '', s)

                        for line in target_lines:
                            if _strip(line) == _strip(result.asm[j].text):
                                if "bytes" not in data:
                                    data["bytes"] = []
                                try:
                                    data["bytes"].extend(result.asm[j].opcodes)
                                except:
                                    # handle function calls!
                                    # call   43 <main+0x43>
                                    # R_X86_64_PLT32 exit-0x4
                                    print(result.asm[j])
                                j += 1

                        find_offset_labels = r"<[^>]*\+0x[0-9a-fA-F]+>"
                        find_unprefixed_addr = r'(?<!0x)\b[0-9a-fA-F]+(?:\b|\Z)'

                        def add_value_and_prefix(match):
                            modified_hex = int(match.group(0), 16) + function.start_addr
                            return f"0x{modified_hex:x}"  # Convert back to hex and prepend '0x'

                        # Remove jump labels and fix addresses
                        data["src"] = re.sub(find_unprefixed_addr, add_value_and_prefix,
                                             re.sub(find_offset_labels, "", "\n".join(target_lines)))
                        if "bytes" in data:
                            data["bytes"] = base64.b64encode(bytes.fromhex("".join(data["bytes"])))

                    await self.perfect(target_cfg, self.extract_vex(current_cfg, function), function)
                    return True
                case 1:
                    print(f"Compilation error: {result}")
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

    @staticmethod
    def cfg_desc_to_nx(desc: CfgDescriptor) -> nx.DiGraph:
        graph = nx.DiGraph()
        for node in desc.nodes:
            graph.add_node(node.id, src=node.label)
        graph.add_edges_from([(edge.from_, edge.to) for edge in desc.edges])
        return graph

    async def compile(self, function: Function) -> Tuple[Optional[int], Optional[str | CompilationResult]]:
        if function.pseudocode:
            options = CompilationRequestOptions(userArguments=' '.join(self._compilerProvenance.arguments),
                                                **self._compilerProvenance.options)
            request = CompilationRequest(source=function.pseudocode, compiler=self._compilerProvenance.family,
                                         lang=self._compilerProvenance.language,
                                         options=options)
            if result := await self._compiler.compile(request):
                if result.code:
                    ansi_escape = re.compile(r'\x1b\[([0-9]+;)*([0-9]+)?[mK]')
                    escaped_errors = ""
                    for line in result.stderr:
                        escaped_errors += ansi_escape.sub('', line.text) + "\n"
                    return 1, escaped_errors
                return 0, result
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
                      prompt="Please modify the source code so that these compilation errors would be resolved. Include"
                             "all headers necessary for the types used."  # If the "
                      # "errors are caused by missing headers, please explicitly out the name of the library in "
                      # "the first line of your response. Afterwards" 
                             "Output the modified function directly - NO EXPLANATION IS NEEDED!!! Don't mark up the code"
                             "block with ```c!!! This would mess up internal processing if you do.",
                      data=f"Source code:{function.pseudocode}\n"
                           f"Errors: {errs}"
                      )
        return (await self.query(query))[0]

    @staticmethod
    def get_source(file, start_offset, end_offset):
        file.seek(start_offset)
        return file.read(end_offset - start_offset)

    def extract_vex(self, cfg: nx.DiGraph, function: Function):
        interface = self._controller.interfaces["ida"]
        cfg = cfg.copy()
        for node, data in cfg.nodes(data=True):
            bytes_ = b""
            if "bytes" in data:
                bytes_ = base64.b64decode(data["bytes"])
            elif "src" in data:
                # Deprecated
                bytes_ = self._dockerClient.containers.run(self._dockerTag,
                                                           command="python3 -c \"from pwn import asm;"
                                                                   f"print(asm(r'''{data['src']}''',"
                                                                   f"vma={hex(function.start_addr)},"
                                                                   f"arch='{arch_to_pwntools_arch_map[interface.procname]}'))\"",
                                                           remove=True)
            if bytes_:
                irsb = pyvex.lift(bytes_, function.start_addr,
                                  arch_to_pyvex_arch_map[interface.procname],
                                  opt_level=self._compilerProvenance.opt_level)
                cfg.nodes[node]["irsb"] = irsb

        return cfg

    def calculate_score_matrix(self, src: nx.DiGraph, target: nx.DiGraph, mode: int = 1, match_threshold: float = 0.9999):
        # the initial scores rn are not the greatest, we gotta find a better way to extract syntactic
        # info out of irsbs
        scores = {}
        for snode, sdata in src.nodes(data=True):
            for tnode, tdata in target.nodes(data=True):
                slines = sdata["irsb"]._pp_str().split("\n")
                tlines = tdata["irsb"]._pp_str().split("\n")
                if mode:
                    sfreqs = Counter(slines)
                    tfreqs = Counter(tlines)
                    all_operations = set(sfreqs.keys()).union(set(tfreqs.keys()))
                    vector1 = np.array([sfreqs[op] if op in sfreqs else 0 for op in all_operations])
                    vector2 = np.array([tfreqs[op] if op in tfreqs else 0 for op in all_operations])
                    similarity = self.cosine_similarity(vector1, vector2)
                else:
                    similarity = self.jaccard_similarity(set(slines), set(tlines))
                if similarity > match_threshold:
                    similarity = 1.0
                scores[(snode, tnode)] = similarity
        return scores

    async def perfect(self, target_cfg: nx.DiGraph, current_cfg: nx.DiGraph, function: Function) -> bool:
        def find_nodes(file, node, depth=0):
            if self.is_user_defined(file.name, node):
                source_text = self.get_source(file, node.extent.start.offset,
                                              node.extent.end.offset)
                print('  ' * depth + f'{node.kind.name}: {node.spelling} | C code: {source_text}')
            for child in node.get_children():
                find_nodes(file, child, depth + 1)

        swapped = False
        g_size1, g_size2 = current_cfg.number_of_nodes(), target_cfg.number_of_nodes()

        if not g_size1 or not g_size2:
            if g_size1 == g_size2:
                return True
            else:
                # generate prompt according
                # ret = score_diff
                return False
        else:
            if g_size1 < g_size2:
                cfg1, cfg2 = current_cfg, target_cfg
            else:
                swapped = True
                cfg1, cfg2, g_size1, g_size2 = target_cfg, current_cfg, g_size2, g_size1

            scores = self.calculate_score_matrix(cfg1, cfg2)

        def pp(cfg):
            for node, data in cfg.nodes(data=True):
                print(node)
                if "src" in data:
                    print(data["src"])
                if "disasms" in data:
                    print(data["disasms"])
                data["irsb"].pp()

        print("Finding MCISI...")
        ret, result, score, size = mcisi(cfg1, cfg2, g_size1, scores)
        if not ret:
            return False
        print(f'[*] score: {score}, size: {size}')

        keys = result.keys()
        matchings = {k: v for k, v in (keys if swapped else list(map(lambda x: (x[1], x[0]), keys)))}
        unmatched_target = list(filter(lambda node: node not in matchings.keys(), target_cfg.nodes))
        redundant_src = list(filter(lambda node: node not in matchings.values(), current_cfg.nodes))

        # we need pairings from bbs back to c

        # solve by cases
        # 1. If a node is detached from all others in target, and another such node exists in source,
        # then we could pair them together, even though they are not part of the MCS.
        # goal: "add" all unmatched, "remove" all redundant
        # we want to see if there are possible matches within these two lists that are not linked
        # solely due to structure. we may look at the initial scoring again. if the scores are all really low,
        # we could remove the redundant and ask the model to add them from scratch (unlikely). otherwise,
        # we ask the model to fix the edges based on the mappings


        # ast:
        # traverse tree to find deepest node (maybe leaf) containing target c code (maybe consider in degree out degree)
        # based on prompt action (add remove) recursively attempt different options (bfs here?)

        # observation: either precise compiler provenance or cross-compiler binary similarity
        # is needed

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
        # if asm == "\n".join(line.asm for line in function.lines):
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
