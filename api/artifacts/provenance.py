from api.artifacts.function import Function
from compiler.types.compilation.compilation import CompilerOptions, ProduceCfgOptions
from compiler.types.filters import ParseFiltersAndOutputOptions
from compiler.types.languages import LanguageKey


class CompilerProvenance:
    """
    Placeholder for compiler provenance strategies, which parses
    compiler information, such as name, version, and libraries,
    as well as auto-generated functions that should not be analyzed.
    Since this task is not a part of our research, we only use a
    single compiler for every binary in our dataset so that these
    information may be acquired deterministically.
    """

    def __init__(self, binary: str):
        self.binary = binary
        self.compile_to_object = False

    @property
    def language(self):
        return LanguageKey.cpp

    @property
    def family(self):
        return "g95"

    @property
    def version(self):
        return 1

    @property
    def opt_level(self) -> int:
        return 2

    @property
    def arguments(self):
        return [] # ["-fno-asm", "-g"]

    @property
    def options(self):
        out = {"compilerOptions": CompilerOptions(produceCfg=ProduceCfgOptions(asm=True, ir=False)),
               "filters": ParseFiltersAndOutputOptions(binaryObject=self.compile_to_object)}
        return out

    @property
    def libraries(self):
        return []

    def function_filter(self, function: Function) -> bool:
        return False
        # return function.name in ['_start', 'deregister_tm_clones',
        # 'register_tm_clones', '__do_global_dtors_aux',
        # 'frame_dummy', '__libc_csu_init', '__libc_csu_fini']
