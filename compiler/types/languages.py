from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, conlist


class LanguageKey(Enum):
    ada = 'ada'
    asm6502 = 'asm6502'
    analysis = 'analysis'
    android_java = 'android-java'
    android_kotlin = 'android-kotlin'
    assembly = 'assembly'
    c = 'c'
    cpp = 'c++'
    cppp = 'cppp'
    c3 = 'c3'
    carbon = 'carbon'
    circle = 'circle'
    circt = 'circt'
    clean = 'clean'
    cmake = 'cmake'
    cmakescript = 'cmakescript'
    cobol = 'cobol'
    cpp_for_opencl = 'cpp_for_opencl'
    cppx = 'cppx'
    snowball = 'snowball'
    cppx_blue = 'cppx_blue'
    cppx_gold = 'cppx_gold'
    cpp2_cppfront = 'cpp2_cppfront'
    crystal = 'crystal'
    csharp = 'csharp'
    cuda = 'cuda'
    d = 'd'
    dart = 'dart'
    erlang = 'erlang'
    fortran = 'fortran'
    fsharp = 'fsharp'
    gimple = 'gimple'
    go = 'go'
    haskell = 'haskell'
    hlsl = 'hlsl'
    hook = 'hook'
    hylo = 'hylo'
    ispc = 'ispc'
    jakt = 'jakt'
    java = 'java'
    julia = 'julia'
    javascript = 'javascript'
    kotlin = 'kotlin'
    llvm = 'llvm'
    llvm_mir = 'llvm_mir'
    mlir = 'mlir'
    modula2 = 'modula2'
    nim = 'nim'
    ocaml = 'ocaml'
    objc = 'objc'
    objc_pp = 'objc++'
    openclc = 'openclc'
    pascal = 'pascal'
    pony = 'pony'
    python = 'python'
    racket = 'racket'
    ruby = 'ruby'
    rust = 'rust'
    scala = 'scala'
    solidity = 'solidity'
    swift = 'swift'
    tablegen = 'tablegen'
    toit = 'toit'
    typescript = 'typescript'
    v = 'v'
    vala = 'vala'
    vb = 'vb'
    zig = 'zig'


class Language(BaseModel):
    # Id of language. Added programmatically based on CELanguages key
    id: LanguageKey
    # UI display name of the language
    name: str
    # Monaco Editor language ID (Selects which language Monaco will use to highlight the code)
    monaco: str
    # Usual extensions associated with the language. First one is used as file input extension
    extensions: conlist(str, min_length=1)
    # Different ways in which we can also refer to this language
    alias: List[str]
    # Format API name to use (See https://godbolt.org/api/formats)
    formatter: Optional[str] = None
    # Whether there's at least 1 compiler in this language that supportsExecute
    supportsExecute: Optional[bool] = None
    # Path in /views/resources/logos to the logo of the language
    logoUrl: Optional[str] = None
    # Path in /views/resources/logos to the logo of the language for dark mode use
    logoUrlDark: Optional[str] = None
    # Data from webpack
    logoData: Optional[dict] = None
    # Data from webpack
    logoDataDark: Optional[dict] = None
    # Example code to show in the language's editor
    example: str = ""
    # The override for the output (default is "asm")
    monacoDisassembly: Optional[str] = None
    # Brief description of the language
    tooltip: Optional[str] = None
    # Default compiler for the language. This is populated when handed to the frontend.
    defaultCompiler: Optional[str] = None
    # Regular expression for preview filter
    previewFilter: Optional[Dict] = None  # Server-side mis-processing causes this to always be an empty dict

