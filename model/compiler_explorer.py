from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from requests import Response


@dataclass
class ClientState:
    pass


@dataclass
class Formatter:
    name: str
    exe: str
    version: str
    styles: List[str]
    type: str


@dataclass
class CompilerData:
    id: str
    data: Dict


@dataclass
class LanguageData:
    id: str
    libraries: List[Dict]
    compilers: Dict[str, CompilerData]


class CompilerExplorerAPI:
    BASE_URL = "https://godbolt.org"

    @classmethod
    def _get(cls, endpoint: str, only_json: bool = False):
        """Helper method for GET requests."""
        session = requests.Session()
        if only_json:
            session.headers.update({'Accept': 'application/json'})
        return session.get(cls.BASE_URL + endpoint)

    @classmethod
    def _post(cls, endpoint: str, data) -> Response:
        """Helper method for POST requests."""
        headers = {"Content-Type": "application/json"}
        return requests.post(cls.BASE_URL + endpoint, json=data, headers=headers)

    @classmethod
    def get_languages(cls) -> Dict[str, LanguageData]:
        """GET /api/languages - return a list of languages."""
        supported_langs = cls._get("/api/languages").text
        out = {}
        for lang in supported_langs.splitlines()[1:]:
            parts = lang.split('|')
            out[parts[0].strip()] = LanguageData(parts[1].strip(), [], {})
        return out

    @classmethod
    def get_compilers(cls, language_id: str = "", simple: bool = True, all_fields: bool = False,
                      fields: List[str] = None):
        """
        GET /api/compilers - return a list of compilers.
        GET /api/compilers/<language-id> - return a list of compilers with matching language.
        The official documentation
        """
        endpoint = "/api/compilers"
        if language_id:
            endpoint += f"/{language_id}"

        if all_fields or fields:
            endpoint += f"?fields={'all' if all_fields else ','.join(fields)}"

        return cls._get(endpoint, not simple)

    @classmethod
    def get_libraries(cls, language_id: str) -> List[Dict]:
        """GET /api/libraries/<language-id> - return a list of libraries available for a language."""
        return cls._get(f"/api/libraries/{language_id}", True).json()

    @classmethod
    def get_shortlink_info(cls, link_id: str) -> Dict:
        """GET /api/shortlinkinfo/<linkid> - return information about a given link."""
        return cls._get(f"/api/shortlinkinfo/{link_id}", True).json()

    @classmethod
    def create_shortlink(cls, client_state):
        """
        POST /api/shortener - saves given state forever to a shortlink and returns the unique id for the link.
        """
        return cls._post("/api/shortener", client_state).json()["url"]

    @classmethod
    def get_formats(cls) -> List[Formatter]:
        """GET /api/formats - return available code formatters."""
        return [Formatter(**format) for format in cls._get("/api/formats", True).json()]

    @classmethod
    def compile(cls, lang: str, compiler_id: str, source: str, allow_store: bool = True,
                files: List = None, bypass_cache: int = 0, options: Dict = None) -> Dict:
        """
        POST /api/compiler/<compiler-id>/compile - perform a compilation.
        """
        assert bypass_cache in range(0, 3)
        data = {
            "source": source,
            "options": options or {},
            "lang": lang,
            "files": files or [],
            "bypassCache": bypass_cache,
            "allowStoreCodeDebug": allow_store
        }
        return cls._post(f"/api/compiler/{compiler_id}/compile", data).json()

    @classmethod
    def format_code(cls, formatter, source, base, use_spaces, tab_width):
        """
        POST /api/format/<formatter> - perform a formatter run.
        """
        data = {
            "source": source,
            "base": base,
            "useSpaces": use_spaces,
            "tabWidth": tab_width
        }
        return cls._post(f"/api/format/{formatter}", data)


class CompilerManager:
    def __init__(self, lang_support: List[str]):
        self.data: Dict[str, LanguageData] = CompilerExplorerAPI.get_languages()
        self.supported_languages = lang_support
        for lang in self.supported_languages:
            self.add_language(lang)

    def add_language(self, lang_id: str) -> bool:
        if lang_id not in self.data:
            return False
        self.data[lang_id].libraries = CompilerExplorerAPI.get_libraries("c")
        for compiler in CompilerExplorerAPI.get_compilers(lang_id).text.splitlines()[1:]:
            parts = compiler.split('|')
            self.data[lang_id].compilers[parts[0].strip()] = CompilerData(parts[1].strip(), {})

    def compilers_for_langauge(self, lang_id: str) -> List[str]:
        if lang_id not in self.supported_languages:
            return []
        return list(self.data[lang_id].compilers.keys())

    def compiler_info(self, lang_id: str, save_all: bool = False, compiler_id: str = "") -> Optional[CompilerData]:
        if not save_all and not compiler_id:
            return
        if compiler_id:
            save_all = False

        if lang_id in self.supported_languages and compiler_id in self.data[lang_id].compilers:
            for info in list(CompilerExplorerAPI.get_compilers(lang_id, False, True).json()):
                if save_all or info["id"] == compiler_id:
                    self.data[lang_id].compilers[compiler_id].data = info
                    if compiler_id:
                        return info

    def compile(self, lang_id: str, compiler_id: str, source_code: str, user_arguments: str = "",
                preprocess: bool = False, gcc_tree=False, ):
        if lang_id in self.data and compiler_id in self.data[lang_id].compilers:
            options = {}
            CompilerExplorerAPI.compile(lang_id, compiler_id, source_code, options=options)


mgr = CompilerManager(["c", "c++"])
mgr.compiler_info("c", "cg95")

"""

{"options":
     {"userArguments":"-O3",
      "compilerOptions":
          {"producePp":null, # preprocess
           "produceGccDump":{}, # gcc tree/rtl
           "produceOptInfo":false,
           "produceCfg":false,
           "produceIr":null,
           "produceOptPipeline":null,
           "produceDevice":false,
           "overrides":
               [{"name":"env",
                 "values":[{"name":"HI","value":"pekka"}]},
                {"name":"arch","value":"corei7"},
                {"name":"stdver","value":"c++17"}]
           }
      "filters":
          {"binaryObject":false,
           "binary":false,"execute":false,"intel":true,"demangle":true,"labels":true,"libraryCode":true,"directives":true,"commentOnly":true,"trim":false,"debugCalls":false
           },
      "tools":[],
      "libraries":[],
      "executeParameters":{"args":"","stdin":""}
    },
 "lang":"c++",
 "files":[],
 "bypassCache":0,
 "allowStoreCodeDebug":true}

{
    "inputFilename": "/tmp/compiler-explorer-compiler202401-7451-1t22jvb.ce44/example.cpp",
    "code": 0,
    "okToCache": true,
    "timedOut": false,
    "stdout": [],
    "stderr": [],
    "truncated": false,
    "execTime": "69",
    "processExecutionResultTime": 0.002061009407043457,
    "compilationOptions": [
        "-g",
        "-o",
        "/tmp/compiler-explorer-compiler202401-7451-1t22jvb.ce44/output.s",
        "-masm=intel",
        "-S",
        "-fdiagnostics-color=always",
        "-march=corei7",
        "-std=c++17",
        "-O3",
        "/tmp/compiler-explorer-compiler202401-7451-1t22jvb.ce44/example.cpp"
    ],
    "downloads": [],
    "tools": [],
    "asmSize": 3201,
    "asm": [
        {
            "text": "square(int):",
            "source": null,
            "labels": []
        },
        {
            "text": "        imul    edi, edi",
            "source": {
                "file": null,
                "line": 3,
                "column": 18
            },
            "labels": []
        },
        {
            "text": "        mov     eax, edi",
            "source": {
                "file": null,
                "line": 4,
                "column": 1
            },
            "labels": []
        },
        {
            "text": "        ret",
            "source": {
                "file": null,
                "line": 4,
                "column": 1
            },
            "labels": []
        }
    ],
    "labelDefinitions": {
        "square(int)": 1
    },
    "parsingTime": "1",
    "filteredCount": 200,
    "popularArguments": {
        "-fwhole-program": {
            "description": "Perform whole program optimizations.",
            "timesused": 0
        },
        "-fprofile-use=": {
            "description": "Enable common options for performing profile feedback directed optimizations, and set",
            "timesused": 0
        },
        "-fprofile-use": {
            "description": "Enable common options for performing profile feedback directed optimizations.",
            "timesused": 0
        },
        "-fprofile-generate=": {
            "description": "Enable common options for generating profile info for profile feedback directed optimizations, and set -fprofile-dir=.",
            "timesused": 0
        },
        "-fprofile-generate": {
            "description": "Enable common options for generating profile info for profile feedback directed optimizations.",
            "timesused": 0
        }
    }
}

"""
