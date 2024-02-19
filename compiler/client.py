import aiohttp
import asyncio

from typing import Dict, List, Optional, Set, Tuple
from aiohttp import ContentTypeError

from .types.compiler_arguments import PossibleArguments
from .types.compiler_info import CompilerInfo
from .types.formatter import FormatterInfo, FormattingRequest, FormattingResponse
from .types.languages import LanguageKey, Language
from .types.libraries import Library
from .types.asm_docs import AssemblyDocumentationRequest, AssemblyDocumentationResponse
from .types.compilation.compilation import CompilationRequest, CompilationResult


class CompilerExplorerAPI:
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


def non_optional_fields(cls):
    return list(map(lambda item: item[0], filter(lambda item: item[1].is_required, cls.model_fields.items())))


class AsyncCompilerClient:
    BASE_URL = "https://godbolt.org/api"

    def __init__(self, lang_support: Set[LanguageKey]):
        self.version = None
        self.releaseBuild = None
        self.session = None
        self.languages = None
        self.supported_languages = lang_support
        self.formats = None

    async def _get(self, endpoint: str, params: Dict = None, only_json: bool = False) -> str | Dict:
        """Helper method for GET requests."""
        if only_json:
            self.session.headers.update({'Accept': 'application/json'})
        async with self.session.get(self.BASE_URL + endpoint, params=params or {}) as response:
            if only_json:
                return await response.json()
            return await response.text()

    async def _post(self, endpoint: str, data: str) -> dict:
        """Helper method for POST requests."""
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}
        async with self.session.post(self.BASE_URL + endpoint, data=data, headers=headers) as response:
            try:
                return await response.json()
            except ContentTypeError:
                # to-do: do actual error handling
                print(await response.text())
                raise Exception

    @staticmethod
    def __specify_fields(fields: bool | List[str]) -> Dict:
        params = {}
        if isinstance(fields, bool) and fields:
            params['fields'] = 'all'
        elif isinstance(fields, List):
            params['fields'] = ','.join(fields)
        return params

    async def start(self):
        self.session = aiohttp.ClientSession()
        all_languages = await self._get_languages()
        self.supported_languages = set(all_languages.keys()) & self.supported_languages
        self.languages = {
            lang: {
                "data": all_languages.get(lang, {}),
                "compilers": compilers,
                "libraries": libraries
            }
            for lang, (compilers, libraries) in zip(
                self.supported_languages,
                [await asyncio.gather(self._get_compilers(lang),
                                      self._get_libraries(lang))
                 for lang in self.supported_languages]
            )
        }
        self.formats = await self._get_formats()
        self.version, self.releaseBuild = await self._get_version_info()

    async def stop(self):
        await self.session.close()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def _get_languages(self, fields: bool | List[str] = True) -> Dict[LanguageKey, Language]:
        """GET /api/languages - return a list of languages."""
        supported_langs = await self._get("/languages", params=self.__specify_fields(fields), only_json=True)
        return {LanguageKey(lang['id']): Language.model_validate(lang) for lang in supported_langs}

    async def _get_compilers(self, lang: LanguageKey = "") -> List[CompilerInfo]:
        """
        GET /api/compilers - return a list of compilers.
        GET /api/compilers/<language-id> - return a list of compilers with matching language.
        The official documentation
        """
        compilers = await self._get(f"/compilers/{lang.value}",
                                    params=self.__specify_fields(non_optional_fields(CompilerInfo)), only_json=True)
        return [CompilerInfo.model_validate(compiler) for compiler in compilers]

    async def _get_libraries(self, lang: LanguageKey) -> List[Library]:
        """GET /api/libraries/<language-id> - return a list of libraries available for a language."""
        libraries = await self._get(f"/libraries/{lang.value}", only_json=True)
        return [Library.model_validate(lib) for lib in libraries]

    async def _get_formats(self) -> List[FormatterInfo]:
        """GET /api/formats - return available code formatters."""
        formats = await self._get("/formats", only_json=True)
        return [FormatterInfo.model_validate(format) for format in formats]

    async def _get_version_info(self) -> Tuple[str, str]:
        return await asyncio.gather(self._get(f"/version"), self._get(f"/releaseBuild"))

    async def asm_documentation(self, request: AssemblyDocumentationRequest) -> AssemblyDocumentationResponse:
        # to-do: fix me later
        result = await self._get(f"/{request.instructionSet}/{request.opcode}")
        return AssemblyDocumentationResponse.model_validate(result)

    async def compile(self, request: CompilationRequest) -> Optional[CompilationResult]:
        """
        POST /api/compiler/<compiler-id>/compile - perform a compilation.
        """

        def check_compiler_in_lang(_compiler: str, _lang: LanguageKey):
            return next(filter(lambda info: info.id == _compiler, self.languages[_lang]['compilers']), None)

        if not request.lang:
            request.lang = next(filter(lambda k: check_compiler_in_lang(request.compiler, k), self.languages), None)
        if request.lang not in self.supported_languages or not check_compiler_in_lang(request.compiler, request.lang):
            return None

        resp = await self._post(f"/compiler/{request.compiler}/compile",
                                request.model_dump_json(by_alias=True, exclude_none=True))
        return CompilationResult.model_validate(resp)

    async def format(self, request: FormattingRequest) -> Optional[FormattingResponse]:
        """
        POST /api/format/<formatter> - perform a formatter run.
        """
        if form := next(filter(lambda f: f.name == request.formatterId, self.formats), None):
            if request.base in form.styles:
                resp = await self._post(f"/format/{request.formatterId}", request.model_dump_json(exclude_none=True))
                return FormattingResponse.model_validate(resp)
        return None

    def cmake(self):
        pass

    def popular_arguments(self) -> PossibleArguments:
        "/popularArguments"
        pass

    def optimization_arguments(self):
        pass
