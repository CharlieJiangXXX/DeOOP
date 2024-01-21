import functools
import os
import sys
from typing import List, Optional

import config
from api.common import loadall
from api.controller import Decompiler
from api.launcher import Launcher
from model.compiler_explorer import CompilerManager


class Session:
    def __init__(self, binary: str, support_decompilers: List[str], proj_dir: Optional[str] = None):
        self._handle = None
        self._binary = binary
        self._projDir = proj_dir or ""
        self._supported = support_decompilers or []
        self._controller = None
        self._compiler = CompilerManager(["cpp"])

    def start(self):
        launcher = Launcher.instance()
        self._handle = launcher.launch(self._binary, decompilers=self._supported)
        launcher.stream_ida_logs(self._handle)
        launcher.execute_cmd(self._handle, "import sys")
        path = config.root_dir.replace("\\", "\\\\")
        launcher.execute_cmd(self._handle, f'sys.path.append("{path}")')

        self._controller = Decompiler(self._handle, self._supported)
        self._projDir and self._controller.load_from_file(self._projDir)
        self._controller.test()

    @classmethod
    def create(cls, binary: str, support_decompilers: List[str], proj_dir: Optional[str] = None):
        obj = cls(binary, support_decompilers, proj_dir)
        obj.start()
        return obj
