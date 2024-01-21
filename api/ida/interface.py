import functools
from typing import Callable, Any, Optional
from ..interface import DecompilerInterface
from ..launcher import Launcher

try:
    import idaapi
    import idc
    import ida_hexrays
except ImportError:
    pass


class IDAInterface(DecompilerInterface):
    def __init__(self, handle: int):
        super().__init__(handle)
        self._decompilerAvailable: Optional[bool] = None

    @staticmethod
    def execute(wait: bool = True, handler: Callable[[Any], None] = None,
                mode: int = Launcher.TaskMode.SAFE.value):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(self, *args, **kwargs):
                launcher = Launcher.instance()

                task = launcher.enqueue_task(self._handle, lambda: func(self, *args, **kwargs),
                                             handler, mode)
                if wait:
                    return task.get_loop().run_until_complete(task)
                return task
            return wrapper
        return decorator

    @execute()
    def binary_base_addr(self) -> int:
        return idaapi.get_imagebase()

    @execute()
    @property
    def binary_hash(self) -> str:
        return idc.retrieve_input_file_md5().hex()

    @execute()
    @property
    def binary_path(self) -> Optional[str]:
        return idaapi.get_input_file_path()

    @execute()
    @property
    def decompiler_available(self) -> bool:
        if self._decompilerAvailable is None:
            self._decompilerAvailable = ida_hexrays.init_hexrays_plugin()

        return self._decompilerAvailable

