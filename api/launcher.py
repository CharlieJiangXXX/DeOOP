import itertools
import os.path
import asyncio
import subprocess
import threading
from enum import IntEnum
from types import TracebackType
from typing import List, Optional, Callable, Any, Dict, Type
import tempfile
import dill

from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client

SessionHandle = int
TaskID = int


def quote_spaces_in_path(path):
    return os.sep.join(f'"{comp}"' if ' ' in comp else comp for comp in path.split(os.sep))


class Launcher:
    _instance = None

    class TaskMode(IntEnum):
        SAFE = -1
        FAST = 0
        READ = 1
        WRITE = 2
        NOWAIT = 3

    def __init__(self):
        self._handle = itertools.count(0)
        self._paths = {}
        self._instances = {}
        self._pendingTasks = {}
        self._tmpFiles = {}
        self._pingEvents = {}
        self._idaReceiver = SimpleXMLRPCServer(("127.0.0.1", 0), allow_none=True, logRequests=False)
        self._idaReceiver.register_function(self.ida_notify, "notify")
        self._idaReceiver.register_function(self.ida_ping, "ping")
        os.environ["DEOOP_IDA_RECEIVER_PORT"] = str(self._idaReceiver.server_address[1])

    def __enter__(self):
        threading.Thread(target=self._idaReceiver.serve_forever, daemon=True).start()
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_inst: Optional[BaseException],
                 traceback: Optional[TracebackType]):
        for instance in self._instances.values():
            url = f"http://127.0.0.1:{instance['ida']}/"
            with xmlrpc.client.ServerProxy(url) as proxy:
                proxy.shutdown()
        self._idaReceiver.shutdown()
        self._idaReceiver.server_close()

    def ida_notify(self, handle: SessionHandle, task_id: TaskID, resp: xmlrpc.client.Binary,
                   exception: xmlrpc.client.Binary):
        future, handler = self._pendingTasks[handle][task_id]
        resp = dill.loads(resp.data)
        exception = dill.loads(exception.data)
        if handler:
            handler(resp)
        future.get_loop().call_soon_threadsafe(future.set_result, (resp, exception))

    def ida_ping(self, handle: SessionHandle, port: int):
        self._instances[handle]["ida"] = port
        self._pingEvents[handle].set()

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = Launcher()
        return cls._instance

    # TO-DO: error handling on set path;

    def set_ida_path(self, path: str):
        self._paths["ida"] = path

    def set_ghidra_path(self, path: str):
        self._paths["ghidra"] = path

    def launch(self, binary: str, try_all: bool = False, decompilers: Optional[List[str]] = None) -> SessionHandle:
        handle = next(self._handle)
        self._pingEvents[handle] = threading.Event()
        os.environ["DEOOP_IDA_HANDLE"] = str(handle)
        self._instances[handle] = {}
        self._pendingTasks[handle] = []
        for decompiler in list(filter(lambda d: try_all or d in decompilers, self._paths.keys())):
            path = self._paths[decompiler]
            match decompiler:
                case "ida":
                    with tempfile.TemporaryFile(delete=False) as tmp_file:
                        os.environ["TVHEADLESS"] = str(1)

                        launcher_dir = os.path.dirname(os.path.realpath(__file__))
                        # try to do some error handling here to deal with duplicate instances
                        subprocess.Popen(
                            [path, '-A', f"-S{quote_spaces_in_path(os.path.join(launcher_dir, '_ida_session.py'))}",
                             f"-L{tmp_file.name}", binary],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

                        self._tmpFiles[handle] = tmp_file.name

                case "ghidra":
                    pass
        return handle

    def decompilers_from_handle(self, handle: SessionHandle) -> List[str]:
        return self._instances[handle].keys()

    def _process_task(self, handle: SessionHandle, task: Callable[[], Any] = None,
                      handler: Callable[[Any], None] = None, mode: TaskMode = TaskMode.SAFE, priority: int = 2,
                      cmd: str = "",
                      path: str = "", env: Dict = None) -> Any:
        # TO-DO: add decompiler list option
        self._pingEvents[handle].wait()
        instances = self._instances[handle]
        for instance in instances:
            match instance:
                case "ida":
                    port = instances["ida"]
                    url = f"http://127.0.0.1:{port}/"

                    with xmlrpc.client.ServerProxy(url) as proxy:
                        if task:
                            q = self._pendingTasks[handle]
                            future = asyncio.Future()
                            q.append((future, handler))
                            proxy.enqueue_task(priority, len(q) - 1, dill.dumps(task), mode.value)
                            return future
                        elif cmd:
                            proxy.execute_cmd(cmd)
                        elif path:
                            proxy.execute_script(path, env or {}, mode.value)
                case _:
                    pass

    def enqueue_task(self, handle: SessionHandle, task: Callable[[], Any], handler: Callable[[Any], None] = None,
                     mode: TaskMode = TaskMode.SAFE, priority: int = 2) -> asyncio.Future:
        return self._process_task(handle, task, handler, mode, priority)

    def execute_cmd(self, handle: SessionHandle, cmd: str) -> None:
        self._process_task(handle, cmd=cmd)

    def execute_script(self, handle: SessionHandle, path: str, env: Dict, mode: TaskMode = TaskMode.WRITE) -> None:
        self._process_task(handle, path=path, env=env, mode=mode)

    def stream_ida_logs(self, handle: SessionHandle):
        self._pingEvents[handle].wait()
        print(f"Streaming IDA session {handle} from {(filename := self._tmpFiles[handle])}")

        def run():
            with open(filename, 'r') as file:
                while True:
                    if line := file.readline():
                        print(f"[IDAStreamer-{handle}] {line.rstrip()}")
                        # this is ugly af, but we can fix it later :)
                        if "Unloading IDP module" in line:
                            break

        threading.Thread(target=run, daemon=False).start()
