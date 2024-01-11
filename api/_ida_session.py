import os
import threading
from typing import Any, Generator, Dict
from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client
import dill

import idaapi
import ida_pro


class IDASession:
    def __init__(self, handle: int, console: bool = False):
        self._handle = handle
        self._console = console
        self._receiverProxy = xmlrpc.client.ServerProxy(
            f"http://localhost:{int(os.environ['DEOOP_IDA_RECEIVER_PORT'])}/")
        with SimpleXMLRPCServer(("localhost", 0), allow_none=True) as server:
            self.server = server
            server.register_function(self.enqueue_task, "enqueue_task")
            server.register_function(self.execute_cmd, "execute_cmd")
            server.register_function(self.execute_script, "execute_script")
            server.register_function(self.shutdown, "shutdown")
            addr, port = server.server_address
            print(f"IDA session {handle} started on {addr}:{port}")
            self._receiverProxy.ping(self._handle, port)
            self._shutdownEvent = threading.Event()
            while not self._shutdownEvent.is_set():
                server.handle_request()
        self.server.server_close()
        ida_pro.qexit(0)

    def shutdown(self) -> None:
        print("Session shutting down gracefully")
        self._shutdownEvent.set()

    def enqueue_task(self, task_id: int, task_info, mode: int) -> None:
        """
        Note: it is possible to run tasks that start new threads. But beware that
        running thread.join() immediately afterward would cause IDA to hang if
        the task is not safe (i.e. execute_sync is involved), possibly
        due to a deadlock situation. Instead, the user should implement a form of
        signaling mechanism to wait until the thread has finished to join.
        """
        func = dill.loads(task_info.data)
        try:
            if mode == -1:
                out = func()
            else:
                l = []

                def wrapper():
                    try:
                        resp = func()
                        l.append(resp)
                        return 0
                    except Exception as e:
                        print(f"Error executing task: {e.__class__}: {e}")

                idaapi.execute_sync(wrapper, mode)
                out = l[0]

            if isinstance(out, Generator):
                out = list(out)
            self._receiverProxy.notify(self._handle, task_id, dill.dumps(out))
        except Exception as e:
            print(f"Error executing task: {e.__class__}: {e}")

    @staticmethod
    def execute_cmd(cmd: str) -> Any:
        eval(cmd)

    @staticmethod
    def execute_script(path: str, env: Dict, mode: int) -> Any:
        idaapi.execute_sync(
            lambda: idaapi.IDAPython_ExecScript(path, env),
            mode
        )


IDASession(int(os.environ["DEOOP_IDA_HANDLE"]))
