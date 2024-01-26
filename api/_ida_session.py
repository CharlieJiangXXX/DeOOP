import os
import threading
from queue import Queue
from typing import Any, Generator, Dict
from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client
import dill
import traceback

import idaapi
import ida_pro


class ExceptionWrapper:
    def __init__(self, e: Exception, trace: str):
        self.e = e
        self.traceback = trace


class IDASession:
    def __init__(self, handle: int, console: bool = False):
        self._handle = handle
        self._console = console
        self._receiverProxy = xmlrpc.client.ServerProxy(
            f"http://localhost:{int(os.environ['DEOOP_IDA_RECEIVER_PORT'])}/")
        self._taskQueue = Queue()

        with SimpleXMLRPCServer(("localhost", 0), allow_none=True) as server:
            self.server = server
            server.timeout = 0.1
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
                self.process_task()
        self.server.server_close()
        ida_pro.qexit(0)

    def shutdown(self) -> None:
        print("Session shutting down gracefully")
        self._shutdownEvent.set()

    def process_task(self):
        if not self._taskQueue.empty():
            task_id, task_info, mode = self._taskQueue.get()
            self.execute_task(task_id, task_info, mode)

    def enqueue_task(self, task_id: int, task_info: xmlrpc.client.Binary, mode: int, threaded: bool) -> None:
        """
        Note: it is possible to run tasks that start new threads. But beware that
        running thread.join() immediately afterward would cause IDA to hang if
        the task is not safe (i.e. execute_sync is involved), possibly
        due to a deadlock situation. Instead, the user should implement a form of
        signaling mechanism to wait until the thread has finished to join.
        """
        self._taskQueue.put((task_id, task_info, mode))

    def execute_task(self, task_id: int, task_info: xmlrpc.client.Binary, mode: int):
        func = dill.loads(task_info.data)
        out, exception, trace = None, None, ""

        try:
            if mode == -1:
                out = func()
            else:
                results = {'output': None, 'exception': None, 'trace': ""}

                def wrapper():
                    try:
                        results['output'] = func()
                    except Exception as e:
                        results['exception'] = e
                        results['trace'] = traceback.format_exc()

                idaapi.execute_sync(wrapper, mode)
                out, exception, trace = results['output'], results['exception'], results['trace']
        except Exception as e:
            exception, trace = e, traceback.format_exc()

        if isinstance(out, Generator):
            out = list(out)

        exception_data = ExceptionWrapper(exception, trace) if exception else None
        self._receiverProxy.notify(self._handle, task_id, dill.dumps(out), dill.dumps(exception_data))

    @staticmethod
    def execute_cmd(cmd: str) -> Any:
        exec(cmd)

    @staticmethod
    def execute_script(path: str, env: Dict, mode: int) -> Any:
        idaapi.execute_sync(
            lambda: idaapi.IDAPython_ExecScript(path, env),
            mode
        )


IDASession(int(os.environ["DEOOP_IDA_HANDLE"]))
