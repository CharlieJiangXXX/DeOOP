import os
import threading
import uuid
from queue import PriorityQueue
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
        idaapi.auto_wait()
        self._handle = handle
        self._console = console
        self._receiverProxy = xmlrpc.client.ServerProxy(
            f"http://127.0.0.1:{int(os.environ['DEOOP_IDA_RECEIVER_PORT'])}/")
        self._taskQueue = PriorityQueue()
        self._tasks = {}

        with SimpleXMLRPCServer(("127.0.0.1", 0), allow_none=True) as server:
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
            (priority, task_id), task_info, mode, unique_id = self._taskQueue.get()
            if self._tasks.get(unique_id, (False,))[0]:
                if mode == -1:
                    threading.Thread(target=self.execute_task, args=(task_id, task_info, -1)).start()
                else:
                    self.execute_task(task_id, task_info, mode)
            del self._tasks[unique_id]

    def enqueue_task(self, priority: int, task_id: int, task_info: xmlrpc.client.Binary, mode: int) -> None:
        unique_id = uuid.uuid4()
        self._taskQueue.put(((priority, task_id), task_info, mode, unique_id))
        self._tasks[unique_id] = (True, priority, task_id, task_info, mode)

    def expedite(self, task_id: int) -> None:
        for unique_id, (priority, active, saved_id, task_info, mode) in self._tasks.items():
            if saved_id == task_id and active and priority > 0:
                self.enqueue_task(0, task_id, task_info, mode)
                self._tasks[unique_id] = (False, saved_id, task_info, mode)
                break

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
