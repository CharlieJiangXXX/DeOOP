import asyncio

from api.launcher import Launcher
import platform

def list_functions():
    import idautils
    functions = idautils.Functions()
    # for function in functions:
    #    function_name = ida_funcs.get_func_name(function)
    #    function_address = ida_funcs.get_func(function).start_ea
    #    print(f"{function_name}: {hex(function_address)}")
    return functions


async def main():
    # program flow:
    # 1. loading datasets, or just binaries
    # 2. launcher launching
    # 3. function retriever
    # 4. pass to compiler
    # 5. llm fix errors

    with Launcher.instance() as launcher:
        launcher.set_ida_path("C:\\Users\\Charlie Jiang.vv001\\Downloads\\IDA Pro 8.3.2\\IDA\\ida64.exe")
        handle = launcher.launch("C:\\Users\\Charlie Jiang.vv001\\Desktop\\test\\mqcmiplugin.dll", True)
        future = launcher.enqueue_task(handle, list_functions, lambda param: print("invoked"),
                                       Launcher.TaskMode.READ.value)
        launcher.execute_cmd(handle, "print('here we go')")
        launcher.stream_ida_logs(handle)
        print(await future)


if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main())