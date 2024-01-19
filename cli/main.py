import asyncio

import openai

from api.launcher import Launcher
import platform

from model.base_model import Query
#from session import Session
from model.model import LanguageModel
from model.gpt import OpenAIGPT


def list_functions():
    import idautils
    # functions = idautils.Functions()
    # for function in functions:
    #    function_name = ida_funcs.get_func_name(function)
    #    function_address = ida_funcs.get_func(function).start_ea
    #    print(f"{function_name}: {hex(function_address)}")
    return idautils.GetIdbDir()


async def main():
    # program flow:
    # 1. loading datasets, or just binaries
    # 2. launcher launching
    # 3. function retriever
    # 4. pass to compiler
    # 5. llm fix errors

    with Launcher.instance() as launcher:
        launcher.set_ida_path("C:\\Users\\Charlie Jiang.vv001\\Downloads\\IDA Pro 8.3.2\\IDA\\ida64.exe")
        #session = Session("C:\\Users\\Charlie Jiang.vv001\\Desktop\\test\\mqcmiplugin.dll", ["ida"])
        #session.start()

async def main_model():
    model = LanguageModel([OpenAIGPT("gpt-3.5-turbo", "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")])
    query = Query(["hi, your name is benjamin"],
                  "what is your name, and what is the language used in the snipped below?",
                  "def fun(): print('hello')", []
                )
    print(await model.query(query, None))
    print("terminating")

if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main_model())