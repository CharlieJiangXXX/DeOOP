import asyncio
import platform

from cli.session import Session
from api.launcher import Launcher
from api.models.gpt import OpenAIGPT
from config import config


async def main():
    with Launcher.instance() as launcher:
        launcher.set_ida_path("C:\\Users\\Charlie Jiang.vv001\\Downloads\\IDA Pro 8.3.2\\IDA\\ida64.exe")
        # cacheing objects like cfg should be done by session (read from file if exists)
        simple = "C:\\Users\\Charlie Jiang.vv001\\Downloads\\challenges-2020\\c\\baby-c\\binary.out"
        hard = "C:\\Users\\Charlie Jiang.vv001\\Desktop\\test\\mqcmiplugin.dll"
        async with Session(simple, ["ida"], models=[OpenAIGPT("gpt-3.5-turbo",
                                                              config.OPENAI_API_KEY)]) as session:
            await session.analyze_all()


if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main())
