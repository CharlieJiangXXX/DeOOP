import asyncio
import os.path
import platform

from cli.session import Session
from api.launcher import Launcher
from api.models.gpt import OpenAIGPT
from config import config


class EvalBinary:
    def __init__(self, path: str):
        assert os.path.isdir(path)
        self.name = os.path.basename(path)
        self.bin = os.path.join(path, "bin.out")
        self.src = os.path.join(path, "source.c")

    async def eval(self):
        async with Session(self.src, self.bin, ["ida"],
                           models=[OpenAIGPT("gpt-3.5-turbo", config.OPENAI_API_KEY)]) as session:
            await session.analyze_all()


class Dataset:
    def __init__(self, path: str):
        assert os.path.isdir(path)
        self.bins = [EvalBinary(os.path.join(path, entry)) for entry in os.listdir(path)]
        self.bins = list(filter(lambda b: b.name in ['2020-bitesize'], self.bins))

    async def eval(self):
        for binary in self.bins:
            await binary.eval()
        # await asyncio.gather(*[binary.eval() for binary in bins])

async def main():
    with Launcher.instance() as launcher:
        launcher.set_ida_path("C:\\Users\\Charlie Jiang.vv001\\Downloads\\IDA Pro 8.3.2\\IDA\\ida64.exe")
        path = "C:\\Users\\Charlie Jiang.vv001\\PycharmProjects\\Verbatim\\datasets\\decompetition-c"
        await Dataset(path).eval()
        hard = "C:\\Users\\Charlie Jiang.vv001\\Desktop\\test\\mqcmiplugin.dll"


if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main())
