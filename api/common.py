import os
import pickle
from typing import Generator


def concat(*args):
    assert args
    return os.path.join(*args).replace("\\", "/")


def loadall(filename: str) -> Generator:
    with open(filename, "rb") as f:
        while True:
            try:
                yield pickle.load(f)
            except EOFError:
                break
