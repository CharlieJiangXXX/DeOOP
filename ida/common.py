import os


def concat(*args):
    assert args
    return os.path.join(*args).replace("\\","/")