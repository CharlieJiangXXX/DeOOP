import os.path
import pickle
from dataclasses import dataclass
from typing import List
import appdirs
from config import *
from api.utils import loadall

from model.compiler_explorer import CompilerManager


@dataclass
class ProjectInfo:
    name: str
    path: str


class DataManager:
    _instance = None

    def __init__(self):
        #self._compiler = CompilerManager(["c", "c++"])
        self._appDirs = appdirs.AppDirs(appname=PRETTY_NAME, appauthor=COMPANY_NAME, version=str(VERSION))
        self._dataDir = self._appDirs.user_data_dir
        not os.path.isdir(self._dataDir) and os.makedirs(self._dataDir, exist_ok=True)
        self._projFile = os.path.join(self._dataDir, "saved_projects")
        open(self._projFile, "a")

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = DataManager()
        return cls._instance

    @property
    def projects(self) -> List[ProjectInfo]:
        not (out := loadall(self._projFile)) and os.remove(self._projFile)
        return list(out)

    def add_project(self, proj: ProjectInfo):
        with open(self._projFile, "ab") as file:
            pickle.dump(proj, file)

    def remove_project(self, proj: ProjectInfo):
        out = [x for x in self.projects if x != proj]
        with open(self._projFile, "wb") as file:
            for x in out:
                pickle.dump(x, file)

    @staticmethod
    def get_file(filename: str, return_as: int):
        """

        :param self:
        :param filename:
        :param return_as:
        0 - file path
        1 - text
        2 - bytes
        :return:
        """
        path = os.path.join("app", ".data", filename)
        assert os.path.isfile(path)
        if not return_as:
            return os.path.abspath(path)
        with open(path, 'r' if return_as == 1 else 'rb') as file:
            return file.read()

    @staticmethod
    def ls(directory: str) -> List[str]:
        return next(os.walk(os.path.join("app", ".data", directory)), (None, None, []))[2]