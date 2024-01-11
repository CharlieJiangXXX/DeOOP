from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

import docker
from docker import DockerClient
from docker.errors import APIError, ImageNotFound, NotFound


# workflow:
# 1. global setting: users may select all compilers they select, which will each get their own docker image
# 2. per-program: based on the program's inferred compiler, we either select an existing image or ask for permission to create a new one
# 3. above steps are done in init: each compiler object only represents one specific compiler


@dataclass
class CompilerInstance(ABC):
    name: str
    version: str

    def __str__(self):
        return f"{self.name}-{self.version}"

    @abstractmethod
    def compile_cmd(self) -> str:
        raise NotImplementedError


@dataclass
class GCCInstance(CompilerInstance):
    def __init__(self, version: str):
        self.name = "gcc"
        self.version = "version"

    def __str__(self):
        return f"gcc{self.version} g++{self.version}"


class CompilerManager:
    BASE_IMG_NAME = "DeOOP-base:1.0.0"
    VOLUME_NAME = "DeOOP-volume"

    def __init__(self):
        self.client: DockerClient = docker.from_env()

        def is_docker_running():
            try:
                return self.client.ping()
            except APIError:
                return False

        if not is_docker_running():
            raise EnvironmentError("Please set up a docker environment before using DeOOP!")

        try:
            self.client.images.get(self.BASE_IMG_NAME)
        except ImageNotFound:
            self.client.images.build(path="..", rm=True, tag=self.BASE_IMG_NAME)

        try:
            self.client.volumes.get(self.BASE_IMG_NAME)
        except NotFound:
            self.client.volumes.create(name=self.VOLUME_NAME)

    def add_compilers(self, compilers: List[CompilerInstance]):
        for compiler in compilers:
            self.client.containers.run(name=self.BASE_IMG_NAME, auto_remove=True, detach=True,
                                       command=f"apt-get update && apt-get install {compiler}"
                                               "rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*",
                                       volumes={self.VOLUME_NAME: {"bind": "/mnt/gcc", "mode": "rw"}})

    def del_compilers(self, compilers: List[CompilerInstance]):
        for compiler in compilers:
            self.client.containers.run(name=self.BASE_IMG_NAME, auto_remove=True, detach=True,
                                       command=f"apt-get remove {compiler}",
                                       volumes={self.VOLUME_NAME: {"bind": "/mnt/gcc", "mode": "rw"}})

    def compile(self, compiler: CompilerInstance, code: str, args: str):
        pass

    def __del__(self):
        self.client.close()
