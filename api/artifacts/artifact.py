try:
    import tomllib as toml_reader
except ModuleNotFoundError:
    import tomli as toml_reader

import tomli_w as toml_writer
from typing import Dict, Any


class Artifact:
    """
    The base class for all artifacts.
    Artifacts record persistent information fetched from decompilers' databases, usually with a cacheing mechanism. The
    primary purpose of artifacts is to allow tracking of changes and storing the current editing status. Hence,
    artifacts should generally not be created or modified by the user, but only obtained through the controller if any
    information is needed.
    All checks and specific operations should be performed by controller directives. Artifact should only handle storing
    and cacheing.
    If a subclass is to represent a unique artifact, it must have a non-trivial, hashable positional argument to be
     used as an identifier. Instantiation of an artifact must be done in the remote process, if any, for the class
     variable _cache will not be synced.
    """
    __slots__ = (
        "last_change",
    )

    _cache = {}

    def __new__(cls, *args, **kwargs):
        identifier = args[0] if args else None
        if identifier and hasattr(identifier, '__hash__') and callable(identifier.__hash__):
            cls_cache = cls._cache.setdefault(cls.__name__, {})
            if identifier not in cls_cache:
                cls_cache[identifier] = super().__new__(cls)
            return cls_cache[identifier]
        return super().__new__(cls)

    def __init__(self, last_change=None):
        self.last_change = last_change

    def __getstate__(self) -> Dict:
        """
        Returns a dict of all the properties of the artifact. With the key as their name
        and the value as their value.

        @return:
        """
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state: Dict):
        """
        Sets all the properties of the artifact given a dict of keys and values.
        Note: the values can also be dicts.

        @param state: Dict
        @return:
        """
        for k in self.__slots__:
            setattr(self, k, state.get(k, None))

    def __eq__(self, other):
        """
        Like a normal == override, but we always ignore last_change.

        @param other: Another Artifact
        @return:
        """
        return not self.diff(other)

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, self.__class__):
            for k in self.__slots__:
                if k == "last_change":
                    continue

                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }
            return diff_dict

        for k in self.__slots__:
            self_attr, other_attr = getattr(self, k), getattr(other, k)
            if self_attr != other_attr:
                if k == "last_change":
                    continue

                diff_dict[k] = {
                    "before": self_attr,
                    "after": other_attr
                }
        return diff_dict

    @classmethod
    def load(cls, toml: Dict) -> 'Artifact':
        instance = cls()  # No arguments passed
        instance.__setstate__(toml)
        return instance

    @classmethod
    def load_many(cls, tomls):
        for toml in tomls.values():
            try:
                yield cls.load(toml)
            except TypeError:
                continue

    @classmethod
    def loads(cls, state: str) -> 'Artifact':
        """
        Parses a TOML form string.

        @param state:
        @return:
        """
        return cls.load(toml_reader.loads(state))

    @classmethod
    def dump_many(cls, objs: Dict) -> Dict:
        """
        Dumps a dictionary of states from live artifacts. Dicts are used to enable faster sorting
        and searching.
        :param objs:
        :return:
        """
        objs_ = {}
        for name, obj in objs.items():
            objs_[name] = obj.__getstate__()
        return objs_

    @staticmethod
    def hex_dumps(state: Dict):
        def _convert_integers_to_hex(obj: Any):
            """
            Recursively converts all integers in the given state to hexadecimal strings.
            """
            if isinstance(obj, dict):
                return {k: _convert_integers_to_hex(v) for k, v in obj.items()}
            elif isinstance(obj, int):
                return hex(obj) if obj >= 0 else obj
            return obj

        return toml_writer.dumps(_convert_integers_to_hex(state))

    def dumps(self) -> str:
        """
        Returns a string in TOML form of the properties of the current artifact. Best used to
        write directly into a file and save as a .toml file.

        @return:
        """
        return self.hex_dumps(self.__getstate__())

    def copy(self) -> "Artifact":
        pass

    @property
    def commit_msg(self) -> str:
        return f"Updated {self}"

    @classmethod
    def invert_diff(cls, diff_dict: Dict):
        inverted_diff = {}
        for k, v in diff_dict.items():
            if k == "before":
                inverted_diff["after"] = v
            elif k == "after":
                inverted_diff["before"] = v
            elif isinstance(v, Dict):
                inverted_diff[k] = cls.invert_diff(v)
            else:
                inverted_diff[k] = v

        return inverted_diff

    def merge(self, other: "Artifact"):
        obj = self.copy()
        if not other or obj == other:
            return obj

        obj_diff = obj.diff(other)

        for attr in self.__slots__:
            if attr in obj_diff and obj_diff[attr]["before"] is None:
                setattr(obj, attr, getattr(other, attr))

        return obj
