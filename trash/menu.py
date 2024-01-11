from typing import List, Optional, Type, Iterator, LiteralString, Dict, Set

import idaapi
import sark.qt
import os

import config
from common import concat

class ActionName:
    def __init__(self, name: str) -> None:
        self.name = config.PLUGIN_NAME + ":" + name

    def __str__(self, *args, **kwargs) -> str:
        return self.name


class ActionHandler(sark.ui.ActionHandler):
    def __init__(self):
        super().__init__()
        self.NAME = str(ActionName(self.get_name()))


class MenuHandler:
    # MenuHandlers should ALWAYS be used together with subclasses of GenericMenuManager
    def __init__(self, action: Type[ActionHandler]) -> None:
        self.action = action
        self.path = self.action.TEXT

    def attach(self) -> bool:
        return idaapi.attach_action_to_menu(self.path, self.action.get_name(), idaapi.SETMENU_APP)

    def detach(self) -> None:
        idaapi.detach_action_from_menu(self.path, self.action.get_name())


class PseudoMenuHandler(ActionHandler):
    PSEUDO_HOOK = None

    def __init__(self) -> None:
        super().__init__()
        self.PSEUDO_HOOK = self.pseudo_hook()

    @classmethod
    def register(cls) -> bool:
        return super().register() and cls.PSEUDO_HOOK and cls.PSEUDO_HOOK.hook()

    @classmethod
    def unregister(cls) -> None:
        super().unregister() and cls.PSEUDO_HOOK and cls.PSEUDO_HOOK.unhook()

    @classmethod
    def pseudo_hook(cls):
        name = cls.get_name()

        class PseudoHook(idaapi.UI_Hooks):
            def finish_populating_widget_popup(self, form, popup):
                if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
                    idaapi.attach_action_to_popup(form, popup, name, concat(config.PLUGIN_NAME, ""))

        return PseudoHook


class GenericMenuManager:
    def __init__(self) -> None:
        self._handlers: Dict[str, List] = {}
        self._registered: Set[Type[ActionHandler]] = set()

    def detach(self) -> None:
        keys = list(self._handlers.keys())
        for key in keys:
            self.remove_dir(key)

        for reg in self._registered:
            reg.unregister()

    def add_handlers(self, base: str, handlers: List[Type[ActionHandler]]) -> None:
        if base not in self._handlers:
            self._handlers[base] = []
        for handler in handlers:
            handler.register()
            self._registered.add(handler)
            mhand = MenuHandler(handler)
            if base not in mhand.path:
                mhand.path = concat(base, mhand.path)
            self._handlers[base].append(mhand)
            mhand.attach()

    def remove_handler(self, base: str, name: Optional[str]) -> Optional[MenuHandler]:
        if base not in self._handlers:
            return

        if name is None:
            out = self._handlers[base].pop()
        else:
            out = None
            for i in range(len(self._handlers)):
                if self._handlers[base][i].action.get_name() == name:
                    out = self._handlers[base].pop(i)
                    break
        if out:
            out.detach()
        return out

    def remove_dir(self, base: str) -> None:
        if base not in self._handlers:
            return
        for handler in self._handlers[base]:
            handler.detach()
        self._handlers.pop(base)


class TopMenuManager:
    """
    Unfortunately this class doesn't work for newer versions of IDA, as the top level menu
    would be automatically destroyed.
    """
    def __init__(self, paths: List[str], entries: List[List[Type[ActionHandler]]]) -> None:
        self._manager = sark.qt.MenuManager()
        self._menus: List[GenericMenuManager] = []
        assert len(paths) == len(entries)
        for i in range(len(entries)):
            self.add_menu(paths[i], entries[i])

    def add_menu(self, path: str, entries: List[Type[ActionHandler]]) -> None:
        self._manager.add_menu(path)
        self._menus.append(GenericMenuManager(path, entries))

    def remove_menu(self, path: str) -> Optional[GenericMenuManager]:
        self._manager.remove_menu(path)
        for i in range(len(self._menus)):
            if self._menus[i].base == path:
                self._menus[i].detach()
                return self._menus.pop(i)
        return None

    def clear(self) -> None:
        for menu in self._menus:
            self._manager.remove_menu(menu.base)
            menu.detach()
        self._manager.clear()
