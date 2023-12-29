import os

import common
from enum import Enum

import idaapi


class KeyType(Enum):
    def value(self):
        return common.concat("Font", super().value())

    Disassembly = "Disassembly"
    HexView = "Hex view"
    DebugRegs = "Debug registers"
    TextInput = "Text input"
    OutputWindow = "Output window"
    TabViews = "Tabular views"


class FontConfig:
    """Read access to IDA's (undocumented) font config."""

    def __init__(self, font_type: KeyType):
        self._key = font_type.value()

    @property
    def family(self):
        return idaapi.reg_read_string('Name', self._key, 'Unspecified')

    @property
    def size(self):
        return idaapi.reg_read_int('Size', 10, self._key)

    @property
    def style(self):
        return idaapi.reg_read_string('Style', self._key)

    @property
    def bold(self):
        return idaapi.reg_read_bool('Bold', False, self._key)

    @property
    def italic(self):
        return idaapi.reg_read_bool('Italic', False, self._key)


class ColorsConfig:
    @property
    def graph_overview_uses_gradients(self):
        return idaapi.reg_read_bool('GraphOverviewGradient', False)

    @property
    def theme_name(self):
        return idaapi.reg_read_string('ThemeName', "", "default")

    # for specific color configs we need to debug ida64.exe to see how the settings are stored.