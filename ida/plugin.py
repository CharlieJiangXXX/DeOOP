import ida_nalt

from function_retriever import *
from fusion_view import *

import ida_hexrays

from sark import *

import config
from common import concat


class DummyHandler(ActionHandler):
    NAME = "explain_function"
    TEXT = 'Explain function'
    HOTKEY = "Ctrl+Alt+G"
    TOOLTIP = 'Use DeOOP to explain the currently selected function'
    ICON = 201


"""
    preprocessing ground truth:
    use intermediate file (with macros inlines etc stripped)

    assembly:
    just use it as is?

    preprocessing pseudocode
    parse out segment data (e.g. global variables, symbols)
    v-tables
    extended topological sort of functions
    use existing methods to determine all possible structures (function call sinks as well as declarations, should be purely procedural)

    find previous work to get size of struct / class, note the role of inheritance in c++!

    challenge 1:
    assembling just some functions, not the whole file?

    the higher the optimization, the more source codes would match to one assembly

    type create propagation
    2. check if there is new type
    if true:
        add new type to list
        check if new type is dupe with anything
            if true:
                use the old type;
            else:
                use the new type;
    else:
        find best type in list

    unsupervised training, but we also need some high quality data
    """


class DeOOPPlugin(idaapi.plugin_t):
    wanted_name = 'DeOOP'
    wanted_hotkey = ''
    comment = "Streamline and augment Hex-Rays pseudocode with fine-tuned CodeLlama"
    menu = None
    flags = 0

    # we need a subview for "IDE view" supporting custom split between editable source code and assembly.
    # compile button, support cmd+z, etc.
    # basically steal from decomperson
    # sort functions topologically

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        self._manager = GenericMenuManager()
        self._manager.add_handlers(concat("Edit", config.PRETTY_NAME), [RetrieveAllHandler])
        self._manager.add_handlers(concat("View", "Open subviews"), [ShowFusion])

        # set compiler - options
        # view current headers (allow edit) - view/OpenSubviews

        # retrieve all functions - edit/plugin
        # type creation & propagation - edit/plugin
        # perfect all functions - edit/plugin
        # deobfuscate all functions - edit/plugin
        # name & type augmentation - edit/plugin

        # export file(s) & debug symbols - File/CreateFile

        # grab vtables
        FunctionRetriever.init()

        return idaapi.PLUGIN_KEEP

    def term(self):
        FunctionRetriever.save()
        self._manager.detach()


def PLUGIN_ENTRY():
    return DeOOPPlugin()
