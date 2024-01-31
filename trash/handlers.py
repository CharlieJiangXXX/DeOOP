import functools
import json
import re
import textwrap
import os

import config


class PerfectHandler(MenuHandler):
    pass


class ExplainHandler(MenuHandler):
    """
    This handler is tasked with querying the model for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    PATH = os.path.join("Edit", config.PLUGIN_NAME, "Explain function")
    NAME = "explain_function"
    TEXT = 'Explain function'
    HOTKEY = "Ctrl+Alt+G"
    TOOLTIP = 'Use DeOOP to explain the currently selected function'
    ICON = 201

    def _activate(self, ctx):
        decompiler_output = ida_api.decompile(ida_api.get_screen_ea())
        v = ida_decompile.get_widget_vdui(ctx.widget)
        gepetto.config.model.query_model_async(
            _("Can you explain what the following C function does and suggest a better name for "
              "it?\n{decompiler_output}").format(decompiler_output=str(decompiler_output)),
            functools.partial(self.callback, address=ida_api.get_screen_ea(), view=v))
        return 1

    @classmethod
    def callback(cls, address, view, response):
        """
        Callback that sets a comment at the given address.
        :param address: The address of the function to comment
        :param view: A handle to the decompiler window
        :param response: The comment to add
        """
        response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

        # Add the response as a comment in IDA, but preserve any existing non-Gepetto comment
        comment = ida_idc.get_func_cmt(address, 0)
        comment = re.sub(
            r'----- ' + _("Comment generated by Gepetto") + ' -----.*?----------------------------------------',
            r"",
            comment,
            flags=re.DOTALL)

        ida_idc.set_func_cmt(address, '----- ' + _("Comment generated by Gepetto") +
                         f" -----\n\n"
                         f"{response.strip()}\n\n"
                         f"----------------------------------------\n\n"
                         f"{comment.strip()}", 0)
        # Refresh the window so the comment is displayed properly
        view and view.refresh_view(False)
        print(f"{config.llm.model} query finished!")


class RenameHandler(MenuHandler):
    """
    This handler requests new variable names from the model and updates the
    decompiler's output.
    """

    PATH = os.path.join("Edit", config.PLUGIN_NAME, "Rename variables")
    NAME = "rename_function"
    TEXT = 'Rename variables'
    HOTKEY = "Ctrl+Alt+R"
    TOOLTIP = f"Use {config.llm.model} to rename this function's variables"
    ICON = 201

    def _activate(self, ctx):
        decompiler_output = ida_decompile.decompile(ida_api.get_screen_ea())
        v = ida_decompile.get_widget_vdui(ctx.widget)
        gepetto.config.model.query_model_async(
            _("Analyze the following C function:\n{decompiler_output}"
              "\nSuggest better variable names, reply with a JSON array where keys are the original"
              " names and values are the proposed names. Do not explain anything, only print the "
              "JSON dictionary.").format(decompiler_output=str(decompiler_output)),
            functools.partial(rename_callback, address=ida_api.get_screen_ea(), view=v))
        return 1

    def rename_callback(address, view, response, retries=0):
        """
        Callback that extracts a JSON array of old names and new names from the
        response and sets them in the pseudocode.
        :param address: The address of the function to work on
        :param view: A handle to the decompiler window
        :param response: The response from the model
        :param retries: The number of times that we received invalid JSON
        """
        j = re.search(r"\{[^}]*?\}", response)
        if not j:
            if retries >= 3:  # Give up obtaining the JSON after 3 times.
                print(
                    _("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
                print(response)
                return
            print(_("Cannot extract valid JSON from the response. Asking the model to fix it..."))
            gepetto.config.model.query_model_async(
                _("The JSON document provided in this response is invalid. Can you fix it?\n"
                  "{response}").format(response=response),
                functools.partial(rename_callback,
                                  address=address,
                                  view=view,
                                  retries=retries + 1))
            return
        try:
            names = json.loads(j.group(0))
        except json.decoder.JSONDecodeError:
            if retries >= 3:  # Give up fixing the JSON after 3 times.
                print(
                    _("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
                print(response)
                return
            print(_("The JSON document returned is invalid. Asking the model to fix it..."))
            gepetto.config.model.query_model_async(
                _("Please fix the following JSON document:\n{json}").format(json=j.group(0)),
                functools.partial(rename_callback,
                                  address=address,
                                  view=view,
                                  retries=retries + 1))
            return

        # The rename function needs the start address of the function
        function_addr = ida_api.get_func(address).start_ea

        replaced = []
        for n in names:
            if ida_api.IDA_SDK_VERSION < 760:
                lvars = {lvar.id: lvar for lvar in view.cfunc.lvars}
                if n in lvars:
                    if view.rename_lvar(lvars[n], names[n], True):
                        replaced.append(n)
            else:
                if ida_decompile.rename_lvar(function_addr, n, names[n]):
                    replaced.append(n)

        # Update possible names left in the function comment
        comment = ida_idc.get_func_cmt(address, 0)
        if comment and len(replaced) > 0:
            for n in replaced:
                comment = re.sub(r'\b%s\b' % n, names[n], comment)
            ida_idc.set_func_cmt(address, comment, 0)

        # Refresh the window to show the new names
        if view:
            view.refresh_view(True)
        print(_("{model} query finished! {replaced} variable(s) renamed.").format(model=str(gepetto.config.model),
                                                                                  replaced=len(replaced)))


class RefineHandler(MenuHandler):
    pass





