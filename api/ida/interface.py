from typing import Optional, List

import networkx as nx

from .flowchart import FlowChart, BasicBlock
from .xref import IDAXrefType
from ..artifacts.line import Line
from ..artifacts.function import Function, Variable
from ..interface import DecompilerInterface
from ..artifacts.address import Address
from ..utils import Xref, AddressRange
from ..launcher import Launcher
from ..exceptions import SetTypeFailed, NoFunction

try:
    import idaapi
    import idc
    import ida_hexrays
    import idautils
    from ida_gdl import qflow_chart_t
    from ida_funcs import func_t
except ImportError:
    pass


class IDAInterface(DecompilerInterface):
    def __init__(self, handle: int):
        super().__init__(handle)
        self._decompilerAvailable: Optional[bool] = None

    execute = DecompilerInterface.execute

    @property
    @execute()
    def binary_base_addr(self) -> int:
        return idaapi.get_imagebase()

    @property
    @execute()
    def binary_hash(self) -> str:
        return idc.retrieve_input_file_md5().hex()

    @property
    @execute()
    def binary_path(self) -> Optional[str]:
        return idaapi.get_input_file_path()

    @property
    @execute()
    def decompiler_available(self) -> bool:
        if self._decompilerAvailable is None:
            self._decompilerAvailable = ida_hexrays.init_hexrays_plugin()

        return self._decompilerAvailable

    @execute()
    def demangle(self, name: str, disable_mask: int = 0) -> str:
        return idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL) or name

    @property
    @execute(mode=Launcher.TaskMode.READ)
    def min_addr(self) -> Address:
        return self.addr(idaapi.cvar.inf.min_ea)

    @property
    @execute(mode=Launcher.TaskMode.READ)
    def max_addr(self) -> Address:
        return self.addr(idaapi.cvar.inf.max_ea)

    @execute(mode=Launcher.TaskMode.READ)
    def addr(self, addr: Optional[int] = None) -> Optional[Address]:
        if addr in (None, idaapi.BADADDR):
            return None
        address = Address(addr)
        address._name = idaapi.get_ea_name(address.value, idaapi.GN_VISIBLE)
        address.offset_in_bin = idaapi.get_fileregion_offset(address.value)
        return address

    @execute(mode=Launcher.TaskMode.WRITE)
    def set_name(self, addr: Address, name: str, force: bool = False) -> bool:
        if (next((value for cond, value in
                  [(not addr._name, idaapi.set_name(addr.value, name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)),
                   (force, idaapi.force_name(addr.value))] if cond), False)):
            addr._name = name
            return True
        return False

    def addr_range(self, start: Optional[int] = None, end: Optional[int] = None) -> AddressRange:
        return AddressRange(self.addr(start) or self.min_addr, self.addr(end) or self.max_addr)

    @execute()
    def xrefs_to(self, addr: Address) -> List[Xref]:
        return list(map(lambda xref: Xref(self.addr(xref.frm), self.addr(xref.to), xref.iscode, xref.user,
                                          IDAXrefType(xref.type)),
                        idautils.XrefsTo(addr.value)))

    @execute()
    def xrefs_from(self, addr: Address) -> List[Xref]:
        return list(map(lambda xref: Xref(self.addr(xref.frm), self.addr(xref.to), xref.iscode, xref.user,
                                          IDAXrefType(xref.type)),
                        idautils.XrefsFrom(addr.value)))

    @staticmethod
    @execute()
    def is_string(addr: int) -> bool:
        return idc.get_str_type(addr) not in (None, -1)

    @execute()
    def line(self, addr: int) -> Line:
        line = Line(self.addr(idaapi.get_item_head(addr)))
        line.comments["regular"] = idaapi.get_cmt(line.start_addr, False)
        line.comments["repeat"] = idaapi.get_cmt(line.start_addr, True)

        def iter_extra(start):
            end = idaapi.get_first_free_extra_cmtidx(line.start_addr, start)
            for idx in range(start, end):
                yield idaapi.get_extra_cmt(line.start_addr, idx) or ''

        line.comments["anterior"] = "\n".join(iter_extra(idaapi.E_PREV))
        line.comments["posterior"] = "\n".join(iter_extra(idaapi.E_NEXT))

        line.asm = idc.GetDisasm(line.start_addr)
        line.xrefs["from"] = self.xrefs_from(line.addr)
        line.xrefs["to"] = self.xrefs_to(line.addr)
        line.size = idaapi.get_item_size(line.start_addr)
        line.bytes = idaapi.get_bytes(line.start_addr, line.size)
        line.type_flags = idaapi.get_full_flags(line.start_addr)
        props = {lambda: idaapi.is_code(line.type_flags): "code",
                 lambda: idaapi.is_data(line.type_flags): "data",
                 lambda: self.is_string(line.start_addr): "string",
                 lambda: idaapi.is_tail(line.type_flags): "tail",
                 lambda: idaapi.is_unknown(line.type_flags): "unknown"}
        line.type_info = next((v for k, v in props.items() if k()), "")
        line.factory = self.line
        return line

    @execute()
    def set_line_comments(self, line: Line, cmt: str, options: int = 0):
        match options:
            case 0 | 1:
                idaapi.set_cmt(line.addr, cmt, options)
            case 2 | 3:
                what = idaapi.E_PREV if options == 2 else idaapi.E_NEXT
                if not cmt:
                    idaapi.del_extra_cmt(line.addr, what)
                    return

                index = 0

                for index, ln in enumerate(cmt.splitlines()):
                    idaapi.update_extra_cmt(line.addr, what + index, ln)

                idaapi.del_extra_cmt(line.addr, what + (index + 1))

    @execute()
    def _raw_func(self, addr: Address):
        raw_func: idaapi.func_t = idaapi.get_func(addr.value)
        return raw_func

    @execute(mode=Launcher.TaskMode.READ)
    def function(self, addr: Address) -> Function:
        raw_func: func_t = self._raw_func(addr)
        if not raw_func:
            raise NoFunction("No function at 0x{:08X}".format(addr.value))

        function = Function(self.addr(raw_func.start_ea))
        function.comparator = lambda a1, a2: (
                (f1 := self._raw_func(self.addr(a1))) and (f2 := self._raw_func(self.addr(a2)))
                and f1.start_ea == f2.start_ea)
        function._end_addr = self.addr(raw_func.end_ea)
        function.flags = raw_func.flags
        function.lines = [self.line(line) for line in idautils.FuncItems(function.start_addr)]
        function.xrefs["to"] = function.lines[0].xrefs_to
        function.xrefs["from"] = [xref for line in function.lines for xref in line.xrefs_from
                                  if not (xref.type.is_flow or (xref.to in function and xref.iscode))]
        function.comments["regular"] = idaapi.get_func_cmt(raw_func, False)
        function.comments["repeat"] = idaapi.get_func_cmt(raw_func, True)
        if frame := idaapi.get_frame(raw_func):
            idx = 0
            lvars = {}

            for offset, name, size in idautils.StructMembers(frame.id):
                lvars[name] = Variable(offset, name, size)
                member = frame.members[idx]
                tinfo = idaapi.tinfo_t()
                idaapi.get_or_guess_member_tinfo(tinfo, member)
                lvars[name].type = tinfo.dstr()
                idaapi.build_stkvar_xrefs(xrefs := idaapi.xreflist_t(), raw_func, member)
                lvars[name].xrefs = list(map(lambda xref: Xref(self.addr(xref.ea), self.addr(None), False, False,
                                                               IDAXrefType(xref.type)), xrefs))

            if ret := lvars.pop(' r', None):
                function.ret_offset = ret.offset
            if fs := lvars.pop(' s', None):
                function.frame_size = fs.offset
                for key in lvars:
                    lvars[key].offset -= fs.offset
            function.lvars = lvars.values()

        function.signature = idc.get_type(function.start_addr)
        function.tinfo = idc.get_tinfo(function.start_addr)
        if self.decompile(function) in [None, 'None']:
            function.pseudocode = None
        function.external = bool(raw_func.flags & idaapi.FUNC_THUNK
                                 or idaapi.segtype(function.start_addr) == idaapi.SEG_XTRN)
        seg_name = idaapi.get_segm_name(idaapi.getseg(function.start_addr))
        function.init = "init" in seg_name
        function.fini = "fini" in seg_name
        function.plt = "plt" in seg_name
        return function

    @execute()
    def set_function_signature(self, function: Function, signature: str):
        if not idc.SetType(function.start_addr, signature):
            raise SetTypeFailed(function.start_addr, signature)
        function.signature = signature

    @execute()
    def set_function_tinfo(self, function: Function, tinfo):
        if not idc.apply_type(function.start_addr, tinfo):
            raise SetTypeFailed(function.start_addr, tinfo)
        function.tinfo = tinfo

    @execute(mode=Launcher.TaskMode.READ)
    def functions_in(self, span: AddressRange):
        # still too slow
        return [self.function(self.addr(func_t)) for func_t in idautils.Functions(span.start_addr, span.end_addr)]

    @execute()
    def decompile(self, function: Function) -> str:
        if self.decompiler_available:
            function.pseudocode = str(idaapi.decompile(function.start_addr))
            return function.pseudocode
        return ""

    @execute(mode=Launcher.TaskMode.READ)
    def flow_chart(self, function: Function, flags: int = 0) -> FlowChart:
        flow_chart = FlowChart(function)
        raw_q = qflow_chart_t("", self._raw_func(function.addr), flow_chart.func.start_addr, flow_chart.func.end_addr,
                              flags)
        flow_chart.size = raw_q.size()
        flow_chart.flags = raw_q.flags
        flow_chart.num_proper = raw_q.nproper

        flow_chart.blocks = [
            BasicBlock(i, self.addr_range(raw_q[i].start_ea, raw_q[i].end_ea), raw_q.calc_block_type(i))
            for i in range(flow_chart.size)]

        for block in flow_chart:
            block.preds = [flow_chart[raw_q.pred(block.index, i)] for i in range(raw_q.npred(block.index))]
            block.succs = [flow_chart[raw_q.succ(block.index, i)] for i in range(raw_q.nsucc(block.index))]

        return flow_chart

    def cfg(self, function: Function) -> nx.DiGraph:
        graph = nx.DiGraph()
        for block in self.flow_chart(function):
            # Make sure all nodes are added (including edge-less nodes)
            graph.add_node(block.range.start_addr)

            for pred in block.preds:
                graph.add_edge(pred.range.start_addr, block.range.start_addr)
            for succ in block.succs:
                graph.add_edge(block.range.start_addr, succ.range.start_addr)

        return graph

    def codeblocks_in(self, span: AddressRange):
        """Get all `CodeBlock`s in a given range.

        Args:
            start - start address of the range. If `None` uses IDB start.
            end - end address of the range. If `None` uses IDB end.
        """
        return [block for function in self.functions_in(span) for block in self.flow_chart(function)]

    @property
    def codeblocks(self):
        return self.codeblocks_in(self.addr_range())
