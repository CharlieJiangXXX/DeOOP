import dataclasses
import enum
import os
from typing import Dict, List, Tuple

import networkx as nx
from clang import cindex
import itertools
from clang.cindex import CursorKind
from functools import cached_property
import matplotlib.pyplot as plt

CF_CURSOR_TYPES = [CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT, CursorKind.IF_STMT, CursorKind.SWITCH_STMT,
                   CursorKind.WHILE_STMT, CursorKind.DO_STMT, CursorKind.FOR_STMT]

                   #CursorKind.GOTO_STMT, CursorKind.INDIRECT_GOTO_STMT, CursorKind.CONTINUE_STMT, CursorKind.BREAK_STMT, CursorKind.RETURN_STMT


class CF_TYPES(enum.Enum):
    IF = "IF"
    ELIF = "ELIF"
    ELSE = "ELSE"
    DO_WHILE = "DOWHILE"
    WHILE = "WHILE"
    FOR = "FOR"
    SWITCH = "SWITCH"
    CASE = "CASE"
    DEFAULT = "DEFAULT"

    @classmethod
    def _missing_(cls, value):
        match value:
            case CursorKind.IF_STMT:
                return cls.IF
            case CursorKind.SWITCH_STMT:
                return cls.SWITCH
            case CursorKind.CASE_STMT:
                return cls.CASE
            case CursorKind.DEFAULT_STMT:
                return cls.DEFAULT
            case CursorKind.DO_STMT:
                return cls.DO_WHILE
            case CursorKind.WHILE_STMT:
                return cls.WHILE
            case CursorKind.FOR_STMT:
                return cls.FOR
        return None

class ASTWalker:
    def __init__(self, src):
        # of course, this is a temporary workaround: src should not be included in the pipeline
        self.src = src
        self.index = cindex.Index.create()
        self.tu = self.index.parse(self.src)

        # two graphs (full, cf) for each function
        self.graphs: Dict[cindex.Cursor, Tuple[nx.DiGraph, nx.DiGraph]] = {}
        self.func = None
        for func in self.functions:
            self.func = func
            self.populate_graph()
            self.generate_cf_subgraph()

    def is_user_defined(self, cursor: cindex.Cursor):
        if cursor.location.file:
            return os.path.samefile(cursor.location.file.name, self.src)
        return False

    def get_source(self, start_offset, end_offset):
        with open(self.src) as f:
            f.seek(start_offset)
            return f.read(end_offset - start_offset)

    @cached_property
    def functions(self) -> List[cindex.Cursor]:
        functions = self.find_functions(self.tu.cursor)
        for func in functions:
            self.graphs[func] = (nx.DiGraph(), nx.DiGraph())
        return functions

    def find_functions(self, node: cindex.Cursor) -> List[cindex.Cursor]:
        if node.kind == CursorKind.FUNCTION_DECL and self.is_user_defined(node):
            return [node]
        # Recurse for children of this node
        functions = list(itertools.chain.from_iterable([self.find_functions(child) for child in node.get_children()]))
        return functions

    @property
    def graph(self) -> nx.DiGraph:
        return self.graphs[self.func][0]

    @property
    def cf_subgraph(self) -> nx.DiGraph:
        return self.graphs[self.func][1]

    # Store cursor structure for each function more conveniently in a nx digraph
    def populate_graph(self):
        def _recurse(cursor: cindex.Cursor, parent=None):
            self.graph.add_node(cursor.hash, data=cursor)
            if parent:
                self.graph.add_edge(parent.hash, cursor.hash)
            for child in cursor.get_children():
                _recurse(child, cursor)
        _recurse(self.func)

    def generate_cf_subgraph(self):
        for chash in nx.topological_sort(self.graph):
            cursor = self.graph.nodes[chash]["data"]
            if cursor.kind in CF_CURSOR_TYPES and chash not in self.cf_subgraph:
                self.cf_subgraph.add_node(cursor.hash, type=CF_TYPES(cursor.kind))
                if cursor.kind == CursorKind.IF_STMT:
                    prev, iterator = None, cursor
                    while True:
                        prev = iterator
                        children = list(iterator.get_children())
                        if len(children) <= 1:
                            break
                        iterator = children[1]
                        self.cf_subgraph.add_edge(prev.hash, iterator.hash)
                        if iterator.kind == CursorKind.IF_STMT:
                            self.cf_subgraph.add_node(iterator.hash, type=CF_TYPES.ELIF)
                        elif iterator.kind == CursorKind.COMPOUND_STMT:
                            self.cf_subgraph.add_node(iterator.hash, type=CF_TYPES.ELSE)
                            break

    def draw(self):
        graph = self.cf_subgraph
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True, node_color='blue', node_size=700)

        """
        Structures in clang AST:
            - If: Every atmoic if block comprises an IF_STMT and has a COMPOUND_STMT successor, which in turn
            contains the contents of the antecedent. If an elif exists, then it would be the second successor of
            the IF_STMT with the same hierarchy as the COMPOUND_STMT. This happens recursively, so each elif may be
            considered an independent if in its own right. If an else statement follows an IF_STMT, it would be the second
            COMPOUND_STMT successor. Hence any IF_STMT has at most two successors, and one iff it is an atomic if block.
            To effectively capture this structure, we BFS the structure tree.
             For each cf statement, we record its immediate CF predecessor. However, if that of an if is a another if (and
             there is nothing in between), we skip it and update the type of that higher stmt to if-elif. if we find out
             a certain if stmt has two compounds, we will update the cf type of its . 

             for node in cf_tree:
                node.schema_proxy = None
                node.schema = None

                @property
                def type(self):
                    if not self._type:
                        return self.type_proxy

                @type.setter
                def type(self, type):
                    if self._type:
                        self._type = type
                    else:
                        self.type_proxy.type = type

             for node in dfs(cf_tree):
                 if node.type == IF_STMT:
                     if node.immediate_predecessor.type == IF_STMT || ELIF:
                        node.schema = IF_ELIF (change this)
                        node.type = ELIF
                     if node.successors_num == 2 && both are compound:
                        node.schema = ITE
                        promote second compound stmt to ELSE.
                 if node.type == WHILE:
                     node.schema = WHILE

             Assign a list of control structures to each
             line. Upon every if statement, whose successors
             we evaluate recursively and contiguously, 
             - Switch: cases are handled on a 
             - While:
             - For: 
        """

        # input: certain lines of code; output: smallest containing structure.
        # for example, if the code block is contained in an if/elif block that has else, the function
        # should return ITE. similar with distinction between complete/incomplete switch cases.

        plt.show()
        # print the entire graph


def main():
    walker = ASTWalker("C:\\Users\\Charlie Jiang.vv001\\PycharmProjects\\Verbatim\\datasets\\c\\2020-baby-c\\source.c")
    for func in walker.functions:
        walker.func = func
        walker.draw()



    #
    #

    # goal: add in else ifs and elses
    # else if condition: parent is an if stmt
    # else condition: if one if has two compound statements as substmt

    # print(node.spelling)
    #
    # build tree

    # for stmt in if_stmts:
    #   source_text = get_source(src, stmt[0].extent.start.offset,
    #                         stmt[0].extent.end.offset)
    #  print(f'Depth: {stmt[1]}')
    # print(source_text)
    # observation: if-elifs are consider nested ifs! else is counted as part of the last if, which would have two compound
    # stmts as subnodes. if there are some other control flow statement inside the if, it is included in its compound statement
    # a if stmt is the elif of another if iff it is of depth +1; a parallel if would have the same depth, whereas one within
    # would have depth > d + 1.
    # depth equal iff parallel

    # print('  ' * depth + f'{node.kind.name}: {node.spelling}')
    # sequential: disconnected nodes?
    # balanced


# tree building from ast (e.g. identify patterns such as else ifs)
# write function to map code to smallest super-cf statement block
# map from schema to cf stmt blocks
# prompt engineering

main()
