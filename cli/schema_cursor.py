import angr
from clang import cindex


# angr.analyses.decompiler.structuring.dream.SequenceNode

def highest_structure_in_subast(file, node):
    if node.kind != cindex.CursorKind.FUNCTION_DECL or not is_user_defined(file, node):
        return

    for child in node.get_children():
        child.
        find_functions(child)


