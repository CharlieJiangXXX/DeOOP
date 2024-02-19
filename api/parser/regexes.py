import copy
import re
from unittest import TestCase

from . import types

from enum import Enum
from typing import Optional, List


class Regexes:
    labelDef = re.compile(r"^(?:\.proc\s+)?([\w$.@]+):")
    labelAssignmentDef = re.compile(r"^([.$\w][\w\d]*)\s+=")
    labelFindNonMips = re.compile(r"[.A-Z_a-z][\w$.]*")
    labelFindMips = re.compile(r"[$.A-Z_a-z][\w$.]*")
    mipsLabelDefinition = re.compile(r"^\$[\w$.]+:")
    labelSearch = re.compile(r"([$%]?)([.@A-Z_a-z][.\dA-Z_a-z]*)")

    dataDefn = re.compile(r"^\s*\.(string|asciz|ascii|[1248]?byte|short|half|[dhx]?word|long|quad|octa|value|zero)")
    fileFind = re.compile(r"^\s*\.file\s+(\d+)\s+\"([^\"]+)\"(\s+\"([^\"]+)\")?.*")
    hasOpcodeRe = re.compile(r"^\s*[A-Za-z]")
    hasNvccOpcodeRe = re.compile(r"^\s*[@A-Za-z|]")
    definesFunction = re.compile(r"^\s*\.(type.*,\s*[#%@]function|proc\s+[.A-Z_a-z][\w$.]*:.*)$")
    definesFunctionOrObject = re.compile(r"\.type\s*([a-z_A-Z0-9]*),\s*@?(function|object|proc)")
    definesGlobal = re.compile(r"^\s*\.(?:globa?l|GLB|export)\s*([.A-Z_a-z][\w$.]*)")
    definesWeak = re.compile(r"^\s*\.(?:weakext|weak)\s*([.A-Z_a-z][\w$.]*)")

    assignmentDef = re.compile(r"^\s*([$.A-Z_a-z][\w$.]+)\s*=")
    directive = re.compile(r"^\s*\..*$")
    startAppBlock = re.compile(r"\s*#APP.*")
    endAppBlock = re.compile(r"\s*#NO_APP.*")
    startAsmNesting = re.compile(r"\s*# Begin ASM.*")
    endAsmNesting = re.compile(r"\s*# End ASM.*")
    cudaBeginDef = re.compile(r"\.(entry|func)\s+(?:\([^)]*\)\s*)?([$.A-Z_a-z][\w$.]*)\($")
    cudaEndDef = re.compile(r"^\s*\)\s*$")

    commentRe = re.compile(r"[#;]")
    instOpcodeRe = re.compile(r"(\.inst\.?\w?)\s*(.*)")
    blockCommentStart = re.compile(r"^\s*/\*")
    blockCommentStop = re.compile(r"\*/")
    commentOnly = re.compile(r"^\s*(((#|@|//).*)|(/\*.*\*/)|(;\s*)|(;[^;].*)|(;;.*\S.*))$")
    commentOnlyNvcc = re.compile(r"^\s*(((#|;|//).*)|(/\*.*\*/))$")
    sourceTag = re.compile(r"^\s*\.loc\s+(\d+)\s+(\d+).*")
    sourceTagWithColumn = re.compile(r"^\s*\.loc\s+(\d+)\s+(\d+)\s+(\d+).*")
    source6502Dbg = re.compile(r"^\s*\.dbg\s+line,\s*\"([^\"]+)\",\s*(\d+)")
    source6502DbgEnd = re.compile(r"^\s*\.dbg\s+line")
    sourceStab = re.compile(r"^\s*\.stabn\s+(\d+),0,(\d+),.*")
    sourceD2Tag = re.compile(r"^\s*\.d2line\s+(\d+),?\s*(\d*).*")
    sourceD2File = re.compile(r"^\s*\.d2file\s+\"(.*)\"")
    stdInLooking = re.compile(r"<stdin>|^-|example\.[^/]+$|<source>")
    startProcBlock = re.compile(r"\.cfi_startproc")
    endBlock = re.compile(r"\.(cfi_endproc|data|text|section)")
    endProcBlock = re.compile(r"\.cfi_endproc")

    sectionDef = re.compile(r"\.(data|text|section)\s*\"?([.a-zA-Z0-9\-]*)\"?")
    findQuotes = re.compile(r'(.*?)("(?:[^"\\]|\\.)*")(.*)')
    binaryIgnoreFunction = re.compile(
        r"^(__.*|_(init|start|fini)|(de)?register_tm_clones|call_gmon_start|frame_dummy|\.plt.*|_dl_relocate_static_pie)$")


def get_source_ref(line: str) -> types.RegexedSourceRef:
    if not (matches := re.match(Regexes.sourceTag, line)):
        return types.RegexedSourceRef()

    ref = types.RegexedSourceRef(file_index=int(matches.group(1)),
                                 line_index=int(matches.group(2)))
    if column_matches := re.match(Regexes.sourceTagWithColumn, line):
        ref.column = int(column_matches.group(3))

    return ref


def get_file_def(line: str) -> Optional[types.AsmFileDef]:
    if not (matches := re.match(Regexes.fileFind, line)):
        return None

    file_def = types.AsmFileDef(file_index=int(matches.group(1)),
                                file_name=str(matches.group(2)))
    if file_name_rest := matches.group(4):
        file_def.file_name = f"{file_def.file_name}/{str(file_name_rest)}"
    return file_def


def expand_tabs(line: str) -> str:
    spaces = " " * 8
    expanded_line = ""

    for c in line:
        if c == '\t':
            total = len(expanded_line)
            spaces_needed = 8 - (total & 7)
            expanded_line += spaces[:spaces_needed]
        else:
            expanded_line += c

    return expanded_line


def get_line_without_comment(line: str) -> str:
    spacing = False
    still_starting = True
    last_index = len(line)

    for index, c in enumerate(line):
        if c in (';', '#'):
            if not spacing:
                last_index = index
            break
        elif spacing:
            if not c.isspace():
                spacing = False
        elif c.isspace():
            if not still_starting:
                spacing = True
                last_index = index
        else:
            still_starting = False

    return line[:last_index].rstrip()


def get_line_without_comment_and_strip_first_word(line):
    word_started = False
    word_ended = False
    spacing = False
    last_index = len(line)
    after_first_word_index = 0

    for index, char in enumerate(line):
        if char in (';', '#'):
            next_index = index + 1
            if next_index < len(line):
                next_char = line[next_index]
                if not next_char.isspace():
                    continue
            if not spacing:
                last_index = index
            break
        elif not word_started and char.isalpha():
            word_started = True
        elif word_started and not word_ended and char.isspace():
            word_ended = True
            after_first_word_index = index
        elif word_ended:
            if spacing:
                if not char.isspace():
                    last_index = len(line)
                    spacing = False
            elif char.isspace():
                spacing = True
                last_index = index
    return line[after_first_word_index:last_index].rstrip()


def is_probably_label(line: str) -> bool:
    return get_line_without_comment(line)[-1] == ":"


def fix_label_indentation(line: str) -> str:
    if is_probably_label(line):
        return line.lstrip()

    return line


def get_used_labels_in_line(line: str) -> List[types.AsmLabel]:
    filtered_line = get_line_without_comment_and_strip_first_word(line)

    if filtered_line.find('"') != -1:
        return []

    labels_in_line = []

    diff_len = len(line) - len(filtered_line) + 1
    start_idx = 0

    for matches in re.finditer(Regexes.labelSearch, filtered_line):
        label = types.AsmLabel(name=str(matches.group(2)),
                               range=types.AsmRange())

        loc = filtered_line.find(label.name, start_idx)
        start_idx = loc + len(label.name)

        label.range.start_col = loc + diff_len
        label.range.end_col = label.range.start_col + len(label.name)

        labels_in_line.append(label)

        if prefix := matches.group(1):
            prefixed_label = copy.deepcopy(label)
            prefixed_label.name = str(prefix) + label.name
            prefixed_label.range.start_col -= 1

            labels_in_line.append(prefixed_label)

    return labels_in_line


def has_opcode(line: str, in_nvcc_code: bool) -> bool:
    # Remove any leading label definition...
    if matches := re.search(Regexes.labelDef, line):
        line = line[len(str(matches.group(0)))]

    line_without_comment = get_line_without_comment(line)

    # .inst generates an opcode, so also counts
    if re.search(Regexes.instOpcodeRe, line_without_comment):
        return True

    # Detect assignment, that's not an opcode...
    if re.match(Regexes.assignmentDef, line_without_comment):
        return False

    if in_nvcc_code:
        return bool(re.match(Regexes.hasNvccOpcodeRe, line_without_comment))

    return bool(re.search(Regexes.hasOpcodeRe, line_without_comment))


def is_example_or_stdin(filename: str) -> bool:
    return bool(re.search(Regexes.stdInLooking, filename))


def get_source_info_from_stabs(line: str) -> Optional[types.AsmStabN]:
    if not (matches := re.search(Regexes.sourceStab, line)):
        return None

    out = types.AsmStabN(type=int(matches.group(1)))
    if out.type == 68:
        out.line = int(matches.group(2))
    return out


def get_6502_dbg_info(line: str) -> Optional[types.AsmSourceInfo]:
    if matches := re.match(Regexes.source6502Dbg, line):
        # todo check if stdin?
        return types.AsmSourceInfo(file=str(matches.group(1)), line=int(matches.group(2)))

    if re.search(Regexes.source6502DbgEnd, line):
        return types.AsmSourceInfo(is_end=True)

    return None


def get_d2_line_info(line: str) -> Optional[int]:
    if matches := re.match(Regexes.sourceD2Tag, line):
        return int(matches.group(1))

    return None


def get_d2_file_info(line: str) -> Optional[str]:
    if matches := re.match(Regexes.sourceD2File, line):
        return str(matches.group(1))

    return None


def start_comment_block(line: str) -> bool:
    return bool(re.search(Regexes.blockCommentStart, line))


def end_comment_block(line: str) -> bool:
    return bool(re.search(Regexes.blockCommentStop, line))


def start_app_block(line: str) -> bool:
    return bool(re.match(Regexes.startAppBlock, line))


def end_app_block(line: str) -> bool:
    return bool(re.match(Regexes.endAppBlock, line))


def start_asm_nesting(line: str) -> bool:
    return bool(re.match(Regexes.startAsmNesting, line))


def end_asm_nesting(line: str) -> bool:
    return bool(re.match(Regexes.endAsmNesting, line))


def start_proc_block(line: str) -> bool:
    return bool(re.search(Regexes.startProcBlock, line))


def end_block(line: str) -> bool:
    return bool(re.search(Regexes.endBlock, line))


def end_proc_block(line: str) -> bool:
    return bool(re.search(Regexes.endProcBlock, line))


def get_label(line: str) -> Optional[str]:
    if matches := re.search(Regexes.labelDef, line):
        return str(matches.group(1))

    return None


def get_label_from_objdump_label(line: str) -> Optional[str]:
    if line.startswith("<") and line.endswith(">:"):
        return line[1:-2]

    return None


def get_label_assignment(line: str) -> Optional[str]:
    if matchAssign := re.search(Regexes.labelAssignmentDef, line):
        return str(matchAssign.group(1))

    return None


def get_assignment_def(line: str) -> Optional[str]:
    if matches := re.match(Regexes.assignmentDef, line):
        return str(matches.group(1))

    return None


def get_cuda_label(line: str) -> Optional[str]:
    if matches := re.search(Regexes.cudaBeginDef, line):
        return str(matches.group(1))

    return None


def get_function_type_defined_label(line: str) -> Optional[str]:
    if matches := re.search(Regexes.definesFunctionOrObject, line):
        return str(matches.group(1))

    return None


def get_weak_defined_label(line: str) -> Optional[str]:
    if matches := re.search(Regexes.definesWeak, line):
        return str(matches.group(1))

    return None


def get_global_defined_label(line: str) -> Optional[str]:
    if matches := re.search(Regexes.definesGlobal, line):
        return str(matches.group(1))

    return None


def get_section_name_def(line: str) -> Optional[str]:
    if matches := re.search(Regexes.sectionDef, line):
        if str(matches.group(1)) == "section":
            return str(matches.group(2))
        return str(matches.group(1))
    return None


def is_just_comments(line: str) -> bool:
    return bool(re.match(Regexes.commentOnly, line))


def is_just_nvcc_comments(line: str) -> bool:
    return bool(re.match(Regexes.commentOnlyNvcc, line))


def is_cuda_end_def(line: str) -> bool:
    return bool(re.match(Regexes.cudaEndDef, line))


def is_data_defn(line: str) -> bool:
    return bool(re.search(Regexes.dataDefn, line))


def is_directive(line: str) -> bool:
    return bool(re.match(Regexes.directive, line))


def is_inst_opcode(line: str) -> bool:
    return bool(re.search(Regexes.instOpcodeRe, line))


def squash_horizontal_whitespace(line: str, at_start: bool = True) -> str:
    squashed = ""

    class HorSpaceState(Enum):
        Start = 0
        Second = 1
        Stop = 2
        JustOne = 3

    state = HorSpaceState.Start if at_start else HorSpaceState.JustOne
    just_spaces = True

    for c in line:
        if not c.isspace():
            squashed += c
            just_spaces = False

        match state:
            case HorSpaceState.Stop:
                if not c.isspace():
                    state = HorSpaceState.JustOne

            case HorSpaceState.JustOne:
                if c.isspace():
                    state = HorSpaceState.Stop
                    squashed += ' '

            case HorSpaceState.Start:
                if c.isspace():
                    state = HorSpaceState.Second
                    squashed += ' '

                else:
                    state = HorSpaceState.Stop

            case HorSpaceState.Second:
                if c.isspace():
                    squashed += ' '
                state = HorSpaceState.Stop

    if at_start and just_spaces:
        return ""

    return squashed


def squash_horizontal_whitespace_with_quotes(line: str, at_start: bool = True) -> str:
    if quotes := re.search(Regexes.findQuotes, line):
        return (f"{squash_horizontal_whitespace_with_quotes(str(quotes.group(1)), at_start)}"
                f"{str(quotes.group(2))}"
                f"{squash_horizontal_whitespace_with_quotes(str(quotes.group(3)), False)}")

    return squash_horizontal_whitespace(line)


def should_ignore_function(name: str, plt: bool) -> bool:
    if re.search(Regexes.binaryIgnoreFunction, name):
        return True
    elif plt:
        return name.endswith("@plt") or name.endswith("@plt>")
    else:
        return False


class TestTextAssemblyUtilities(TestCase):
    def test_get_source_ref(self):
        ref = get_source_ref("        .loc 1 351 7")
        self.assertEqual(ref.file_index, 1)
        self.assertEqual(ref.line_index, 351)
        self.assertEqual(ref.column, 7)

        file_def = get_file_def(
            r'        .file 2 "/opt/compiler-explorer/gcc-10.2.0/include/c++/10.2.0/bits/char_traits.h"')
        self.assertEqual(file_def.file_index, 2)
        self.assertEqual(file_def.file_name,
                         "/opt/compiler-explorer/gcc-10.2.0/include/c++/10.2.0/bits/char_traits.h")

        endproc1 = end_block("\t.cfi_endproc")
        self.assertTrue(endproc1)

        endproc2 = end_proc_block("\t.cfi_endproc")
        self.assertTrue(endproc2)

        indented_label = get_line_without_comment("\tlabel:")
        self.assertEqual(indented_label, "\tlabel:")

    def test_clang_style_file_directive(self):
        file_def = get_file_def(r'        .file 1 "/dir/src" "filename.cpp"')
        self.assertEqual(file_def.file_index, 1)
        self.assertEqual(file_def.file_name, "/dir/src/filename.cpp")

    def test_expand_tabs(self):
        self.assertEqual(expand_tabs("no tabs in here"), "no tabs in here")
        self.assertEqual(expand_tabs("0\t1234567A"), "0       1234567A")
        self.assertEqual(expand_tabs("01\t234567A"), "01      234567A")
        self.assertEqual(expand_tabs("012\t34567A"), "012     34567A")
        self.assertEqual(expand_tabs("0123\t4567A"), "0123    4567A")
        self.assertEqual(expand_tabs("01234\t567A"), "01234   567A")
        self.assertEqual(expand_tabs("012345\t67A"), "012345  67A")
        self.assertEqual(expand_tabs("0123456\t7A"), "0123456 7A")
        self.assertEqual(expand_tabs("01234567\tA"), "01234567        A")
        self.assertEqual(expand_tabs("\tpush\trbp"), "        push    rbp")

    def test_line_filters(self):
        filtered_line1 = get_line_without_comment("   mov eax, [_mylabel+8]  ")
        self.assertEqual(filtered_line1, "   mov eax, [_mylabel+8]")

        filtered_line2 = get_line_without_comment_and_strip_first_word("   mov eax, [_mylabel+8]  # some comment")
        self.assertEqual(filtered_line2, " eax, [_mylabel+8]")

        line1 = get_line_without_comment_and_strip_first_word("   mov eax, ptr [_mylabel+8]")
        self.assertEqual(line1, " eax, ptr [_mylabel+8]")

        line2 = get_line_without_comment_and_strip_first_word("   mov eax, ptr [_mylabel+8]     # comment")
        self.assertEqual(line2, " eax, ptr [_mylabel+8]")

        line3 = get_line_without_comment("_label123:  # comment")
        self.assertEqual(line3, "_label123:")

        line4 = get_line_without_comment("_label123:")
        self.assertEqual(line4, "_label123:")

        line5 = get_line_without_comment_and_strip_first_word("   mov eax, ptr #notacomment")
        self.assertEqual(line5, " eax, ptr #notacomment")

        line6 = get_line_without_comment_and_strip_first_word("        movl    $.L.str, %edi")
        self.assertEqual(line6, "    $.L.str, %edi")

    def test_potential_label_spotting(self):
        labels = get_used_labels_in_line("  mov ptr eax, <_somelabel+8>  # my comments")
        self.assertEqual(len(labels), 3)
        self.assertEqual(labels[2].name, "_somelabel")

        jbe = get_used_labels_in_line("        jbe     .LBB0_3")
        self.assertEqual(len(jbe), 1)
        self.assertEqual(jbe[0].name, ".LBB0_3")
        self.assertEqual(jbe[0].range.start_col, 17)
        self.assertEqual(jbe[0].range.end_col, 24)

        movlower = get_used_labels_in_line("        movw    r1, #:lower16:.LC0")
        self.assertEqual(len(movlower), 3)
        self.assertEqual(movlower[0].name, "r1")
        self.assertEqual(movlower[1].name, "lower16")
        self.assertEqual(movlower[2].name, ".LC0")

        movldollarlabel = get_used_labels_in_line("        movl    $.L.str, %edi")
        self.assertEqual(len(movldollarlabel), 4)
        self.assertEqual(movldollarlabel[0].name, ".L.str")
        self.assertEqual(movldollarlabel[1].name, "$.L.str")
        self.assertEqual(movldollarlabel[2].name, "edi")
        self.assertEqual(movldollarlabel[3].name, "%edi")

        bltid = get_used_labels_in_line("        bltid   r18,$L2")
        self.assertEqual(len(bltid), 3)
        self.assertEqual(bltid[0].name, "r18")
        self.assertEqual(bltid[1].name, "L2")
        self.assertEqual(bltid[2].name, "$L2")

        morelabels = get_used_labels_in_line("        movsd   xmm0, qword ptr [rsi + 8*rax]")
        self.assertEqual(len(morelabels), 5)
        self.assertEqual(morelabels[0].name, "xmm0")
        self.assertEqual(morelabels[0].range.start_col, 17)
        self.assertEqual(morelabels[0].range.end_col, 21)

        self.assertEqual(morelabels[1].name, "qword")
        self.assertEqual(morelabels[1].range.start_col, 23)
        self.assertEqual(morelabels[1].range.end_col, 28)

        self.assertEqual(morelabels[2].name, "ptr")
        self.assertEqual(morelabels[2].range.start_col, 29)
        self.assertEqual(morelabels[2].range.end_col, 32)

        self.assertEqual(morelabels[3].name, "rsi")
        self.assertEqual(morelabels[3].range.start_col, 34)
        self.assertEqual(morelabels[3].range.end_col, 37)

        self.assertEqual(morelabels[4].name, "rax")
        self.assertEqual(morelabels[4].range.start_col, 42)
        self.assertEqual(morelabels[4].range.end_col, 45)

        quoted = get_used_labels_in_line(r'.ascii  \"Hello world\\000\"')
        self.assertEqual(len(quoted), 0)

    def test_squashes_horizontal_whitespace(self):
        self.assertEqual(squash_horizontal_whitespace(""), "")
        self.assertEqual(squash_horizontal_whitespace(" "), "")
        self.assertEqual(squash_horizontal_whitespace("    "), "")
        self.assertEqual(squash_horizontal_whitespace(" abc"), " abc")
        self.assertEqual(squash_horizontal_whitespace("   abc"), "  abc")
        self.assertEqual(squash_horizontal_whitespace("       abc"), "  abc")
        self.assertEqual(squash_horizontal_whitespace("abc abc"), "abc abc")
        self.assertEqual(squash_horizontal_whitespace("abc   abc"), "abc abc")
        self.assertEqual(squash_horizontal_whitespace("abc     abc"), "abc abc")
        self.assertEqual(squash_horizontal_whitespace(" abc  abc"), " abc abc")
        self.assertEqual(squash_horizontal_whitespace("  abc abc"), "  abc abc")
        self.assertEqual(squash_horizontal_whitespace("  abc     abc"), "  abc abc")
        self.assertEqual(squash_horizontal_whitespace("    abc   abc"), "  abc abc")

    def test_squashes_horizontal_whitespace_with_quotes(self):
        squashed = squash_horizontal_whitespace_with_quotes(
            r'  .string   "   abc  etc"   # hello   "  wor  ld"', True)
        self.assertEqual(squashed, r'  .string "   abc  etc"  # hello "  wor  ld"')

    def test_data_definitions(self):
        self.assertTrue(is_data_defn(r'  .string   "   abc  etc"   # hello   "  wor  ld"'))
        self.assertTrue(is_data_defn(r'        .ascii  "Hello world\000"'))
        self.assertTrue(is_data_defn(r'        .ascii  "moo\012\000"'))
        self.assertTrue(is_data_defn(r'        .4byte  0x37d'))
        self.assertTrue(is_data_defn(r'        .byte   0x2'))
        self.assertTrue(is_data_defn(r'        .asciz   "Hello world"'))

    def test_labels(self):
        self.assertEqual(get_label("hello:"), "hello")
        self.assertEqual(get_label(".LC0:"), ".LC0")
        self.assertEqual(get_label("_Z12testFunctionPii:"), "_Z12testFunctionPii")
        self.assertEqual(get_label("_ZNSt9bad_allocC2Ev:"), "_ZNSt9bad_allocC2Ev")
        self.assertEqual(get_label("..___tag_value_main.2:"), "..___tag_value_main.2")
        self.assertEqual(get_label("$Ltext0:"), "$Ltext0")
        self.assertEqual(get_label(
            "_ZN95_$LT$example..Bla$LT$$u27$a$GT$$u20$as$u20$core..convert..Into$LT$alloc..string..String$GT$$GT$4into17h38301ffbb2e8fb47E:"),
                         "_ZN95_$LT$example..Bla$LT$$u27$a$GT$$u20$as$u20$core..convert..Into$LT$alloc..string..String$GT$$GT$4into17h38301ffbb2e8fb47E")
        self.assertEqual(get_label_assignment(".Lset0 = .Lpubnames_end1-.Lpubnames_begin1"),
                         ".Lset0")
        self.assertEqual(get_label_assignment("$LFB0 = ."), "$LFB0")
        self.assertEqual(get_label("__do_global_dtors_aux:"), "__do_global_dtors_aux")

    def test_objdump_filtering(self):
        self.assertTrue(should_ignore_function("__do_global_dtors_aux", False))

    def test_6502_debugging(self):
        match1 = get_6502_dbg_info(r'	.dbg	line, "/tmp/test.c", 2')
        self.assertEqual(match1.file, "/tmp/test.c")
        self.assertEqual(match1.line, 2)

        match2 = get_6502_dbg_info(r'	.dbg	line')
        self.assertTrue(match2.is_end)
        self.assertEqual(match2.file, "")
        self.assertEqual(match2.line, 0)

    def test_instruction_directives(self):
        self.assertTrue(is_inst_opcode("        .inst.n 0xdefe"))

    def test_d2_source_directives(self):
        matchf = get_d2_file_info(
            r'        .d2file   "/tmp/compiler-explorer-compiler202107-8023-z5iran.8cqm/example.cpp"')
        self.assertEqual(matchf, "/tmp/compiler-explorer-compiler202107-8023-z5iran.8cqm/example.cpp")

        matchlc = get_d2_line_info(r'        .d2line         4,8')
        self.assertEqual(matchlc, 4)

        matchl = get_d2_line_info(r'        .d2line         5')
        self.assertEqual(matchl, 5)
