from pydantic import BaseModel

from . import regexes, types

from dataclasses import dataclass, Field, field
from typing import Optional, List, Dict, Set
from abc import ABC, abstractmethod


class Filter(BaseModel):
    binary: bool = False
    unused_labels: bool = False
    library_functions: bool = False
    directives: bool = False
    comment_only: bool = False
    whitespace: bool = False
    plt: bool = False

    dont_mask_filenames: bool = False
    compatmode: bool = False

    code_only: bool = False


def _is_hex(c: str) -> bool:
    return c.isdigit() or 'a' <= c.lower() <= 'f'


class IParser(ABC):
    @dataclass
    class State:
        stopParsing = False

        currentSourceRef: types.AsmSourceInfo = field(default_factory=types.AsmSourceInfo)
        previousLabel = ""
        text = ""
        currentFilename = ""
        currentSection = ""
        currentLine: types.AsmLine = field(default_factory=types.AsmLine)

    def __init__(self):
        self.reproducible = False
        self.filter: Filter = Filter()
        self.lines: List[types.AsmLine] = []
        self.state = self.State()

    def parse(self, asm: str) -> None:
        self.state.text = ''

        for c in asm:
            if c == '\r':
                # Skip carriage return assuming there's going to be a line feed
                continue
            elif c == '\n':
                self.on_eol()  # Process end-of-line
                continue

            match self.on_char(c):
                case 0:
                    self.state.text += c
                case 1:
                    continue
                case 2:
                    break

        if self.state.text:
            # If the last line wasn't terminated, still parse
            self.on_eol()

    @abstractmethod
    def on_eol(self) -> None:
        pass

    def on_char(self, c: str) -> int:
        return 0

    # @abstractmethod
    # def output_json(self, output_stream: TextIOBase) -> None:
    #    pass

    # @abstractmethod
    # def output_debug_json(self, output_stream: TextIOBase) -> None:
    #    pass

    @abstractmethod
    def output_text(self) -> None:
        pass


class AssemblyTextParser(IParser):
    def __init__(self):
        super().__init__()
        self.files: Dict[int, str] = {}
        self.labels_defined: Dict[str, int] = {}
        self.usercode_labels: Set[str] = set()
        self.used_labels: Dict[str, Set[str]] = {}
        self.data_used_labels: Dict[str, Set[str]] = {}
        self.weakly_used_labels: Dict[str, Set[str]] = {}
        self.aliased_labels: Dict[str, str] = {}

        @dataclass
        class State(IParser.State):
            stopParsing = False
            hasProcMarkers = False
            hasStartedCommentBlock = False

            mayRemovePreviousLabel = True
            keepInlineCode = False
            lastOwnSource: types.AsmSourceInfo = field(default_factory=types.AsmSourceInfo)

            inNvccDef = False
            inNvccCode = False
            inCustomAssembly = 0

            previousParentLabel = ""
            previousLabelOnSameAddress = ""
            currentSourceFile = ""
            filteredLines: List = field(default_factory=list)

        self.state = State()

    def amend_previous_lines_with(self, source: types.AsmSourceInfo) -> None:
        for line in self.lines:
            if line.is_label:
                line.source = types.AsmSourceInfo(file=source.file, file_idx=source.file_idx, line=source.line,
                                                  column=source.column, is_end=False, inside_proc=source.inside_proc,
                                                  is_usercode=source.is_usercode and not line.is_internal_lable)
                if not line.is_internal_label:
                    break
            else:
                break

    def handle_stabs(self, line: str) -> bool:
        if stabs_opt := regexes.get_source_info_from_stabs(line):
            # cf http://www.math.utah.edu / docs / info / stabs_11.html  # SEC48
            if stabs_opt.type == 68:
                self.state.currentSourceRef = types.AsmSourceInfo(line=stabs_opt.line)
            elif type in [100, 132]:
                self.state.currentSourceRef = types.AsmSourceInfo()
                self.state.previousLabel = ""
            return True
        return False

    def handle_file_def(self, line: str) -> bool:
        file_def = regexes.get_file_def(line)
        if file_def:
            self.files[file_def.file_index] = file_def.file_name
            return True
        return False

    def handle_source(self, line: str) -> bool:
        ref = regexes.get_source_ref(line)
        if ref.file_index:
            self.state.hasProcMarkers = True
            self.state.currentSourceRef.file_idx = ref.file_index
            self.state.currentSourceRef.line = ref.line_index
            self.state.currentSourceRef.column = ref.column
            self.state.currentSourceRef.inside_proc = True
            self.amend_previous_lines_with(self.state.currentSourceRef)
            return True
        return False

    def get_label_from_line(self, line: str) -> Optional[str]:
        if match_label := regexes.get_label(line):
            return match_label

        if match_assign := regexes.get_label_assignment(line) or regexes.get_assignment_def(line):
            self.state.currentLine.is_assignment = True
            return match_assign

        if match_cuda := regexes.get_cuda_label(line):
            self.state.inNvccDef = True
            self.state.inNvccCode = True
            return match_cuda

        return None

    def ensure_blank(self) -> None:
        if self.lines and self.lines[-1].text:
            self.lines.append(types.AsmLine())

    @staticmethod
    def is_empty_or_just_whitespace(line: str) -> bool:
        return not line or all(c.isspace() for c in line)

    def handle_d2(self, line: str) -> bool:
        if line_src := regexes.get_d2_line_info(line):
            self.state.currentSourceRef = types.AsmSourceInfo(file=self.state.currentSourceFile,
                                                              line=line_src,
                                                              is_usercode=regexes.is_example_or_stdin(
                                                                  self.state.currentSourceFile))
            self.amend_previous_lines_with(self.state.currentSourceRef)
            return True

        if file := regexes.get_d2_file_info(line):
            self.state.currentSourceFile = file
            return True

        return False

    def handle_6502(self, line: str) -> bool:
        if source := regexes.get_6502_dbg_info(line):
            if not source.is_end:
                self.state.currentSourceRef = types.AsmSourceInfo(file=source.file, line=source.line)
            return True
        return False

    def handle_section(self, line: str) -> bool:
        if name_def := regexes.get_section_name_def(line):
            self.state.currentSection = name_def
            return True
        return False

    def handle_label_aliasing(self) -> None:
        if self.state.previousLabelOnSameAddress:
            if not self.state.currentLine.is_assignment:
                if self.state.currentLine.is_label:
                    self.aliased_labels[self.state.currentLine.label] = self.state.previousLabelOnSameAddress
                elif self.state.currentLine.has_opcode or self.state.currentLine.is_data:
                    self.state.previousLabelOnSameAddress = ""
            else:
                self.state.previousLabelOnSameAddress = ""

        if self.state.currentLine.is_label and not self.state.currentLine.is_assignment:
            self.state.previousLabelOnSameAddress = self.state.currentLine.label

    def handle_label_definition(self, line: str) -> None:
        if found_label := self.get_label_from_line(line):
            self.state.currentLine.label = found_label
            self.state.currentLine.is_label = True
            self.state.currentLine.is_internal_label = self.is_internal_label(self.state.currentLine.label)
            self.state.previousLabel = self.state.currentLine.label
            self.labels_defined[self.state.currentLine.label] = len(self.lines) + 1
            if not self.state.currentLine.is_internal_label:
                self.state.previousParentLabel = self.state.currentLine.label
        else:
            self.state.currentLine.is_label = False
            self.state.currentLine.is_internal_label = False

    def extract_used_labels_from_directive(self, line: str) -> None:
        if weakDef := regexes.get_weak_defined_label(line):
            self.used_labels[weakDef].add(self.state.previousLabel)
        elif globalDef := regexes.get_global_defined_label(line):
            self.usercode_labels.add(globalDef)
            self.used_labels[globalDef].add(self.state.previousLabel)

    def extract_used_labels_from_line(self, line: str, opcode: bool) -> None:
        data = not opcode
        self.state.currentLine.labels = regexes.get_used_labels_in_line(line)
        for label in self.state.currentLine.labels:
            if opcode:
                if label.name != self.state.previousParentLabel:
                    self.used_labels[label.name].add(self.state.previousParentLabel)
            elif data:
                self.data_used_labels[label.name].add(self.state.previousLabel)
                if self.state.currentSourceRef.inside_proc:
                    self.data_used_labels[label.name].add(self.state.previousParentLabel)

    def redetermine_labels(self) -> List[types.AsmLabelPair]:
        labels = []
        line_number = 1
        for line in self.lines:
            if line.is_label:
                labels.append(types.AsmLabelPair(first=line.label, second=line_number))
            line_number += 1
        return labels

    @staticmethod
    def is_internal_label(label: str):
        return label.startswith(".") or label.startswith("$") or label.startswith("L")

    def mark_previous_internal_label_as_inside_proc(self) -> None:
        for line in self.lines:
            if not line.is_label:
                break
            if line.is_internal_label:
                line.source.inside_proc = True
                break

    def remove_undefined_labels(self, line: types.AsmLine):
        line.labels = list(filter(lambda label: label.name in self.labels_defined, line.labels))

    def filter_non_labels(self):
        def _filter(labels):
            return {label: refs for label, refs in labels.items() if label in self.labels_defined}

        self.used_labels = _filter(self.used_labels)
        self.weakly_used_labels = _filter(self.weakly_used_labels)

    def is_used(self, label: str, depth: int = 1) -> bool:
        if label in self.usercode_labels:
            return True

        if used := self.used_labels.get(label) is not None:
            for ref in used:
                if ref.empty() or self.is_used(ref, 0):
                    return True

        if depth > 0:
            for labels in (self.weakly_used_labels, self.data_used_labels):
                if (refs := labels.get(label)) is not None:
                    for ref in refs:
                        if self.is_used(ref, depth - 1):
                            return True

        return False

    def is_used_by_alias(self, label: str) -> bool:
        if alias := self.aliased_labels.get(label) is not None:
            return self.is_used(alias, 1)
        return False

    def is_data_used_by_alias(self, label: str) -> bool:
        if weak := self.data_used_labels.get(label) is not None:
            for ref in weak:
                if self.is_used_by_alias(ref):
                    return True
        return False

    def mark_label_usage(self) -> None:
        for label, idx in self.labels_defined.items():
            line = self.lines[idx - 1]
            if self.is_used(line.label):
                line.is_used = True
            elif self.is_used_by_alias(line.label):
                line.is_used_through_alias = True
            elif self.is_data_used_by_alias(line.label):
                line.is_used_data_through_alias = True

    def remove_unused(self) -> None:
        remove = False
        is_used = False
        is_used_through_alias = False
        is_data_used_through_alias = False
        i = 0

        while i < len(self.lines):
            line = self.lines[i]
            print(line)
            remove_only_this = False

            if line.is_label:
                is_used = line.is_used
                is_used_through_alias = line.is_used_through_alias
                is_data_used_through_alias = line.is_used_data_through_alias

                if self.filter.unused_labels:
                    if remove and is_used:
                        remove = False
                    elif not remove and not is_used:
                        if is_used_through_alias:
                            remove_only_this = True
                        elif not is_data_used_through_alias:
                            if line.is_internal_label or line.is_inline_asm:
                                remove_only_this = True
                            elif line.closest_parent_label:
                                remove = line.closest_parent_label not in self.used_labels
                                remove_only_this = not remove and line.is_internal_label
                            else:
                                remove = True

            if remove or remove_only_this or \
                    (not is_used and not is_used_through_alias and not is_data_used_through_alias and
                     self.filter.compatmode and self.filter.directives and line.is_data and
                     not line.source.inside_proc):
                self.state.filteredLines.append(line)
                self.lines.pop(i)
            else:
                self.remove_undefined_labels(line)

                if line.source.file_idx != 0:
                    try:
                        file = self.files[line.source.file_idx]
                        match_stdin = regexes.is_example_or_stdin(file)
                        line.source.is_usercode = match_stdin
                        line.source.file = file
                    except KeyError:
                        line.source = None

                i += 1

    def on_eol(self) -> None:
        self.state.currentLine = types.AsmLine()
        line = self.state.text

        if self.filter.comment_only:
            if self.state.hasStartedCommentBlock:
                self.state.hasStartedCommentBlock = not regexes.end_comment_block(line)
                self.state.text = ""
                return
            self.state.hasStartedCommentBlock = regexes.start_comment_block(line)

        if self.is_empty_or_just_whitespace(line):
            self.ensure_blank()
            return

        if regexes.start_app_block(line) or regexes.start_asm_nesting(line):
            self.state.inCustomAssembly += 1
        elif regexes.end_app_block(line) or regexes.end_asm_nesting(line):
            self.state.inCustomAssembly -= 1

        filtered_line = line
        if self.state.inCustomAssembly > 0:
            filtered_line = regexes.fix_label_indentation(filtered_line)
        filtered_line = regexes.expand_tabs(filtered_line)
        if self.filter.whitespace:
            filtered_line = regexes.squash_horizontal_whitespace_with_quotes(filtered_line, True)
        self.state.currentLine.text = filtered_line

        if regexes.start_proc_block(self.state.currentLine.text) and self.state.currentSourceRef.line == 0:
            self.mark_previous_internal_label_as_inside_proc()
            if self.filter.directives:
                self.state.text = ""
                return

        handled_source_directive = False
        if regexes.end_block(self.state.currentLine.text) \
                or self.state.inNvccCode and '}' in self.state.currentLine.text:
            self.state.currentSourceRef = None
            self.state.previousLabel = ""
            self.state.lastOwnSource = None
        else:
            handled_source_directive = self.handle_file_def(self.state.currentLine.text) \
                                       or self.handle_source(self.state.currentLine.text) \
                                       or self.handle_stabs(self.state.currentLine.text) \
                                       or self.handle_6502(self.state.currentLine.text) \
                                       or self.handle_d2(self.state.currentLine.text)

        if not handled_source_directive:
            self.handle_section(self.state.currentLine.text)

        if self.filter.library_functions and self.state.lastOwnSource and \
                not self.state.lastOwnSource.line and self.state.currentFilename == "":
            if self.state.mayRemovePreviousLabel and len(self.lines):
                self.state.keepInlineCode = True
                if self.lines[-1].text and self.lines[-1].is_label:
                    self.lines.pop()
                    self.state.keepInlineCode = False
                self.state.mayRemovePreviousLabel = False

            if not self.state.keepInlineCode:
                self.state.text = ""
                return
        else:
            self.state.mayRemovePreviousLabel = True

        if self.filter.comment_only and (regexes.is_just_comments(line) and not self.state.inNvccCode) \
                or (regexes.is_just_nvcc_comments(line) and self.state.inNvccCode):
            self.state.text = ""
            return

        if handled_source_directive:
            self.state.currentLine.is_data = False
            self.state.currentLine.is_directive = True
            self.state.currentLine.is_label = False
            self.state.currentLine.is_internal_label = False
        else:
            self.handle_label_definition(self.state.currentLine.text)
            self.state.currentLine.is_data = regexes.is_data_defn(self.state.currentLine.text)
            self.state.currentLine.is_directive = False

        if self.state.inNvccDef:
            if regexes.is_cuda_end_def(self.state.currentLine.text):
                self.state.inNvccDef = False

        elif not self.state.currentLine.is_label and not self.state.currentLine.is_data:
            if not handled_source_directive:
                self.state.currentLine.is_directive = regexes.is_directive(self.state.currentLine.text)

            # .inst generates an opcode, so does not count as a directive
            if self.state.currentLine.is_directive and not regexes.is_inst_opcode(self.state.currentLine.text):
                self.extract_used_labels_from_directive(self.state.currentLine.text)
                if self.filter.directives:
                    self.state.filteredLines.append(self.state.currentLine)
                    self.state.text = ""
                    return

        self.state.currentLine.is_inline_asm = (self.state.inCustomAssembly > 0)
        self.state.currentLine.has_opcode = regexes.has_opcode(self.state.currentLine.text, self.state.inNvccCode)
        self.state.currentLine.labels.clear()
        if not self.state.currentLine.is_label:
            for cond, state in ((self.state.currentLine.has_opcode, True), (self.state.currentLine.is_data, False)):
                cond and self.extract_used_labels_from_line(self.state.currentLine.text, state)

        if self.state.currentLine.is_assignment or self.state.currentLine.label == self.state.previousParentLabel:
            self.state.currentLine.closest_parent_label = ""
        else:
            self.state.currentLine.closest_parent_label = self.state.previousParentLabel

        self.state.currentLine.source = self.state.currentSourceRef
        self.state.currentLine.section = self.state.currentSection
        self.handle_label_aliasing()
        print(self.state.currentLine)
        self.lines.append(self.state.currentLine)
        self.state.text = ""

    def parse(self, asm: str) -> None:
        super().parse(asm)
        self.filter_non_labels()
        self.mark_label_usage()
        self.remove_unused()

    def output_text(self):
        for line in self.lines:
            print(f"{line.text}\n")


# if (filters.intel && !filters.binary) options = options.concat('-x86-asm-syntax=intel');
# if (filters.binary) options = options.concat('-filetype=obj');


class ObjDumpParser(IParser):
    def __init__(self):
        super().__init__()

        @dataclass
        class ObjDumpParserState(IParser.State):
            inComment = False
            inSomethingWithALabel = False
            hasPrefixingWhitespace = False
            inAddress = False
            inLabel = False
            inOpcodes = False
            inSectionStart = False
            inSectionName = False
            inSourceRef = False
            inRelocation = False
            skipRestOfTheLine = False
            ignoreUntilNextLabel = False
            checkNextFileForLibraryCode = False

            currentLabelReference: types.AsmLabel = field(default_factory=types.AsmLabel)

            @classmethod
            def reset(cls):
                cls.currentLine = types.AsmLine()
                cls.text = ""
                cls.hasPrefixingWhitespace = False
                cls.inComment = False
                cls.inAddress = True
                cls.inOpcodes = False
                cls.inLabel = False
                cls.inSectionStart = False
                cls.inSectionName = False
                cls.inSourceRef = False
                cls.skipRestOfTheLine = False
                cls.inRelocation = False

        self.state = ObjDumpParserState()
        self.labels = []

    def on_eol(self) -> None:
        if self.state.inLabel:
            if not self.state.text:
                self.state.inLabel = False
                return

            if label := regexes.get_label_from_objdump_label(self.state.text):
                self.state.text = label

            self.state.ignoreUntilNextLabel = regexes.should_ignore_function(self.state.text, self.filter.plt)
            if self.state.ignoreUntilNextLabel:
                return

            self.state.checkNextFileForLibraryCode = True
            self.state.previousLabel = self.state.text
            self.state.currentLine.label = self.state.text
            self.state.text += ":"
            self.state.currentLine.is_label = True

            self.labels.append(types.AsmLabelPair(first=self.state.previousLabel, second=len(self.lines) + 1))

        if not self.state.ignoreUntilNextLabel:
            if self.state.inSourceRef:
                if line_num := int(self.state.text) > 0:
                    self.state.currentSourceRef.line = line_num

            elif self.state.text:
                self.state.currentLine.text = self.state.text
                self.state.currentLine.section = self.state.currentSection

                if not self.state.currentLine.is_label:
                    self.state.currentLine.text = ' ' + self.state.currentLine.text

                    for label in self.state.currentLine.labels:
                        # cols start at 1, and we added a space, so add 2
                        label.range.start_col += 2
                        label.range.end_col += 2

                self.state.currentLine.source = self.state.currentSourceRef
                self.lines.append(self.state.currentLine)

        self.state.reset()

    def update_label_ref(self) -> None:
        if self.state.ignoreUntilNextLabel:
            self.state.currentLabelReference = types.AsmLabel()
            return

        self.state.currentLabelReference.range.end_col = len(self.state.text)
        try:
            self.state.currentLabelReference.name = self.state.text[:self.state.currentLabelReference.range.start_col]

            if not regexes.should_ignore_function(self.state.currentLabelReference.name, self.filter.plt):
                self.state.currentLine.labels.append(self.state.currentLabelReference)
        except:
            # ignore erroneous nonsense
            self.state.currentLabelReference.name = ""

    def update_opcodes(self) -> None:
        if self.state.ignoreUntilNextLabel:
            self.state.text = ""
            self.state.inOpcodes = False
            return

        self.state.currentLine.opcodes.extend(self.state.text.split())

    def undo_last_line_if_label(self):
        last_line = self.lines[-1]
        if last_line.is_label:
            self.labels = [label for label in self.labels if label.first != last_line.label]
            self.lines.pop()

    def check_file_is_lib(self, filename: str) -> None:
        if self.state.checkNextFileForLibraryCode:
            self.state.checkNextFileForLibraryCode = False

            if self.file_in_library(filename):
                if len(self.lines):
                    self.undo_last_line_if_label()

                self.state.reset()
                self.state.ignoreUntilNextLabel = True

    def parse_line_head(self) -> None:
        is_file = False
        if self.state.text or (is_file := self.state.text[0] == '/'):
            self.state.inAddress = False
            self.state.inOpcodes = False
            if is_file:
                self.state.currentFilename = self.state.text
                self.state.skipRestOfTheLine = True
                self.check_file_is_lib(self.state.currentFilename)
        else:
            maybe_not_hex_afterall = False

            if not self.state.ignoreUntilNextLabel:
                addr = 0
                bitsdone = 0
                for c in reversed(self.state.text):
                    if not _is_hex(c):
                        maybe_not_hex_afterall = True
                        break

                    hint = int(c)
                    if hint != 0:
                        # note: the if works for cases in 64 bit objdumps where label lines are formatted like this "0000000000408000 <_init>:"
                        #  because it most likely won't get to the last/first hex chunk this way.
                        #  Otherwise makes gcc think it's gonna be bigger than a int64_t and complain about potential overflows.
                        #  (or maybe some other bit of the code is wrong??)
                        addr += hint << bitsdone
                    bitsdone += 4

                self.state.currentLine.address = addr

            if maybe_not_hex_afterall:
                # it might be a label that we can ignore because its noise..
                self.state.skipRestOfTheLine = True
                self.state.inAddress = False
            else:
                self.state.inAddress = False
                self.state.inOpcodes = True

        self.state.text = ""

    def on_char(self, c: str) -> int:
        if self.state.skipRestOfTheLine:
            return 1

        if self.state.inAddress:
            if c == '/':
                self.state.inAddress = False
                self.state.inSourceRef = True
                return 0
            if c == ':':
                self.parse_line_head()
            elif c.isspace():
                if self.state.text == "Disassembly":
                    self.state.inAddress = False
                    self.state.inSectionStart = True
                    self.state.currentSection = ""
                    return 0
                if self.state.text:
                    self.parse_line_head()
                    self.state.inAddress = False
                    self.state.inLabel = True
            return 1
        elif self.state.inOpcodes:
            if c.isspace():
                if self.state.text[-1].isspace():
                    self.update_opcodes()
                    return 1
            else:
                if c == 'R':
                    self.state.inRelocation = True
                    self.state.inOpcodes = False
                    self.state.text += "   "
                elif not _is_hex(c):
                    self.state.inOpcodes = False
                return 0
        elif self.state.inRelocation:
            # R_XXXXXX<tab>data for reloc
            # data can be symbols, symbol + addend, or some value alone.
            # Simply change TAB to single space then take everything until EOL as data.
            if c == '\t':
                self.state.text += ' '
                return 1
        elif self.state.inSectionStart:
            if not self.state.inSectionName:
                if self.state.text == "Disassembly of section ":
                    self.state.inSectionName = True
                    self.state.text = ""
                    self.state.currentSection = c
                    return 1
            else:
                if c == ':':
                    self.state.skipRestOfTheLine = True
                    self.state.text = ""
                    return 0
                self.state.currentSection += c
                return 1
        elif self.state.inSourceRef:
            if c == ':':
                self.state.currentFilename = self.state.text
                self.state.currentSourceRef = types.AsmSourceInfo(file=self.state.currentFilename)
                self.state.text = ""
                self.check_file_is_lib(self.state.currentFilename)
                return 1
        elif not self.state.inComment:
            if c == '#':
                self.state.inComment = True
                return 0
            if c == '<':
                self.state.inSomethingWithALabel = True
                self.state.currentLabelReference.range = types.AsmRange(start_col=len(self.state.text) + 1)
                return 0
            if self.state.inSomethingWithALabel:
                if c == '>':
                    self.state.inSomethingWithALabel = False
                    if not self.state.currentLabelReference.name:
                        self.update_label_ref()
                    return 0
                if c == '+':
                    self.state.inSomethingWithALabel = False
                    self.update_label_ref()
                    return 0

        if c.isspace() and not self.state.text:
            return 1
        return 0

    def parse(self, asm: str) -> None:
        self.state.inAddress = True
        super().parse(asm)
