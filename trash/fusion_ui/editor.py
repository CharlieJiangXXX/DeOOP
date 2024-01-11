from PyQt5.Qsci import QsciScintilla, QsciLexerCPP, QsciLexerAsm, QsciAPIs
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QFontMetrics
from PyQt5.QtWidgets import QMenu

_lexer_mapping = {"cpp": QsciLexerCPP, "asm": QsciLexerAsm}


class FusionEditor(QsciScintilla):
    def __init__(self, language: str):
        super().__init__(parent=None)

        lexer = _lexer_mapping[language]()
        # lexer.setDefaultColor(QColor("white"))
        # lexer.setFont(QFont(self._themes["font"]))
        self.setLexer(lexer)
        self.setPaper(QColor("white"))

        # Autocompletion
        apis = QsciAPIs(self.lexer())
        self.setAutoCompletionSource(QsciScintilla.AutoCompletionSource.AcsAll)
        self.setAutoCompletionThreshold(1)
        self.setAutoCompletionCaseSensitivity(True)
        self.setWrapMode(QsciScintilla.WrapMode.WrapNone)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setAutoCompletionThreshold(1)
        self.setAutoCompletionFillupsEnabled(True)

        # Setting up lexers
        lexer.setColor(QColor("#808080"), lexer.Comment)
        lexer.setColor(QColor("#FFA500"), lexer.Keyword)
        lexer.setColor(QColor("#FFFFFF"), lexer.ClassName)
        lexer.setColor(QColor("#59ff00"), lexer.TripleSingleQuotedString)
        lexer.setColor(QColor("#59ff00"), lexer.TripleDoubleQuotedString)
        lexer.setColor(QColor("#3ba800"), lexer.SingleQuotedString)
        lexer.setColor(QColor("#3ba800"), lexer.DoubleQuotedString)
        lexer.setColor(QColor("black"), lexer.Default)

        self.setTabWidth(4)
        self.setMarginLineNumbers(1, True)
        self.setAutoIndent(True)
        self.setMarginWidth(1, "#0000")
        left_margin_index = 0
        left_margin_width = 7
        self.setMarginsForegroundColor(QColor("black"))
        self.setMarginsBackgroundColor(QColor("black"))
        font_metrics = QFontMetrics(self.font())
        left_margin_width_pixels = font_metrics.horizontalAdvance(" ") * left_margin_width
        self.SendScintilla(self.SCI_SETMARGINLEFT, left_margin_index, left_margin_width_pixels)
        self.setFolding(QsciScintilla.FoldStyle.BoxedTreeFoldStyle)
        self.setMarginSensitivity(2, True)
        self.setFoldMarginColors(
            QColor("gray"), QColor("gray")
        )
        self.setBraceMatching(QsciScintilla.BraceMatch.StrictBraceMatch)
        self.setCaretLineVisible(True)
        self.setCaretLineBackgroundColor(QColor("#20d3d3d3"))
        self.setWrapMode(QsciScintilla.WrapMode.WrapNone)
        self.setAutoCompletionThreshold(1)
        self.setBackspaceUnindents(True)
        self.setIndentationGuides(True)
        self.setReadOnly(False)

        self.context_menu = QMenu(self)
        self.context_menu.addAction("Cut").triggered.connect(self.cut)
        self.context_menu.addAction("Copy").triggered.connect(self.copy)
        self.context_menu.addAction("Paste").triggered.connect(self.paste)
        self.context_menu.addAction("Select All").triggered.connect(self.selectAll)
        self.context_menu.addSeparator()

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, point):
        self.context_menu.popup(self.mapToGlobal(point))
