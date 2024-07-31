import os

from PyQt6 import QtGui
from PyQt6.QtCore import QEvent, Qt, QStringListModel, QModelIndex, pyqtSignal
from PyQt6.QtGui import QPixmap, QEnterEvent, QFont, QStandardItemModel, QFocusEvent, QStandardItem
from PyQt6.QtWidgets import QMainWindow, QSplashScreen, QApplication, QWidget, QHBoxLayout, QVBoxLayout, QListView, \
    QFrame, QStyle, QLabel, QPushButton, QStackedWidget, QDialog, QLineEdit, QFileDialog, QButtonGroup
from widgets import DeOOPListView, FileBrowserWidget, LabeledEdit, DirectoryBrowserWidget

from app.data_manager import DataManager
from app.theme import Theme
from app.config import *
from project import ProjectWindow


class BigIcon(QWidget):
    def __init__(self):
        super().__init__()


class ProjectList(QWidget):
    def __init__(self):
        super().__init__()

        self._layout = QVBoxLayout()

        projs = DataManager.instance().projects
        if not projs:
            self._title = QLabel("Welcome to Verbatim")
            self._desc = QLabel(
                "Verbatim is a decompiler-agnostic psedocode augmentor and deobfuscator capable of producing "
                "semantically equivalent and readable C code from optimized binary with powerful language "
                "models. Get started now!")
            self._title.setFont(QFont("Consolas", 15))
            self._desc.setFont(QFont("Consolas", 10))
            self._desc.setWordWrap(True)

            self._welcomeLayout = QVBoxLayout()
            self._welcomeLayout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            self._welcomeLayout.addWidget(self._title)
            self._welcomeLayout.addWidget(self._desc)

            self._layout.addLayout(self._welcomeLayout)

        self._actionsLayout = QHBoxLayout()
        self._newProjButton = QPushButton("New project")
        self.project_dialog = NewProjectDialog()
        self._newProjButton.clicked.connect(self.project_dialog.exec)
        self._actionsLayout.addWidget(self._newProjButton)
        self._layout.addLayout(self._actionsLayout)

        if projs:
            self._projectsFrame = QFrame()
            self._projectsFrame.setStyleSheet("""
                            QFrame {{
                                background-color: darkgrey;
                                border: 0px;
                                border-radius: 15px;
                            }}
                            """)

            self._projectsFrameLayout = QVBoxLayout()
            self._searchBar = QLabel()
            self._listView = DeOOPListView()
            self._listModel = QStandardItemModel()
            for proj in projs:
                self._listModel.appendRow(QStandardItem(proj))
            self._listView.setModel(self._listModel)

            self._projectsFrameLayout.addWidget(self._searchBar)
            self._projectsFrameLayout.addWidget(self._listView)
            self._projectsFrame.setLayout(self._projectsFrameLayout)
            self._layout.addWidget(self._projectsFrame)

        self.setLayout(self._layout)


class DeOOPWindow(QMainWindow):
    def __init__(self):
        # TO-DO: background color support, fancy list view
        # fixed size that's calculated based on screen size (i.e. smaller for smaller screens, but has an upper threshold)
        #

        super().__init__()
        self._theme = Theme()
        self.display_splashcreen()
        self.setWindowTitle(f"Welcome to {PRETTY_NAME}!")

        self._sidebar = DeOOPListView()
        self._sidebarModel = QStringListModel()
        self._sidebarModel.setStringList(["Projects", "Customize"])
        self._sidebar.setModel(self._sidebarModel)
        (selection := self._sidebar.selectionModel()).select((idx := self._sidebarModel.index(0, 0)),
                                                             selection.SelectionFlag.Select)
        selection.setCurrentIndex(idx, selection.SelectionFlag.Select)

        self._stackedView = QStackedWidget()
        self._projList = ProjectList()
        self._projList.project_dialog.project_created.connect(self.add_project)
        self._stackedView.addWidget(self._projList)
        self._stackedView.addWidget(QWidget())
        self._sidebar.clicked.connect(lambda index: self._stackedView.setCurrentIndex(index.row()))

        self._mainLayout = QHBoxLayout()
        self._mainLayout.addWidget(self._sidebar)
        self._mainLayout.addWidget(self._stackedView)

        self._container = QWidget()
        self._container.setLayout(self._mainLayout)
        self.setCentralWidget(self._container)

        self._openProjects = []

    def add_project(self, project: QWidget):
        self._openProjects.append(project)
        project.show()
        self.hide()

    def display_splashcreen(self):
        # make this dynamic
        splash = QPixmap(DataManager.get_file("splash_sample.png", 0))
        screen = QSplashScreen(splash)
        # splashscreen: de \inf p
        # detect environment
        # init compiler explorer
        # parse configs
        screen.show()
        DataManager.instance()
        screen.hide()


class FromBinaryView(QWidget):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._inputBinary = FileBrowserWidget('Binary:',
                                              "Binaries (*.exe *.dll *.sys *.so *.bin *.dylib *.bundle"
                                              "*.o *.a *.lib *.mach-o)",
                                              "Choose an executable, driver, or library from which to"
                                              "create this project.")

        self._projName = LabeledEdit("Name:", text_changed=lambda _: self.update_creation_hint())
        self._projLocation = DirectoryBrowserWidget("Location:", text_changed=lambda _: self.update_creation_hint())
        self._creationHint = QLabel("The project will be created in: ")
        self._creationHint.setWordWrap(True)

        self._decompilerLayout = QHBoxLayout()
        self._decompilerLayout.addWidget(QLabel("Primary decompiler:"))
        self._decompilerButtonGroup = QButtonGroup()
        self._idaButton = QPushButton("IDA")
        self._ghidraButton = QPushButton("Ghidra")
        self._decompilerButtonGroup.addButton(self._idaButton)
        self._decompilerLayout.addWidget(self._idaButton)
        self._decompilerButtonGroup.addButton(self._ghidraButton)
        self._decompilerLayout.addWidget(self._ghidraButton)

        # stacked view containing settings
        #

        self._layout = QVBoxLayout()
        self._layout.addWidget(self._inputBinary)
        self._layout.addWidget(self._projName)
        self._layout.addWidget(self._projLocation)
        self._layout.addWidget(self._creationHint)
        self._layout.addLayout(self._decompilerLayout)
        self.setLayout(self._layout)

    def update_creation_hint(self) -> None:
        self._creationHint.setText(f"The project will be created in: "
                                   f"{os.path.join(self._projLocation.edit.text(), self._projName.edit.text())}")

class FromIDAView(QWidget):
    pass


class FromGhidraView(QWidget):
    pass


class NewProjectDialog(QDialog):
    project_created = pyqtSignal(QWidget)

    def __init__(self, parent: QWidget = None, flags: Qt.WindowType = Qt.WindowType.Window):
        super().__init__(parent, flags)

        self._layout = QVBoxLayout()
        self._mainLayout = QHBoxLayout()

        # Left side - Listview for decompilers
        self._decompilerList = DeOOPListView()
        self._decompilerModel = QStringListModel()
        self._decompilerModel.setStringList(['Binary', 'IDA', 'Ghidra'])
        self._decompilerList.setModel(self._decompilerModel)
        self._mainLayout.addWidget(self._decompilerList)

        self._stackedView = QStackedWidget()
        self._stackedView.addWidget(FromBinaryView())
        self._mainLayout.addWidget(self._stackedView)
        self._decompilerList.clicked.connect(lambda index: self._stackedView.setCurrentIndex(index.row()))

        self._cancelButton = QPushButton('Cancel')
        self._createButton = QPushButton("Create")
        self._createButton.clicked.connect(self.on_create)
        self._buttonsLayout = QHBoxLayout()
        self._buttonsLayout.addWidget(self._cancelButton)
        self._buttonsLayout.addWidget(self._createButton)

        self._layout.addLayout(self._mainLayout)
        self._layout.addLayout(self._buttonsLayout)
        self.setLayout(self._layout)

    def on_create(self):
        # checking content
        # create based on config
        self.project_created.emit(ProjectWindow())
        self.close()
