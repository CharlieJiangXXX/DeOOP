# theme name
# icon and font for each component
import os

from PyQt6.QtWidgets import QStyle

from app.data_manager import DataManager


class Theme:
    def __init__(self):
        self._name = "Default Dark"


class ThemeController:
    def locally_available_themes(self):
        downloaded = os.listdir(os.path.join("app", ".data", "theme"))


    def download(self):
        pass

    def remove(self):
        pass

    def preview(self):
        pass

    def set_default(self):
        pass

    def reset(self):
        """
        Reset to defaults of current theme (discard user settings)
        :return:
        """
        pass


class DeOOPStyle(QStyle):
    pass