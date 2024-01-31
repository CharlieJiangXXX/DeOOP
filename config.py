import os
import shutil

try:
    import tomllib as toml_reader
except ModuleNotFoundError:
    import tomli as toml_reader


class Config:
    def __init__(self):
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(self.root_dir, 'config.toml')
        template_path = os.path.join(self.root_dir, 'config_template.toml')
        if not os.path.exists(config_path):
            shutil.copy(template_path, config_path)
        with open(config_path, 'rb') as f:
            config_data = toml_reader.load(f)
        for k, v in config_data.items():
            setattr(self, k, v)


config = Config()
