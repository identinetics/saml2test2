"""
The config loader is the compatibility abstraction layer to provide the "old style" config to the source, while
creating a new configuration style, and then refactoring the source
"""

import logging
import os
from importlib.machinery import SourceFileLoader

from saml2test.cloader import Loader

# works only with python 3.4 now, rest could be implemented
# see http://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path

CONFIG_FILE_NAME = 'config.py'
CONFIG_CLASS_NAME = 'Config'

logger = logging.getLogger("")

def exit_on_mandatory_config_file(e):
    print("Error accessing mandatory config file {}".format(config_file))
    print("Error {0}: {1}".format(e.errno, e.strerror))
    os._exit(-1)


class ConfigFileNotReadable(EnvironmentError):
    pass

class ConfigLoader(object):

    def __init__(self, path):
        self.config_path = path
        self.test_config_file_read(path + os.path.sep + CONFIG_FILE_NAME)
        self.config_files = [path + os.path.sep + CONFIG_FILE_NAME]
        self._load()

    def _load(self):
        self.config_class_loader = Loader(CONFIG_CLASS_NAME, CONFIG_CLASS_NAME, self.config_files)
        self.config_class = self.config_class_loader.get_class()
        setattr(self.config_class,'CONFIG_SRC_DIR', self.config_path)

    def conf_CONF(self):
        conf = self.config_class()
        return conf


    def test_config_file_read(self, config_file):
        try:
            open(config_file)
        except Exception as e:
            raise ConfigFileNotReadable(e.errno, e.strerror, e.filename)
        # should be done by callee