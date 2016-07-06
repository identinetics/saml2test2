from importlib.machinery import SourceFileLoader
import inspect
import os


class Loader(object):

    def __init__(self,fullname,class_name,file_list):
        self.config_classes = []
        self.add_classes_from_file_list(class_name, file_list)

    def get_class(self):
        cls = self.select_underived_config_class()
        return cls

    def _load_module_class(self, fullname, class_name, config_file):
        module = SourceFileLoader(fullname, config_file).load_module()
        conf_class = getattr(module, class_name)
        return conf_class

    def add_classes_from_file_list(self, class_name, file_list):
        for config_file in file_list:
            modulename = os.path.splitext(os.path.basename(config_file))[0]
            conf_class = self._load_module_class(modulename, class_name, config_file)

            self.config_classes.append(conf_class)

        return self.config_classes

    def select_underived_config_class(self):
        """
        The magic: We expect our main config class to be the subclass of all others.
        So it will have longest base (list of base classes it is subclassing)
        """
        max_base = 0
        candidate = None
        for config_class in self.config_classes:
            base_classes = inspect.getmro(config_class)
            if len(base_classes) > max_base:
                candidate = config_class
                max_base = len(base_classes)

        return candidate