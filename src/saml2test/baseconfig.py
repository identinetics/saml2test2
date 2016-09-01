from saml2test.checkedconfig import CheckedConfig

class BaseConfig(CheckedConfig):
    def config(self):
        self.CONFIG = {}

    def set_base(self,value):
        self._BASE = value
        return

    def get_base(self):
        try:
            return self._BASE
        except AttributeError as e:
            base = self.param_base()
            return base

    def del_base(self):
        del self._BASE

    BASE = property(get_base,set_base,del_base,"Config Base")


