from saml2test.baseconfig import BaseConfig

class JsonConfig(BaseConfig):
    def __init__(self,json_data,configdir):
        self.json_data = json_data
        self.CONFIG_SRC_DIR = configdir
        super(JsonConfig, self).__init__()

    def config(self):
        super(JsonConfig,self).config()

        for key in self.json_data.keys():
            val = self.json_data[key]
            setattr(self,key,val)
        pass