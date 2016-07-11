from saml2test.exampleconfig.config import Config as ExampleConfig

class Config(ExampleConfig):
    def config(self):
        super(Config, self).config()

        self.ENTITY_ID = "https://idp1.test.wpv.portalverbund.at/idp/shibboleth"
        self.PORT = 8087
        self.BASE = 'http://localhost:8087/'


