"""
This file serves as an example on how to derive a configuration from the default setup
"""

# Import a Config class to derive from, rename it on import, because ...
from saml2test.exampleconfig.config import Config as ExampleConfig

# ... this class name has to be Config.
class Config(ExampleConfig):

    """
    Parameters are set in the config() method. Make sure you call the Superclass config() first to have the
    defaults initialized.
    """
    def config(self):
        super(Config, self).config()

        self.ENTITY_ID = "https://idp1.test.wpv.portalverbund.at/idp/shibboleth"
        self.PORT = 8087
        self.BASE = 'http://localhost:8087/'

        self.CONFIG.update(
            {
                'acs-post': {
                    'cert_file': 'pki/mycert.pem',
                    'description': 'Basic SP',
                    'entityid': self.BASE + 'basic/sp.xml',
                    'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
                    'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                    'service': {
                        'sp': {
                            'endpoints': {
                                'assertion_consumer_service': [
                                    (self.BASE + 'acs/post', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')],
                                'discovery_response': [
                                    (self.BASE + 'disco',
                                     'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                     '-protocol')],
                                'single_logout_service': [
                                    (self.BASE + 'slo',
                                     'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
                }
            }
        )
