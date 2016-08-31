"""
This file serves as an example on how to derive a configuration from the default setup
"""

# Import a Config class to derive from, rename it on import, because ...
from saml2test.exampleconfig.config import Config as ExampleConfig

# ... this class name has to be Config.
class Config(ExampleConfig):

    """
    The self.BASE parameter is special, because it is already used in the Superclass config(). To override it, you
    define a method param_base returning the value for self.BASE
    """
    # TODO: move to abstract or higher
    def param_base(self):
        return 'http://localhost:8087/'

    """
    Parameters are set in the config() method. Make sure you call the Superclass config() first to have the
    defaults initialized.
    """

    def config(self):
        self.FLOWS = [
            "flows.yaml",
        ]
        self.FLOWS_PROFILES = [
            "saml2int",
        ]

        # === Test Driver Config ===
        self.DO_NOT_VALIDATE_TLS = True     # Do not validate TLS certificates
        self.PORT = 8087
        self.METADATA = [
            {'metadata': [
                # need to use internal container address for mdfeed.samltest.fed-lab.org due
                # to a limitation in docker routing:
                ('http://samltest.fed-lab.org/split/testidp01SamltestFed-labOrg_idpShibboleth.xml',)],
             'class': 'saml2.mdstore.MetaDataExtern'}]

        # Each key in CONFIG represents an entity to be configured with pysaml2:
        # https://github.com/rohe/pysaml2/blob/master/doc/howto/config.rst
        self.CONFIG = {}
        self.CONFIG.update({
            'acs-post': {
                'cert_file': 'pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'pki/mykey.pem',
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
            },

            'acs-redirect': {
                'cert_file': 'pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'acs/redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')],
                            'discovery_response': [
                                (self.BASE + 'disco',
                                 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                 '-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
            },

            'acs-artifact': {
                'cert_file': 'pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'acs/artifact', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact')],
                            'discovery_response': [
                                (self.BASE + 'disco',
                                 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                 '-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
            },

            'acs-ecp': {
                'cert_file': 'pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'ecp', 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                            'discovery_response': [
                                (self.BASE + 'disco',
                                 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                 '-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
            },

            'coco': {
                'cert_file': 'pki/mycert.pem',
                'description': 'CoCo SP',
                'entity_category': [
                    'http://www.geant.net/uri/dataprotection-code-of-conduct/v1'],
                'entityid': self.BASE + 'coco/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'acs/redirect',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                                (self.BASE + 'acs/post',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                                (self.BASE + 'acs/artifact',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                                (self.BASE + 'ecp',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                            'discovery_response': [(
                                self.BASE + 'disco',
                                'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                '-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]},
                        'name': 'Code of Conduct SP',
                        'optional_attributes': ['displayName',
                                                'schacHomeOrganization'],
                        'required_attributes': [
                            'eduPersonPrincipalName',
                            'eduPersonScopedAffiliation',
                            'mail']}},
            },

            'required': {
                'cert_file': 'pki/mycert.pem',
                'description': 'Required Attributes SP',
                'entityid': self.BASE + 'required/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'acs/redirect',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                                (self.BASE + 'acs/post',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                                (self.BASE + 'acs/artifact',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                                (self.BASE + 'ecp',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                            'discovery_response': [
                                (self.BASE + 'disco',
                                 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]},
                        'name': 'SP that requires attributes',
                        'optional_attributes': ['displayName',
                                                'schacHomeOrganization'],
                        'required_attributes': [
                            'eduPersonPrincipalName',
                            'eduPersonScopedAffiliation',
                            'mail']}},
            },

            'rs': {
                'cert_file': 'pki/mycert.pem',
                'description': 'RS SP',
                'entity_category': [
                    'http://refeds.org/category/research-and-scholarship'],
                'entityid': self.BASE + 'rs/sp.xml',
                'key_file': 'pki/mykey.pem',
                'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (self.BASE + 'acs/redirect',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                                (self.BASE + 'acs/post',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                                (self.BASE + 'acs/artifact',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                                (self.BASE + 'ecp',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                            'discovery_response': [
                                (self.BASE + 'disco',
                                 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                                 '-protocol')],
                            'single_logout_service': [
                                (self.BASE + 'slo',
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
            }}
        )

        # === Test Target configuration
        self.ENTITY_ID = "https://testidp01.samltest.fed-lab.org/idp/shibboleth"
        self.IDP_BASE = "https://testidp01.samltest.fed-lab.org"
        self.CONTENT_HANDLER_TRIGGER = {
            # To trigger the robobrowser content handler add combinations of test-id and url(s):
            'IDP-AuthnRedirect-nid_unspecified': ["%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE],
        }
        self.CONTENT_HANDLER_INTERACTION = [
            {  # This interaction fills out the login form
                "matches": {
                    # 'Trigger this interaction on the URL and title
                    "url": "%s/idp/profile/SAML2/Redirect/SSOzi" % self.IDP_BASE,
                    "title": 'Web Login Service'
                },
                # TODO: Documentation about parameter page-type
                "page-type": "login",
                "control": {
                    "type": "form",
                    # Parameters to be set on submitting the form
                    "set": {"j_username": "tester@testinetics.at", "j_password": "test", "_eventId_proceed": ''}
                }
            },
            {  # After the login, the IDP shows a result page, which needs a button clicked for getting the redirect
                # back to the SP: This interaction is just pressing the button.
                "matches": {
                    "url": "%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE,
                    "content": "you must press the Continue button"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    # Empty set: No parameters, just press the submit button
                    "set": {}
                }

            },
            {  # After the login, the IDP also shows a result page, for some options
                "matches": {
                    "url": "%s/idp/profile/SAML2/Redirect/SSO" % self.IDP_BASE,
                    "content": "You are about to access the service"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    # Empty set: No parameters, just press the submit button
                    "set": {},
                    # multiple submits on that page ... choose which one to send
                    "submit": "_eventId_proceed"
                }

            },
            #--
            # Interactions below are older examples, not used for the idp1.test.wpv.portalverbund.at
            {
                "matches": {
                    "url": "%s/sso/post" % self.IDP_BASE,
                    "title": 'IDP test login'
                },
                "page-type": "login",
                "control": {
                    "type": "form",
                    "set": {"login": "admin", "password": "admin"}
                }
            },
            {
                "matches": {
                    "url": "%s/sso/redirect" % self.IDP_BASE,
                    "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                }
            },
            {
                "matches": {
                    "url": "%s/sso/post" % self.IDP_BASE,
                    "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "index": 0,
                    "type": "form",
                    "set": {}
                }
            },
            {
                "matches": {
                    "url": "%s/slo/soap" % self.IDP_BASE,
                    # "title": "SAML 2.0 POST"
                },
                "page-type": "other",
                "control": {
                    "type": "response",
                    "pick": {"form": {"action": "%s/sls" % self.IDP_BASE}}
                }
            },
        ]
