from saml2test.baseconfig import BaseConfig

class Config(BaseConfig):
    def config(self):
        self.ENTITY_ID = "https://idp1.test.wpv.portalverbund.at/idp/shibboleth"
        self.FLOWS = [
            "saml2test/exampleconfig/flows.yaml",
            ]
        self.FLOWS_PROFILES = [
            "saml2int",
        ]
        # Do not validate TLS certificates (Note: signature validation is configured in pysaml2 config)
        self.DO_NOT_VALIDATE_TLS = True
        self.PORT = 8087
        self.METADATA = [
            {'metadata': [('http://mdfeed.test.wpv.portalverbund.at/split/idp1TestWpvPortalverbundAt_idpShibboleth.xml',)], 'class': 'saml2.mdstore.MetaDataExtern'}]
        self.BASE = 'http://localhost:8087/'
        self.CONFIG = {}
        self.CONFIG.update({
            'acs-post': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
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
                },
            'acs-redirect': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'Basic SP',
                'entityid': self.BASE + 'basic/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'CoCo SP',
                'entity_category': [
                    'http://www.geant.net/uri/dataprotection-code-of-conduct/v1'],
                'entityid': self.BASE + 'coco/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
            're_eu': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RE & EU',
                'entity_category': [
                    'http://www.swamid.se/category/research-and-education',
                    'http://www.swamid.se/category/eu-adequate-protection'],
                'entityid': self.BASE + 're_eu/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                                 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
                },
            're_hei': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RE & HEI',
                'entity_category': [
                    'http://www.swamid.se/category/research-and-education',
                    'http://www.swamid.se/category/hei-service'],
                'entityid': self.BASE + 're_hei/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                            'single_logout_service': [(
                                self.BASE + 'slo',
                                'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
                },
            're_nren': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RE & NREN',
                'entity_category': [
                    'http://www.swamid.se/category/research-and-education',
                    'http://www.swamid.se/category/nren-service'],
                'entityid': self.BASE + 're_nren/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                            'single_logout_service': [(
                                self.BASE + 'slo',
                                'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
                },
            're_nren_hei': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RE & NREN & HEI',
                'entity_category': [
                    'http://www.swamid.se/category/sfs-1993-1153',
                    'http://www.swamid.se/category/research-and-education',
                    'http://www.swamid.se/category/hei-service'],
                'entityid': self.BASE + 're_nren_hei/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
                'name_form':
                    'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
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
                },
            're_nren_sfs': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RE & NREN & SFS',
                'entity_category': [
                    'http://www.swamid.se/category/sfs-1993-1153',
                    'http://www.swamid.se/category/research-and-education',
                    'http://www.swamid.se/category/nren-service'],
                'entityid': self.BASE + 're_nren_sfs/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
                'name_form':
                    'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
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
                                                       'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
                },
            'required': {
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'Required Attributes SP',
                'entityid': self.BASE + 'required/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
                'cert_file': 'saml2test/exampleconfig/pki/mycert.pem',
                'description': 'RS SP',
                'entity_category': [
                    'http://refeds.org/category/research-and-scholarship'],
                'entityid': self.BASE + 'rs/sp.xml',
                'key_file': 'saml2test/exampleconfig/pki/mykey.pem',
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
