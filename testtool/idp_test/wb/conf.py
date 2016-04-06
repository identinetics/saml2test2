PORT = 8087
METADATA = [
    {'metadata': [('./local_idp.xml',)], 'class': 'saml2.mdstore.MetaDataFile'}]
BASE = 'http://localhost:8087/'
CONFIG = {
    'basic': {
        'cert_file': './pki/mycert.pem',
        'description': 'Basic SP',
        'entityid': 'http://localhost:8087/basic/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [
                        ('http://localhost:8087/disco',
                         'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                         '-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    'coco': {
        'cert_file': './pki/mycert.pem',
        'description': 'CoCo SP',
        'entity_category': [
            'http://www.geant.net/uri/dataprotection-code-of-conduct/v1'],
        'entityid': 'http://localhost:8087/coco/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [(
                        'http://localhost:8087/disco',
                        'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                        '-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]},
                'name': 'Code of Conduct SP',
                'optional_attributes': ['displayName',
                                        'schacHomeOrganization'],
                'required_attributes': [
                    'eduPersonPrincipalName',
                    'eduPersonScopedAffiliation',
                    'mail']}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    're_eu': {
        'cert_file': './pki/mycert.pem',
        'description': 'RE & EU',
        'entity_category': [
            'http://www.swamid.se/category/research-and-education',
            'http://www.swamid.se/category/eu-adequate-protection'],
        'entityid': 'http://localhost:8087/re_eu/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [(
                        'http://localhost:8087/disco',
                        'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                        '-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    're_hei': {
        'cert_file': './pki/mycert.pem',
        'description': 'RE & HEI',
        'entity_category': [
            'http://www.swamid.se/category/research-and-education',
            'http://www.swamid.se/category/hei-service'],
        'entityid': 'http://localhost:8087/re_hei/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [(
                        'http://localhost:8087/disco',
                        'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                        '-protocol')],
                    'single_logout_service': [(
                        'http://localhost:8087/slo',
                        'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    're_nren': {
        'cert_file': './pki/mycert.pem',
        'description': 'RE & NREN',
        'entity_category': [
            'http://www.swamid.se/category/research-and-education',
            'http://www.swamid.se/category/nren-service'],
        'entityid': 'http://localhost:8087/re_nren/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [(
                        'http://localhost:8087/disco',
                        'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                        '-protocol')],
                    'single_logout_service': [(
                        'http://localhost:8087/slo',
                        'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    're_nren_hei': {
        'cert_file': './pki/mycert.pem',
        'description': 'RE & NREN & HEI',
        'entity_category': [
            'http://www.swamid.se/category/sfs-1993-1153',
            'http://www.swamid.se/category/research-and-education',
            'http://www.swamid.se/category/hei-service'],
        'entityid': 'http://localhost:8087/re_nren_hei/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form':
            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [
                        ('http://localhost:8087/disco',
                         'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                         '-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    're_nren_sfs': {
        'cert_file': './pki/mycert.pem',
        'description': 'RE & NREN & SFS',
        'entity_category': [
            'http://www.swamid.se/category/sfs-1993-1153',
            'http://www.swamid.se/category/research-and-education',
            'http://www.swamid.se/category/nren-service'],
        'entityid': 'http://localhost:8087/re_nren_sfs/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form':
            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [
                        ('http://localhost:8087/disco',
                                            'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                                               'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    'required': {
        'cert_file': './pki/mycert.pem',
        'description': 'Required Attributes SP',
        'entityid': 'http://localhost:8087/required/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [
                        ('http://localhost:8087/disco',
                         'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]},
                'name': 'SP that requires attributes',
                'optional_attributes': ['displayName',
                                        'schacHomeOrganization'],
                'required_attributes': [
                    'eduPersonPrincipalName',
                    'eduPersonScopedAffiliation',
                    'mail']}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'},
    'rs': {
        'cert_file': './pki/mycert.pem',
        'description': 'RS SP',
        'entity_category': [
            'http://refeds.org/category/research-and-scholarship'],
        'entityid': 'http://localhost:8087/rs/sp.xml',
        'key_file': './pki/mykey.pem',
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://localhost:8087/acs/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8087/acs/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8087/acs/artifact',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8087/ecp',
                         'urn:oasis:names:tc:SAML:2.0:bindings:PAOS')],
                    'discovery_response': [
                        ('http://localhost:8087/disco',
                         'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery'
                         '-protocol')],
                    'single_logout_service': [
                        ('http://localhost:8087/slo',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]}}},
        'xmlsec_binary': '/opt/local/bin/xmlsec1'}}
