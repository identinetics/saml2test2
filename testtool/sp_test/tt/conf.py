METADATA = [{
    'class': 'saml2.mdstore.MetaDataFile',
    'metadata': [('/Users/rolandh/code/pysaml2/example/sp-wsgi/sp.xml',)]
}]
BASE = 'http://localhost:8088'
CONFIG = {
    'basic': {
        'cert_file': '../../pki/mycert.pem',
        'description': 'Basic IDP',
        'entityid': 'http://localhost:8088/basic/idp.xml',
        'key_file': '../../pki/mykey.pem',
        'name_form':
            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'idp': {
                'endpoints': {
                    'artifact_resolution_service': [
                        ('http://localhost:8088/ars',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')],
                    'assertion_id_request_service': [
                        ('http://localhost:8088/airs',
                         'urn:oasis:names:tc:SAML:2.0:bindings:URI')],
                    'authn_query_service': [
                        ('http://localhost:8088/aqs',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')],
                    'manage_name_id_service': [
                        ('http://localhost:8088/mni/soap',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'),
                        ('http://localhost:8088/mni/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8088/mni/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8088/mni/art',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact')],
                    'name_id_mapping_service': [
                        ('http://localhost:8088/nim/soap',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'),
                        ('http://localhost:8088/nim/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8088/nim/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8088/nim/art',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact')],
                    'single_logout_service': [
                        ('http://localhost:8088/slo/soap',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'),
                        ('http://localhost:8088/slo/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')],
                    'single_sign_on_service': [
                        ('http://localhost:8088/sso/redirect',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                        ('http://localhost:8088/sso/post',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                        ('http://localhost:8088/sso/art',
                         'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'),
                        ('http://localhost:8088/sso/paos',
                         'urn:oasis:names:tc:SAML:2.0:bindings:SOAP')]},
                'policy': {
                    'default': {
                        'attribute_restrictions': None,
                        'lifetime': {'minutes': 15},
                        'name_form':
                            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'}}
            }
        },
        'xmlsec_binary': '/opt/local/bin/xmlsec1'}}
