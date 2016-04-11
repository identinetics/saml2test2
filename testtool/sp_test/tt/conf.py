from saml2 import BINDING_SOAP
from saml2 import BINDING_URI
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_ARTIFACT

METADATA = [{
    'class': 'saml2.mdstore.MetaDataFile',
    'metadata': [('/Users/rolandh/code/pysaml2/example/sp-wsgi/sp.xml',)]
}]
PORT = 8086
BASE = 'http://localhost:{}'.format(PORT)
CONFIG = {
    'basic': {
        'cert_file': '../../pki/mycert.pem',
        'description': 'Basic IDP',
        'entityid': '{}/basic/idp.xml'.format(BASE),
        'key_file': '../../pki/mykey.pem',
        'name_form':
            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'idp': {
                'endpoints': {
                    'artifact_resolution_service': [
                        ('{}/ars'.format(BASE), BINDING_SOAP)],
                    'assertion_id_request_service': [
                        ('{}/airs'.format(BASE), BINDING_URI)],
                    'authn_query_service': [
                        ('{}/aqs'.format(BASE), BINDING_SOAP)],
                    'manage_name_id_service': [
                        ('{}/mni/soap'.format(BASE), BINDING_SOAP),
                        ('{}/mni/post'.format(BASE), BINDING_HTTP_POST),
                        ('{}/mni/redirect'.format(BASE), BINDING_HTTP_REDIRECT),
                        ('{}/mni/art'.format(BASE), BINDING_HTTP_ARTIFACT)],
                    'name_id_mapping_service': [
                        ('{}/nim/soap'.format(BASE), BINDING_SOAP),
                        ('{}/nim/post'.format(BASE), BINDING_HTTP_POST),
                        ('{}/nim/redirect'.format(BASE), BINDING_HTTP_REDIRECT),
                        ('{}/nim/art'.format(BASE), BINDING_HTTP_ARTIFACT)],
                    'single_logout_service': [
                        ('{}/slo/soap'.format(BASE), BINDING_SOAP),
                        ('{}/slo/post'.format(BASE), BINDING_HTTP_POST)],
                    'single_sign_on_service': [
                        ('{}/sso/redirect'.format(BASE), BINDING_HTTP_REDIRECT),
                        ('{}/sso/post'.format(BASE), BINDING_HTTP_POST),
                        ('{}/sso/art'.format(BASE), BINDING_HTTP_ARTIFACT),
                        ('{}/sso/paos'.format(BASE), BINDING_SOAP)]},
                'policy': {
                    'default': {
                        'attribute_restrictions': None,
                        'lifetime': {'minutes': 15},
                        'name_form':
                            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'}}
            }
        },
        'xmlsec_binary': '/opt/local/bin/xmlsec1'}}
