from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

PORT = 8087
BASE = "http://localhost:{}/".format(PORT)

CONFIG = {
    'description': 'Basic SP',
    "entityid": "{base}{sp_id}/sp.xml",
    "key_file": "./pki/mykey.pem",
    "cert_file": "./pki/mycert.pem",
    'name_form': NAME_FORMAT_URI,
    'validate_certificate': False,
    'service': {
        'sp': {
            'endpoints': {
                "assertion_consumer_service": [
                    ("{base}acs/post", BINDING_HTTP_POST)
                ],
                'discovery_response': [
                    ('{base}disco', BINDING_DISCO)]
            }
        },
    },
    'xmlsec_binary': xmlsec_path
}

METADATA = [{
        "class": "saml2.mdstore.MetaDataFile",
        "metadata": [('/Users/rolandh/code/pysaml2/example/idp2/idp.xml',)]}],
