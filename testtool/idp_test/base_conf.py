from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = '/usr/local/bin/xmlsec1'

PORT = 8087
BASE = "http://localhost:{}/".format(PORT)

# CoCo gives access to these attributes:
# "eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail",
# "displayName", "schacHomeOrganization"

CONFIG = {
    'description': 'Basic SP',
    "entityid": "{base}{sp_id}/sp.xml",
    "key_file": "./pki/mykey.pem",
    "cert_file": "./pki/mycert.pem",
    'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
    'service': {
        'sp': {
            'endpoints': {
                "assertion_consumer_service": [
                    ("{base}acs/redirect",BINDING_HTTP_REDIRECT),
                    ("{base}acs/post", BINDING_HTTP_POST),
                    ("{base}acs/artifact", BINDING_HTTP_ARTIFACT),
                    ("{base}ecp", BINDING_PAOS)
                ],
                "single_logout_service": [
                    ("{base}slo", BINDING_SOAP)
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
        "metadata": [('./local_idp.xml',)]}],
