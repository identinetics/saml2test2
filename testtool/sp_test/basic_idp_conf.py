from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI
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
    xmlsec_path = '/usr/local/bin/xmlsec1'

BASE = "http://localhost:8088"

# CoCo gives access to these attributes:
# "eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail",
# "displayName", "schacHomeOrganization"

CONFIG = {
    'description': 'Basic IdP',
    "entityid": "{base}/{idp_id}/idp.xml",
    "key_file": "../pki/mykey.pem",
    "cert_file": "../pki/mycert.pem",
    'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
    'service': {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                    ("%s/sso/art" % BASE, BINDING_HTTP_ARTIFACT),
                    ("%s/sso/paos" % BASE, BINDING_SOAP)
                ],
                "single_logout_service": [
                    ("%s/slo/soap" % BASE, BINDING_SOAP),
                    ("%s/slo/post" % BASE, BINDING_HTTP_POST)
                ],
                "artifact_resolution_service": [
                    ("%s/ars" % BASE, BINDING_SOAP)
                ],
                "assertion_id_request_service": [
                    ("%s/airs" % BASE, BINDING_URI)
                ],
                "authn_query_service": [
                    ("%s/aqs" % BASE, BINDING_SOAP)
                ],
                "manage_name_id_service": [
                    ("%s/mni/soap" % BASE, BINDING_SOAP),
                    ("%s/mni/post" % BASE, BINDING_HTTP_POST),
                    ("%s/mni/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/mni/art" % BASE, BINDING_HTTP_ARTIFACT)
                ],
                "name_id_mapping_service": [
                    ("%s/nim/soap" % BASE, BINDING_SOAP),
                    ("%s/nim/post" % BASE, BINDING_HTTP_POST),
                    ("%s/nim/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/nim/art" % BASE, BINDING_HTTP_ARTIFACT)
                ]
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                },
            },
        },
    },
    'xmlsec_binary': xmlsec_path
}

METADATA = [{
        "class": "saml2.mdstore.MetaDataFile",
        "metadata": [('/Users/rolandh/code/pysaml2/example/sp-wsgi/sp.xml',)]}]
