from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.entity_category.edugain import COCO
#from saml2.extension.idpdisc import BINDING_DISCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = '/usr/local/bin/xmlsec1'

BASE = "http://localhost:8087"

# CoCo gives access to these attributes:
# "eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail",
# "displayName", "schacHomeOrganization"

CONFIG = {
    "basic": {
        'description': 'Verify Entity Categories SP',
        "entityid": "{}/{}/sp.xml".format(BASE, 'basic'),
        "key_file": "../pki/mykey.pem",
        "cert_file": "../pki/mycert.pem",
        "metadata": [{
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [('./local_idp.xml',)]}],
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    "assertion_consumer_service": [
                        ("{}/acs/redirect".format(BASE),BINDING_HTTP_REDIRECT),
                        ("{}/acs/post".format(BASE), BINDING_HTTP_POST)
                    ],
                }
            },
        },
        'xmlsec_binary': xmlsec_path
    },
    "required": {
        'description': 'Required Attributes SP',
        "entityid": "{}/{}/sp.xml".format(BASE, "required"),
        "key_file": "../pki/mykey.pem",
        "cert_file": "../pki/mycert.pem",
        "metadata": [{
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [('./local_idp.xml',)]}],
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    "assertion_consumer_service": [
                        ("{}/acs/redirect".format(BASE),BINDING_HTTP_REDIRECT),
                        ("{}/acs/post".format(BASE), BINDING_HTTP_POST)
                    ],
                },
                "required_attributes": ["eduPersonPrincipalName",
                                        "eduPersonScopedAffiliation", "mail"],
                "optional_attributes": ['displayName', 'schacHomeOrganization'],
            },
        },
        'xmlsec_binary': xmlsec_path
    },
    "coco": {
        'description': 'CoCo SP',
        "entityid": "{}/{}/sp.xml".format(BASE, "coco"),
        'entity_category': [COCO],
        "key_file": "../pki/mykey.pem",
        "cert_file": "../pki/mycert.pem",
        "metadata": [{
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [('./local_idp.xml',)]}],
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    "assertion_consumer_service": [
                        ("{}/acs/redirect".format(BASE),BINDING_HTTP_REDIRECT),
                        ("{}/acs/post".format(BASE), BINDING_HTTP_POST)
                    ],
                },
                "required_attributes": ["eduPersonPrincipalName",
                                        "eduPersonScopedAffiliation", "mail"],
                "optional_attributes": ['displayName', 'schacHomeOrganization'],
                'name': 'Code of Conduct SP'
            },
        },
        'xmlsec_binary': xmlsec_path
    },
    "research_and_scholarship": {
        'description': 'R&S SP',
        "entityid": "{}/{}/sp.xml".format(BASE, "research_and_scholarship"),
        'entity_category': [RESEARCH_AND_SCHOLARSHIP],
        "key_file": "../pki/mykey.pem",
        "cert_file": "../pki/mycert.pem",
        "metadata": [{
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [('./local_idp.xml',)]}],
        'name_form': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'service': {
            'sp': {
                'endpoints': {
                    "assertion_consumer_service": [
                        ("{}/acs/redirect".format(BASE),BINDING_HTTP_REDIRECT),
                        ("{}/acs/post".format(BASE), BINDING_HTTP_POST)
                    ],
                },
                'name': 'Research and Scholarship SP'
            },
        },
        'xmlsec_binary': xmlsec_path
    }
}

IDP_BASE = "https://localhost:8088"

INTERACTION = [
    {
        "matches": {
            "url": "%s/sso/redirect" % IDP_BASE,
            "title": 'IDP test login'
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "roland", "password": "dianakra"}
        }
    }, {
        "matches": {
            "url": "%s/sso/post" % IDP_BASE,
            "title": 'IDP test login'
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "roland", "password": "dianakra"}
        }
    },
    {
        "matches": {
            "url": "%s/sso/redirect" % IDP_BASE,
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
            "url": "%s/sso/post" % IDP_BASE,
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
            "url": "%s/slo/post" % IDP_BASE,
            "title": "SAML 2.0 POST"
        },
        "page-type": "other",
        "control": {
            "index": 0,
            "type": "form",
            "set": {}
        }
    }
]
