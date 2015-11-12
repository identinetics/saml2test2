from saml2test.request import HttpRedirectAuthnRequest
from saml2test.check_metadata import CheckSaml2IntMetaData

__author__ = 'roland'

ORDDESC = ["IDP-Connection"]

DESC = {
    "Connection": "Connection",
    "IDToken": "ID Token",
    "UserInfo": "Userinfo Endpoint",
    "nonce": "nonce Request Parameter",
    "scope": "scope Request Parameter",
    "display": "display Request Parameter",
    "prompt": "prompt Request Parameter",
    "Req": "Misc Request Parameters",
    "OAuth": "OAuth behaviors",
    "redirect_uri": "redirect_uri",
    "ClientAuth": "Client Authentication",
    "Discovery": "Discovery",
    "Registration": "Dynamic Client Registration",
    "Rotation": "Key Rotation",
    "request_uri": "request_uri Request Parameter",
    "request": "request Request Parameter",
    "claims": "claims Request Parameter",
}

FLOWS = {
    'IDP-Metadata-verify': {
        'tc_id': "mv",
        "desc": 'Verifies that the IdP metadata adheres to the saml2int spec',
        "sequence": [CheckSaml2IntMetaData],
        "profile": ".",
    },
    'IDP-Connection-verify': {
        'tc_id': "S2c-16",
        "desc": 'Uses AuthnRequest to check connectivity',
        "sequence": [HttpRedirectAuthnRequest],
        "profile": ".",
    },
}