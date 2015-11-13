from aatest.func import set_request_args

from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2test.request import HttpRedirectAuthnRequest
from saml2test.check_metadata import CheckSaml2IntMetaData

__author__ = 'roland'

ORDDESC = ["IDP-Connection"]

DESC = {
    "Metadata": "Metadata",
    "Connection": "Connection",
    "AuthnHttpRedirect": "AuthnHttpRedirect",
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
    'AuthnHttpRedirect-nid_transient': {
        "tc_id": "S2c-10",
        "name": 'AuthnRequest, NameID-trans',
        "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, '
                 'transient name ID',
        "sequence": [
            (HttpRedirectAuthnRequest,
             {set_request_args: {"nameid_format": NAMEID_FORMAT_TRANSIENT}})],
        'profile': '.',
        'tests': {
            'verify_subject': {'name_id.format': NAMEID_FORMAT_TRANSIENT}
        }
    },
    # 'authn-nid_email': {
    #     "tc_id": "S2c-20",
    #     "name": 'AuthnRequest email nameID',
    #     "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-email'
    #              'specified',
    #     "sequence": [AuthnRequestNID_Email],
    #     "tests": {"pre": [CheckSaml2IntMetaData],
    #               "post": []},
    #     "depend":["authn"]
    # },
    # 'authn-nid_no': {
    #     "tc_id": "S2c-21",
    #     "name": 'AuthnRequest no NameID format',
    #     "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, no NameID format '
    #              'specified',
    #     "sequence": [AuthnRequestNID_no],
    #     "tests": {"pre": [CheckSaml2IntMetaData],
    #               "post": []},
    #     "depend":["authn"]
    # },
    # 'authn-nid_unspecified': {
    #     "tc_id": "S2c-21",
    #     "name": 'AuthnRequest using unspecified NameID format',
    #     "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-unspec',
    #     "sequence": [AuthnRequestNID_Unspecified],
    #     "tests": {"pre": [CheckSaml2IntMetaData],
    #               "post": []},
    #     "depend":["authn"]
    # },
}
