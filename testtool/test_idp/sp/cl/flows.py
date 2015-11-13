from aatest.func import set_request_args

from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2test.request import AuthnRedirectRequest
from saml2test.request import AuthnPostRequest
from saml2test.check_metadata import CheckSaml2IntMetaData

__author__ = 'roland'

DESC = {
    "IDP-Metadata": "Metadata",
    "IDP-Connection": "Connection",
    "IDP-AuthnRedirect": "AuthnRedirect",
    "IDP-AuthnPost": "AuthnRedirect",
}

ORDDESC = ["IDP-Metadata", "IDP-Connection", "IDP-AuthnRedirect",
           "IDP-AuthnPost"]

FLOWS = {
    'IDP-Metadata-verify': {
        'tc_id': "idp-mv",
        "desc": 'Verifies that the IdP metadata adheres to the saml2int spec',
        "sequence": [CheckSaml2IntMetaData],
        "profile": ".",
    },
    'IDP-Connection-verify': {
        'tc_id': "idp-con-01",
        "desc": 'Uses AuthnRequest to check connectivity',
        "sequence": [AuthnRedirectRequest],
        "profile": ".",
    },
    'IDP-AuthnRedirect-nid_transient': {
        "tc_id": "idp-auth-re-01",
        "name": 'AuthnRequest, NameID-trans',
        "desc": 'Basic SAML2 AuthnRequest, HTTP-Redirect, '
                 'transient name ID',
        "sequence": [
            (AuthnRedirectRequest,
             {set_request_args: {"nameid_format": NAMEID_FORMAT_TRANSIENT}})],
        'profile': '.',
        'tests': {
            'verify_subject': {'name_id.format': NAMEID_FORMAT_TRANSIENT}
        }
    },
    'IDP-AuthnRedirect-nid_email': {
        "tc_id": "idp-auth-re-02",
        "name": 'AuthnRequest, email nameID',
        "desc": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-email '
                 'specified',
        "sequence": [
            (AuthnRedirectRequest,
             {set_request_args: {
                 "nameid_format": NAMEID_FORMAT_EMAILADDRESS}})],
        'profile': '.',
        'tests': {
            'verify_subject': {'name_id.format': NAMEID_FORMAT_EMAILADDRESS}
        }
    },
    'IDP-AuthnRedirect-no_nid': {
        "tc_id": "idp-auth-re-03",
        "name": 'AuthnRequest no specified nameID format',
        "desc": 'Basic SAML2 AuthnRequest, HTTP-Redirect, no NameID format '
                 'specified',
        "sequence": [
            (AuthnRedirectRequest,
             {set_request_args: {"nameid_format": ''}})],
        'profile': '.',
    },
    'IDP-AuthnRedirect-nid_unspecified': {
        "tc_id": "idp-auth-re-04",
        "name": 'AuthnRequest with unspecified nameID format',
        "desc": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-unspec',
        "sequence": [
            (AuthnRedirectRequest,
             {set_request_args: {"nameid_format": NAMEID_FORMAT_UNSPECIFIED}})],
        'profile': '.',
    },
    'IDP-AuthnPost': {
        "tc_id": "idp-auth-post-01",
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "desc": 'AuthnRequest using HTTP-POST',
        "sequence": [AuthnPostRequest],
        'profile': '.',
    },
    
}
