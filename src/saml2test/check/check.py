import inspect
import sys
from urllib.parse import parse_qs

from aatest.check import Check
from aatest.check import CRITICAL
from aatest.check import OK
from aatest.check import WARNING

from saml2.mdstore import REQ2SRV
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.samlp import AuthnRequest
from saml2.samlp import STATUS_SUCCESS
from saml2.response import AuthnResponse
from saml2.sigver import verify_redirect_signature

__author__ = 'roland'


class VerifySubject(Check):
    """Verify that the correct named.format and sp_name_qualifier
    was returned """

    cid = 'verify_subject'

    def __call__(self, conv=None, output=None):
        response = conv.events.get_message('protocol_response',
                                           AuthnResponse).response
        # Assumes only one assertion
        # TODO deal with more then one assertion if necessary
        subj = response.assertion[0].subject
        request = conv.events.get_message('protocol_request', AuthnRequest)

        res = {}
        # Nameid format
        nformat = sp_name_qualifier = ''
        if "name_id.format" in self._kwargs:
            nformat = self._kwargs["name_id.format"]
        else:
            if request.name_id_policy:
                nformat = request.name_id_policy.format
                sp_name_qualifier = request.name_id_policy.sp_name_qualifier

        if request.name_id_policy:
            sp_name_qualifier = request.name_id_policy.sp_name_qualifier

        if nformat:
            try:
                assert subj.name_id.format == nformat
                if sp_name_qualifier:
                    assert subj.name_id.sp_name_qualifier == sp_name_qualifier
            except AssertionError:
                res['message'] = "The IdP returns wrong NameID format"
                res['status'] = CRITICAL

        return res


class VerifyAttributes(Check):
    """Verify that the correct attributes where returned"""

    cid = 'verify_attributes'

    def __call__(self, conv=None, output=None):
        ava = conv.events.get_message('protocol_response', AuthnResponse).ava

        conf = conv.entity.config
        entcat = conv.extra_args["entcat"]

        req_attr = conf.getattr('required_attributes', 'sp')

        ec_attr = []
        for ec in conf.entity_category:
            ec_attr.extend(entcat[ec])

        # I would expect IdPs to release attributes that I'm allowed
        # to receive according to the ent cat classification and
        # I require them
        missing = []
        if req_attr:
            for attr in req_attr:
                if attr in ec_attr and attr not in ava:
                    missing.append(attr)

        if missing:
            res = {
                "message":
                    "Attributes I expected but not received: {}".format(
                        missing),
                'status': CRITICAL
            }
        else:
            res = {}

        return res


class VerifyFunctionality(Check):
    """
    Verifies that the IdP supports the needed functionality
    """

    def _nameid_format_support(self, conv, nameid_format):
        md = conv.entity.metadata
        entity = md[conv.entity_id]
        for idp in entity["idpsso_descriptor"]:
            for nformat in idp["name_id_format"]:
                if nameid_format == nformat["text"]:
                    return {}

        self._message = "No support for NameIDFormat '%s'" % nameid_format
        self._status = CRITICAL

        return {}

    def _srv_support(self, conv, service):
        md = conv.entity.metadata
        entity = md[conv.entity_id]
        for desc in ["idpsso_descriptor", "attribute_authority_descriptor",
                     "auth_authority_descriptor"]:
            try:
                srvgrps = entity[desc]
            except KeyError:
                pass
            else:
                for srvgrp in srvgrps:
                    if service in srvgrp:
                        return {}

        self._message = "No support for '%s'" % service
        self._status = CRITICAL
        return {}

    def _binding_support(self, conv, request, binding, typ):
        service = REQ2SRV[request]
        md = conv.entity.metadata
        entity_id = conv.entity_id
        func = getattr(md, service, None)
        try:
            func(entity_id, binding, typ)
        except UnknownPrincipal:
            self._message = "Unknown principal: %s" % entity_id
            self._status = CRITICAL
        except UnsupportedBinding:
            self._message = "Unsupported binding at the IdP: %s" % binding
            self._status = CRITICAL

        return {}

    def _func(self, conv):
        oper = conv.oper
        args = conv.oper.args
        res = self._srv_support(conv, REQ2SRV[oper.request])
        if self._status != OK:
            return res

        res = self._binding_support(conv, oper.request, args["request_binding"],
                                    "idpsso")
        if self._status != OK:
            return res

        if "name_id.format" in args and args["name_id.format"]:
            if args["name_id.format"] == NAMEID_FORMAT_UNSPECIFIED:
                pass
            else:
                res = self._nameid_format_support(conv, args["name_id.format"])

        if "name_id_policy" in args and args["name_id_policy"]:
            if args["name_id_policy"].format == NAMEID_FORMAT_UNSPECIFIED:
                pass
            else:
                res = self._nameid_format_support(conv,
                                                  args["name_id_policy"].format)

        return res


class CheckLogoutSupport(Check):
    """
    Verifies that the tested entity supports single log out
    """
    cid = "check-logout-support"
    msg = "Does not support logout"

    def _func(self, conv):
        mds = conv.entity.metadata.metadata[0]
        # Should only be one
        ed = mds.entity.values()[0]

        assert len(ed["idpsso_descriptor"])

        idpsso = ed["idpsso_descriptor"][0]
        try:
            assert idpsso["single_logout_service"]
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        return {}


class VerifyLogout(Check):
    cid = "verify_logout"
    msg = "Logout failed"

    def _func(self, conv):
        # Check that the logout response says it was a success
        resp = conv.events.last_item('protocol_response')
        status = resp.response.status
        try:
            assert status.status_code.value == STATUS_SUCCESS
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        # Check that there are no valid cookies
        # should only result in a warning
        httpc = conv.entity
        try:
            assert httpc.cookies(conv.destination) == {}
        except AssertionError:
            self._message = "Remaining cookie ?"
            self._status = WARNING

        return {}


class VerifyIfRequestIsSigned(Check):
    """
    Verify that a Request is signed. If HTTP_REDIRECT is used the
    whole message can be signed. Otherwise the XML document must be signed.
    """
    cid = 'request_is_signed'
    msg = 'Request was not signed'

    def _func(self, conv):
        req = conv.events.last_item('request')
        # First, was the whole message signed
        if 'SigAlg' in req:
            if not verify_redirect_signature(req['SAMLRequest'],
                                             conv.entity.sec):
                conv.trace.error(
                    "Was not able to verify Redirect message signature")

        # Secondly, was the XML doc signed
        # This check is done as part of the normal message parsing

        pass


class Verify_AuthnRequest(Check):
    cid = 'verify_authnrequest'

    def _func(self, conv):
        redirect = conv.events.last_item('redirect')
        if not '?' in redirect:
            self._message = "Incorrect redirect url"
            self._status = CRITICAL
            return {}

        req = dict(
            [(k, v[0]) for k, v in parse_qs(redirect.split('?')[1]).items()])

        try:
            saml_req = req["SAMLRequest"]
        except KeyError:
            self._message = "No SAMLRequest query parameter"
            self._status = CRITICAL
            return {}

        _srv = conv.entity
        if not _srv.parse_authn_request(saml_req):
            self._message = "No or incorrect AuthnRequest"
            self._status = CRITICAL

        return {}


class VerifyEndpoint(Check):
    cid = 'has_endpoint'

    def _func(self, conv):
        entity_id = conv.events.last_item('issuer')
        md = conv.entity.metadata
        try:
            srv = md.service(entity_id, self._kwargs['typ'],
                             self._kwargs['service'],
                             binding=self._kwargs['binding'])
        except KeyError:
            self._message = "Can't find service"
            self._status = CRITICAL
        else:
            if not srv:
                self._message = "Can't find service"
                self._status = CRITICAL

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
