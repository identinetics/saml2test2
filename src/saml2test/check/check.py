import inspect
import sys
from urllib.parse import parse_qs

from aatest.check import Check
from aatest.check import CRITICAL
from aatest.check import OK
from aatest.check import TestResult
from aatest.check import WARNING
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import EV_PROTOCOL_RESPONSE
from aatest.events import EV_REDIRECT_URL
from aatest.events import EV_RESPONSE

from saml2 import request
from saml2.mdstore import REQ2SRV
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.samlp import AuthnRequest
from saml2.samlp import STATUS_SUCCESS
from saml2.response import AuthnResponse, STATUSCODE2EXCEPTION
from saml2.sigver import verify_redirect_signature


__author__ = 'roland'

#response.status.status_code.value  ''
class VerifySamlStatus(Check):
    """Verify that the expected SAML status code was returned """

    cid = 'verify_saml_status'

    def _func(self, conv=None, output=None):

        res = TestResult(self.cid)

        if "saml_status" in self._kwargs:
            status_value = self._kwargs["saml_status"]
        else:
            res.message = "Configuration Error: Missing saml_status in assert verify_saml_status"
            res.status = CRITICAL
            return res

        if status_value == 'urn:oasis:names:tc:SAML:2.0:status:Success':
            """
            We can't check for success because saml2 testing doesn't tell. So we assume, that if we don't see any
            status errors it should have been a success.
            """
            we_had_errors = False
            for test_exception in STATUSCODE2EXCEPTION:
                try:
                    exception = conv.events.get_message(EV_PROTOCOL_RESPONSE, test_exception)
                except Exception as e:
                    pass
                else:
                    we_had_errors = True

            if we_had_errors:
                res.message = "ERROR: {}: {}".format(exception.__class__.__name__, str(exception))
                res.status = CRITICAL
            else:
                res.message = "No errors reported, assuming {}".format(status_value)
            return res

        else:


            try:
                status_error_exception = STATUSCODE2EXCEPTION[status_value]
            except Exception as e:
                res.message = "Configuration Error: Can not find a definition for {} ".format(status_value)
                res.status = CRITICAL
                return res

            try:
                exception = conv.events.get_message(EV_PROTOCOL_RESPONSE, status_error_exception)
            except Exception as e:
                res.message = "Status error {} was not found ".format(status_value)
                res.status = CRITICAL
                return res

            res.message = "{}: {}".format(exception.__class__.__name__, str(exception))


        return res

        if "saml_status" in self._kwargs:
            status_value = self._kwargs["saml_status"]
            if response.status.status_code.value == status_value:
                res = TestResult(self.cid)
            else:
                res.message = "The test target returned status = %s, but the "
                "test configuration expected %s." % \
                (response.status.status_code.value.status_value)
                res.status = CRITICAL
        else:
                res.message = "Missing  saml_status in assert verify_saml_status"
                res.status = CRITICAL

        return res



class VerifySubject(Check):
    """Verify that the correct named.format and sp_name_qualifier
    was returned """

    cid = 'verify_subject'

    def _func(self, conv=None, output=None):
        response = conv.events.get_message(EV_PROTOCOL_RESPONSE,
                                           AuthnResponse).response
        # Assumes only one assertion
        # TODO deal with more then one assertion if necessary
        subj = response.assertion[0].subject
        request = conv.events.get_message(EV_PROTOCOL_REQUEST, AuthnRequest)

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

        res = TestResult(self.cid)
        if nformat:
            if subj.name_id.format == nformat:
                if sp_name_qualifier:
                    if subj.name_id.sp_name_qualifier != sp_name_qualifier:
                        res.message = "The IdP returns wrong NameID format"
                        res.status = CRITICAL
            else:
                res.message = "The IdP returns wrong NameID format"
                res.status = CRITICAL

        return res


class VerifyAttributes(Check):
    """Verify that the correct attributes where returned"""

    cid = 'verify_attributes'

    def _func(self, conv=None):
        ava = conv.events.get_message(EV_PROTOCOL_RESPONSE, AuthnResponse).ava

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

        res = TestResult(self.cid)
        if missing:
            res.message = "Attributes I expected but not received: {}".format(
                missing)
            res.status = CRITICAL

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
                    return TestResult(self.cid)

        return TestResult(
            self.cid, status=CRITICAL,
            message="No support for NameIDFormat '%s'" % nameid_format)

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
                        return TestResult(self.cid)

        return TestResult(self.cid, status=CRITICAL,
                          message="No support for '%s'" % service)

    def _binding_support(self, conv, request, binding, typ):
        service = REQ2SRV[request]
        md = conv.entity.metadata
        entity_id = conv.entity_id
        func = getattr(md, service, None)
        res = TestResult(self.cid)
        try:
            func(entity_id, binding, typ)
        except UnknownPrincipal:
            res.message = "Unknown principal: %s" % entity_id
            res.status = CRITICAL
        except UnsupportedBinding:
            res.message = "Unsupported binding at the IdP: %s" % binding
            res.status = CRITICAL

        return res

    def _func(self, conv):
        oper = conv.oper
        args = conv.oper.args
        res = self._srv_support(conv, REQ2SRV[oper.request])
        if res.status != OK:
            return res

        res = self._binding_support(conv, oper.request, args["request_binding"],
                                    "idpsso")
        if res.status != OK:
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
            return TestResult(self.cid, status=CRITICAL, message=self.msg)
        else:
            return TestResult(self.cid)


class VerifyLogout(Check):
    cid = "verify_logout"
    msg = "Logout failed"

    def _func(self, conv):
        # Check that the logout response says it was a success
        resp = conv.events.last_item(EV_PROTOCOL_RESPONSE)
        status = resp.response.status
        res = TestResult(self.cid)
        if status.status_code.value != STATUS_SUCCESS:
            res.message = self.msg
            res.status = CRITICAL
        else:
            # Check that there are no valid cookies
            # should only result in a warning

            if conv.entity.cookies(conv.destination):
                res.message = "Remaining cookie ?"
                res.status = WARNING

        return res


class VerifyIfRequestIsSigned(Check):
    """
    Verify that a Request is signed. If HTTP_REDIRECT is used the
    whole message can be signed. Otherwise the XML document must be signed.
    """
    cid = 'request_is_signed'
    msg = 'Request was not signed'

    def _func(self, conv):
        req = conv.events.last_item(EV_RESPONSE)
        res = TestResult(self.cid)
        # First, was the whole message signed
        if 'SigAlg' in req:
            if not verify_redirect_signature(
                    req['SAMLRequest'], conv.entity.sec):
                res.message = "Was not able to verify Redirect message " \
                                "signature"
                res.status = CRITICAL

        # Secondly, was the XML doc signed
        req = conv.events.get_message(EV_PROTOCOL_REQUEST, request.AuthnRequest)
        if req.message.signature is None:
            res.message = 'Missing response signature'
            res.status = CRITICAL

        return res


class Verify_AuthnRequest(Check):
    cid = 'verify_authnrequest'

    def _func(self, conv):
        redirect = conv.events.last_item(EV_REDIRECT_URL)
        res = TestResult(self.cid)
        if '?' not in redirect:
            res.message = "Incorrect redirect url"
            res.status = CRITICAL
            return res

        req = dict(
            [(k, v[0]) for k, v in parse_qs(redirect.split('?')[1]).items()])

        try:
            saml_req = req["SAMLRequest"]
        except KeyError:
            res.message = "No SAMLRequest query parameter"
            res.status = CRITICAL
            return res

        _srv = conv.entity
        if not _srv.parse_authn_request(saml_req):
            res.message = "No or incorrect AuthnRequest"
            res.status = CRITICAL

        return res


class VerifyEndpoint(Check):
    cid = 'has_endpoint'

    def _func(self, conv):
        entity_id = conv.events.last_item('issuer')
        md = conv.entity.metadata
        res = TestResult(self.cid)
        try:
            srv = md.service(entity_id, self._kwargs['typ'],
                             self._kwargs['service'],
                             binding=self._kwargs['binding'])
        except KeyError:
            res.message = "Can't find service"
            res.status = CRITICAL
        else:
            if not srv:
                res.message = "Can't find service"
                res.status = CRITICAL

        return res


class VerifyDigestAlgorithm(Check):
    cid = 'verify_digest_alg'

    def _func(self, conv):
        digest_algorithms = conv.crypto_algorithms['digest_algorithms']
        req = conv.events.get_message(EV_PROTOCOL_REQUEST, request.AuthnRequest)
        res = TestResult(self.cid)
        if req.message.signature is None:
            res.message = 'Missing response signature'
            res.status = CRITICAL

        for ref in req.message.signature.signed_info.reference:
            if ref.digest_method.algorithm not in digest_algorithms:
                res.message = "Not allowed digest algorithm: {}".format(
                    ref.digest_method.algorithm)
                res.status = CRITICAL
                break

        return res


class VerifSignatureAlgorithm(Check):
    cid = 'verify_signature_alg'

    def _func(self, conv):
        signing_algorithms = conv.crypto_algorithms['signing_algorithms']
        req = conv.events.get_message(EV_PROTOCOL_REQUEST, request.AuthnRequest)
        res = TestResult(self.cid)
        if req.message.signature is None:
            res.message = 'Missing response signature'
            res.status = CRITICAL

        sig_alg = req.message.signature.signed_info.signature_method.algorithm
        if sig_alg not in signing_algorithms:
            res.message = "Not allowed digest algorithm: {}".format(sig_alg)
            res.status = CRITICAL

        return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
