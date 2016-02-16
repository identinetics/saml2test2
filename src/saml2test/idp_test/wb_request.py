import sys
import inspect
import logging

from urllib.parse import urlencode

from aatest import Unknown
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import EV_REQUEST_ARGS
from aatest.events import EV_HTTP_ARGS
from aatest.events import EV_RESPONSE
from aatest.events import EV_REDIRECT_URL
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

from saml2.httputil import Redirect
from saml2.httputil import Response
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.s_utils import sid

from saml2test.idp_test.cl_request import LogOutRequest

from saml2test.message import ProtocolMessage
from saml2test.request import RedirectRequest
from saml2test.request import PostRequest
from saml2test.request import SoapRequest
from saml2test.request import map_arguments
from saml2test.request import ServiceProviderRequestHandlerError

from saml2test.check.check import VerifyFunctionality

__author__ = 'roland'

logger = logging.getLogger(__name__)


class AuthnRequest(ProtocolMessage):
    def response(self, binding, http_args):
        resp = None
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        elif http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])
        else:
            for header in http_args["headers"]:
                if header[0] == "Location":
                    resp = Redirect(header[1])

        if not resp:
            resp = ServiceError("Don't know how to return a response")

        return resp

    def construct_message(self):
        """
        A slightly modified version of the
        prepare_for_negotiated_authenticate() method of saml2.client.Saml2Client
        :return: Information necessary to do a requests.request operation
        """

        args = {'binding': self.binding}
        try:
            args['entityid'] = self.req_args['entityid']
        except KeyError:
            pass

        destination = self.entity._sso_location(**args)

        if not destination:
            logger.error(
                "'{}' does not support HTTP-Redirect binding for SSO "
                "location.".format(args['entityid']))
            raise ServiceProviderRequestHandlerError(
                "IdP must support HTTP-Redirect binding for SSO location.")

        logger.info("destination to provider: %s", destination)

        self.req_args = map_arguments(self.req_args,
                                      {'name_id.format': 'nameid_format'})

        request_id, request = self.entity.create_authn_request(
            destination=destination, **self.req_args)

        self.conv.events.store(EV_PROTOCOL_REQUEST, request)
        self.conv.events.store(EV_REQUEST_ARGS, self.req_args)

        _req_str = str(request)

        self.conv.trace.request(_req_str)
        logger.info("AuthNReq: %s", _req_str)

        args = {}
        for param in ['sigalg', 'relay_state']:
            try:
                args[param] = self.req_args[param]
            except KeyError:
                pass

        http_info = self.entity.apply_binding(self.binding, _req_str,
                                              destination, **args)

        self.conv.events.store(EV_HTTP_ARGS, http_info)
        self.conv.trace.info("http_info: {}".format(http_info))

        if self.binding in [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]:
            return self.response(self.binding, http_info), request_id
        else:
            return http_info, request_id

    def handle_response(self, result, response_args, *args):
        logger.debug("response_args: {}".format(response_args))
        _cli = self.conv.entity
        try:
            resp = _cli.parse_authn_request_response(
                result['SAMLResponse'], self.req_args['response_binding'],
                response_args["outstanding"])
        except Exception as e:
            message = "{}: {}".format(type(e).__name__, str(e))
            logger.error(message)
            self.conv.trace.error(message)
            raise ServiceProviderRequestHandlerError(message)

        if not resp:
            message = "Could not parse authn response from IdP: {}".format(
                resp)
            logger.error(message)
            self.conv.trace.error(message)
            raise ServiceProviderRequestHandlerError(message)

        # Message has been answered
        # try:
        #     del self.response_args["outstanding"][resp.in_response_to]
        # except KeyError:
        #     if not _cli.allow_unsolicited:
        #         raise ServiceProviderRequestHandlerError(
        #             "Got unsolicited response with id: '{}'".format(
        #                 resp.in_response_to))

        self.conv.trace.reply(resp)
        self.conv.events.store(EV_RESPONSE, resp)


class Discovery(ProtocolMessage):
    def construct_message(self):
        session_id = sid()
        sp = self.entity
        url = sp.config.getattr("endpoints", "sp")["discovery_response"][0][0]
        return_to = "{url}?{query}".format(
            url=url, query=urlencode(({"sid": session_id})))
        redirect_url = sp.create_discovery_service_request(
            self.req_args['discovery_service_url'],
            sp.config.entityid,
            **{"return": return_to})
        logger.debug("Redirect to Discovery Service: %s", redirect_url)
        self.conv.events.store(EV_REDIRECT_URL, redirect_url, sub='discovery')
        return SeeOther(redirect_url)

    def handle_response(self, result, response_args, *args):
        idp_entity_id = result["entityID"]
        session_id = result["sid"]
        self.conv.events.store(EV_RESPONSE, response_args, sub='discovery')
        request_origin = response_args["outstanding"][session_id]

        del response_args["outstanding"][session_id]
        return idp_entity_id, request_origin


class AuthnRedirectRequest(RedirectRequest):
    request = "authn_request"
    req_cls = AuthnRequest
    tests = {}

    def _make_request(self):
        self.request_inst = self.req_cls(self.conv, self.req_args,
                                         binding=self._binding)
        response, request_id = self.request_inst.construct_message()
        self.conv.events.store('outstanding', {request_id: "/"})
        return response

    def handle_response(self, result, *args):
        self.request_inst.handle_response(result, self.response_args)


class AuthnPostRequest(PostRequest):
    request = "authn_request"
    req_cls = AuthnRequest
    tests = {}

    def _make_request(self):
        self.request_inst = self.req_cls(self.conv, self.req_args,
                                         binding=self._binding)
        http_info, request_id = self.request_inst.construct_message()
        self.conv.events.store('outstanding', {request_id: "/"})
        return http_info

    def handle_response(self, result, *args):
        self.request_inst.handle_response(result, self.response_args)


class AttributeQuery(SoapRequest):
    request = "authn_request"
    req_cls = AuthnRequest
    tests = {}

    def _make_request(self):
        self.request_inst = self.req_cls(self.conv, self.req_args,
                                         binding=self._binding)
        http_info, request_id = self.request_inst.construct_message()
        self.conv.events.store('outstanding', {request_id: "/"})
        return http_info

    def handle_response(self, result, *args):
        self.request_inst.handle_response(result, self.response_args)


class LogOutRequestSoap(SoapRequest):
    req_cls = LogOutRequest
    tests = {"pre": [VerifyFunctionality], "post": []}

    def _make_request(self):
        self.request_inst = self.req_cls(self.conv, self.req_args,
                                         binding=self._binding)
        http_info, request_id = self.request_inst.construct_message()
        return http_info

    def handle_response(self, result, *args):
        self.request_inst.handle_response(result, self.response_args)


# -----------------------------------------------------------------------------


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    raise Unknown("Couldn't find the operation: '{}'".format(name))
