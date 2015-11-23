import sys
import inspect
import logging
from urllib.parse import urlencode

from aatest import Unknown
from saml2 import BINDING_HTTP_ARTIFACT

from saml2.httputil import Response, SeeOther
from saml2.httputil import Redirect
from saml2.httputil import ServiceError
from saml2.s_utils import sid

from saml2test.request import ProtocolMessage
from saml2test.request import map_arguments
from saml2test.request import ServiceProviderRequestHandlerError

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

    def make_request(self):
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

        destination = self.client._sso_location(**args)

        if not destination:
            logger.error(
                "'{}' does not support HTTP-Redirect binding for SSO "
                "location.".format(args['entityid']))
            raise ServiceProviderRequestHandlerError(
                "IdP must support HTTP-Redirect binding for SSO location.")

        logger.info("destination to provider: %s", destination)

        self.req_args = map_arguments(self.req_args,
                                      {'name_id.format': 'nameid_format'})

        request_id, request = self.client.create_authn_request(
            destination=destination, **self.req_args)

        self.conv.protocol_request.append(request)

        _req_str = str(request)

        logger.info("AuthNReq: %s", _req_str)

        args = {}
        for param in ['sigalg', 'relay_state']:
            try:
                args[param] = self.req_args[param]
            except KeyError:
                pass

        return self.response(
            self.binding,
            self.client.apply_binding(self.binding, _req_str, destination,
                                      **args))

    def handle_response(self, result, response_args):
        _cli = self.conv.client
        try:
            resp = _cli.parse_authn_request_response(
                result['SAMLResponse'], self.req_args['response_binding'],
                response_args["outstanding"])
        except Exception as e:
            message = "{}: {}".format(type(e).__name__, str(e))
            logger.error("%s: %s", type(e).__name__, str(e))
            raise ServiceProviderRequestHandlerError(message)

        if not resp:
            message = "Could not parse authn response from IdP: {}".format(
                resp)
            logger.error(message)
            raise ServiceProviderRequestHandlerError(message)

        # Message has been answered
        try:
            del self.response_args["outstanding"][resp.in_response_to]
        except KeyError:
            if not _cli.allow_unsolicited:
                raise ServiceProviderRequestHandlerError(
                    "Got unsolicited response with id: '{}'".format(
                        resp.in_response_to))

        self.conv.protocol_response.append(resp)


class Discovery(ProtocolMessage):
    def make_request(self):
        session_id = sid()
        sp = self.client
        url = sp.config.getattr("endpoints", "sp")["discovery_response"][0][0]
        return_to = "{url}?{query}".format(
            url=url, query=urlencode(({"sid": session_id})))
        redirect_url = sp.create_discovery_service_request(
            self.req_args['discovery_service_url'],
            sp.config.entityid,
            **{"return": return_to})
        logger.debug("Redirect to Discovery Service: %s", redirect_url)
        return SeeOther(redirect_url)

    def handle_response(self, result, response_args):
        idp_entity_id = result["entityID"]
        session_id = result["sid"]
        request_origin = response_args["outstanding"][session_id]

        del response_args["outstanding"][session_id]
        return idp_entity_id, request_origin


# -----------------------------------------------------------------------------


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    raise Unknown("Couldn't find the operation: '{}'".format(name))
