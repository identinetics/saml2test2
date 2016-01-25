import inspect
import logging
import sys

from aatest import Unknown

# from saml2 import samlp
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.ident import code

import saml2.xmldsig as ds

from saml2.mdstore import destinations
from saml2.time_util import in_a_while
from saml2test.check.check import VerifyFunctionality
from saml2test.request import map_arguments
from saml2test.request import PostRequest
from saml2test.request import SoapRequest
from saml2test.request import UnknownBinding
from saml2test.message import ProtocolMessage
from saml2test.request import RedirectRequest

__author__ = 'roland'

logger = logging.getLogger(__name__)


class AuthnRequest(ProtocolMessage):
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

        logger.info("destination to provider: %s", destination)

        self.req_args = map_arguments(self.req_args,
                                      {'name_id.format': 'nameid_format'})

        request_id, request = self.entity.create_authn_request(
            destination=destination, **self.req_args)

        self.conv.events.store('request_args', self.req_args)
        self.conv.events.store('protocol_request', request)

        _req_str = str(request)

        logger.info("AuthNReq: %s", _req_str)

        args = {}
        for param in ['sigalg', 'relay_state']:
            try:
                args[param] = self.req_args[param]
            except KeyError:
                pass

        if self.binding == BINDING_HTTP_POST:
            if 'relay_state' not in args:
                args['relay_state'] = ''
            args['typ'] = 'SAMLRequest'
            http_info = self.entity.use_http_post(_req_str, destination, **args)
            http_info["url"] = destination
            http_info["method"] = "POST"
        else:
            http_info = self.entity.apply_binding(self.binding, _req_str,
                                                  destination, **args)

        self.conv.events.store('http_info', http_info)
        return http_info, request_id

    def handle_response(self, result, response_args, **kwargs):
        _cli = self.conv.entity
        try:
            _outstanding = response_args['outstanding']
        except KeyError:
            _outstanding = self.conv.events.last_item('outstanding')
        resp = _cli.parse_authn_request_response(
            result['SAMLResponse'], self.req_args['response_binding'],
            _outstanding)
        self.conv.events.store('protocol_response', resp)


class LogOutRequest(ProtocolMessage):
    def construct_message(self):
        _cli = self.conv.entity
        _entity_id = self.req_args['entity_id']
        _name_id = self.req_args['name_id']

        sls_args = {
            'entity_id': _entity_id, 'binding': self.binding, 'typ': 'idpsso'}

        try:
            srvs = _cli.metadata.single_logout_service(**sls_args)
        except:
            msg = "No SLO '{}' service".format(self.binding)
            raise UnknownBinding(msg)

        destination = destinations(srvs)[0]
        logger.info("destination to provider: %s", destination)
        self.conv.destination = destination

        try:
            session_info = _cli.users.get_info_from(_name_id, _entity_id, False)
            session_indexes = [session_info['session_index']]
        except KeyError:
            session_indexes = None

        try:
            expire = self.req_args['expire']
        except KeyError:
            expire = in_a_while(minutes=5)

        req_id, request = _cli.create_logout_request(
            destination, _entity_id, name_id=_name_id,
            reason=self.req_args['reason'],
            expire=expire, session_indexes=session_indexes)

        self.conv.events.store('request_args', self.req_args)
        self.conv.events.store('protocol_request', request)

        # to_sign = []
        if self.binding.startswith("http://"):
            sign = True
        else:
            try:
                sign = self.req_args['sign']
            except KeyError:
                sign = _cli.logout_requests_signed

        sigalg = None
        key = None
        if sign:
            if self.binding == BINDING_HTTP_REDIRECT:
                try:
                    sigalg = self.req_args["sigalg"]
                except KeyError:
                    sigalg = ds.sig_default
                try:
                    key = self.req_args["key"]
                except KeyError:
                    key = _cli.signkey

                srequest = str(request)
            else:
                srequest = _cli.sign(request)
        else:
            srequest = str(request)

        relay_state = _cli._relay_state(req_id)

        http_info = _cli.apply_binding(self.binding, srequest, destination,
                                       relay_state, sigalg=sigalg,
                                       key=key)

        if self.binding != BINDING_SOAP:
            _cli.state[req_id] = {
                "entity_id": _entity_id, "operation": "SLO",
                "name_id": code(_name_id), "reason": self.req_args['reason'],
                "not_on_of_after": expire, "sign": sign}

        self.conv.events.store('http_info', http_info)

        return http_info, req_id

    def handle_response(self, result, response_args, *args):
        resp = self.conv.entity.parse_logout_request_response(result['text'],
                                                              self.binding)
        self.conv.events.store('protocol_response', resp)


class AuthnRedirectRequest(RedirectRequest):
    request = "authn_request"
    req_cls = AuthnRequest
    tests = {}

    def _make_request(self):
        self.request_inst = self.req_cls(self.conv, self.req_args,
                                         binding=self._binding,
                                         msg_param=self.msg_param)
        http_info, request_id = self.request_inst.construct_message()
        self.conv.events.store('outstanding', {request_id: "/"})
        return http_info

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
                                         binding=BINDING_SOAP)
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
