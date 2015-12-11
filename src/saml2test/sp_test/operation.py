import sys
import inspect
import logging
from requests import Response
from urllib.parse import parse_qs

from aatest.operation import Operation
from saml2 import BINDING_HTTP_POST

from saml2.profile import ecp
from saml2.samlp import AuthnRequest
from saml2.time_util import utc_time_sans_frac
from saml2test.message import ProtocolMessage
from saml2test.sp_test.response import RedirectResponse

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Login(Operation):
    start_page = ''

    def run(self, **kwargs):
        self.conv.events.store(
            'time_stamp', (self.start_page, utc_time_sans_frac()))
        res = self.conv.entity.send(self.start_page)
        loc = res.headers['location']
        self.conv.events.store('redirect', loc)
        self.conv.trace.info("redirect response: {}".format(res.text))
        return res

    def handle_response(self, result, response_args=None, *args):
        if response_args is not None:
            logger.debug("response_args: {}".format(response_args))

        if isinstance(result, Response):
            # result should be a redirect (302 or 303)
            loc = result.headers['location']
            query = parse_qs(loc.split('?')[1])
            saml_req = query["SAMLRequest"][0]
            self.conv.events.store('RelayState', query["RelayState"][0])
        else:
            saml_req = result["SAMLRequest"]
            try:
                self.conv.events.store('RelayState', result["RelayState"])
            except KeyError:
                pass

        _srv = self.conv.entity
        _req = _srv.parse_authn_request(saml_req)
        self.conv.events.store('protocol_message:xml', _req.xmlstr)
        self.conv.events.store('protocol_message', _req.message)
        self.conv.events.store('issuer', _req.message.issuer.text)


class AuthenticationResponse(ProtocolMessage):
    def __init__(self, conv, req_args, binding, identity, **kwargs):
        ProtocolMessage.__init__(self, conv, req_args, binding)
        try:
            self.op_type = kwargs['op_type']
        except KeyError:
            self.op_type = ''
        else:
            del kwargs['op_type']
        self.identity = identity
        self.msg_args = kwargs

    def construct_message(self, resp_args):
        _args = resp_args.copy()
        _args.update(self.msg_args)
        _resp = self.conv.entity.create_authn_response(self.identity, **_args)

        if self.op_type == "ecp":
            kwargs = {"soap_headers": [
                ecp.Response(
                    assertion_consumer_service_url=resp_args['destination'])]}
        else:
            kwargs = {}

        # because I don't plan to involve a web browser
        if resp_args['binding'] == BINDING_HTTP_POST:
            args = {
                'relay_state': self.conv.events.last_item('RelayState'),
                'typ': 'SAMLRequest',
                'destination': resp_args['destination']}
            http_args = self.entity.use_http_post(
                "%s" % _resp, **args)
            http_args["url"] = resp_args['destination']
            http_args["method"] = "POST"
        else:
            http_args = self.conv.entity.apply_binding(
                resp_args['binding'], "%s" % _resp,
                destination=resp_args['destination'],
                relay_state=self.conv.events.last_item('RelayState'),
                response=True, **kwargs)

        return http_args

    def handle_response(self, result, response_args):
        self.conv.events.store('result', result)


class AuthenticationResponseRedirect(RedirectResponse):
    request = "authn_request"
    msg_cls = AuthenticationResponse
    tests = {}

    def __init__(self, conv, io, sh, **kwargs):
        RedirectResponse.__init__(self, conv, io, sh, **kwargs)
        self.msg_args = {}

    def _make_response(self):
        self.msg = self.msg_cls(self.conv, self.req_args, binding=self._binding,
                                **self.msg_args)

        _authn_req = self.conv.events.get_message('protocol_message',
                                                  AuthnRequest)
        resp_args = self.conv.entity.response_args(_authn_req)
        self.conv.events.store('response args', resp_args)

        http_info = self.msg.construct_message(resp_args)

        return http_info

    def handle_response(self, result, *args):
        self.request_inst.handle_response(result, self.response_args)


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj
