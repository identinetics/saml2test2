import sys
import inspect
import logging
from requests import Response
from urllib.parse import parse_qs, urlparse, urlunparse

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
        self.conv.events.store('start_page', self.start_page)
        self.conv.trace.info("Doing GET on {}".format(self.start_page))
        res = self.conv.entity.send(self.start_page)
        self.conv.trace.info("Got a {} response".format(res.status_code))
        if res.status_code in [302, 303]:
            loc = res.headers['location']
            self.conv.events.store('redirect', loc)
            self.conv.trace.info("Received HTML: {}".format(res.text))
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
        self.conv.trace.reply(_req.xmlstr)
        _msg = _req.message
        self.conv.trace.info("{}: {}".format(_msg.__class__.__name__, _msg))
        self.conv.trace.info('issuer: {}'.format(_msg.issuer.text))
        self.conv.events.store('protocol_message:xml', _req.xmlstr)
        self.conv.events.store('protocol_message', _msg)
        self.conv.events.store('issuer', _msg.issuer.text)


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

        self.conv.trace.info('Constructed response message: {}'.format(_resp))

        if self.op_type == "ecp":
            kwargs = {"soap_headers": [
                ecp.Response(
                    assertion_consumer_service_url=resp_args['destination'])]}
        else:
            kwargs = {}

        self.conv.trace.info(
            "Response binding used: {}".format(resp_args['binding']))
        self.conv.trace.info(
            "Destination for response: {}".format(resp_args['destination']))

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

    def handle_response(self, result, *args):
        if result.status_code in [302, 303]:
            self.conv.events.store('redirect', result)
        else:
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
        self.msg.handle_response(result, self.response_args)


class FollowRedirect(Operation):
    def __init__(self, conv, io, sh, **kwargs):
        Operation.__init__(self, conv, io, sh, **kwargs)
        self.send_args = kwargs

    def run(self):
        base_url = self.conv.events.last_item('start_page')
        _redirect = self.conv.events.last_item('redirect')
        loc = _redirect.headers['location']
        if loc.startswith('/'):
            p = list(urlparse(base_url))
            p[2] = loc
            url = urlunparse(p)
        else:
            url = base_url + loc
        res = self.conv.entity.send(url)
        self.conv.trace.info("Got a {} response".format(res.status_code))
        self.conv.trace.info("Received HTML: {}".format(res.text))
        return res

    def handle_response(self, response, *args):
        self.conv.events.store('html_src', response.text)


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj
