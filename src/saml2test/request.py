import sys
import inspect
import logging
from urllib.parse import urlencode

from aatest import Break
from aatest import Unknown
from aatest.operation import Operation

# from saml2 import samlp
from saml2 import SAMLError
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2.httputil import Response

from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.time_util import utc_time_sans_frac

__author__ = 'roland'

logger = logging.getLogger(__name__)


class MissingMetadata(Exception):
    pass


class UnknownBinding(Exception):
    pass


class ServiceProviderRequestHandlerError(Exception):
    pass


def map_arguments(args, map):
    for fro, to in map.items():
        try:
            args[to] = args[fro]
        except KeyError:
            pass
        else:
            del args[fro]
    return args


class Request(Operation):
    name_id_formats = [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT]
    bindings = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]
    message = None

    def __init__(self, conv, io, sh, **kwargs):
        Operation.__init__(self, conv, io, sh, **kwargs)
        self.expect_error = {}
        self.req_args = {}
        self.op_args = {}
        self.csi = None
        self.entity = self.conv.entity
        self.trace = self.conv.trace
        self.relay_state = ''
        self.request_id = ''
        self.response_args = {}
        self.request_inst = None

    def expected_error_response(self, response):
        if isinstance(response, SAMLError):
            if self.expect_error["stop"]:
                raise Break("Stop requested after received expected error")
        else:
            self.conv.trace.error("Expected error, didn't get it")
            raise Break("Did not receive expected error")

    def _make_request(self):
        raise NotImplemented

    def handle_response(self, *args):
        raise NotImplemented

    def op_setup(self):
        metadata = self.conv.entity.metadata
        try:
            entity = metadata[self.conv.entity_id]
        except KeyError:
            raise MissingMetadata("No metadata available for {}".format(
                self.conv.entity_id))

        for arg in ['nameid_format', 'response_binding']:
            if not arg in self.req_args:
                self.req_args[arg] = ''

        for idp in entity["idpsso_descriptor"]:
            for nformat in self.name_id_formats:
                if self.req_args["nameid_format"]:
                    break
                for nif in idp["name_id_format"]:
                    if nif["text"] == nformat:
                        self.req_args["nameid_format"] = nformat
                        break
            for bind in self.bindings:
                if self.req_args["response_binding"]:
                    break
                for sso in idp["single_sign_on_service"]:
                    if sso["binding"] == bind:
                        self.req_args["response_binding"] = bind
                        break


class RedirectRequest(Request):
    _class = None
    _args = {}
    _method = 'GET'
    _binding = BINDING_HTTP_REDIRECT

    def run(self):
        info = self._make_request()
        if isinstance(info, Response):
            return info

        _method = info['method']
        _loc = ''
        for header, value in info['headers']:
            if header == 'Location':
                _loc = value
                break

        self.trace.info("redirect.url: {}".format(_loc))
        self.conv.events.store('time_stamp', (_loc, utc_time_sans_frac()))
        res = self.entity.send(_loc, _method)
        self.trace.info("redirect response: {}".format(res.text))
        return res


def unpack_form(_str, ver="SAMLRequest"):
    SR_STR = "name=\"%s\" value=\"" % ver
    RS_STR = 'name="RelayState" value="'

    i = _str.find(SR_STR)
    i += len(SR_STR)
    j = _str.find('"', i)

    sr = _str[i:j]

    k = _str.find(RS_STR, j)
    k += len(RS_STR)
    l = _str.find('"', k)

    rs = _str[k:l]

    return {ver: sr, "RelayState": rs}


def form_post(_dict):
    return urlencode(_dict)


class PostRequest(Request):
    _class = None
    _args = {}
    _method = 'POST'
    _binding = BINDING_HTTP_POST

    def run(self):
        send_args = self._make_request()
        if isinstance(send_args, Response):
            logger.debug(send_args)
            return send_args

        _loc = send_args['url']
        self.trace.info("post.url: {}".format(_loc))
        self.conv.events.store('timestamp', (_loc, utc_time_sans_frac()))
        res = self.entity.send(**send_args)
        self.trace.info("post response: {}".format(res.text))
        return res


class SoapRequest(Request):
    _class = None
    _args = {}
    _method = 'POST'
    _binding = BINDING_SOAP

    def run(self):
        send_args = self._make_request()
        if isinstance(send_args, Response):
            return send_args

        # _method = info['method']
        _loc = send_args['url']
        self.trace.info("post.url: {}".format(_loc))
        self.conv.events.store('timestamp', (_loc, utc_time_sans_frac()))
        res = self.entity.send(**send_args)
        self.trace.info("post response: {}".format(res.text))
        return res


# -----------------------------------------------------------------------------

def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    raise Unknown("Couldn't find the operation: '{}'".format(name))
