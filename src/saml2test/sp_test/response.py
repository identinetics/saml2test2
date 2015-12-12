from aatest.operation import Operation
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.time_util import utc_time_sans_frac
from saml2test.request import MissingMetadata

__author__ = 'roland'


class Response(Operation):
    name_id_formats = [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT]
    bindings = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP]
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

    def _make_response(self):
        return {}

    def handle_request(self, *args):
        raise NotImplemented

    def op_setup(self):
        metadata = self.conv.entity.metadata
        issuer = self.conv.events.last_item('issuer')
        try:
            entity = metadata[issuer]
        except KeyError:
            raise MissingMetadata(
                "No metadata available for {}".format(issuer))


class RedirectResponse(Response):
    _class = None
    _args = {}
    _method = 'GET'
    _binding = BINDING_HTTP_REDIRECT

    def run(self):
        send_args = self._make_response()
        if isinstance(send_args, Response):
            return send_args

        self.conv.events.store("send_args", send_args)
        self.conv.events.store('time_stamp',
                               (send_args['url'], utc_time_sans_frac()))
        res = self.entity.send(**send_args)
        self.trace.info("Got a {} response".format(res.status_code))
        self.trace.info("Received HTML: {}".format(res.text))
        return res
