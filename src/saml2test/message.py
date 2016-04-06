import logging

from aatest.events import EV_REQUEST_ARGS
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import EV_HTTP_ARGS
from aatest.events import EV_PROTOCOL_RESPONSE

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP

from saml2 import xmldsig
from saml2.mdstore import destinations
from saml2.time_util import in_a_while
from saml2.ident import code

from saml2test.request import UnknownBinding

logger = logging.getLogger(__name__)

__author__ = 'roland'


class ProtocolMessage(object):
    def __init__(self, conv, req_args, binding, msg_param=None):
        self.conv = conv
        self.entity = conv.entity
        self.req_args = req_args
        self.binding = binding
        self.msg_param = msg_param or {}
        self.response_args = {}

    def construct_message(self, *args):
        raise NotImplementedError


# -----------------------------------------------------------------------------

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

        self.conv.events.store(EV_REQUEST_ARGS, self.req_args,
                               sender=self.__class__, sub='construct_message')
        self.conv.events.store(EV_PROTOCOL_REQUEST, request,
                               sender=self.__class__, sub='construct_message')

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
                    sigalg = xmldsig.sig_default
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

        self.conv.events.store(EV_HTTP_ARGS, http_info, sender=self.__class__,
                               sub='construct_message')

        return http_info, req_id

    def handle_response(self, result, response_args, *args):
        if isinstance(result, dict):
            res = result['text']
        else:
            res = result

        resp = self.conv.entity.parse_logout_request_response(res, self.binding)

        self.conv.events.store(EV_PROTOCOL_RESPONSE, resp,
                               sender=self.__class__, sub='handle_response')

# -----------------------------------------------------------------------------
