import inspect
import sys
from aatest import OperationError
from aatest.events import EV_PROTOCOL_RESPONSE
from aatest.events import NoSuchEvent
from saml2.samlp import NameIDPolicy

__author__ = 'roland'

def set_name_id(oper, args):
    assertion = oper.conv.protocol_response[-1].assertion
    oper.req_args["name_id"] = assertion.subject.name_id


def set_name_id_policy(oper, args):
    oper.req_args["name_id_policy"] = NameIDPolicy(**args)


def set_user_credentials(oper, args):
    _client = oper.conv.entity
    _client.user = args["user"]
    _client.passwd = args["password"]


def setup_logout(oper, args):
    try:
        resp = oper.conv.events.last_item(EV_PROTOCOL_RESPONSE)
    except NoSuchEvent:
        raise OperationError("No session to log out from found in previous responses")
    assertion = resp.assertion
    subj = assertion.subject
    oper.req_args["name_id"] = subj.name_id
    oper.req_args["entity_id"] = assertion.issuer.text
    oper.req_args["reason"] = 'tired'


def set_message_param(oper, args):
    oper.msg_param.update(args)


def set_entity_id(oper, args):
    oper.req_args['entityid'] = oper.conv.entity_id


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from aatest.func import factory as aafactory

    return aafactory(name)
