import inspect
import sys
from aatest.events import EV_PROTOCOL_RESPONSE
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
    resp = oper.conv.events.last_item(EV_PROTOCOL_RESPONSE)
    assertion = resp.assertion
    subj = assertion.subject
    oper.req_args["name_id"] = subj.name_id
    oper.req_args["entity_id"] = assertion.issuer.text
    oper.req_args["reason"] = 'tired'


def set_message_param(oper, args):
    oper.msg_param.update(args)


def add_post_condition(oper, args):
    pass


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from aatest.func import factory as aafactory

    return aafactory(name)