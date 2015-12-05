import inspect
import sys
from saml2.samlp import NameIDPolicy

__author__ = 'roland'


def set_name_id(oper, args):
    assertion = oper.conv.protocol_response[-1].assertion
    oper.req_args["name_id"] = assertion.subject.name_id


def set_name_id_policy(oper, args):
    oper.req_args["name_id_policy"] = NameIDPolicy(**args)


def set_user_credentials(oper, args):
    _client = oper.conv.client
    _client.user = args["user"]
    _client.passwd = args["password"]


def setup_logout(oper, args):
    resp = oper.conv.events.last_item('protocol_response')
    assertion = resp.assertion
    subj = assertion.subject
    oper.req_args["name_id"] = subj.name_id
    oper.req_args["entity_id"] = assertion.issuer.text
    oper.req_args["reason"] = 'tired'


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from aatest.func import factory as aafactory

    return aafactory(name)
