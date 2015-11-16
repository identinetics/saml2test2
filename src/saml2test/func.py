import inspect
import sys

__author__ = 'roland'


def set_name_id(oper, args):
    assertion = oper.conv.protocol_response[-1].assertion
    oper.req_args["name_id"] = assertion.subject.name_id


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from aatest.func import factory as aafactory

    return aafactory(name)
