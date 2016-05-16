import inspect
import sys
from aatest.func import add_pre_condition
from aatest.func import add_post_condition
from saml2.argtree import add_path
from saml2.time_util import utc_time_sans_frac
import socket

__author__ = 'roland'


def get_ip():
    return socket.gethostbyname(socket.gethostname())


def set_start_page(oper, args):
    oper.start_page = oper.conv.extra_args["target_info"]["start_page"]


def set_userid(oper, args):
    if args:
        oper.msg_args['userid'] = args
    else:
        oper.msg_args['userid'] = oper.conv.extra_args["target_info"]["userid"]


def set_identity(oper, args):
    if args:
        oper.msg_args['identity'] = args
    else:
        oper.msg_args['identity'] = oper.conv.extra_args[
            "target_info"]["identity"]


def set_authn(oper, args):
    if args:
        oper.msg_args['authn'] = args
    else:
        oper.msg_args['authn'] = oper.conv.extra_args[
            'target_info']['AuthnResponse']['default_args']['authn']
        oper.msg_args['authn']['authn_instant'] = utc_time_sans_frac()


def set_subject_address(oper, args):
    t = {}
    if args == '0.0.0.0':
        # set it to whatever IP address this machine has
        ipaddress = get_ip()
    else:
        ipaddress = args

    oper.op_args['farg'] = add_path(
        t, ['assertion', 'subject', 'subject_confirmation',
            'subject_confirmation_data', 'address', ipaddress])


def add_post_assertion(oper, args):
    add_post_condition(oper,args)


def add_pre_assertion(oper, args):
    add_pre_condition(oper, args)


def sign_assertion(oper, args):
    oper.sign_assertion = args


def sign_response(oper, args):
    oper.sign_response = args


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from aatest.func import factory as aafactory

    return aafactory(name)
