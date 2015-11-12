#!/usr/bin/env python

import importlib
import logging
import os
import argparse
import sys

from aatest.io import ClIO
from aatest.session import SessionHandler
from aatest.common import setup_logger

from saml2test.common import make_client
from saml2test.common import map_prof
from saml2test.common import Trace
from saml2test.prof_util import ProfileHandler
from saml2test.tool import ClTester

__author__ = 'roland'


logger = logging.getLogger("")


# def run_one(test_id, flows, profile, profiles, **kw_args):
#     _flow = flows[test_id]
#     _cli = make_client(**kw_args)
#     conversation = Conversation(_flow, _cli, kw_args["msg_factory"],
#                                 interaction=kw_args["conf"].INTERACTION,
#                                 trace_cls=Trace)
#     # noinspection PyTypeChecker
#     try:
#         run_flow(profiles, conversation, test_id, kw_args["conf"],
#                  profile, kw_args["check_factory"])
#     except Exception as err:
#         exception_trace("", err, logger)
#         print(conversation.trace)


# def main(flows, profile, profiles, **kw_args):
#     test_list = make_list(flows, profile, map_prof, **kw_args)
#
#     for tid in test_list:
#         _flow = flows[tid]
#         _cli = make_client(**kw_args)
#         conversation = Conversation(_flow, _cli, kw_args["msg_factory"],
#                                     interaction=kw_args["conf"].INTERACTION,
#                                     trace_cls=Trace)
#
#         # noinspection PyTypeChecker
#         try:
#             run_flow(profiles, conversation, tid, kw_args["conf"],
#                      profile, kw_args["check_factory"])
#         except Exception as err:
#             exception_trace("", err, logger)
#             print(conversation.trace)


if __name__ == '__main__':
    from saml2test import profiles
    from saml2test import request
    from saml2test.check import factory as check_factory
    from saml2.saml import factory as saml_message_factory

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-l', dest="log_name")
    parser.add_argument('-p', dest="profile")
    parser.add_argument('-t', dest="testid")
    parser.add_argument('-e', dest="entity_id")
    parser.add_argument('-k', dest="insecure", action='store_true')
    parser.add_argument(dest="config")
    cargs = parser.parse_args()

    if cargs.flows is None:
        FLOWS = importlib.import_module("flows")
    elif "/" in cargs.flows:
        head, tail = os.path.split(cargs.flows)
        sys.path.insert(0, head)
        if tail.endswith(".py"):
            tail = tail[:-3]
        FLOWS = importlib.import_module(tail)
    else:
        FLOWS = importlib.import_module(cargs.flows)

    CONF = importlib.import_module(cargs.config)

    if cargs.log_name:
        setup_logger(logger, cargs.log_name)
    else:
        setup_logger(logger)

    kwargs = {"base_url": CONF.BASE, "flows": FLOWS.FLOWS, "conf": CONF,
              "orddesc": FLOWS.ORDDESC, "profiles": profiles,
              "operation": request, "profile": cargs.profile,
              "msg_factory": saml_message_factory, "desc": FLOWS.DESC,
              "check_factory": check_factory, "profile_handler": ProfileHandler,
              "cache": {}, "entity_id": cargs.entity_id,
              'map_prof': map_prof, 'make_client': make_client,
              'trace_cls': Trace}

    if cargs.insecure:
        kwargs["insecure"] = True

    if cargs.testid:
        io = ClIO(**kwargs)
        sh = SessionHandler(session={}, **kwargs)
        sh.init_session({}, profile=cargs.profile)
        tester = ClTester(io, sh, **kwargs)
        tester.run(cargs.testid, **kwargs)
        io.dump_log(sh.session, cargs.testid)
    else:
        _sh = SessionHandler(session={}, **kwargs)
        _sh.init_session({}, profile=cargs.profile)

        for tid in _sh.session["flow_names"]:
            io = ClIO(**kwargs)
            sh = SessionHandler({}, **kwargs)
            sh.init_session({}, profile=cargs.profile)
            tester = ClTester(io, sh, **kwargs)

            if tester.run(tid, **kwargs):
                io.result(sh.session)
