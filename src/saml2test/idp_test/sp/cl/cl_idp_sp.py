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
from saml2test.util import collect_ec, read_multi_conf, parse_yaml_conf
from saml2test.io import SamlClIO
from saml2test import profiles
from saml2test import request
from saml2test.check import factory as check_factory
from saml2.saml import factory as saml_message_factory

__author__ = 'roland'

logger = logging.getLogger("")



parser = argparse.ArgumentParser()
parser.add_argument('-e', dest="entity_id")
parser.add_argument('-f', dest='flows')
parser.add_argument('-i', dest="interaction")
parser.add_argument('-k', dest="insecure", action='store_true')
parser.add_argument('-l', dest="log_name")
parser.add_argument('-p', dest="profile", action='append')
parser.add_argument('-t', dest="testid")
parser.add_argument('-y', dest='yamlflow', action='append')
parser.add_argument(dest="config")
cargs = parser.parse_args()

fdef = {'Flows': {}, 'Order': [], 'Desc': []}
for flow_def in cargs.yamlflow:
    spec = parse_yaml_conf(flow_def)
    fdef['Flows'].update(spec['Flows'])
    for param in ['Order', 'Desc']:
        try:
            fdef[param].extend(spec[param])
        except KeyError:
            pass

# Filter based on profile
keep = []
for key, val in fdef['Flows'].items():
    for p in cargs.profile:
        if p in val['profile'].split(' '):
            keep.append(key)

for key in list(fdef['Flows'].keys()):
    if key not in keep:
        del fdef['Flows'][key]

CONF = importlib.import_module(cargs.config)
spconf = read_multi_conf(CONF)

if cargs.log_name:
    setup_logger(logger, cargs.log_name)
elif cargs.testid:
    setup_logger(logger, "{}.log".format(cargs.testid))
else:
    setup_logger(logger)

kwargs = {"base_url": CONF.BASE, "conf": CONF, 'spconf': spconf,
          "flows": fdef['Flows'], "orddesc": fdef['Order'],
          "desc": fdef['Desc'],
          "profiles": profiles, "operation": request,
          "profile": cargs.profile, "msg_factory": saml_message_factory,
          "check_factory": check_factory, "profile_handler": ProfileHandler,
          "cache": {}, "entity_id": cargs.entity_id,
          'map_prof': map_prof, 'make_client': make_client,
          'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()}}

if cargs.interaction:
    kwargs['interaction_conf'] = importlib.import_module(
        cargs.interaction).INTERACTION

if cargs.insecure:
    kwargs["insecure"] = True

if cargs.testid:
    if cargs.testid not in fdef['Flows']:
        print(
            "The test id ({}) does not appear in the test definitions".format(
                cargs.testid))
        exit()

    io = SamlClIO(**kwargs)
    sh = SessionHandler(session={}, **kwargs)
    sh.init_session({}, profile=cargs.profile)
    tester = ClTester(io, sh, **kwargs)
    tester.run(cargs.testid, **kwargs)
    # io.dump_log(sh.session, cargs.testid)
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
