#!/usr/bin/env python3
import copy

import importlib
import logging
import argparse

from aatest.common import setup_logger

from saml2test import metadata

from saml2test.common import make_client
from saml2test.common import map_prof
from saml2test.common import Trace
from saml2test.prof_util import ProfileHandler
from saml2test.util import collect_ec, get_check
from saml2test.util import parse_yaml_conf

from saml2.saml import factory as saml_message_factory

__author__ = 'roland'

logger = logging.getLogger("")


def setup(use='cl'):
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
        spec = parse_yaml_conf(flow_def, use=use)
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
    spconf = copy.deepcopy(CONF.CONFIG)
    acnf = list(spconf.values())[0]
    mds = metadata.load(True, acnf, CONF.METADATA)

    if cargs.log_name:
        setup_logger(logger, cargs.log_name)
    elif cargs.testid:
        setup_logger(logger, "{}.log".format(cargs.testid))
    else:
        setup_logger(logger)

    kwargs = {"base_url": copy.copy(CONF.BASE), 'spconf': spconf,
              "flows": fdef['Flows'], "orddesc": fdef['Order'],
              "desc": fdef['Desc'], 'metadata': mds,
              "profile": cargs.profile, "msg_factory": saml_message_factory,
              "check_factory": get_check, "profile_handler": ProfileHandler,
              "cache": {}, "entity_id": cargs.entity_id,
              'map_prof': map_prof, 'make_client': make_client,
              'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()}}

    if cargs.interaction:
        kwargs['interaction_conf'] = importlib.import_module(
            cargs.interaction).INTERACTION

    if cargs.insecure:
        kwargs["insecure"] = True

    return cargs.testid, kwargs