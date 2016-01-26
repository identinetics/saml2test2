#!/usr/bin/env python3
import copy
import importlib
import logging
import argparse
import requests
import yaml

from aatest.common import setup_logger
from aatest.comhandler import ComHandler

from saml2test import metadata

from saml2test.util import collect_ec
from saml2test.util import get_check

from saml2test.idp_test.common import make_entity
from saml2test.idp_test.common import map_prof
from saml2test.idp_test.common import Trace
from saml2test.idp_test.prof_util import ProfileHandler
from saml2test.idp_test.util import parse_yaml_conf

from saml2.saml import factory as saml_message_factory
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = 'roland'

logger = logging.getLogger("")


def load_flows(fdef, yamlflow, use):
    spec = parse_yaml_conf(yamlflow, use=use)
    for param in ['Flows', 'Desc']:
        try:
            fdef[param].update(spec[param])
        except KeyError:
            pass

    fdef['Order'].extend(spec['Order'])

    return fdef


def arg(param, cargs, conf):
    try:
        return getattr(cargs, param)
    except AttributeError:
        try:
            return conf[param]
        except KeyError:
            return None


def setup(use='cl'):
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest="insecure", action='store_true')
    parser.add_argument('-x', dest="break", action='store_true')
    parser.add_argument('-t', dest="testid")
    parser.add_argument('-T', dest='toolconf')
    parser.add_argument(dest="config")
    cargs = parser.parse_args()

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}

    conf = yaml.safe_load(open(cargs.toolconf, 'r'))
    try:
        for yf in conf['yaml_flow']:
            fdef = load_flows(fdef, yf, use)
    except KeyError:
        pass

    # Filter flows based on profile
    keep = []
    for key, val in fdef['Flows'].items():
        for p in conf['profile']:
            if p in val['profiles']:
                keep.append(key)

    for key in list(fdef['Flows'].keys()):
        if key not in keep:
            del fdef['Flows'][key]

    CONF = importlib.import_module(conf['samlconf'])
    spconf = copy.deepcopy(CONF.CONFIG)
    acnf = list(spconf.values())[0]
    mds = metadata.load(True, acnf, CONF.METADATA, 'sp')

    if arg('log_name', cargs, conf):
        setup_logger(logger, cargs.log_name)
    elif arg('testid', cargs, conf):
        setup_logger(logger, "{}.log".format(cargs.testid))
    else:
        setup_logger(logger)

    ch = []
    for item in conf['content_handler']:
        for key, kwargs in item.items():  # should only be one
            if key == 'robobrowser':
                from aatest.contenthandler import robobrowser
                ch.append(robobrowser.factory(**kwargs))
    comhandler = ComHandler(ch)

    kwargs = {"base_url": copy.copy(CONF.BASE), 'spconf': spconf,
              "flows": fdef['Flows'], "order": fdef['Order'],
              "desc": fdef['Desc'], 'metadata': mds,
              "profile": conf['profile'], "msg_factory": saml_message_factory,
              "check_factory": get_check, "profile_handler": ProfileHandler,
              "cache": {}, "entity_id": conf['entity_id'],
              'map_prof': map_prof, 'make_entity': make_entity,
              'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()},
              'com_handler': comhandler}

    if cargs.insecure or conf['insecure']:
        kwargs["insecure"] = True

    return cargs, kwargs