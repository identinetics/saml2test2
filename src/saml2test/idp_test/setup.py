#!/usr/bin/env python3

import copy
import importlib
import logging
import argparse
import os
import requests
import sys
import yaml

from aatest.common import setup_logger
from aatest.comhandler import ComHandler
from saml2.httputil import Response

from saml2test import metadata

from saml2test.util import collect_ec
from saml2test.util import get_check

from saml2test.idp_test.common import make_entity
from saml2test.idp_test.common import map_prof
from saml2test.idp_test.common import Trace
from saml2test.idp_test.prof_util import ProfileHandler
from saml2test.idp_test.func import factory
from saml2test.idp_test.cl_request import factory as cl_factory
from saml2test.idp_test.wb_request import factory as wb_factory

from aatest.parse_cnf import parse_json_conf
from aatest.parse_cnf import parse_yaml_conf

from saml2.saml import factory as saml_message_factory
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from saml2test import operation

from saml2test import configloader

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = 'roland'

logger = logging.getLogger("")

def load_flows(fdef, flow_spec, use):
    cls_factories = {'cl': cl_factory, 'wb': wb_factory, '': operation.factory}

    if flow_spec.endswith('.yaml'):
        spec = parse_yaml_conf(flow_spec, cls_factories, factory, use=use)
    elif flow_spec.endswith('.json'):
        spec = parse_json_conf(flow_spec, cls_factories, factory, use=use)
    else:
        raise Exception('Unknown file type')

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


def setup(use='cl', cargs=None):
    if cargs is None:
        parser = argparse.ArgumentParser()
        parser.add_argument('-k', dest="insecure", action='store_true')
        parser.add_argument('-x', dest="break", action='store_true')
        parser.add_argument('-t', dest="testid")
        parser.add_argument('-T', dest='toolconf')   # TODO: is this really optional?
        parser.add_argument(dest="config")
        cargs = parser.parse_args()

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}

    try:
        with open(cargs.toolconf, 'r') as fd:
            conf = yaml.safe_load(fd)
    except FileNotFoundError as e:
        raise Exception('unable to open tool configuration file: cwd=' + os.getcwd() + ', ' + str(e))
    try:
        for yf in conf['flows']:
            fdef = load_flows(fdef, yf, use)
    except KeyError:
        pass # TODO: is it really OK not to have any flows?

    # Filter flows based on profile
    keep = []
    for key, val in fdef['Flows'].items():
        for p in conf['profile']:
            if p in val['profiles']:
                keep.append(key)

    for key in list(fdef['Flows'].keys()):
        if key not in keep:
            del fdef['Flows'][key]

    sys.path.insert(0, '.')
    CONF = importlib.import_module(conf['samlconf'])


    loader = configloader.ConfigLoader()
    try:
        CONF = loader.conf_CONF()
    except configloader.ConfigFileNotReadable as e:
        configloader.exit_on_mandatory_config_file(e)

    #CONF = loader.load_file(conf['samlconf'] + ".py", 'configuration')
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
    try:
        c_handler = conf['content_handler']
    except KeyError:
        comhandler = None
    else:
        for item in c_handler:
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
              "cache": {},
              'map_prof': map_prof, 'make_entity': make_entity,
              'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()},
              'com_handler': comhandler, 'conf': CONF, 'response_cls': Response,
              'template_root': conf['template_root'], 'static': conf['static']}

    try:
        kwargs["entity_id"] = conf['entity_id']
    except KeyError:
        kwargs['disco_srv'] = conf['disco_srv']

    if cargs.insecure or conf['insecure']:
        kwargs["insecure"] = True

    return cargs, kwargs