#!/usr/bin/env python3

import copy
import importlib
import logging
import argparse
import os
import requests
import sys
import yaml
import os

from aatest.common import setup_logger
from saml2test.comhandler import ComHandler
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
from saml2test.webserver import staticfiles, mako
from saml2test.robobrowser import robobrowser

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TT_CONFIG_FILENAME = 'configuration.yaml'
TD_SP_DIR = 'td_sp'
TD_SP_CONFIG_FILENAME = 'configuration_created.py'
TD_SP_CONFIG_METADATA_FILENAME = 'metadata_created.xml'

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

def inject_configuration_base_path(CONF,path):
	"""
		inject the paths into the config to trick around the
		limitation that the tools are designed to work from a
		single working directory.
		files in metadata are a list of tuples? Why?
	"""
	new_md = []
	for md in CONF.METADATA:
		new_files = []
		for md_file_tuple in md['metadata']:
			new_file_tuple = ()
			for md_file in md_file_tuple:
				new_file = os.path.join(path,TD_SP_DIR,md_file)
				new_file_tuple = new_file_tuple + (new_file,)
			new_files.append(new_file_tuple)
		new_entry = {'metadata':new_files, 'class':md['class']}
		new_md.append(new_entry)
	CONF.METADATA = new_md

	for config in CONF.CONFIG.items():
		config[1]['key_file'] = os.path.join(path, TD_SP_DIR, config[1]['key_file'])
		config[1]['cert_file'] = os.path.join(path, TD_SP_DIR, config[1]['cert_file'])

	return CONF

def setup(use='cl', cargs=None):
    if cargs is None:
        parser = argparse.ArgumentParser()
        parser.add_argument('-k', dest="insecure", action='store_true')
        parser.add_argument('-x', dest="break", action='store_true')
        parser.add_argument('-m', dest="metadata", action='store_true')
        parser.add_argument('-o', dest='outputfile')
        parser.add_argument(dest="configdir")
        cargs = parser.parse_args()

    flow_definitions = {'Flows': {}, 'Order': [], 'Desc': {}}

    loader = configloader.ConfigLoader(cargs.configdir)
    try:
        CONF = loader.conf_CONF()
    except configloader.ConfigFileNotReadable as e:
        configloader.exit_on_mandatory_config_file(e)

    #try:
    #    with open(cargs.toolconf, 'r') as fd:
    #        conf = yaml.safe_load(fd)
    #except FileNotFoundError as e:
    #    raise Exception('unable to open tool configuration file: cwd=' + os.getcwd() + ', ' + str(e))
    #try:
    #    for yf in conf['flows']:
    #        fdef = load_flows(fdef, yf, use)
    #except KeyError:
    #    pass # TODO: is it really OK not to have any flows?

    for flow_file in CONF.FLOWS:
        flow_definitions = load_flows(flow_definitions, flow_file, use)

    # Filter flows based on profile
    keep = []
    for key, val in flow_definitions['Flows'].items():
        for p in CONF.FLOWS_PROFILES:
            if p in val['profiles']:
                keep.append(key)

    for key in list(flow_definitions['Flows'].keys()):
        if key not in keep:
            del flow_definitions['Flows'][key]

    spconf = copy.deepcopy(CONF.CONFIG)
    acnf = list(spconf.values())[0]
    mds = metadata.load(True, acnf, CONF.METADATA, 'sp')

    setup_logger(logger)

    ch = []

    """
    TODO: This code still bows to the idea of having multiple comhandlers.
    Needs cleanup.
    """

    try:
        if CONF.CONTENT_HANDLER_INTERACTION:
            rb = robobrowser.factory(CONF.CONTENT_HANDLER_INTERACTION)
            ch.append(rb)

            comhandler = ComHandler(ch)
            if not CONF.DO_NOT_VALIDATE_TLS:
                comhandler.verify_ssl = False
            comhandler.set_triggers( CONF.CONTENT_HANDLER_TRIGGER )
    except KeyError:
        comhandler = None

    mako_path = mako.__path__[0] + os.sep
    staticfiles_path = staticfiles.__path__[0] + os.sep

    kwargs = {"base_url": copy.copy(CONF.BASE), 'spconf': spconf,
              "flows": flow_definitions['Flows'], "order": flow_definitions['Order'],
              "desc": flow_definitions['Desc'], 'metadata': mds,
              "profile": CONF.FLOWS_PROFILES, "msg_factory": saml_message_factory,
              "check_factory": get_check, "profile_handler": ProfileHandler,
              "cache": {},
              'map_prof': map_prof, 'make_entity': make_entity,
              'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()},
              'com_handler': comhandler, 'conf': CONF, 'response_cls': Response,
              'template_root': mako_path, 'static': staticfiles_path }

    try:
        kwargs["entity_id"] = CONF.ENTITY_ID
    except KeyError:
        kwargs['disco_srv'] = conf['disco_srv']

    kwargs["insecure"] = CONF.DO_NOT_VALIDATE_TLS

    return cargs, kwargs, CONF
