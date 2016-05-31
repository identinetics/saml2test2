#!/usr/bin/env python3
import copy
import importlib
import logging
import argparse
import requests
import sys
import yaml
import os

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

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TT_CONFIG_FILENAME = 'configuration.yaml'
TD_SP_DIR = 'td_sp'
TD_SP_CONFIG_FILENAME = 'configuration_created.py'
TD_SP_CONFIG_METADATA_FILENAME = 'metadata_created.xml'

__author__ = 'roland'

logger = logging.getLogger("")

class ConfigLoader:
	# TODO: refactor me into the framework
	def load_config(self, config_file):
		self.test_config_file_read(config_file)
		# works only with python 3.4, see http://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path 	
		from importlib.machinery import SourceFileLoader
		configuration = SourceFileLoader("configuration", config_file).load_module()
		configuration._source = config_file 
		return configuration
		
	def test_config_file_read(self,config_file):
		try:
			open(config_file)
		except Exception as e:
			print ("Error accessing {}".format(config_file))
			print ("Error {0}: {1}".format(e.errno, e.strerror) )
			os._exit(-1)

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
        parser.add_argument('-t', dest="testid")
        parser.add_argument('-T', dest='toolconf')
        parser.add_argument(dest="configdir")
        cargs = parser.parse_args()

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}

    if cargs.toolconf:
        conf = yaml.safe_load(open(cargs.toolconf, 'r'))
    else:
        config_file = os.path.join(cargs.configdir, TT_CONFIG_FILENAME)
        conf = yaml.safe_load(open(config_file, 'r'))
    try:
        for yf in conf['flows']:
            flows_file = os.path.join(cargs.configdir, yf)
            fdef = load_flows(fdef, flows_file, use)
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

    #sys.path.insert(0, '.')
    #CONF = importlib.import_module(conf['samlconf'])
    configuration_fp = os.path.join(cargs.configdir,TD_SP_DIR,TD_SP_CONFIG_FILENAME)
    CONF = ConfigLoader().load_config(configuration_fp)
    CONF = inject_configuration_base_path(CONF,cargs.configdir)
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
                    
                    """
                    	tricking around aatest just loading from cwd
                    	TODO: Fixing in aatest
                    """
                    my_cwd = os.getcwd()
                    os.chdir(cargs.configdir)
                    ch.append(robobrowser.factory(**kwargs))
                    os.chdir(my_cwd)
                    
        comhandler = ComHandler(ch)

    kwargs = {"base_url": copy.copy(CONF.BASE), 'spconf': spconf,
              "flows": fdef['Flows'], "order": fdef['Order'],
              "desc": fdef['Desc'], 'metadata': mds,
              "profile": conf['profile'], "msg_factory": saml_message_factory,
              "check_factory": get_check, "profile_handler": ProfileHandler,
              "cache": {},
              'map_prof': map_prof, 'make_entity': make_entity,
              'trace_cls': Trace, 'conv_args': {'entcat': collect_ec()},
              'com_handler': comhandler, 'conf': CONF, 'response_cls': Response}

    try:
        kwargs["template_root"] = conf['template_root']
    except KeyError:
        pass

    try:
        kwargs["static"] = conf['static']
    except KeyError:
        pass

    try:
        kwargs["entity_id"] = conf['entity_id']
    except KeyError:
        kwargs['disco_srv'] = conf['disco_srv']

    if cargs.insecure or conf['insecure']:
        kwargs["insecure"] = True

    return cargs, kwargs
