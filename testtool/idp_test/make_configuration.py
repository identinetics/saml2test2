#!/usr/bin/env python
import copy
import pprint
import yaml
import argparse
import sys
import os

"""
configuration maker for IDP tests

builds the test driver (=SP) configuration and metadata from:
	./td_sp/configuration.py and the files referenced there (metadata,
	keys, config )

the test (target) does not need any processing and is ready as is.

Notes:
	This classes should go elsewhere within the framework, the test
	script will repeat some of this functionality. 
	mk_metadata should get independent from its cwd.
TODO:
	works only with python 3.4, see http://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path 
"""

INPUT_DIR = 'td_sp'
INPUT_FILENAME = 'configuration.py'
OUTPUT_DIR = 'td_sp'
CONFIG_OUTPUT_FILENAME = 'configuration_created.py'
METADATA_OUTPUT_FILENAME = 'metadata_created.xml'

__author__ = 'rolandh, thomaswar'

class Arguments:
	def __init__(self):
		parser = argparse.ArgumentParser(
			description='Create a test driver (SP) config from a config directory')
		parser.add_argument('directory', metavar='dir', nargs=1,
			help='the directory that contains the td_sp/configuration.py ... hint: could be named "idp_test"')
		self.a = parser.parse_args()
		
		self.configuration_dir = self.a.directory[0]
		
	def args(self):
		return self.a

class ConfigLoader:
	def load_config(self, config_file):
		self.test_config_file_read(config_file)
				
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

class ConfigMaker:
	def sp_config_filepath(self,configuration):
		rel_path_from_config = configuration.SP_CONFIG_FILE		
		configuration_source_dir = os.path.dirname(configuration._source)
		filename = os.path.join( configuration_source_dir, rel_path_from_config )
		return filename
		
	def make(self,configuration):
		CONFIG = configuration.CONFIG
		BASE = configuration.BASE
		METADATA = configuration.METADATA
		PORT = configuration.PORT
		
		COMBOS = yaml.safe_load(open(self.sp_config_filepath(configuration)).read())
		
		pp = pprint.PrettyPrinter(indent=2)
		
		cnf = {}
		for key, spec in COMBOS.items():
		    _config = copy.deepcopy(CONFIG)
		    _config["description"] = spec['description']
		    _config["entityid"] = CONFIG["entityid"].format(base=BASE, sp_id=key)
		
		    try:
		        _config["entity_category"] = spec['entity_category']
		    except KeyError:
		        pass
		
		    endpdict = {}
		    for endp, vals in _config["service"]["sp"]["endpoints"].items():
		        _vals = []
		        for _url, binding in vals:
		            _vals.append((_url.format(base=BASE), binding))
		        endpdict[endp] = _vals
		
		    _config["service"]["sp"]["endpoints"] = endpdict
		
		    try:
		        sp_service = spec['service']['sp']
		    except KeyError:
		        pass
		    else:
		        for param, val in sp_service.items():
		            _config["service"]["sp"][param] = val
		
		    cnf[key] = _config
		
		_str = "METADATA = {}\n".format(METADATA)
		_str += "PORT = '{}'\n".format(PORT)
		_str += "BASE = '{}'\n".format(BASE)
		_str += "CONFIG = {}\n".format(pp.pformat(cnf))
		return _str

class ConfigWriter:
	def write(self, output_path, content):
		self.makedirs(output_path)
		self.write_file(output_path,content)
	
	def write_file(self,output_path, content):
		output_file = open(output_path, "w")
		output_file.write(content)
		output_file.close()		

	def makedirs(self,output_path):
		path_without_filename = os.path.dirname(output_path)
		if not os.path.exists(path_without_filename):
		    os.makedirs(path_without_filename)		

class MetadataMaker:
	script_name = 'mk_metadata.py'
	def __init__(self):
		self.metadata_script = self.guess_metadata_script()
		if not self.metadata_script:
			raise Exception('{} not found'.format(self.script_name))
			
	def guess_metadata_script(self):
		return self.guess_metadata_script_by_path(os.path.dirname(os.path.abspath(__file__)))
	def guess_metadata_script_by_path(self,path):
		script_path = os.path.join(path,self.script_name)
		if os.path.exists(script_path):
			return script_path
		rest = os.path.dirname(path)
		if rest and len(rest) > 3:
			path = self.guess_metadata_script_by_path(rest)
			return path
		return None
		
	def command(self, source, dest):
		modulname = os.path.splitext(os.path.basename(source))[0]
		return " ".join([self.metadata_script, modulname, '-o', dest])

	def make(self,source,dest):
		cmd = self.command(source,dest)		
		os.system(cmd)


def change_cwd_for_mk_metadata(source):
	cwd = os.getcwd()
	new_cwd = os.path.dirname(source)		
	os.chdir(new_cwd)
	return cwd


args = Arguments()
configuration_fp = os.path.join( args.configuration_dir, INPUT_DIR, INPUT_FILENAME ) 


configuration_output_fp = os.path.join( args.configuration_dir, OUTPUT_DIR, CONFIG_OUTPUT_FILENAME ) 
print ("creating SP configuration in: {}".format(configuration_output_fp))

configuration = ConfigLoader().load_config(configuration_fp)
out_str = ConfigMaker().make(configuration)
ConfigWriter().write(configuration_output_fp, out_str)

metadata_output_fp = os.path.join(args.configuration_dir, OUTPUT_DIR, METADATA_OUTPUT_FILENAME ) 
print ("creating SP metadata in: {}".format(metadata_output_fp))

"""
mk_metadata can only handle files in its cwd, so we change cwd to where
the output files are (and the input files have to be)
"""
mm = MetadataMaker()
my_cwd = change_cwd_for_mk_metadata(configuration_output_fp)
mm.make(configuration_output_fp, METADATA_OUTPUT_FILENAME)
os.chdir(my_cwd)
