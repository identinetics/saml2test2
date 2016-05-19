#!/usr/bin/env python3
import argparse
import importlib
import sys

from future.backports.urllib.parse import urlparse
from saml2.config import Config
from saml2.metadata import entity_descriptor
from saml2.metadata import entities_descriptor
from saml2.metadata import metadata_tostring_fix
from saml2.sigver import security_context
from saml2.validate import valid_instance

from saml2test.util import read_multi_conf

__author__ = 'roland'


def load_module_from_path(module_name, path):
    if sys.version_info.major == 2:
        import imp
        return imp.load_source(module_name, path)
    elif sys.version_info.major == 3 and sys.version_info.minor >= 5:
        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, path)
        foo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(foo)
        return foo
    else:
        from importlib.machinery import SourceFileLoader

        return SourceFileLoader(module_name, path).load_module()


def name_format(eid):
    p = urlparse(eid)
    part1 = p[1].replace(':', '-')
    part2 = p[2][1:].replace('/','-')
    return '{}-{}'.format(part1, part2)


parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='valid',
                    help="How long, in days, the metadata is valid from the "
                         "time of creation")
parser.add_argument('-c', dest='cert', help='certificate')
parser.add_argument('-i', dest='id',
                    help="The ID of the entities descriptor")
parser.add_argument('-k', dest='keyfile',
                    help="A file with a key to sign the metadata with")
parser.add_argument('-n', dest='name', default="")
parser.add_argument('-p', dest='path',
                    help="path to the configuration file")
parser.add_argument('-s', dest='sign', action='store_true',
                    help="sign the metadata")
parser.add_argument('-x', dest='xmlsec',
                    help="xmlsec binaries to be used for the signing")
parser.add_argument('-o', dest='outputfile',
                    help="write into output file instead of stdout")
parser.add_argument('-S', dest='separate', action='store_true',
                    help="write into one output file per entity")
parser.add_argument(dest="config")
args = parser.parse_args()

if '/' in args.config:
    if not args.config.endswith('.py'):
        args.config += '.py'
    _cnf = load_module_from_path('conf', args.config)
else:
    sys.path.insert(0, '.')
    _cnf = importlib.import_module(args.config)

res = read_multi_conf(_cnf, True)
eds = []
for key, cnf in res.items():
    eds.append(entity_descriptor(cnf))

if args.valid:
    valid_for = int(args.valid) * 24
else:
    valid_for = 0

nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}

conf = Config()
conf.key_file = args.keyfile
conf.cert_file = args.cert
conf.debug = 1
conf.xmlsec_binary = args.xmlsec
secc = security_context(conf)

desc, xmldoc = entities_descriptor(eds, valid_for, args.name, args.id,
                                   args.sign, secc)
valid_instance(desc)
if args.separate:
    for entdesc in desc.entity_descriptor:
        xmldoc = metadata_tostring_fix(entdesc, nspair)
        output = xmldoc.decode("utf-8")
        output_file = open(name_format(entdesc.entity_id), "w+")
        output_file.write(output)
        output_file.close()
else:
    xmldoc = metadata_tostring_fix(desc, nspair, xmldoc)
    output = xmldoc.decode("utf-8")

    if args.outputfile:
        output_file = open(args.outputfile, "w+")
        output_file.write(output)
        output_file.close()
    else:
        print(output)
