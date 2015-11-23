#!/usr/bin/env python
import argparse
import importlib
from saml2.config import Config
from saml2.metadata import entity_descriptor
from saml2.metadata import entities_descriptor
from saml2.metadata import metadata_tostring_fix
from saml2.sigver import security_context
from saml2.validate import valid_instance
from saml2test.util import read_multi_conf

__author__ = 'roland'

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='valid',
                    help="How long, in days, the metadata is valid from the time of creation")
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
parser.add_argument(dest="config")
args = parser.parse_args()

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
xmldoc = metadata_tostring_fix(desc, nspair, xmldoc)
print(xmldoc.decode("utf-8"))
