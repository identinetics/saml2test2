#!/usr/bin/env python
import importlib

import argparse
import copy
import pprint

import sys
import yaml

__author__ = 'rolandh'

parser = argparse.ArgumentParser() # TODO: -i. -o and -b are not optional!
parser.add_argument('-i', dest="input", default='conf.yaml')
parser.add_argument('-o', dest="output", default='conf.py')
parser.add_argument('-b', dest='base', default='base_conf')
cargs = parser.parse_args()

COMBOS = yaml.safe_load(open(cargs.input).read())
sys.path.insert(0, '.')
BCONF = importlib.import_module(cargs.base)

pp = pprint.PrettyPrinter(indent=2)

cnf = {}
for key, spec in COMBOS.items():
    _config = copy.deepcopy(BCONF.CONFIG)
    _config["description"] = spec['description']
    _config["entityid"] = BCONF.CONFIG["entityid"].format(base=BCONF.BASE,
                                                          sp_id=key)

    try:
        _config["entity_category"] = spec['entity_category']
    except KeyError:
        pass

    endpdict = {}
    for endp, vals in _config["service"]["sp"]["endpoints"].items():
        _vals = []
        for _url, binding in vals:
            _vals.append((_url.format(base=BCONF.BASE), binding))
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

_str = "METADATA = {}\n".format(BCONF.METADATA)
_str += "PORT = '{}'\n".format(BCONF.PORT)
_str += "BASE = '{}'\n".format(BCONF.BASE)
_str += "CONFIG = {}".format(pp.pformat(cnf))

fil = open(cargs.output, "w")
fil.write(_str)
fil.close()
