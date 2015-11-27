#!/usr/bin/env python
import copy
import pprint
import yaml

from base_conf import CONFIG
from base_conf import BASE
from base_conf import METADATA

__author__ = 'rolandh'

COMBOS = yaml.safe_load(open("conf.yaml").read())

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
_str += "BASE = '{}'\n".format(BASE)
_str += "CONFIG = {}".format(pp.pformat(cnf))
#_str = _str.replace("u'", "'")

fil = open("conf.py", "w")
fil.write(_str)
fil.close()
