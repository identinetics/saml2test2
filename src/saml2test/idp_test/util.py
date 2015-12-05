import yaml
import pkgutil

from aatest import check as aa_check
from aatest.func import factory as aafactory

from saml2test.check import check_metadata
from saml2test import check as st_check

from saml2test.idp_test.func import factory
from saml2.config import SPConfig
from saml2test.idp_test.cl_request import factory as cl_factory
from saml2test.idp_test.wb_request import factory as wb_factory


__author__ = 'roland'


def collect_ec():
    from saml2 import entity_category

    package = entity_category
    prefix = package.__name__ + "."
    ec_map = {}
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__,
                                                         prefix):
        module = __import__(modname, fromlist="dummy")
        try:
            _base = module.RELEASE['']
        except KeyError:
            _base = []
        for key, val in module.RELEASE.items():
            if key == '':
                continue
            else:
                ec_map[key] = val
                ec_map[key].extend(_base)

    return ec_map


def read_multi_conf(cnf, metadata_construction=False):
    res = {}
    for key, val in cnf.CONFIG.items():
        res[key] = SPConfig().load(val,
                                   metadata_construction=metadata_construction)
    return res


def _get_cls(name, use='cl'):
    if use == 'cl':
        factory = cl_factory
    else:
        factory = wb_factory

    try:
        _mod, _cls = name.split('.')
    except ValueError:
        cls = factory(name)
    else:
        if _mod == 'check_metadata':
            cls = check_metadata.factory(_cls)
        else:
            raise Exception("Unknown Module: '{}'".format(name))
    return cls


def _get_func(dic):
    """

    :param dic: A key, value dictionary
    :return: A dictionary with the keys replace with references to functions
    """
    res = {}
    for fname, val in dic.items():
        func = factory(fname)
        if func is None:
            func = aafactory(fname)

        if func is None:
            raise Exception("Unknown function: '{}'".format(fname))
        res[func] = val

    return res


def parse_yaml_conf(cnf_file, use='cl'):
    stream = open(cnf_file, 'r')
    yc = yaml.safe_load(stream)
    stream.close()
    for tid, spec in yc['Flows'].items():
        seq = []
        for func in spec["sequence"]:
            if isinstance(func, list):
                seq.append((_get_cls(func[0], use), _get_func(func[1])))
            else:
                seq.append(_get_cls(func, use))
        spec["sequence"] = seq

    return yc


def get_check(check_id):

    package = st_check
    prefix = package.__name__ + "."
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__,
                                                         prefix):
        module = __import__(modname, fromlist="dummy")
        chk = module.factory(check_id)
        if chk:
            return chk

    return aa_check.factory(check_id)
