from aatest import Unknown
import yaml

from aatest.func import factory as aafactory

from saml2test.check import check_metadata

from saml2test import operation
from saml2test.idp_test.func import factory
from saml2test.idp_test.cl_request import factory as cl_factory
from saml2test.idp_test.wb_request import factory as wb_factory


__author__ = 'roland'


def _get_cls(name, use='cl'):
    if use == 'cl':
        factory = cl_factory
    else:
        factory = wb_factory

    try:
        cls = factory(name)
    except Unknown:
        try:
            cls = operation.factory(name)
        except Unknown:
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
            if isinstance(func, dict):  # Must be only one key, value item
                key, val = list(func.items())[0]
                seq.append((_get_cls(key), _get_func(val)))
            else:
                seq.append(_get_cls(func, use))
        spec["sequence"] = seq

    return yc


