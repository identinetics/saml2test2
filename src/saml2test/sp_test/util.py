import yaml

from aatest.func import factory as aafactory

from saml2test.check import check_metadata

from saml2test.sp_test.operation import factory as cls_factory
from saml2test.sp_test.func import factory as func_factory


__author__ = 'roland'


def _get_cls(name):
    try:
        _mod, _cls = name.split('.')
    except ValueError:
        cls = cls_factory(name)
    else:
        if _mod == 'check_metadata':
            cls = check_metadata.factory(_cls)
        else:
            raise Exception("Unknown Module: '{}'".format(name))
    return cls


def get_funcs(dic):
    """

    :param dic: Dictionary
    :return: A dictionary with the keys replace with references to functions
    """
    res = {}
    for fname, val in dic.items():
        func = func_factory(fname)
        if func is None:
            func = aafactory(fname)

        if func is None:
            raise Exception("Unknown function: '{}'".format(fname))
        res[func] = val

    return res


def parse_yaml_conf(cnf_file):
    stream = open(cnf_file, 'r')
    yc = yaml.safe_load(stream)
    stream.close()
    for tid, spec in yc['Flows'].items():
        seq = []
        for func in spec["sequence"]:
            if isinstance(func, dict):  # Must be only one key, value item
                key, val = list(func.items())[0]
                seq.append((_get_cls(key), get_funcs(val)))
            else:
                seq.append(_get_cls(func))
        spec["sequence"] = seq

    return yc


