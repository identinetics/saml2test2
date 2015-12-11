import pkgutil

from aatest import check as aa_check
from saml2.config import SPConfig
from saml2test import check as s2t_check

__author__ = 'roland'


def get_check(check_id):

    package = s2t_check
    prefix = package.__name__ + "."
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__,
                                                         prefix):
        module = __import__(modname, fromlist="dummy")
        chk = module.factory(check_id)
        if chk:
            return chk

    return aa_check.factory(check_id)


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


def read_multi_conf(cnf, metadata_construction=False, cnf_cls=SPConfig):
    res = {}
    for key, val in cnf.CONFIG.items():
        res[key] = cnf_cls().load(val,
                                  metadata_construction=metadata_construction)
    return res


