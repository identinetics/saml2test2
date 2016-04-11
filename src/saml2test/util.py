import pkgutil

from aatest import check as aa_check
from aatest import as_unicode
from saml2.config import SPConfig
from saml2.httputil import get_post
from saml2.httputil import getpath
from saml2.httputil import geturl
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


def extract_from_request(environ, kwargs=None):
    if kwargs is None:
        kwargs = {}

    request = None
    try:
        request = environ["QUERY_STRING"]
    except KeyError:
        pass
    if not request:
        try:
            request = as_unicode(get_post(environ))
        except KeyError:
            pass
    kwargs["request"] = request
    # authentication information
    try:
        kwargs["authn"] = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        pass
    try:
        kwargs["cookie"] = environ["HTTP_COOKIE"]
    except KeyError:
        pass

    # intended audience
    kwargs["requrl"] = geturl(environ)
    kwargs["url"] = geturl(environ, query=False)
    kwargs["baseurl"] = geturl(environ, query=False, path=False)
    kwargs["path"] = getpath(environ)
    return kwargs
