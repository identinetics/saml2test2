from saml2.config import IdPConfig
from saml2.config import SPConfig
from saml2.mdstore import MetadataStore

__author__ = 'roland'


def load(insecure, conf, md_conf, typ):
    try:
        md_conf = conf["metadata"]
        del conf["metadata"]
    except KeyError:
        pass

    if typ == 'sp':
        _cnf = SPConfig().load(conf)
    else:
        _cnf = IdPConfig().load(conf)

    if insecure:
        disable_validation = True
    else:
        disable_validation = False

    mds = MetadataStore(_cnf.attribute_converters, _cnf,
                        disable_ssl_certificate_validation=disable_validation)

    mds.imp(md_conf)

    return mds
