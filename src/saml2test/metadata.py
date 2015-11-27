from saml2 import saml
from saml2 import md
from saml2 import xmldsig
from saml2 import xmlenc
from saml2.config import SPConfig
from saml2.mdstore import load_extensions, MetadataStore

__author__ = 'roland'


def load(insecure, conf, md_conf):
    try:
        md_conf = conf["metadata"]
        del conf["metadata"]
    except KeyError:
        pass

    _cnf = SPConfig().load(conf)

    if insecure:
        disable_validation = True
    else:
        disable_validation = False

    mds = MetadataStore(_cnf.attribute_converters, _cnf,
                        disable_ssl_certificate_validation=disable_validation)

    mds.imp(md_conf)

    return mds
