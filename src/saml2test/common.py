import logging
import aatest
import time
from saml2.client import Saml2Client
from saml2.config import SPConfig

__author__ = 'roland'

logger = logging.getLogger(__name__)

class Trace(aatest.Trace):
    @staticmethod
    def format(resp):
        _d = {"claims": resp.to_dict()}
        if resp.jws_header:
            _d["jws header parameters"] = resp.jws_header
        if resp.jwe_header:
            _d["jwe header parameters"] = resp.jwe_header
        return _d

    def response(self, resp):
        delta = time.time() - self.start
        try:
            cl_name = resp.__class__.__name__
        except AttributeError:
            cl_name = ""

        txt = resp
        self.trace.append("%f %s: %s" % (delta, cl_name, txt))


def make_client(sp, **kw_args):
    try:
        conf = SPConfig().load(kw_args["spconf"][sp])
    except KeyError:
        logging.warning("known SP configs: {}".format(kw_args["spconf"].keys()))
        raise

    conf.metadata = kw_args['metadata']

    return Saml2Client(config=conf)


def map_prof(a, b):
    if a == b:
        return True
    else:
        return False
