import logging
import aatest
import time
from saml2.client import Saml2Client
from saml2.config import SPConfig

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Trace(aatest.Trace):
    def response(self, resp):
        delta = time.time() - self.start
        try:
            cl_name = resp.__class__.__name__
        except AttributeError:
            cl_name = ""

        txt = resp
        self.trace.append("%f %s: %s" % (delta, cl_name, txt))


def make_entity(sp, **kw_args):
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
