import logging
from aatest.summation import represent_result

from oic.utils.http_util import Response, NotFound

from aatest.check import ERROR
from aatest.check import OK
from aatest.check import WARNING
from aatest.check import INCOMPLETE
from aatest.io import IO
from saml2test.idp_test.inut import get_test_info

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


class WebIO(IO):
    def __init__(self, conf, flows, desc, profile_handler, profile, lookup,
                 cache=None, environ=None, start_response=None, session=None,
                 **kwargs):
        IO.__init__(self, flows, profile, desc, profile_handler, cache,
                    session=session, **kwargs)

        self.conf = conf
        self.lookup = lookup
        self.environ = environ
        self.start_response = start_response

    def flow_list(self):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])

        argv = {
            "tests": self.session["tests"],
            "profile": self.session["profile"],
            "test_info": list(self.session["test_info"].keys()),
            "base": self.conf.BASE,
            "headlines": self.desc,
            "testresults": TEST_RESULTS
        }

        return resp(self.environ, self.start_response, **argv)

    def test_info(self, testid):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])

        _conv = self.session["conv"]
        info = get_test_info(self.session, testid)

        argv = {
            "profile": info["profile_info"],
            "trace": info["trace"],
            "events": info["events"],
            "result": represent_result(_conv.events).replace("\n", "<br>\n")
        }

        return resp(self.environ, self.start_response, **argv)

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)
