#!/usr/bin/env python3
import logging

from aatest.io import ClIO
from aatest.session import SessionHandler

from saml2test.tool import ClTester
from saml2test.io import SamlClIO
from saml2test.setup import setup

__author__ = 'roland'

logger = logging.getLogger("")


if __name__ == "__main__":
    test_id, kwargs = setup()

    if test_id:
        if test_id not in kwargs['flows']:
            print(
                "The test id ({}) does not appear in the test definitions".format(
                    test_id))
            exit()

        io = SamlClIO(**kwargs)
        sh = SessionHandler(session={}, **kwargs)
        sh.init_session({}, profile=kwargs['profile'])
        tester = ClTester(io, sh, **kwargs)
        tester.run(test_id, **kwargs)
    else:
        _sh = SessionHandler(session={}, **kwargs)
        _sh.init_session({}, profile=kwargs['profile'])

        for tid in _sh.session["flow_names"]:
            io = ClIO(**kwargs)
            sh = SessionHandler({}, **kwargs)
            sh.init_session({}, profile=kwargs['profile'])
            tester = ClTester(io, sh, **kwargs)

            if tester.run(tid, **kwargs):
                io.result(sh.session)
