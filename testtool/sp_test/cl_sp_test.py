#!/usr/bin/env python3
import logging

from aatest.io import ClIO
from aatest.session import SessionHandler

from saml2test.sp_test.tool import ClTester
from saml2test.sp_test.io import SamlClIO
from saml2test.sp_test.setup import setup

__author__ = 'roland'

logger = logging.getLogger("")


if __name__ == "__main__":
    test_id, kwargs = setup()

    sh = SessionHandler(session={}, **kwargs)
    sh.init_session({}, profile=kwargs['profile'])

    if test_id:
        if test_id not in kwargs['flows']:
            print(
                "The test id ({}) does not appear in the test definitions".format(
                    test_id))
            exit()

        io = SamlClIO(**kwargs)
        tester = ClTester(io, sh, **kwargs)
        tester.run(test_id, **kwargs)
    else:
        for tid in sh.session["flow_names"]:
            # New fresh session handler for every test
            _sh = SessionHandler({}, **kwargs)
            _sh.init_session({}, profile=kwargs['profile'])
            io = ClIO(**kwargs)
            tester = ClTester(io, _sh, **kwargs)
            if tester.run(tid, **kwargs):
                io.result(sh.session)
