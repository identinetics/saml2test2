#!/usr/bin/env python3
import logging
from aatest.result import Result

from aatest.session import SessionHandler
from aatest.io import ClIO

from saml2test.sp_test.tool import ClTester
from saml2test.sp_test.setup import setup

__author__ = 'roland'

logger = logging.getLogger("")


if __name__ == "__main__":
    test_id, kwargs, opargs = setup()

    sh = SessionHandler(session={}, **kwargs)
    sh.init_session(profile=kwargs['profile'])

    if test_id:
        res = Result(sh, kwargs['profile_handler'])
        if test_id not in kwargs['flows']:
            print(
                "The test id ({}) does not appear in the test definitions".format(
                    test_id))
            exit()

        inut = ClIO(**kwargs)
        tester = ClTester(inut, sh, **kwargs)
        if tester.run(test_id, **kwargs):
            res.print_info(sh, test_id)
    else:
        for tid in sh["flow_names"]:
            # New fresh session handler for every test
            _sh = SessionHandler({}, **kwargs)
            _sh.init_session(profile=kwargs['profile'])
            res = Result(_sh, kwargs['profile_handler'])

            inut = ClIO(**kwargs)
            tester = ClTester(inut, _sh, **kwargs)
            if tester.run(tid, **kwargs):
                if 'debug' in opargs and opargs['debug']:
                    res.print_info(tid)
                elif 'dump' in opargs and opargs['dump']:
                    res.print_info(tid)
                else:
                    res.result()
            else:
                res.print_info(tid)


