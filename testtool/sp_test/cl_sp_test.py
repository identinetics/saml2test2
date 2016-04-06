#!/usr/bin/env python3
import logging

from aatest.session import SessionHandler

from saml2test.sp_test.tool import ClTester
from saml2test.sp_test.io import SamlClIO
from saml2test.sp_test.setup import setup

__author__ = 'roland'

logger = logging.getLogger("")


if __name__ == "__main__":
    test_id, kwargs, opargs = setup()

    sh = SessionHandler(session={}, **kwargs)
    sh.init_session(profile=kwargs['profile'])

    if test_id:
        if test_id not in kwargs['flows']:
            print(
                "The test id ({}) does not appear in the test definitions".format(
                    test_id))
            exit()

        inut = SamlClIO(**kwargs)
        tester = ClTester(inut, sh, **kwargs)
        if tester.run(test_id, **kwargs):
            inut.print_info(sh, test_id)
    else:
        for tid in sh["flow_names"]:
            # New fresh session handler for every test
            _sh = SessionHandler({}, **kwargs)
            _sh.init_session(profile=kwargs['profile'])
            inut = SamlClIO(**kwargs)
            tester = ClTester(inut, _sh, **kwargs)
            if tester.run(tid, **kwargs):
                if 'debug' in opargs and opargs['debug']:
                    inut.print_info(tid)
                else:
                    inut.result(_sh)
            else:
                inut.debug_log(_sh, tid)

            if 'dump' in opargs and opargs['dump']:
                inut.print_info(tid)

