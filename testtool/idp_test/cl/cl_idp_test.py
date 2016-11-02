#!/usr/bin/env python3
import logging
import os

from aatest.io import ClIO
from aatest.session import SessionHandler
from future.backports.urllib.parse import quote

from saml2test.idp_test.cl_tool import ClTester
from saml2test.idp_test.setup import setup

__author__ = 'roland'

logger = logging.getLogger("")


def safe_path(entity_id, test_id):
    s = quote(entity_id)
    s = s.replace('/', '%2F')

    if not os.path.isdir('log/{}'.format(s)):
        os.makedirs('log/{}'.format(s))

    return 'log/{}/{}'.format(s, test_id)


if __name__ == "__main__":
    cargs, kwargs = setup()

    if cargs.testid:
        if cargs.testid not in kwargs['flows']:
            print(
                "The test id ({}) does not appear in the test definitions".format(
                    cargs.testid))
            exit()

        webio = ClIO(**kwargs)
        sh = SessionHandler(session={}, **kwargs)
        sh.init_session(profile=kwargs['profile'])
        tester = ClTester(webio, sh, **kwargs)
        tester.run(cargs.testid, **kwargs)
        webio.result()
        """
            webio.print_info does not exist
        """
        #filename = safe_path(kwargs['entity_id'], cargs.testid)
        #webio.print_info(cargs.testid, filename)
    else:
        _sh = SessionHandler(session={}, **kwargs)
        _sh.init_session(profile=kwargs['profile'])

        for tid in _sh["flow_names"]:
            webio = ClIO(**kwargs)
            sh = SessionHandler(session={}, **kwargs)
            sh.init_session(profile=kwargs['profile'])
            tester = ClTester(webio, sh, **kwargs)

            # quickfix: webio needs a session
            webio.session = sh
            if tester.run(tid, **kwargs):
                webio.result()
