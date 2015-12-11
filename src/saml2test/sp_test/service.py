import logging

from aatest.session import SessionHandler

from saml2test.idp_test.io import SamlClIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.wb_tool import Tester

logger = logging.getLogger(__name__)

test_id, app_args = setup('wb')

io = SamlClIO(**app_args)
sh = SessionHandler(session={}, **app_args)
sh.init_session({}, profile=app_args['profile'])
tester = Tester(io, sh, **app_args)
tester.setup(test_id, **app_args)
tester.run(test_id, **app_args)
