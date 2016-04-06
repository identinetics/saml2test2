import logging

from aatest import tool
from aatest import exception_trace
from aatest import Trace

from saml2test.conversation import Conversation

logger = logging.getLogger(__name__)

__author__ = 'roland'


class OperationError(Exception):
    pass


class ClTester(tool.Tester):
    def __init__(self, io, sh, profile, flows, check_factory,
                 msg_factory, cache, make_entity, map_prof,
                 trace_cls, com_handler, **kwargs):
        tool.Tester.__init__(self, io, sh, profile, flows,
                             check_factory, msg_factory, cache, make_entity,
                             map_prof, trace_cls, com_handler, **kwargs)
        self.features = {}

    def run(self, test_id, **kw_args):
        self.sh.session_setup(path=test_id)
        _flow = self.flows[test_id]
        _cli = self.make_entity(_flow["sp"], **kw_args)
        self.conv = Conversation(_flow, _cli, kw_args["msg_factory"],
                                 trace_cls=Trace, **kw_args["conv_args"])
        self.conv.entity_id = kw_args["entity_id"]
        _cli.conv = self.conv
        self.conv.sequence = self.sh["sequence"]

        self.sh["conv"] = self.conv

        self.com_handler.conv = self.conv
        self.com_handler.auto_close_urls = self.my_endpoints()
        if 'insecure' in kw_args:
            self.com_handler.verify_ssl = False

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            self.inut.print_info(self.sh, test_id)
            return self.inut.err_response(self.sh, "run", err)

    def my_endpoints(self):
        return [e for e, b in
                self.conv.entity.config.getattr("endpoints", "sp")[
                    "assertion_consumer_service"]]
