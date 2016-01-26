import logging
from urllib.parse import parse_qs

from aatest import tool
from aatest import FatalError
from aatest import exception_trace
from aatest import Trace
from aatest.conversation import Conversation
from aatest.interaction import Action
from aatest.interaction import InteractionNeeded
from saml2test.tool import restore_operation

logger = logging.getLogger(__name__)

__author__ = 'roland'


class OperationError(Exception):
    pass


# def restore_operation(conv, io, sh):
#     cls = conv.events.last('operation').data
#     _oper = cls(conv=conv, io=io, sh=sh)
#     req_args = conv.events.last_item('request_args')
#     _oper.request_inst = _oper.req_cls(conv, req_args,
#                                        binding=_oper._binding)
#     _oper.response_args = {
#         "outstanding": conv.events.last_item('outstanding')}
#     return _oper


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
        self.conv.sequence = self.sh.session["sequence"]

        self.sh.session["conv"] = self.conv

        self.com_handler.conv = self.conv
        self.com_handler.auto_close_urls = self.my_endpoints()
        if 'insecure' in kw_args:
            self.com_handler.verify_ssl = False

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            self.io.dump_log(self.sh.session, test_id)
            return self.io.err_response(self.sh.session, "run", err)

    def my_endpoints(self):
        return [e for e, b in
                self.conv.entity.config.getattr("endpoints", "sp")[
                    "assertion_consumer_service"]]
