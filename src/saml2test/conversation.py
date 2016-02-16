import logging
from aatest import conversation
from aatest.events import EV_OPERATION
from aatest.events import EV_REQUEST_ARGS

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Conversation(conversation.Conversation):
    def restore_operation(self, io, sh):
        cls = self.events.last_item(EV_OPERATION)
        _oper = cls(conv=self, io=io, sh=sh)
        req_args = self.events.last_item(EV_REQUEST_ARGS)
        _oper.request_inst = _oper.req_cls(self, req_args,
                                           binding=_oper._binding)
        _oper.response_args = {
            "outstanding": self.events.last_item('outstanding')}
        return _oper
