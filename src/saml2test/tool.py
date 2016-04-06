from aatest.events import EV_REQUEST_ARGS

__author__ = 'roland'


def restore_operation(conv, inut, sh):
    cls = conv.events.last('operation').data
    oper = cls(conv=conv, inut=inut, sh=sh)
    req_args = conv.events.last_item(EV_REQUEST_ARGS)
    oper.request_inst = oper.req_cls(conv, req_args, binding=oper._binding)
    oper.response_args = {
        "outstanding": conv.events.last_item('outstanding')}
    return oper
