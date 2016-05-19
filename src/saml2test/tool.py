from aatest.events import EV_REQUEST_ARGS, NoSuchEvent

__author__ = 'roland'


def restore_operation(conv, inut, sh):
    cls = conv.events.last('operation').data
    oper = cls(conv=conv, inut=inut, sh=sh)

    try:
        req_args = conv.events.last_item(EV_REQUEST_ARGS)
    except NoSuchEvent:
        req_args = {}

    try:
        _req_cls = oper.req_cls
    except AttributeError:
        pass
    else:
        oper.request_inst = _req_cls(conv, req_args, binding=oper._binding)

    try:
        outs = conv.events.last_item('outstanding')
    except NoSuchEvent:
        pass
    else:
        oper.response_args = {"outstanding": outs}
    return oper
