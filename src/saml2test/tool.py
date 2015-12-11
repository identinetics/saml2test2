__author__ = 'roland'


def restore_operation(conv, io, sh):
    cls = conv.events.last('operation').data
    _oper = cls(conv=conv, io=io, sh=sh)
    req_args = conv.events.last_item('request_args')
    _oper.request_inst = _oper.req_cls(conv, req_args,
                                       binding=_oper._binding)
    _oper.response_args = {
        "outstanding": conv.events.last_item('outstanding')}
    return _oper
