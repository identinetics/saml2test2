__author__ = 'roland'


class ProtocolMessage(object):
    def __init__(self, conv, req_args, binding, msg_param=None):
        self.conv = conv
        self.entity = conv.entity
        self.req_args = req_args
        self.binding = binding
        self.msg_param = msg_param or {}
        self.response_args = {}

    def construct_message(self, *args):
        raise NotImplementedError


