__author__ = 'roland'


class ProtocolMessage(object):
    def __init__(self, conv, req_args, binding):
        self.conv = conv
        self.entity = conv.entity
        self.req_args = req_args
        self.binding = binding
        self.response_args = {}

    def construct_message(self, *args):
        raise NotImplementedError


