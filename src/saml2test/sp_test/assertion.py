import inspect
from aatest.check import Check
from aatest.check import CRITICAL
import sys

__author__ = 'roland'


class VerifyEndpoint(Check):
    """
    Verify that an entity got redirected to the correct endpoint
    """
    cid = 'verify_endpoint'

    def _func(self, conv):
        res = {}
        _url = conv.events.last_item('redirect')

        endps = conv.entity.config.endpoint(service=self._kwargs['service'],
                                            binding=self._kwargs['binding'],
                                            context='idp')
        try:
            assert _url in endps
        except AssertionError:
            res['message'] = "The SP redirected to the wrong endpoint"
            res['status'] = CRITICAL

        return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None