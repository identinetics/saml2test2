import re
import sys
import inspect

from aatest.check import Check
from aatest.check import CRITICAL
from aatest.events import EV_HTML_SRC

__author__ = 'roland'


class VerifyPage(Check):
    """
    Verify that the specified patterns appear in the HTML page
    """
    cid = "verify_page"
    msg = "HTML verification failed"

    def _func(self, conv):
        html = conv.events.last_item(EV_HTML_SRC)
        pattern = conv.extra_args['target_info']['echopageContentPattern']

        for pat in pattern:
            if not re.search(pat, html):
                self._message = "Could not find '{}' on page".format(pat)
                self._status = CRITICAL

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
