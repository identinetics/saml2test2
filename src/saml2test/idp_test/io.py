from aatest.check import INCOMPLETE
from aatest.io import ClIO
from aatest.io import SIGN
from aatest.summation import end_tags
from aatest.summation import test_summation
from aatest.summation import represent_result

__author__ = 'roland'


def evaluate(session, info):
    _state = INCOMPLETE
    try:
        if end_tags(info):
            _sum = test_summation(info["test_output"], session["testid"])
            _state = _sum["status"]
    except (AttributeError, KeyError):
        pass

    session["flow"]['state'] = _state
    return _state


class SamlClIO(ClIO):
    def result(self, session):
        _conv = session["conv"]
        info = {
            "test_output": _conv.test_output,
            "trace": _conv.trace
        }
        _state = evaluate(session, info)
        print(("{} {}".format(SIGN[_state], session["node"].name)))

    def represent_result(self, info, session):
        return represent_result(info, session, evaluate)
