import logging
from saml2.time_util import in_a_while
from aatest import exception_trace

from aatest.check import INCOMPLETE
from aatest.io import IO
from aatest.io import SIGN
from aatest.summation import end_tags
from aatest.summation import trace_output
from aatest.summation import do_assertions
from aatest.summation import test_summation
from aatest.summation import represent_result

__author__ = 'roland'

logger = logging.getLogger(__name__)

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


class SamlClIO(IO):
    def flow_list(self, session):
        pass

    @staticmethod
    def represent_result(info, session):
        return represent_result(info, session)

    def dump_log(self, session, test_id):
        try:
            _conv = session["conv"]
        except KeyError:
            pass
        else:
            try:
                _pi = self.profile_handler(session).get_profile_info(test_id)
            except Exception as err:
                raise

            if _pi:
                sline = 60*"="
                output = ["%s: %s" % (k, _pi[k]) for k in ["Issuer", "Profile",
                                                           "Test ID"]]
                output.append("Timestamp: %s" % in_a_while())
                output.extend(["", sline, ""])
                output.extend(trace_output(_conv.trace))
                output.extend(["", sline, ""])
                output.extend(do_assertions(_conv.events))
                output.extend(["", sline, ""])
                # and lastly the result
                info = {
                    "test_output": do_assertions(_conv.events),
                    "trace": _conv.trace
                }
                output.append(
                    "RESULT: {}".format(self.represent_result(info, session)))
                output.append("")

                txt = "\n".join(output)

                print(txt)

    @staticmethod
    def result(session):
        _conv = session["conv"]
        info = {
            "test_output": _conv.events.get_data('test_output'),
            "trace": _conv.trace
        }
        _state = evaluate(session, info)
        print(("{} {}".format(SIGN[_state], session["node"].name)))

    def err_response(self, session, where, err):
        if err:
            exception_trace(where, err, logger)

        try:
            _tid = session["testid"]
            self.dump_log(session, _tid)
        except KeyError:
            pass

