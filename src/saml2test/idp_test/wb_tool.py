import logging
from aatest import tool, ConfigurationError
from aatest import END_TAG
from aatest import Trace
from aatest import exception_trace

from aatest.check import State
from aatest.check import OK
from aatest.conversation import Conversation
from aatest.events import EV_CONDITION
from aatest.events import EV_RESPONSE
from aatest.result import safe_path, Result
from aatest.session import Done
from aatest.verify import Verify

from future.backports.urllib.parse import parse_qs

from saml2.httputil import Redirect
from saml2test.tool import restore_operation

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Tester(tool.Tester):
    def setup(self, test_id, **kw_args):
        self.sh.session_setup(path=test_id)
        _flow = self.flows[test_id]
        _cli = self.make_entity(_flow["sp"], **kw_args)
        self.conv = Conversation(_flow, _cli, kw_args["msg_factory"],
                                 trace_cls=Trace, **kw_args["conv_args"])
        self.conv.entity_id = kw_args["entity_id"]
        self.conv.sequence = self.sh["sequence"]
        self.conv.events.store('test_id', test_id, sub='setup',
                               sender=self.__class__)

        self.sh['conv'] = self.conv

        if 'insecure' in kw_args:
            self.conv.interaction.verify_ssl = False
        return True

    def fname(self, test_id):
        _pname = '_'.join(self.profile)
        try:
            return safe_path(self.conv.entity_id, _pname, test_id)
        except KeyError:
            return safe_path('dummy', _pname, test_id)

    def run(self, test_id, **kw_args):
        if not self.setup(test_id, **kw_args):
            raise ConfigurationError()

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            res = Result(self.sh, None)
            res.print_info(self.sh, test_id)
            return self.inut.err_response("run", err)

    def test_result(self):
        try:
            if self.conv.flow["tests"]:
                _ver = Verify(self.chk_factory, self.conv)
                _ver.test_sequence(self.conv.flow["tests"])
        except KeyError:
            pass
        except Exception as err:
            raise

        if self.conv.events.last_item('operation') == Done:
            self.conv.events.store(EV_CONDITION, State(END_TAG, status=OK),
                                   sub='test_result', sender=self.__class__)
            return True
        else:
            return False

    def handle_response(self, resp, *args):
        if resp is None:
            return

        self.conv.events.store(EV_RESPONSE, resp, sub='handle_response',
                               sender=self.__class__)
        logger.debug(resp)

        _oper = restore_operation(self.conv, self.inut, self.sh)
        return _oper.handle_response(resp)

    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.inut.flow_list(self.sh)
            else:
                try:
                    p = self.sh["testid"].split('-')
                except KeyError:
                    return self.inut.flow_list(self.sh)
                else:
                    resp = Redirect("%sopresult#%s" % (self.inut.conf.BASE,
                                                       p[1]))
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def cont(self, environ, ENV):
        query = parse_qs(environ["QUERY_STRING"])
        path = query["path"][0]
        index = int(query["index"][0])

        try:
            index = self.sh["index"]
        except KeyError:  # Cookie delete broke session
            self.setup(path, **ENV)
        except Exception as err:
            return self.inut.err_response("session_setup", err)
        else:
            self.conv = self.sh["conv"]

        index += 1

        try:
            return self.run_flow(path, ENV["conf"], index)
        except Exception as err:
            exception_trace("", err, logger)
            self.inut.print_info(self.sh, path)
            return self.inut.err_response("run", err)

    def async_response(self, conf):
        index = self.sh["index"]
        item = self.sh["sequence"][index]
        self.conv = self.sh["conv"]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item

        logger.info("<--<-- {} --- {}".format(index, cls))
        resp = self.conv.operation.parse_response(self.sh["testid"],
                                                  self.inut,
                                                  self.message_factory)
        if resp:
            return resp

        index += 1

        return self.run_flow(self.sh["testid"], index=index)
