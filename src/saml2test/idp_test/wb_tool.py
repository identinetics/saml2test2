import logging
from aatest import tool
from aatest import END_TAG
from aatest import Trace
from aatest import exception_trace
from aatest.conversation import Conversation
from aatest.session import Done
from aatest.verify import Verify
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
        self.conv.sequence = self.sh.session["sequence"]
        self.conv.events.store('test_id', test_id)

        if 'insecure' in kw_args:
            self.conv.interaction.verify_ssl = False

    def run(self, test_id, **kwargs):
        # noinspection PyTypeChecker
        try:
            return self.do_operation(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            self.io.dump_log(self.sh.session, test_id)
            return self.io.err_response(self.sh.session, "run", err)

    def do_operation(self, test_id, index=0):
        if index >= len(self.conv.sequence):
            return None

        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        _ss = self.sh.session
        try:
            _ss["node"].complete = False
        except KeyError:
            pass

        self.conv.test_id = test_id
        self.conv.index = index

        item = self.conv.sequence[index]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item
            funcs = {}

        logger.info("<--<-- {} --- {} -->-->".format(index, cls))
        self.conv.events.store('operation', cls)
        try:
            _oper = cls(conv=self.conv, io=self.io, sh=self.sh)
            _oper.setup()
            logger.debug("Running operation")
            return _oper()
        except Exception as err:
            self.sh.session["index"] = index
            return self.io.err_response(self.sh.session, "run_sequence",
                                        err)

    def test_result(self):
        try:
            if self.conv.flow["tests"]:
                _ver = Verify(self.chk_factory, self.conv.msg_factory,
                              self.conv)
                _ver.test_sequence(self.conv.flow["tests"])
        except KeyError:
            pass
        except Exception as err:
            raise

        if self.conv.events.last_item('operation') == Done:
            self.conv.events.store('condition', END_TAG)
            return True
        else:
            return False

    def handle_response(self, resp, conv, *args):
        if resp is None:
            return

        self.conv.events.store('received', resp)
        logger.debug(resp)

        _oper = restore_operation(self.conv, self.io, self.sh)
        return _oper.handle_response(resp)
