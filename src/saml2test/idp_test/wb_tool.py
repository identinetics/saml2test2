import logging
from aatest import tool, ConfigurationError
from aatest import END_TAG
from aatest import Trace
from aatest import ConditionError
from aatest import exception_trace
from aatest.summation import store_test_state

from aatest.check import State
from aatest.check import OK, ERROR
from aatest.conversation import Conversation
from aatest.events import EV_CONDITION, EV_FAULT, EV_RESPONSE
from aatest.result import safe_path, Result
from aatest.session import Done
from aatest.verify import Verify
from aatest.comhandler import HandlerResponse

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
        try:
            self.conv.entity_id = kw_args["entity_id"]
        except KeyError:
            self.conv.disco_srv = kw_args['disco_srv']

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
        except AttributeError:
            return safe_path('disco', _pname, test_id)
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
            return self.webio.err_response("run", err)

    def run_flow(self, test_id, index=0, profiles=None, **kwargs):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        _ss = self.sh
        try:
            _ss["node"].complete = False
        except KeyError:
            pass

        self.conv.test_id = test_id
        res = Result(self.sh, self.kwargs['profile_handler'])

        if index >= len(self.conv.sequence):
            return None

        _oper = None
        for item in self.conv.sequence[index:]:
            if isinstance(item, tuple):
                cls, funcs = item
            else:
                cls = item
                funcs = {}

            logger.info("<--<-- {} --- {} -->-->".format(index, cls))
            self.conv.events.store('operation', cls, sender='run_flow')
            try:
                _oper = cls(conv=self.conv, webio=self.webio, sh=self.sh,
                            profile=self.profile, test_id=test_id,
                            funcs=funcs, check_factory=self.chk_factory,
                            cache=self.cache)
                # self.conv.operation = _oper
                if profiles:
                    profile_map = profiles.PROFILEMAP
                else:
                    profile_map = None
                _oper.setup(profile_map)
                oper_response = _oper()
            except ConditionError:
                store_test_state(self.sh, self.conv.events)
                res.store_test_info()
                res.print_info(test_id, self.fname(test_id))
                return False
            except Exception as err:
                exception_trace('run_flow', err)
                self.conv.events.store(EV_FAULT, err)
                # self.sh["index"] = index
                store_test_state(self.sh, self.conv.events)
                res.store_test_info()
                res.print_info(test_id, self.fname(test_id))
                return False
            else:
                # *?*
                #if isinstance(oper_response, self.response_cls):
                #    return oper_response

                if oper_response:
                    if False:
                        return oper_response

                    if self.com_handler:

                        self.com_handler.conv = self.conv
                        #self.com_handler.auto_close_urls = self.my_endpoints()

                        if kwargs.conf.DO_NOT_VALIDATE_TLS:
                            self.com_handler.verify_ssl = False
                        else:
                            self.com_handler.verify_ssl = True

                        com_handler_response = self.com_handler(oper_response)

                        if com_handler_response.status == HandlerResponse.STATUS_NOT_TRIGGERED:
                            return oper_response

                        if com_handler_response.status == HandlerResponse.STATUS_NO_INTERACTION_FOUND:
                            response = self.webio.respond(com_handler_response)
                            return response

                        if com_handler_response.status == HandlerResponse.STATUS_ERROR:
                            msg = 'Com handler failed to process interaction'
                            self.conv.events.store(EV_CONDITION, State('Assertion Error', ERROR, message=msg),
                                                    sender='wb_tool')
                            store_test_state(self.sh, self.conv.events)
                            res.store_test_info()
                            res.print_info(test_id, self.fname(test_id))
                            return False


                    """
                    Guesswork about what was intended to happen here.
                    Cases:
                    1. If it is an saml2.httputil.Redirect, it should be handle by the browser.
                    Are there other cases?
                    """

                    if isinstance(oper_response, Redirect):
                        # saml2.httputil.Redirect
                        return oper_response




                    if False:
                        """
                        Basically, now clear idea what this code whas expected to do ?
                        Was this just a draft? Really working with all test flavours?
                        """

                        if com_handler_response.content_processed:
                            oper_response = _oper.handle_response(self.get_response(oper_response))

                            if oper_response:
                                return self.webio.respond(oper_response)

                        else:
                            return oper_response



            # should be done as late as possible, so all processing has been
            # done
            try:
                _oper.post_tests()
            except ConditionError:
                store_test_state(self.sh, self.conv.events)
                res.store_test_info()
                res.print_info(test_id, self.fname(test_id))
                return False

            index += 1

        _ss['index'] = self.conv.index = index

        try:
            if self.conv.flow["assert"]:
                _ver = Verify(self.chk_factory, self.conv)
                _ver.test_sequence(self.conv.flow["assert"])
        except KeyError:
            pass
        except Exception as err:
            logger.error(err)
            raise

        if isinstance(_oper, Done):
            self.conv.events.store(EV_CONDITION, State('Done', OK),
                                   sender='run_flow')
            store_test_state(self.sh, self.conv.events)
            res.store_test_info()
            res.print_info(test_id, self.fname(test_id))
        else:
            store_test_state(self.sh, self.conv.events)
            res.store_test_info()

        return True

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

        _oper = restore_operation(self.conv, self.webio, self.sh)
        return _oper.handle_response(resp)

    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.webio.flow_list(self.sh)
            else:
                try:
                    p = self.sh["testid"].split('-')
                except KeyError:
                    rendered = self.webio.flow_list(self.sh, tt_entityid=self.webio.kwargs['entity_id'])
                    return rendered
                else:
                    resp = Redirect("%sopresult#%s" % (self.webio.conf.BASE,
                                                       p[1]))
                    return resp(self.webio.environ, self.webio.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.webio.err_response("session_setup", err)

    def cont(self, environ, ENV):
        query = parse_qs(environ["QUERY_STRING"])
        path = query["path"][0]
        index = int(query["index"][0])

        try:
            index = self.sh["index"]
        except KeyError:  # Cookie delete broke session
            self.setup(path, **ENV)
        except Exception as err:
            return self.webio.err_response("session_setup", err)
        else:
            self.conv = self.sh["conv"]

        index += 1

        try:
            return self.run_flow(path, ENV["conf"], index)
        except Exception as err:
            exception_trace("", err, logger)
            self.webio.print_info(self.sh, path)
            return self.webio.err_response("run", err)

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
                                                  self.webio,
                                                  self.message_factory)
        if resp:
            return resp

        index += 1

        return self.run_flow(self.sh["testid"], index=index)
