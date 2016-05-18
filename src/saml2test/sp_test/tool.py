import logging

from urllib.parse import parse_qs

from aatest import tool
from aatest import FatalError
from aatest import exception_trace
from aatest import Trace
from aatest.check import OK
from aatest.check import State
from aatest.conversation import Conversation
from aatest.events import EV_RESPONSE, EV_CONDITION
from aatest.events import EV_HTTP_RESPONSE
from aatest.func import set_arg
from aatest.interaction import Action
from aatest.interaction import InteractionNeeded
from aatest.result import Result, safe_path
from aatest.session import Done
from aatest.summation import store_test_state
from aatest.verify import Verify

from saml2.httputil import Response
from saml2.httputil import Redirect

from saml2test.tool import restore_operation

logger = logging.getLogger(__name__)

__author__ = 'roland'


class OperationError(Exception):
    pass


class ClTester(tool.Tester):
    def __init__(self, io, sh, profile, flows, check_factory,
                 msg_factory, cache, make_entity, map_prof,
                 trace_cls, **kwargs):
        tool.Tester.__init__(self, io, sh, profile, flows,
                             check_factory, msg_factory, cache, make_entity,
                             map_prof, trace_cls, **kwargs)
        self.features = {}
        try:
            self.interactions = kwargs['interaction_conf']
        except (KeyError, AttributeError):
            self.interactions = None

    def run(self, test_id, **kw_args):
        self.sh.session_setup(path=test_id)
        _flow = self.flows[test_id]

        _entity = self.make_entity(_flow["idp"], **kw_args)

        self.conv = Conversation(_flow, _entity, kw_args["msg_factory"],
                                 trace_cls=Trace, **kw_args["conv_args"])
        self.conv.entity_id = kw_args["entity_id"]
        _entity.conv = self.conv
        self.conv.sequence = self.sh["sequence"]
        if 'insecure' in kw_args:
            self.conv.interaction.verify_ssl = False

        if self.interactions:
            self.conv.interaction.interactions = self.interactions
        self.sh["conv"] = self.conv

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            self.inut.print_info(self.sh, test_id)
            return self.inut.err_response("run", err)

    def my_endpoints(self):
        return [e for e, b in
                self.conv.entity.config.getattr("endpoints", "sp")[
                    "assertion_consumer_service"]]

    def intermit(self, response):
        _last_action = None
        _same_actions = 0
        if response.status_code >= 400:
            done = True
        else:
            done = False

        url = response.url
        content = response.text
        while not done:
            rdseq = []
            while response.status_code in [302, 301, 303]:
                url = response.headers["location"]
                if url in rdseq:
                    raise FatalError("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise FatalError(
                            "Too long sequence of redirects: %s" % rdseq)

                logger.info("HTTP %d Location: %s" % (response.status_code,
                                                      url))
                # If back to me
                for_me = False
                for redirect_uri in self.my_endpoints():
                    if url.startswith(redirect_uri):
                        # Back at the RP
                        self.conv.entity.cookiejar = self.cjar["rp"]
                        for_me = True
                        try:
                            base, query = url.split("?")
                        except ValueError:
                            pass
                        else:
                            response = parse_qs(query)
                            self.conv.events.store(EV_RESPONSE, response)
                            return response

                if for_me:
                    done = True
                    break
                else:
                    try:
                        logger.info("GET %s" % url)
                        response = self.conv.entity.send(url, "GET")
                    except Exception as err:
                        raise FatalError("%s" % err)

                    content = response.text
                    logger.info("<-- CONTENT: %s" % content)
                    self.position = url
                    self.conv.events.store(EV_HTTP_RESPONSE, response.text)

                    if response.status_code >= 400:
                        done = True
                        break

            if done or url is None:
                break

            _base = url.split("?")[0]

            try:
                _spec = self.conv.interaction.pick_interaction(response, _base)
            except InteractionNeeded:
                self.position = url
                cnt = content.replace("\n", '').replace("\t", '').replace("\r",
                                                                          '')
                logger.error("URL: %s" % url)
                logger.error("Page Content: %s" % cnt)
                raise
            except KeyError:
                self.position = url
                cnt = content.replace("\n", '').replace("\t", '').replace("\r",
                                                                          '')
                logger.error("URL: %s" % url)
                logger.error("Page Content: %s" % cnt)
                # self.err_check("interaction-needed")

            if _spec == _last_action:
                _same_actions += 1
                if _same_actions >= 3:
                    self.conv.trace.error("Interaction loop detection")
                    raise OperationError()
            else:
                _last_action = _spec

            if len(_spec) > 2:
                logger.info(">> %s <<" % _spec["page-type"])
                if _spec["page-type"] == "login":
                    self.login_page = content

            _op = Action(_spec["control"])
            if self.conv.interaction.verify_ssl == False:
                op_args = {"verify": False}
            else:
                op_args = {}

            try:
                response = _op(self, url, response, self.features, **op_args)
                if isinstance(response, dict):
                    self.conv.events.store(EV_RESPONSE, response)
                    return response
                content = response.text
                self.conv.events.store(EV_HTTP_RESPONSE, response)

                if response.status_code >= 400:
                    txt = "Got status code '%s', error: %s" % (
                        response.status_code, content)
                    logger.error(txt)
                    raise OperationError()
            except (FatalError, InteractionNeeded, OperationError):
                raise
            except Exception as err:
                self.conv.trace.error(err)

    def handle_response(self, resp, index, oper=None):
        if resp is None:
            return

        if self.conv.interaction.interactions:
            res = self.intermit(resp)
            if isinstance(res, dict):
                if oper is None:
                    oper = restore_operation(self.conv, self.inut, self.sh)

                oper.handle_response(res)
        else:
            oper.handle_response(resp)


class WebTester(tool.Tester):
    def fname(self, test_id):
        _pname = '_'.join(self.profile)
        try:
            return safe_path(self.conv.entity_id, _pname, test_id)
        except KeyError:
            return safe_path('dummy', _pname, test_id)

    def match_profile(self, test_id, **kwargs):
        _spec = self.flows[test_id]
        # There must be an intersection between the two profile lists.
        if set(self.profile).intersection(set(_spec["profiles"])):
            return True
        else:
            return False

    def setup(self, test_id, **kw_args):
        if not self.match_profile(test_id):
            return False

        self.sh.session_setup(path=test_id)
        _flow = self.flows[test_id]
        _ent = self.make_entity(_flow['idp'], **kw_args)
        self.conv = Conversation(_flow, _ent,
                                 msg_factory=kw_args["msg_factory"],
                                 trace_cls=self.trace_cls,
                                 target_info=kw_args['target_info'])
        _ent.conv = self.conv
        self.conv.entity_id = _ent.config.entityid
        #self.com_handler.conv = self.conv
        self.conv.sequence = self.sh["sequence"]

        try:
            self.conv.crypto_algorithms = kw_args['algorithms']
        except KeyError:
            pass

        self.sh["conv"] = self.conv
        return True

    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.inut.flow_list()
            else:
                try:
                    resp = Redirect("%s/opresult#%s" % (
                        self.inut.conf.BASE, self.sh["testid"][0]))
                except KeyError:
                    return self.inut.flow_list()
                else:
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def do_next(self, resp, filename, path, **kwargs):
        sh = self.sh

        self.conv = sh['conv']
        self.handle_response(resp, {})

        store_test_state(sh, sh['conv'].events)
        res = Result(sh, kwargs['profile_handler'])
        res.store_test_info()

        self.conv.index += 1
        lix = len(self.conv.sequence)
        while self.conv.sequence[self.conv.index] != Done:
            resp = self.run_flow(self.conv.test_id, index=self.conv.index)
            store_test_state(sh, sh['conv'].events)
            if isinstance(resp, Response):
                self.inut.print_info(path, filename)
                return resp
            if self.conv.index >= lix:
                break

        _done = False
        for _cond in self.conv.events.get_data(EV_CONDITION):
            if _cond.test_id == 'Done' and _cond.status == OK:
                _done = True
                break

        if not _done:
            self.conv.events.store(EV_CONDITION, State('Done', OK),
                                   sender='do_next')

            if 'assert' in self.conv.flow:
                _ver = Verify(self.chk_factory, self.conv)
                _ver.test_sequence(self.conv.flow["assert"])

            store_test_state(sh, sh['conv'].events)
            res.store_test_info()

        return self.inut.flow_list(filename)

    def get_response(self, resp):
        try:
            loc = resp.headers['location']
        except (AttributeError, KeyError):  # May be a dictionary
            try:
                return resp.response
            except AttributeError:
                try:
                    return resp.text
                except AttributeError:
                    if isinstance(resp, dict):
                        try:
                            self.conv.events.store('RelayState',
                                                   resp["RelayState"])
                        except KeyError:
                            pass
                        return resp["SAMLRequest"]
        else:
            try:
                _resp = dict(
                    [(k, v[0]) for k, v in parse_qs(loc.split('?')[1]).items()])
            except IndexError:
                return loc
            else:
                self.conv.events.store(EV_RESPONSE, _resp)
                self.conv.events.store('RelayState', _resp["RelayState"])
                return _resp["SAMLRequest"]

