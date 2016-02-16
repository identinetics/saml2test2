import logging
from urllib.parse import parse_qs

from aatest import tool
from aatest import FatalError
from aatest import exception_trace
from aatest import Trace
from aatest.conversation import Conversation
from aatest.events import EV_RESPONSE
from aatest.events import EV_HTTP_RESPONSE
from aatest.interaction import Action
from aatest.interaction import InteractionNeeded
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
        self.conv.sequence = self.sh.session["sequence"]
        if 'insecure' in kw_args:
            self.conv.interaction.verify_ssl = False

        if self.interactions:
            self.conv.interaction.interactions = self.interactions
        self.sh.session["conv"] = self.conv

        # noinspection PyTypeChecker
        try:
            return self.run_flow(test_id)
        except Exception as err:
            exception_trace("", err, logger)
            self.io.dump_log(self.sh.session, test_id)
            return self.io.err_response(self.sh.session, "run", err)

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
                #self.err_check("interaction-needed")

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
                    oper = restore_operation(self.conv, self.io, self.sh)

                oper.handle_response(res)
        else:
            oper.handle_response(resp)