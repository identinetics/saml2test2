import json
import logging
import os

from aatest.summation import represent_result
from future.backports.urllib.parse import unquote

from aatest.io import IO
from aatest.log import with_or_without_slash
from aatest.check import ERROR
from aatest.check import OK
from aatest.check import WARNING
from aatest.check import INCOMPLETE
from saml2.httputil import NotFound
from saml2.httputil import Response

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


def get_test_info(session, test_id):
    return session["test_info"][test_id]


class WebIO(IO):
    """ Create HTML responses for the web test interface """
    def __init__(self, conf=None, flows=None, profile='',
                 profile_handler=None, desc=None,
                 lookup=None, cache=None, environ=None,
                 start_response=None, **kwargs):
        IO.__init__(self, flows, profile, desc=desc,
                    profile_handler=profile_handler, cache=cache, **kwargs)
        self.conf = conf
        self.lookup = lookup
        self.environ = environ
        self.start_response = start_response
        self.cache = cache
        self.kwargs = kwargs # TODO: clarify purpose (seems to be similar to conf + additions)

    def static(self, path):
        logger.info("[static]sending: %s" % (path,))

        try:
            text = open(path, 'rb').read()
            if path.endswith(".ico"):
                self.start_response('200 OK', [('Content-Type',
                                                "image/x-icon")])
            elif path.endswith(".html"):
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif path.endswith(".json"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/json')])
            elif path.endswith(".jwt"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/jwt')])
            elif path.endswith(".txt"):
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif path.endswith(".css"):
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            else:
                self.start_response('200 OK', [('Content-Type', "text/plain")])
            return [text]
        except IOError:
            resp = NotFound()
            return resp(self.environ, self.start_response)

    def _display_log(self, root, issuer, profile):
        item = []
        if profile:
            path = os.path.join(root, issuer, profile).replace(":", "%3A")
            argv = {"issuer": unquote(issuer), "profile": profile}

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isfile(fn):
                    item.append((unquote(_name), os.path.join(profile, _name)))
        else:
            if issuer:
                argv = {'issuer': unquote(issuer), 'profile': ''}
                path = os.path.join(root, issuer).replace(":", "%3A")
            else:
                argv = {'issuer': '', 'profile': ''}
                path = root

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isdir(fn):
                    item.append((unquote(_name), os.path.join(path, _name)))

        resp = Response(mako_template="logs.mako",
                        template_lookup=self.lookup,
                        headers=[])

        item.sort()
        argv["logs"] = item
        return resp(self.environ, self.start_response, **argv)

    def display_log(self, root, issuer="", profile="", testid=""):
        logger.info("display_log root: '%s' issuer: '%s', profile: '%s' testid: '%s'",
                    root, issuer, profile, testid)
        if testid:
            path = os.path.join(root, issuer, profile, testid).replace(":", "%3A")
            return self.static(path)
        else:
            if issuer:
                return self._display_log(root, issuer, profile)
            else:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

    def flow_list(self, logfilename='', tt_entityid=''):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])

        display_args = {
            "config_name": self.conf.CONF_NAME,
            "flows": self.session["tests"],
            "profile": self.session["profile"],
            "test_info": list(self.session["test_info"].keys()),
            "base": self.conf.BASE,
            "headlines": self.desc,
            "testresults": TEST_RESULTS,
            "tt_entityid": tt_entityid,
            "td_conf_source_uri": self.conf.SOURCE_URI,
            "tc_id_infobase": "https://identinetics.github.io/SAML-Testcases/index.html#"
        }

        rendered = resp(self.environ, self.start_response, **display_args)  # __call__ will execute start_response
        return rendered

    def single_flow(self, path, logfilename='', tt_entityid='', ):
        flowstatus = None
        for jatnode in self.session._dict['tests']:
            if jatnode.name == path:
                flowstatus = jatnode
                break
        result_json = json.dumps({
            'testid': path,
            'tc_id': flowstatus.tc_id,
            'status': TEST_RESULTS[flowstatus.state],
        }, sort_keys=True)
        self.start_response('200 OK', [('Content-Type', 'application/json')])
        return result_json

    def test_info(self, testid):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])
        info = get_test_info(self.session, testid)
        argv = {
            "profile": info["profile_info"],
            "trace": info["trace"],
            "events": info["events"],
            "result": represent_result(
                self.session['conv'].events).replace("\n", "<br>\n")
        }
        logger.debug(argv)
        return resp(self.environ, self.start_response, **argv)

    # def store_test_info(self, profile_info=None):
    #     _conv = self.session["conv"]
    #     _info = {
    #         "trace": _conv.trace,
    #         "events": _conv.events,
    #         "index": self.session["index"],
    #         "seqlen": len(self.session["sequence"]),
    #         "descr": self.session["node"].desc
    #     }
    #
    #     try:
    #         _info["node"] = self.session["node"]
    #     except KeyError:
    #         pass
    #
    #     if profile_info:
    #         _info["profile_info"] = profile_info
    #     else:
    #         try:
    #             _info["profile_info"] = get_profile_info(self.session,
    #                                                      self.session["testid"])
    #         except KeyError:
    #             pass
    #
    #     self.session["test_info"][self.session["testid"]] = _info

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)

    def respond(self, resp):
        if isinstance(resp, Response):
            return resp(self.environ, self.start_response)
        else:
            return resp

    def sorry_response(self, homepage, err, context=None, exception=None):
        resp = Response(mako_template="sorry.mako",
                        template_lookup=self.lookup,
                        headers=[])
        errmsg = str(err)
        ctxmsg = "<br/>Context: " + context if context else ''
        tbmsg = "<br/>Exception: " + exception if exception else ''
        argv = {"htmlpage": homepage,
                "error_msg": errmsg,
                "context_msg": ctxmsg,
                "traceback_msg": tbmsg}
        return resp(self.environ, self.start_response, **argv)

    def opresult(self, *argv):
        return self.flow_list()
