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
        self.kwargs = kwargs

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

    def _display(self, root, issuer, profile):
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
        logger.info(
            "display_log root: '%s' issuer: '%s', profile: '%s' testid: '%s'",
            root, issuer, profile, testid)
        if testid:
            path = os.path.join(root, issuer, profile, testid).replace(
                ":", "%3A")
            return self.static(path)
        else:
            if issuer:
                return self._display(root, issuer, profile)
            else:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

    def flow_list(self, filename=''):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])

        argv = {
            "flows": self.session["tests"],
            "profile": self.session["profile"],
            "test_info": list(self.session["test_info"].keys()),
            "base": self.conf.BASE,
            "headlines": self.desc,
            "testresults": TEST_RESULTS
        }

        return resp(self.environ, self.start_response, **argv)

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

    def sorry_response(self, homepage, err):
        resp = Response(mako_template="sorry.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"htmlpage": homepage,
                "error": str(err)}
        return resp(self.environ, self.start_response, **argv)

    def opresult(self, *argv):
        return self.flow_list()
