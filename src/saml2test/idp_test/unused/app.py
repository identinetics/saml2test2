#!/usr/bin/env python

import os
import logging
from aatest.check import State, OK
from aatest.events import EV_CONDITION
from aatest.result import Result, safe_path
from aatest.verify import Verify
from future.backports.urllib.parse import quote_plus
from future.backports.urllib.parse import parse_qs

from aatest.summation import store_test_state
from aatest.session import SessionHandler, Done

from saml2.httputil import BadRequest
from saml2.httputil import get_post
from saml2.httputil import Response
from saml2test.idp_test.webio import WebIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.wb_tool import Tester

SERVER_LOG_FOLDER = "server_log"

if not os.path.isdir(SERVER_LOG_FOLDER):
    os.makedirs(SERVER_LOG_FOLDER)

try:
    from mako.lookup import TemplateLookup
except Exception as ex:
    raise ex

LOGGER = logging.getLogger("")


def pick_args(args, kwargs):
    return dict([(k, kwargs[k]) for k in args])


def do_next(tester, resp, sh, webio, filename, path):
    tester.conv = tester.sh['conv']
    tester.handle_response(resp, {})

    store_test_state(sh, sh['conv'].events)
    tester.webio.store_test_info()

    tester.conv.index += 1
    lix = len(tester.conv.sequence)
    while tester.conv.sequence[tester.conv.index] != Done:
        resp = tester.run_flow(tester.conv.test_id, index=tester.conv.index)
        store_test_state(sh, sh['conv'].events)
        if isinstance(resp, Response):
            webio.print_info(path, filename)
            return resp
        if tester.conv.index >= lix:
            break

    if tester.conv.events.last_item(EV_CONDITION).test_id == 'Done':
        pass
    else:
        if 'assert' in tester.conv.flow:
            _ver = Verify(tester.chk_factory, tester.conv)
            _ver.test_sequence(tester.conv.flow["assert"])
        tester.conv.events.store(EV_CONDITION, State('Done', status=OK))

    store_test_state(sh, sh['conv'].events)
    tester.webio.store_test_info()
    return webio.flow_list(filename)


class Application(object):
    def __init__(self, webenv):
        self.webenv = webenv

    def application(self, environ, start_response):
        LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
        session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')
        LOGGER.info("path: %s" % path)

        try:
            sh = session['session_info']
        except KeyError:
            sh = SessionHandler(**self.webenv)
            sh.session_init()
            session['session_info'] = sh

        webio = WebIO(session=sh, **self.webenv)
        webio.environ = environ
        webio.start_response = start_response

        tester = Tester(webio, sh, **self.webenv)

        if path == "robots.txt":
            return webio.static("static/robots.txt")
        elif path == "favicon.ico":
            return webio.static("static/favicon.ico")
        elif path.startswith('acs/site/static'):
            path = path[4:]
            return webio.static(path)
        elif path.startswith("site/static/") or path.startswith('static/'):
            return webio.static(path)
        elif path.startswith("export/"):
            return webio.static(path)

        if path == "" or path == "/":  # list
            return tester.display_test_list()
        elif "flow_names" not in sh:
            sh.session_init()

        if path == "logs":
            return webio.display_log("log", issuer="", profile="", testid="")
        elif path.startswith("log"):
            if path == "log" or path == "log/":
                _cc = webio.conf.CLIENT
                try:
                    _iss = _cc["srv_discovery_url"]
                except KeyError:
                    _iss = _cc["provider_info"]["issuer"]
                parts = [quote_plus(_iss)]
            else:
                parts = []
                while path != "log":
                    head, tail = os.path.split(path)
                    # tail = tail.replace(":", "%3A")
                    # if tail.endswith("%2F"):
                    #     tail = tail[:-3]
                    parts.insert(0, tail)
                    path = head

            return webio.display_log("log", *parts)
        elif path.startswith("tar"):
            path = path.replace(":", "%3A")
            return webio.static(path)

        elif path.startswith("test_info"):
            p = path.split("/")
            try:
                return webio.test_info(p[1])
            except KeyError:
                return webio.not_found()
        elif path == "continue":
            return tester.cont(environ, self.webenv)
        elif path == 'reset':
            for param in ['flow', 'flow_names', 'index', 'node', 'profile',
                          'sequence', 'test_info', 'test_id', 'tests']:
                del sh[param]
            return tester.display_test_list()
        elif path == "opresult":
            if tester.conv is None:
                return webio.sorry_response("", "No result to report")

            return webio.opresult(tester.conv, sh)
        # expected path format: /<testid>[/<endpoint>]
        elif path in sh["flow_names"]:
            resp = tester.run(path, **self.webenv)
            store_test_state(sh, sh['conv'].events)
            filename = self.webenv['profile_handler'](sh).log_path(path)
            if isinstance(resp, Response):
                res = Result(sh, self.webenv['profile_handler'])
                res.store_test_info()
                res.print_info(path, tester.fname(path))
                return webio.respond(resp)
            else:
                return webio.flow_list(filename)
        elif path == "acs/post":
            qs = get_post(environ).decode('utf8')
            resp = dict([(k, v[0]) for k, v in parse_qs(qs).items()])
            filename = self.webenv['profile_handler'](sh).log_path(tester.conv.test_id)

            return do_next(tester, resp, sh, webio, filename, path)
        elif path == "acs/redirect":
            qs = environ['QUERY_STRING']
            resp = dict([(k, v[0]) for k, v in parse_qs(qs).items()])
            filename = self.webenv['profile_handler'](sh).log_path(tester.conv.test_id)

            return do_next(tester, resp, sh, webio, filename, path)
        elif path == "acs/artifact":
            pass
        elif path == "ecp":
            pass
        elif path == "disco":
            pass
        elif path == "slo":
            pass
        else:
            resp = BadRequest()
            return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    from mako.lookup import TemplateLookup

    cargs, kwargs = setup('wb')

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    LOOKUP = TemplateLookup(directories=['./' + 'templates', './' + 'htdocs'],
                            module_directory='./' + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    kwargs['lookup'] = LOOKUP
    _conf = kwargs['conf']

    _app = Application(webenv=kwargs)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', _conf.PORT),
                                        SessionMiddleware(_app.application,
                                                          session_opts))

    if _conf.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(_conf.SERVER_CERT, _conf.SERVER_KEY,
                                            _conf.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "SP listening on port:%s%s" % (_conf.PORT, extra)
    LOGGER.info(txt)
    print(txt)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
