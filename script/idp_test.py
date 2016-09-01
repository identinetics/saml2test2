#!/usr/bin/env python

#import sys
#print('\n'.join(sys.path))


import os
import logging
from aatest.check import State, OK, ERROR
from aatest.events import EV_CONDITION, EV_PROTOCOL_RESPONSE, NoSuchEvent
from aatest.result import Result
from aatest.verify import Verify
from future.backports.urllib.parse import quote_plus
from future.backports.urllib.parse import parse_qs

from aatest.summation import store_test_state
from aatest.session import Done
#from aatest.session import SessionHandler

from saml2.httputil import BadRequest
from saml2.httputil import get_post
from saml2.httputil import Response
from saml2.httputil import ServiceError
from saml2.response import StatusError

from saml2test.idp_test.inut import WebIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.wb_tool import Tester
from saml2test.request import ServiceProviderRequestHandlerError
from saml2test.session import SessionHandler
from saml2test.checkedconfig import ConfigError

from saml2.entity import Entity
from saml2 import BINDING_HTTP_POST
from saml2 import samlp

from saml2test.idp_test.metadata import MyMetadata
import json
import threading
SERVER_LOG_FOLDER = os.path.abspath("server_log")
if not os.path.isdir(SERVER_LOG_FOLDER):
    os.makedirs(SERVER_LOG_FOLDER)

try:
    from mako.lookup import TemplateLookup
except Exception as ex:
    raise ex

LOGGER = logging.getLogger("")


def pick_args(args, kwargs):
    return dict([(k, kwargs[k]) for k in args])


def do_next(tester, resp, sh, inut, filename, path):
    tester.conv = tester.sh['conv']
    res = Result(tester.sh, tester.kwargs['profile_handler'])
    try:
        tester.handle_response(resp, {})
        # store_test_state(sh, sh['conv'].events)  this does actually nothing?
        res.store_test_info()

    except StatusError as err:
        # store event to be found in assertion test
        tester.conv.events.store(EV_PROTOCOL_RESPONSE,err)
        msg = "{}: {}".format(err.__class__.__name__, str(err))

    except ServiceProviderRequestHandlerError as err:
        msg = str(err)
        tester.conv.events.store(EV_CONDITION, State('SP Error', ERROR,  message=msg),
                                 sender='do_next')

    tester.conv.index += 1
    lix = len(tester.conv.sequence)
    while tester.conv.sequence[tester.conv.index] != Done:
        resp = tester.run_flow(tester.conv.test_id, index=tester.conv.index)
        store_test_state(sh, sh['conv'].events)
        if isinstance(resp, Response):
            res.store_test_info()
            return resp(inut.environ, inut.start_response)
        elif resp is False:
            break
        if tester.conv.index >= lix:
            break

    _done = False
    for _cond in tester.conv.events.get_data(EV_CONDITION):
        if _cond.test_id == 'Done' and _cond.status == OK:
            _done = True
            break

    if not _done:
        tester.conv.events.store(EV_CONDITION, State('Done', OK),
                                 sender='do_next')

        if 'assert' in tester.conv.flow:
            _ver = Verify(tester.chk_factory, tester.conv)
            try:
                _ver.test_sequence(tester.conv.flow["assert"])
            except NoSuchEvent as err:
                tester.conv.events.store(EV_CONDITION, State('Assertion Error', ERROR, message=msg),
                                         sender='idp_test')
            except Exception as err:
                msg = "ERROR Assertion verification had gone wrong."
                raise Exception(msg)

        store_test_state(sh, sh['conv'].events)
        res.store_test_info()

    html_page = inut.flow_list(filename)
    return html_page


class SessionStore(list):
    def append(self, element):
        key = hex(id(element['session_info']))
        for e in self:
            e_key = hex(id(e['session_info']))
            if e_key == key:
                return
        list.append(self,element)

    def get_session_by_conv_id(self,conv_id):
        for e in self:
            try:
                session_info = e['session_info']
                conv = session_info['conv']
                id = conv.id
                if id == conv_id:
                    return session_info
            except KeyError as e:
                # entries without these infos are broken (unfinished). Ignoring.
                pass
        return None


class Application(object):
    def __init__(self, webenv):
        self.webenv = webenv
        self.session_store = SessionStore()

    def _static(self, path):
        if path in ["robots.txt", 'favicon.ico']:
            return "{}/robots.txt".format(self.webenv['static'])
        else:
            for p in ['acs/site/static/', 'site/static/', 'static/', 'export/']:
                if path.startswith(p):
                    return '{}/{}'.format(self.webenv['static'], path[len(p):])
        return ''

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

        self.session_store.append(session)

        inut = WebIO(session=sh, **self.webenv)
        inut.environ = environ
        inut.start_response = start_response

        tester = Tester(inut, sh, **self.webenv)

        _path = self._static(path)
        if _path:
            return inut.static(_path)

        if path == "" or path == "/":  # list
            return tester.display_test_list()
        elif "flow_names" not in sh:
            sh.session_init()

        if path == "logs":
            return inut.display_log("log", issuer="", profile="", testid="")
        elif path.startswith("log"):
            if path == "log" or path == "log/":
                _cc = inut.conf.CLIENT
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

            return inut.display_log("log", *parts)
        elif path.startswith("tar"):
            path = path.replace(":", "%3A")
            return inut.static(path)

        elif path.startswith("test_info"):
            p = path.split("/")
            try:
                return inut.test_info(p[1])
            except KeyError:
                return inut.not_found()
        elif path == "continue":
            return tester.cont(environ, self.webenv)
        elif path == 'reset':
            for param in ['flow', 'flow_names', 'index', 'node', 'profile',
                          'sequence', 'test_info', 'testid', 'tests']:
                try:
                    del sh[param]
                except KeyError:
                    pass
            return tester.display_test_list()
        elif path == "opresult":
            if tester.conv is None:
                return inut.sorry_response(self.webenv['base_url'],
                                           "No result to report")

            return inut.opresult(tester.conv, sh)
        # expected path format: /<testid>[/<endpoint>]
        elif path in sh["flow_names"]:
            resp = tester.run(path, **self.webenv)
            store_test_state(sh, sh['conv'].events)
            filename = self.webenv['profile_handler'](sh).log_path(path)
            if isinstance(resp, Response):
                res = Result(sh, self.webenv['profile_handler'])
                res.store_test_info()
                res.print_info(path, tester.fname(path))
                return inut.respond(resp)
            else:
                return inut.flow_list(filename)
        elif path == "acs/post":
            qs = get_post(environ).decode('utf8')
            resp = dict([(k, v[0]) for k, v in parse_qs(qs).items()])

            try:
                test_id = sh['conv'].test_id
            except KeyError as err:
                test_id = None

            if not test_id:
                """
                In other words: we've been contacted by robobrowser and are in a different environment now, than the
                code expects us to be. .... Hopefully, trickery and recreating of the environment will lead mostly
                to more intended effects than unintended ones.

                This is unfinished business: You can add other bindings here, to expand what RB can be used to test.
                """
                try:
                    txt = resp['SAMLResponse']
                    xmlstr = Entity.unravel(txt, BINDING_HTTP_POST)
                except Exception as e:
                    msg = 'Decoding not supported in the SP'
                    raise Exception(msg)

                rsp = samlp.any_response_from_string(xmlstr)
                original_request_id = rsp.in_response_to
                requester_session = self.session_store.get_session_by_conv_id(original_request_id)

                # recreating the environment. lets hope it is somewhat reentrant resistant
                sh = requester_session
                inut = WebIO(session=sh, **self.webenv)
                inut.environ = environ
                inut.start_response = start_response

                tester = Tester(inut, sh, **self.webenv)





            profile_handler = self.webenv['profile_handler']
            _sh = profile_handler(sh)
            #filename = self.webenv['profile_handler'](sh).log_path(test_id)
            #_sh.session.update({'conv': 'foozbar'})
            filename = _sh.log_path(test_id)

            html_page = do_next(tester, resp, sh, inut, filename, path)
            return html_page
        elif path == "acs/redirect":
            qs = environ['QUERY_STRING']
            resp = dict([(k, v[0]) for k, v in parse_qs(qs).items()])
            filename = self.webenv['profile_handler'](sh).log_path(
                sh['conv'].test_id)

            return do_next(tester, resp, sh, inut, filename, path)
        elif path == "acs/artifact":
            pass
        elif path == "ecp":
            pass
        elif path == "disco":
            qs = parse_qs(environ['QUERY_STRING'])
            resp = dict([(k, v[0]) for k, v in qs.items()])
            filename = self.webenv['profile_handler'](sh).log_path(
                sh['conv'].test_id)
            return do_next(tester, resp, sh, inut, filename, path=path)
        elif path == "slo":
            pass
        elif path == 'all':
            for test_id in sh['flow_names']:
                resp = tester.run(test_id, **self.webenv)
                store_test_state(sh, sh['conv'].events)
                if resp is True or resp is False:
                    continue
                elif resp:
                    return resp(environ, start_response)
                else:
                    resp = ServiceError('Unkown service error')
                    return resp(environ, start_response)

            filename = self.webenv['profile_handler'](sh).log_path(path)
            return inut.flow_list(filename)
        else:
            resp = BadRequest()
            return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    from mako.lookup import TemplateLookup

    try:
        cargs, kwargs, CONF = setup('wb')
    except ConfigError as e:
        str = e.error_details_as_string()
        print ('Error: {}'.format(e))
        if (str):
            print (str)
        os.sys.exit(-1)

    if CONF.config_infos:
        print ('Please notice these infos:')
        for info in CONF.config_infos:
            print (info)

    if cargs.metadata:
        md = MyMetadata(cargs, kwargs)
        xml = md.get_xml_output()
        if cargs.outputfile:
            output_file = open(cargs.outputfile, "w+")
            output_file.write(xml)
            output_file.close()
        else:
            print(xml)
        exit(0)

    if cargs.json:
        cdict = CONF.__dict__
        json_dump = json.dumps(cdict, indent=1)
        configdir = cargs.configdir
        json_ready = json_dump.replace(configdir, '.')

        md = MyMetadata(cargs, kwargs)
        xml = md.get_xml_output()

        generated_dir = os.path.join(configdir, 'generated')
        if not os.path.exists(generated_dir):
            os.makedirs(generated_dir)
        output_file = open(os.path.join(generated_dir,'config.json'), "w")
        output_file.write(json_ready)
        output_file.close()
        output_file = open(os.path.join(generated_dir,'metadata.xml'), "w")
        output_file.write(xml)
        output_file.close()
        exit(0)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    _tr = kwargs['template_root']
    LOOKUP = TemplateLookup(directories=[_tr + 'templates', _tr + 'htdocs'],
                            module_directory=_tr + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    kwargs['lookup'] = LOOKUP
    _conf = kwargs['conf']

    _app = Application(webenv=kwargs)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', int(_conf.PORT)),
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
