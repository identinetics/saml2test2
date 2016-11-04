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
from werkzeug.http import parse_accept_header


from aatest.summation import store_test_state
from aatest.session import Done
#from aatest.session import SessionHandler

from saml2.httputil import BadRequest
from saml2.httputil import get_post
from saml2.httputil import Response
from saml2.httputil import ServiceError
from saml2.response import StatusError

from saml2test.idp_test.webio import WebIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.wb_tool import Tester
from saml2test.request import ServiceProviderRequestHandlerError
from saml2test.session import SessionHandler
from saml2test.checkedconfig import ConfigError
from saml2test.acfile import WebUserAccessControlFile

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


def do_next(tester, resp, sh, webio, filename, path):
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
            return resp(webio.environ, webio.start_response)
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
                msg = str(err)
                tester.conv.events.store(EV_CONDITION, State('Assertion Error', ERROR, message=msg),
                                         sender='idp_test')
            except Exception as err:
                msg = str(err)
                tester.conv.events.store(EV_CONDITION, State('Assertion Test Program Error', ERROR, message=msg),
                                         sender='idp_test')
                msg = "ERROR Assertion verification had gone wrong."
                raise Exception(msg)

        store_test_state(sh, sh['conv'].events)
        res.store_test_info()

    html_page = webio.flow_list(filename)
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

    def is_static_path(self, path):
        if path in ["robots.txt", 'favicon.ico']:
            return "{}/robots.txt".format(self.webenv['static'])
        else:
            for p in ['acs/site/static/', 'site/static/', 'static/', 'export/']:
                if path.startswith(p):
                    return '{}/{}'.format(self.webenv['static'], path[len(p):])
        return ''

    def set_mimetype(self, environ):
        client_accepts = dict(parse_accept_header(environ['HTTP_ACCEPT']))
        if 'application/json' in client_accepts:
            self.mime_type = 'application/json'
        else:
            #fallback if the client has not told us that it is calling the API
            self.mime_type = 'text/html'

    def application(self, environ, start_response):
        LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
        session = environ['beaker.session']
        path = environ.get('PATH_INFO', '').lstrip('/')
        LOGGER.info("path: %s" % path)

        try:
            sh = session['session_info']
            local_webenv = session['webenv']
        except KeyError:
            sh = SessionHandler(**self.webenv)
            sh.session_init()
            local_webenv = self.webenv
            session['session_info'] = sh
            session['webenv'] = local_webenv
        self.session_store.append(session)

        webio = WebIO(session=sh, **local_webenv)
        webio.environ = environ # WSGI environment
        webio.start_response = start_response

        tester = Tester(webio, sh, **local_webenv)

        _static_path = self.is_static_path(path)
        if _static_path:
            return webio.static(_static_path)

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
            return tester.cont(environ, local_webenv)
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
                return webio.sorry_response(local_webenv['base_url'], "No result to report")

            return webio.opresult(tester.conv, sh)
        # expected path format: /<testid>[/<endpoint>]
        elif path in sh["flow_names"]:
            self.set_mimetype(environ)
            resp = tester.run(path, **local_webenv)
            store_test_state(sh, sh['conv'].events)
            logfilename = local_webenv['profile_handler'](sh).log_path(path)
            if isinstance(resp, Response):
                res = Result(sh, local_webenv['profile_handler'])
                res.store_test_info()
                res.print_info(path, tester.fname(path))
                return webio.respond(resp)
            else:
                if self.mime_type == 'application/json':
                    return webio.single_flow(path)
                else:
                    return webio.flow_list()
        elif path == "acs/post":
            formdata = get_post(environ).decode('utf8')
            resp = dict([(k, v[0]) for k, v in parse_qs(formdata).items()])

            try:
                test_id = sh['conv'].test_id
            except KeyError as err:
                test_id = None

            if not test_id:
                """
                    Do we have been initialized already, or is the user just on the wrong page ?
                """
                if not resp:
                    return tester.display_test_list()
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
                webio = WebIO(session=sh, **local_webenv)
                webio.environ = environ
                webio.start_response = start_response

                tester = Tester(webio, sh, **local_webenv)

            profile_handler = local_webenv['profile_handler']
            _sh = profile_handler(sh)
            #filename = self.webenv['profile_handler'](sh).log_path(test_id)
            #_sh.session.update({'conv': 'foozbar'})
            logfilename = _sh.log_path(test_id)

            content = do_next(tester, resp, sh, webio, logfilename, path)
            return content
        elif path == "acs/redirect":
            formdata = environ['QUERY_STRING']
            resp = dict([(k, v[0]) for k, v in parse_qs(formdata).items()])
            logfilename = local_webenv['profile_handler'](sh).log_path(
                sh['conv'].test_id)

            return do_next(tester, resp, sh, webio, logfilename, path)
        elif path == "acs/artifact":
            pass
        elif path == "ecp":
            pass
        elif path == "disco":
            formdata = parse_qs(environ['QUERY_STRING'])
            resp = dict([(k, v[0]) for k, v in formdata.items()])
            logfilename = local_webenv['profile_handler'](sh).log_path(
                sh['conv'].test_id)
            return do_next(tester, resp, sh, webio, logfilename, path=path)
        elif path == "slo":
            pass
        elif path == 'all':
            for test_id in sh['flow_names']:
                resp = tester.run(test_id, **local_webenv)
                store_test_state(sh, sh['conv'].events)
                if resp is True or resp is False:
                    continue
                elif resp:
                    return resp(environ, start_response)
                else:
                    resp = ServiceError('Unkown service error')
                    return resp(environ, start_response)

            logfilename = local_webenv['profile_handler'](sh).log_path(path)
            return webio.flow_list(logfilename)
        elif path == 'swconf':
            """
                switch config by user request
                parameters: ?github=<name of the github repo>&email=<user email>
            """
            formdata = parse_qs(environ['QUERY_STRING'])
            resp = dict([(k, v[0]) for k, v in formdata.items()])

            try:
                ac_file_name = local_webenv['conf'].ACCESS_CONTROL_FILE
            except Exception as e:
                ac_file_name = None

            if ac_file_name:
                try:
                    ac_file = WebUserAccessControlFile(local_webenv['conf'].ACCESS_CONTROL_FILE)
                except Exception as e:
                    return webio.sorry_response(local_webenv['base_url'],e)

                has_access = ac_file.test(resp['github'], resp['email'])
                if not has_access:
                    return webio.sorry_response(local_webenv['base_url'],'permission denied')

            # reading from github should set readjson, but to be sure ...
            setup_cargs=type('setupcarg', (object,), {'github': True, 'configdir': resp['github'], 'readjson': True })()

            try:
                user_cargs, user_kwargs, user_CONF = setup('wb', setup_cargs)
            except ConfigError as e:
                errstr = e.error_details_as_string()
                print('Error: {}'.format(e))

                return webio.sorry_response(local_webenv['base_url'],errstr)
            except Exception as e:
                return webio.sorry_response(local_webenv['base_url'],e)

            """
                picking the config stuff that the user is allowed to override
            """
            local_webenv['conf'] = user_CONF
            local_webenv['flows'] = user_kwargs['flows']

            """
                Todo: having this not cluttered would be nicer
                In other words: refactoring of setup.py
            """
            local_webenv['entity_id'] = local_webenv['conf'].ENTITY_ID
            local_webenv["insecure"] = local_webenv['conf'].DO_NOT_VALIDATE_TLS
            local_webenv["profile"] = local_webenv['conf'].FLOWS_PROFILES

            import copy
            from saml2test import metadata
            spconf = copy.deepcopy(user_CONF.CONFIG)
            acnf = list(spconf.values())[0]
            mds = metadata.load(True, acnf, user_CONF.METADATA, 'sp')
            local_webenv["metadata"] = mds


            # new webenv into session
            session['webenv'] = local_webenv

            sh = SessionHandler(**local_webenv)
            sh.session_init()
            session['session_info'] = sh

            webio = WebIO(session=sh, **local_webenv)
            webio.environ = environ
            webio.start_response = start_response

            tester = Tester(webio, sh, **local_webenv)
            return tester.display_test_list()
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

    if _conf.BASE.startswith("https") and _conf.SERVER_TLS:
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
