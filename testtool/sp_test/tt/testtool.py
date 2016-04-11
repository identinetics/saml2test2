import copy
import importlib
import logging
import sys
import traceback
import yaml

from aatest import Trace
from aatest.events import Events
from aatest.events import EV_REQUEST
from aatest.events import EV_RESPONSE
from aatest.session import SessionHandler

from future.backports.urllib.parse import parse_qs

from mako.lookup import TemplateLookup

from saml2.httputil import NotFound, SeeOther
from saml2.httputil import get_post
from saml2.httputil import ServiceError
from saml2.httputil import Response

from saml2.config import IdPConfig
from saml2.mdstore import MetadataStore

from saml2test.idp_test.prof_util import ProfileHandler
from saml2test.sp_test.io import WebIO
from saml2test.sp_test.setup import make_entity
from saml2test.sp_test.tool import WebTester
from saml2test.sp_test.util import parse_yaml_conf
from saml2test.util import extract_from_request
from saml2test.util import get_check

__author__ = 'roland'

logger = logging.getLogger("")
LOGFILE_NAME = 'tt.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


POSTFIX2MIME = {
    'ico': "image/x-icon",
    'gif': "image/gif",
    'png': "image/png",
    'jpg': "image/jpeg",
    'html': 'text/html',
    'json': 'application/json',
    'txt': 'text/plain',
    'css': 'text/css',
    'xml': "text/xml"
}


# noinspection PyUnresolvedReferences
def static(path, environ, start_response):
    logger.info("[static]sending: %s" % (path,))

    _post = path.rsplit('.', 1)[-1]

    try:
        content = POSTFIX2MIME[_post]
    except KeyError:
        content = "text/xml"

    try:
        resp = Response(open(path, 'rb').read(), content=content)
        return resp(environ, start_response)
    except IOError:
        _dir = os.getcwd()
        resp = NotFound("{} not in {}".format(path, _dir))
    except Exception as err:
        resp = NotFound('{}'.format(err))

    return resp(environ, start_response)


def css(environ, event_db):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp


def start_page(environ, start_response, target):
    msg = open('start_page.html').read().format(target=target)
    resp = Response(msg)
    return resp(environ, start_response)


# =============================================================================


class Application(object):
    def __init__(self, idp_conf, mds, base, **kwargs):
        self.idp_conf = idp_conf
        self.mds = mds
        self.base = base
        self.kwargs = kwargs

        self.events = Events()
        self.endpoints = {}
        self.register_endpoints()

    def register_endpoints(self):
        ic = list(self.idp_conf.values())[0]
        spe = ic.service_per_endpoint()
        blen = len(self.base) + 1
        for url, (service, binding) in spe.items():
            url = url[blen:]
            self.endpoints[url] = (service, binding)

    def store_response(self, response):
        self.events.store(EV_RESPONSE, response.info())

    def wsgi_wrapper(self, environ, func, **kwargs):
        kwargs = extract_from_request(environ, kwargs)
        self.events.store(EV_REQUEST, kwargs)
        args = func(**kwargs)

        try:
            resp, state = args
            self.store_response(resp)
            return resp
        except TypeError:
            resp = args
            self.store_response(resp)
            return resp
        except Exception as err:
            logger.error("%s" % err)
            raise

    def handle(self, environ, tester, service, binding):
        _sh = tester.sh
        qs = get_post(environ).decode('utf8')
        resp = dict([(k, v[0]) for k, v in parse_qs(qs).items()])
        filename = self.kwargs['profile_handler'](_sh).log_path(
            _sh['conv'].test_id)

        return tester.do_next(resp, filename)

    @staticmethod
    def pick_grp(name):
        return name.split('-')[1]

    # publishes the IdP endpoints
    def application(self, environ, start_response):
        logger.info("Connection from: %s" % environ["REMOTE_ADDR"])
        session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')
        logger.info("path: %s" % path)
        self.events.store(EV_REQUEST, path)

        try:
            sh = session['session_info']
        except KeyError:
            sh = SessionHandler(**self.kwargs)
            sh.session_init()
            session['session_info'] = sh

        inut = WebIO(session=sh, **self.kwargs)
        inut.environ = environ
        inut.start_response = start_response

        tester = WebTester(inut, sh, **self.kwargs)

        if path == "robots.txt":
            return static("static/robots.txt", environ, start_response)
        elif path.startswith("static/"):
            return static(path, environ, start_response)
        elif path == 'test_info':
            resp = Response(self.events.to_html())
            return resp(environ, start_response)
        elif path == "" or path == "/":  # list
            return tester.display_test_list()
        elif path in self.kwargs['flows'].keys():  # Run flow
            resp = tester.run(path, **self.kwargs)
            if resp is True or resp is False:
                return tester.display_test_list()
            else:
                return resp(environ, start_response)
        elif path == 'display':
            return inut.flow_list()
        elif path == "opresult":
            resp = SeeOther(
                "/display#{}".format(self.pick_grp(sh['conv'].test_id)))
            return resp(environ, start_response)
        elif path.startswith("test_info"):
            p = path.split("/")
            try:
                return inut.test_info(p[1])
            except KeyError:
                return inut.not_found()
        elif path == 'all':
            for test_id in sh['flow_names']:
                resp = tester.run(test_id, **self.kwargs)
                if resp is True or resp is False:
                    continue
                elif resp:
                    return resp(environ, start_response)
                else:
                    resp = ServiceError('Unkown service error')
                    return resp(environ)
            return tester.display_test_list()

        for endpoint, (service, binding) in self.endpoints:
            if path == endpoint:
                logger.info("service: {}, binding: {}".format(service, binding))
                try:
                    resp = self.handle(environ, tester, service, binding)
                    return resp(environ, start_response)
                except Exception as err:
                    print("%s" % err)
                    message = traceback.format_exception(*sys.exc_info())
                    print(message)
                    logger.exception("%s" % err)
                    resp = ServiceError("%s" % err)
                    return resp(environ)

        logger.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)


if __name__ == '__main__':
    import argparse
    from beaker.middleware import SessionMiddleware

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    from saml2.saml import factory as saml_message_factory

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-p', dest="profile", action='append')
    parser.add_argument('-t', dest="target_info")
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-y', dest='yaml_flow', action='append')
    parser.add_argument(
        '-c', dest="ca_certs",
        help=("CA certs to use to verify HTTPS server certificates, ",
              "if HTTPS is used and no server CA certs are defined then ",
              "no cert verification will be done"))
    parser.add_argument(dest="config")
    args = parser.parse_args()

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        # 'session.key': "{}.beaker.session.id".format(
        #     urlparse(_base).netloc.replace(":", "."))
    }

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}
    for flow_def in args.yaml_flow:
        spec = parse_yaml_conf(flow_def)
        fdef['Flows'].update(spec['Flows'])
        fdef['Desc'].update(spec['Desc'])
        fdef['Order'].extend(spec['Order'])

    # Filter based on profile
    keep = []
    for key, val in fdef['Flows'].items():
        for p in args.profile:
            if p in val['profiles']:
                keep.append(key)

    for key in list(fdef['Flows'].keys()):
        if key not in keep:
            del fdef['Flows'][key]

    stream = open(args.target_info, 'r')
    target_info = yaml.safe_load(stream)
    stream.close()

    config = importlib.import_module(args.config)

    _idp_conf = {}
    for eid, conf in config.CONFIG.items():
        _idp_conf[eid] = IdPConfig()
        _idp_conf[eid].load(config.CONFIG['basic'])

    if args.insecure:
        disable_validation = True
    else:
        disable_validation = False

    ic = list(_idp_conf.values())[0]
    mds = MetadataStore(ic.attribute_converters, ic,
                        disable_ssl_certificate_validation=disable_validation)

    mds.imp(config.METADATA)
    for key in config.CONFIG.keys():
        _idp_conf[key].metadata = mds

    kwargs = {"base_url": copy.copy(config.BASE), 'idpconf': _idp_conf,
              "flows": fdef['Flows'], "order": fdef['Order'],
              "desc": fdef['Desc'], 'metadata': mds,
              "profile": args.profile, "msg_factory": saml_message_factory,
              "check_factory": get_check, 'conf': config,
              "cache": {}, "entity_id": ic.entityid,
              "profile_handler": ProfileHandler, 'map_prof': None,
              'trace_cls': Trace, 'lookup': LOOKUP,
              'make_entity': make_entity,
              # 'conv_args': {'entcat': collect_ec(),
              'target_info': target_info
              }

    if args.ca_certs:
        kwargs['ca_certs'] = args.ca_certs

    _app = Application(idp_conf=_idp_conf, mds=mds, base=config.BASE,
                       target=target_info, **kwargs)

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(config.PORT)),
        SessionMiddleware(_app.application, session_opts))

    if ic.entityid.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT,
                                            config.SERVER_KEY,
                                            config.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "SP test tool started. EntityID: {}".format(ic.entityid)
    logger.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
