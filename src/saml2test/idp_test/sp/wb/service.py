import logging
import flask

from beaker.middleware import SessionMiddleware

from flask import Flask
from flask.globals import g
from flask.sessions import SessionInterface
from flask.templating import render_template

from aatest.session import SessionHandler
# import pickle
from saml2.response import AuthnResponse

from saml2.s_utils import rndstr

from saml2test.idp_test.io import SamlClIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.sp.wb.result_db import ResultDB
from saml2test.idp_test.sp.wb.tool import Tester

logger = logging.getLogger(__name__)


class RequestCache(dict):
    pass


class BeakerSessionInterface(SessionInterface):
    def open_session(self, app, request):
        session = request.environ['beaker.session']
        return session

    def save_session(self, app, session, response):
        session.save()


def setup_tester():
    test_id, app_args = setup('wb')
    events = flask.session["events"]

    if not test_id:
        test_id = events.get('test_id')[0].data

    io = SamlClIO(**app_args)
    sh = SessionHandler(session={}, **app_args)
    sh.init_session({}, profile=app_args['profile'])
    tester = Tester(io, sh, **app_args)
    tester.setup(test_id, **app_args)
    tester.conv.events = flask.session["events"]
    tester.conv.trace = flask.session['trace']
    tester.conv.base_url = app_args["base_url"]
    tester.conv.test_id = test_id

    return tester


def entcat_test(tinfo):
    for prof in tinfo['profiles']:
        if prof == 'entcat' or prof.startswith('entcat:'):
            return True
    return False


test_id, app_args = setup('wb')

app = Flask('saml2test')

app.config.update(dict(
    TESTS=app_args["flows"],
    DISCOVERY_SERVICE=app_args.get("discovery_service", None),
    SECRET_KEY=app_args.get("secret_key", rndstr()),
    RESULT_DB='result_db'
))

session_opts = {
    # TODO can't be server-side due to pyff redirecting to disco endpoint twice
    "session.type": "memory",
    "session.validate_key": app.config["SECRET_KEY"]
}

app.wsgi_app = SessionMiddleware(app.wsgi_app, session_opts)
app.session_interface = BeakerSessionInterface()


def get_db():
    if not hasattr(g, 'result_db'):
        g.result_db = ResultDB(app.config["RESULT_DB"])
    return g.result_db


@app.route("/")
def index():
    test_results = flask.session.get("test_results", {})
    print(app.config['TESTS'])
    return render_template("test_list.html", tests=app.config['TESTS'],
                           test_results=test_results)


@app.route("/tests/<test_id>")
def run_test(test_id):
    io = SamlClIO(**app_args)
    sh = SessionHandler(session={}, **app_args)
    sh.init_session({}, profile=app_args['profile'])
    tester = Tester(io, sh, **app_args)
    tester.setup(test_id, **app_args)

    if 'events' not in flask.session:
        flask.session["events"] = tester.conv.events
    if 'trace' not in flask.session:
        flask.session["trace"] = tester.conv.trace

    print("TRACE", tester.conv.trace)
    return tester.run(test_id, **app_args)


#
# @app.route("/<test_id>/disco")
# def disco(test_id):
#     # TODO store selected IdP in session and don't redirect to discovery
#     # service every time?
#
#     idp_entity_id, request_origin = DS(
#         flask.session["request_cache"]).parse_discovery_response(
#         flask.request.args)
#
#     authn_req = SSO(flask.session["request_cache"]).make_authn_request(
#         app.config['SP'][test_id], idp_entity_id, request_origin)
#     return authn_req


@app.route("/acs/post", methods=["POST"])
def acs():
    tester = setup_tester()
    for ev in tester.conv.events:
        print(ev)

    tester.handle_response(flask.request.form, {})
    test_id = tester.conv.events.last_item('test_id')
    tester.conv.events.store("test_result", (test_id, tester.test_result()))
    test_results = dict([x for x in tester.conv.events.get_data('test_result')])

    _check = tester.conv.events.get_data('check')
    check_result = {a: {b: c} for a, b, c in _check}

    print('{}{}{}'.format(30 * '-', 'CHECK', 30 * '-'))
    print("CHECK", check_result)
    print('{}{}{}'.format(30 * '-', 'RESULT', 30 * '-'))
    print(test_results)
    print('{}{}{}'.format(30 * '-', 'INFO', 30 * '-'))
    print(app.config["TESTS"])
    print('{}{}{}'.format(30 * '-', 'TRACE', 30 * '-'))
    print("TRACE", tester.conv.trace)
    print(60 * '-')

    for a, item in check_result.items():
        for b, c in item.items():
            if b == 'verify_entity_category':
                print(a, b, c['test_result'].status)

    entcat_tests = dict(
        [(t, entcat_test(v)) for t, v in app.config['TESTS'].items()])

    return render_template("test_main.html",
                           base=tester.conv.base_url,
                           tests=app.config["TESTS"],
                           test_results=test_results,
                           check_result=check_result,
                           ec_tests=entcat_tests)


@app.route("/test_info/<test_id>")
def show_test_info(test_id):
    tester = setup_tester()
    events = tester.conv.events
    trace = tester.conv.trace
    _check = events.get_data('check')
    check_result = {a: {b: c} for a, b, c in _check}

    print("TRACE", trace)

    tinfo = app.config["TESTS"][test_id]

    if entcat_test(tinfo):
        template = "test_entcat_info.html"
        ava = tester.conv.events.get_message('protocol_response',
                                             AuthnResponse).ava
        # the specific test_result
        result = check_result[test_id]['verify_entity_category']['test_result']
    elif 'saml2int' in tinfo['profiles']:
        template = "test_saml2int_info.html"
        ava = None
        result = check_result[test_id]
    else:
        template = "test_other_info.html"
        ava = None
        result = check_result[test_id]

    return render_template(template, info=tinfo, result=result, trace=trace,
                           ava=ava)


@app.route("/results_overview")
def results_overview():
    db = get_db()

    results_overview = {}

    for idp_entity_id in db:
        if idp_entity_id not in results_overview:
            results_overview[idp_entity_id] = {}

        for result_entry in db[idp_entity_id]:
            results_overview[idp_entity_id][result_entry.test_id] = result_entry

    return render_template("results_overview.html", tests=app.config["TESTS"],
                           results_overview=results_overview)
