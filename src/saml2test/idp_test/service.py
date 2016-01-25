import logging
from aatest.io import eval_state
from aatest.summation import trace_output, condition
from aatest.verify import Verify
import flask
from aatest.check import State, OK, STATUSCODE

from beaker.middleware import SessionMiddleware

from flask import Flask
from flask.globals import g
from flask.sessions import SessionInterface
from flask.templating import render_template

from aatest.session import SessionHandler
# import pickle
from saml2.httputil import ServiceError
from saml2.response import AuthnResponse

from saml2.s_utils import rndstr
from saml2.time_util import in_a_while

from saml2test.idp_test.io import SamlClIO
from saml2test.idp_test.setup import setup
from saml2test.idp_test.result_db import ResultDB
from saml2test.idp_test.wb_tool import Tester

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

    return tester, app_args


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

    flask.session["events"] = tester.conv.events
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
    tester, app_args = setup_tester()
    for ev in tester.conv.events:
        print(ev)

    tester.handle_response(flask.request.form, {})

    if 'assert' in tester.conv.flow:
        _ver = Verify(app_args['check_factory'], app_args['msg_factory'],
                      tester.conv)
        _ver.test_sequence(tester.conv.flow["assert"])

    sline = 60 * "="
    print("Timestamp: {}".format(in_a_while()))
    print("\n", sline, "\n")
    for l in trace_output(tester.conv.trace):
        print(l)
    print("\n", sline, "\n")
    for l in condition(tester.conv.events):
        print(l)
    print("\n", sline, "\n")

    try:
        test_results = flask.session['test_results']
    except KeyError:
        test_results = {}

    entcat_tests = dict(
        [(t, entcat_test(v)) for t, v in app.config['TESTS'].items()])

    test_results[tester.conv.events.get_data('test_id')[0]] = eval_state(
        tester.conv.events)

    check_result = ['{}: {}'.format(s.test_id, STATUSCODE[s.status]) for s in
                    tester.conv.events.get_data('condition')]

    flask.session['test_results'] = test_results
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
