from aatest import Trace
import argparse
import copy
import importlib
import logging
from saml2.config import IdPConfig

from saml2.saml import factory as saml_message_factory

from aatest.common import setup_logger
from saml2.server import Server

from saml2test import metadata
from saml2test.util import collect_ec, get_check
from saml2test.sp_test.util import parse_yaml_conf
import yaml

__author__ = 'roland'

logger = logging.getLogger(__name__)


def setup(use='cl'):
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest="debug", action='store_true')
    parser.add_argument('-D', dest="dump", action='store_true')
    parser.add_argument('-e', dest="entity_id")
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-i', dest="interaction")
    parser.add_argument('-k', dest="insecure", action='store_true')
    parser.add_argument('-l', dest="log_name")
    parser.add_argument('-p', dest="profile", action='append')
    parser.add_argument('-t', dest="testid")
    parser.add_argument('-y', dest='yamlflow', action='append')
    parser.add_argument('-T', dest="target_info")
    parser.add_argument(
        '-c', dest="ca_certs",
        help=("CA certs to use to verify HTTPS server certificates, ",
              "if HTTPS is used and no server CA certs are defined then ",
              "no cert verification will be done"))
    parser.add_argument(dest="config")

    cargs = parser.parse_args()

    fdef = {'Flows': {}, 'Order': [], 'Desc': []}
    for flow_def in cargs.yamlflow:
        spec = parse_yaml_conf(flow_def)
        fdef['Flows'].update(spec['Flows'])
        for param in ['Order', 'Desc']:
            try:
                fdef[param].extend(spec[param])
            except KeyError:
                pass

    # Filter based on profile
    keep = []
    for key, val in fdef['Flows'].items():
        for p in cargs.profile:
            if p in val['profiles']:
                keep.append(key)

    for key in list(fdef['Flows'].keys()):
        if key not in keep:
            del fdef['Flows'][key]

    CONF = importlib.import_module(cargs.config)
    idpconf = copy.deepcopy(CONF.CONFIG)
    acnf = list(idpconf.values())[0]
    mds = metadata.load(True, acnf, CONF.METADATA, 'idp')

    stream = open(cargs.target_info, 'r')
    target_info = yaml.safe_load(stream)
    stream.close()

    if cargs.log_name:
        setup_logger(logger, cargs.log_name)
    elif cargs.testid:
        setup_logger(logger, "{}.log".format(cargs.testid))
    else:
        setup_logger(logger)

    kwargs = {"base_url": copy.copy(CONF.BASE), 'idpconf': idpconf,
              "flows": fdef['Flows'], "orddesc": fdef['Order'],
              "desc": fdef['Desc'], 'metadata': mds,
              "profile": cargs.profile, "msg_factory": saml_message_factory,
              "check_factory": get_check, 'ca_certs': cargs.ca_certs,
              "cache": {}, "entity_id": cargs.entity_id,
              "profile_handler": None, 'map_prof': None,
              'make_entity': make_entity, 'trace_cls': Trace,
              'conv_args': {'entcat': collect_ec(), 'target_info': target_info}}

    opargs = {}
    if cargs.debug:
        opargs["debug"] = True
    if cargs.dump:
        opargs["dump"] = True

    if cargs.interaction:
        kwargs['interaction_conf'] = importlib.import_module(
            cargs.interaction).INTERACTION

    if cargs.insecure:
        kwargs["insecure"] = True

    return cargs.testid, kwargs, opargs


def make_entity(idp_name='basic', **kw_args):
    try:
        conf = kw_args["idpconf"][idp_name]
    except KeyError:
        logging.warning(
            "known IDP configs: {}".format(kw_args["idpconf"].keys()))
        raise

    return Server(config=conf)
