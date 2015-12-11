import json
import pprint
import argparse
import os.path
import sys
import traceback
from importlib import import_module

from saml2 import root_logger

from saml2.mdstore import MetadataStore, MetaData
from saml2.saml import NAME_FORMAT_UNSPECIFIED
from saml2.server import Server
from saml2.config import IdPConfig
from saml2.config import logging

from saml2test.sp_test import Conversation

from aatest import FatalError
from aatest import CheckError
from aatest import ContextFilter
from aatest import exception_trace
from aatest.check import CRITICAL

__author__ = 'rolandh'

# formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(
# message)s")
formatter_2 = logging.Formatter(
    "%(delta).6f - %(levelname)s - [%(name)s] %(message)s")

cf = ContextFilter()
cf.start()

streamhandler = logging.StreamHandler(sys.stderr)
streamhandler.setFormatter(formatter_2)

memoryhandler = logging.handlers.MemoryHandler(1024 * 10, logging.DEBUG)
memoryhandler.addFilter(cf)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(memoryhandler)
logger.setLevel(logging.DEBUG)


class Foo(object):

    def idp_configure(self, metadata_construction=False):
        sys.path.insert(0, self.args.configpath)
        mod = import_module(self.args.config)
        self.idp_config = IdPConfig().load(mod.CONFIG, metadata_construction)

        if not self.args.insecure:
            self.idp_config.verify_ssl_cert = False
        else:
            if self.args.ca_certs:
                self.idp_config.ca_certs = self.args.ca_certs
            else:
                self.idp_config.ca_certs = "../keys/cacert.pem"
        # hack to change idp cert without config change. TODO: find interface to
        # change IDP cert after __init__
        if self.args.oper == 'sp-04':
            self.idp_config.cert_file = os.path.join(self.args.keysdir,
                                                     "non_md_cert.pem")
            self.idp_config.key_file = os.path.join(self.args.keysdir,
                                                    "non_md_key.pem")
            for f in [self.idp_config.cert_file, self.idp_config.key_file]:
                if not os.path.isfile(f):
                    print("File not found: %s" % os.path.abspath(f))
                    raise FileNotFoundError

        self.idp = Server(config=self.idp_config)

    def test_summation(self, sid):
        status = 0
        for item in self.test_log:
            if item["status"] > status:
                status = item["status"]

        if status == 0:
            status = 1

        info = {
            "id": sid,
            "status": status,
            "tests": self.test_log
        }

        if status == 5:
            info["url"] = self.test_log[-1]["url"]
            info["htmlbody"] = self.test_log[-1]["message"]

        return info

    def output_log(self, memhndlr, hndlr2):
        """
        """

        print(80 * ":", file=sys.stderr)
        hndlr2.setFormatter(formatter_2)
        memhndlr.setTarget(hndlr2)
        memhndlr.flush()
        memhndlr.close()

    def run(self):
        self.args = self._parser.parse_args()

        if self.args.pysamllog:
            root_logger.addHandler(memoryhandler)
            root_logger.setLevel(logging.DEBUG)

        if self.args.metadata:
            return self.make_meta()
        elif self.args.list:
            return self.list_operations()
        elif self.args.oper == "check":
            return self.verify_metadata()
        else:
            if not self.args.oper:
                raise Exception("Missing test case specification")
            self.args.oper = self.args.oper.strip("'")
            self.args.oper = self.args.oper.strip('"')

        self.setup()

        try:
            oper = self.operations.OPERATIONS[self.args.oper]
        except KeyError:
            if self.tests:
                try:
                    oper = self.tests.OPERATIONS[self.args.oper]
                except ValueError:
                    print("Undefined testcase " + self.args.oper,
                          file=sys.stderr)
                    return
            else:
                print("Undefined testcase " + self.args.oper, file=sys.stderr)
                return

        if self.args.pretty:
            pp = pprint.PrettyPrinter(indent=4)
        else:
            pp = None

        logger.info("Starting conversation")
        conv = Conversation(self.idp, self.idp_config,
                            self.interactions, self.json_config,
                            check_factory=self.check_factory,
                            entity_id=self.entity_id,
                            constraints=self.constraints,
                            commandlineargs=self.args)
        try:
            conv.do_sequence_and_tests(oper["sequence"], oper["tests"])
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
            err = None
        except CheckError as err:
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
        except FatalError as err:
            if conv:
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
        except Exception as err:
            if conv:
                conv.test_output.append({"status": CRITICAL,
                                         "name": "test driver error",
                                         "id": "critial exception"})
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
            logger.error("Unexpected exception in test driver %s" %
                         traceback.format_exception(*sys.exc_info()))

        if pp:
            pp.pprint(tsum)
        else:
            print(json.dumps(tsum), file=sys.stdout)

        if tsum["status"] > 1 or self.args.debug or err:
            self.output_log(memoryhandler, streamhandler)

    def setup(self):
        self.json_config = self.json_config_file()

        _jc = self.json_config

        try:
            self.interactions = _jc["interaction"]
        except KeyError:
            self.interactions = []

        self.idp_configure()

        metadata = MetadataStore(self.idp_config.attribute_converters,
                                 self.idp_config)
        info = _jc["metadata"].encode("utf-8")
        md = MetaData(self.idp_config.attribute_converters, info)
        md.load()
        metadata[0] = md
        self.idp.metadata = metadata
        # self.idp_config.metadata = metadata

        if self.args.testpackage:
            self.tests = import_module("sp_test.package.%s" %
                                       self.args.testpackage)

        try:
            self.entity_id = _jc["entity_id"]
            # Verify its the correct metadata
            assert self.entity_id in md.entity.keys()
        except KeyError:
            if len(md.entity.keys()) == 1:
                self.entity_id = md.entity.keys()[0]
            else:
                raise Exception("Don't know which entity to talk to")

        if "constraints" in _jc:
            self.constraints = _jc["constraints"]
            if "name_format" not in self.constraints:
                self.constraints["name_format"] = NAME_FORMAT_UNSPECIFIED

    def make_meta(self):
        pass

    def list_operations(self):
        res = []
        for key, val in self.operations.OPERATIONS.items():
            res.append({"id": key, "name": val["name"]})

        print(json.dumps(res))

    def verify_metadata(self):
        pass
