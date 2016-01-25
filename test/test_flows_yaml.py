from aatest.yamlcnf import parse_yaml_conf
from saml2test import operation
from saml2test.idp_test import func
from saml2test.idp_test import cl_request
from saml2test.idp_test import wb_request

__author__ = 'roland'


def test_1():
    cls_factories = {
        '': operation.factory,
        'cl': cl_request.factory,
        'wb': wb_request.factory,
    }
    func_factory = func.factory
    x = parse_yaml_conf('saml2test_flows.yaml', cls_factories, func_factory,
                        'cl')
    assert len(x['Flows']) == 16
